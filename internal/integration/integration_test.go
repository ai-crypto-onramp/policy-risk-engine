// Package integration contains end-to-end integration tests for the
// policy/risk engine against real Postgres + Redis (via testcontainers) and
// the gRPC + REST evaluate path. These tests are skipped unless the
// integration flag is enabled (set INTEGRATION=1 or DOCKER_HOST is available).
package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/api"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/caps"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/db"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/evaluate"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/velocity"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
	policypb "github.com/ai-crypto-onramp/policy-risk-engine/proto/policy/v1"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION") == "" && os.Getenv("DOCKER_HOST") == "" {
		// Still allow running if docker daemon is reachable.
		if _, err := net.DialTimeout("tcp", "localhost:2375", 200*time.Millisecond); err != nil {
			t.Skip("INTEGRATION not set / docker not reachable; skipping")
		}
	}
}

// startPostgres brings up a Postgres container, applies migrations, and
// returns a DSN + cleanup function.
func startPostgres(t *testing.T) (dsn string, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	pgC, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("policytest"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	connStr, err := pgC.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres conn string: %v", err)
	}
	cleanup = func() {
		_ = pgC.Terminate(ctx)
	}
	if err := db.MigrateUp(connStr, "../../migrations"); err != nil {
		cleanup()
		t.Fatalf("migrate up: %v", err)
	}
	return connStr, cleanup
}

// startRedis brings up a Redis container + cleanup.
func startRedis(t *testing.T) (url string, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	redisC, err := redis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Fatalf("start redis: %v", err)
	}
	host, err := redisC.Host(ctx)
	if err != nil {
		_ = redisC.Terminate(ctx)
		t.Fatalf("redis host: %v", err)
	}
	port, err := redisC.MappedPort(ctx, "6379")
	if err != nil {
		_ = redisC.Terminate(ctx)
		t.Fatalf("redis port: %v", err)
	}
	return fmt.Sprintf("redis://%s:%s", host, port.Port()), func() { _ = redisC.Terminate(ctx) }
}

func startService(t *testing.T, dsn string) (*api.Services, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	bundle, err := engine.LoadBundleFromDir("../../policies")
	if err != nil {
		cancel()
		t.Fatalf("load bundle: %v", err)
	}
	eng := engine.NewOPAEngine(bundle)
	capsCfg := caps.DefaultConfig()
	authCfg := &api.AuthConfig{}

	database, err := db.Connect(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect db: %v", err)
	}
	audStore := db.NewAuditStore(database)
	if err := audStore.EnsurePolicyVersion(eng.Version(), eng.Hash(), "", "integration-test"); err != nil {
		cancel()
		t.Fatalf("ensure policy version: %v", err)
	}
	wl := whitelist.NewService(db.NewWhitelistStore(database))
	rev := review.NewService(db.NewReviewStore(database))
	audSvc := audit.NewService(audit.NewSigner(nil), audStore, audit.NewMemorySink(), 1024).WithSyncPersist()
	vel := velocity.NewMemoryCounter()
	evalSvc := evaluate.NewService(eng, vel, &capsCfg, wl, rev, audSvc)
	evalSvc.SetSessionValidDefault(true)
	services := &api.Services{
		Evaluate: evalSvc, Whitelist: wl, Review: rev, Audit: audSvc,
		Engine: eng, Auth: authCfg, DB: database,
	}
	port := freePort(t)
	srv := api.NewServer(services, ":"+strconv.Itoa(port))
	go func() { _ = srv.ListenAndServe() }()
	grpcSrv, grpcLis, err := api.NewGRPCServer(services, strconv.Itoa(freePort(t)))
	if err != nil {
		cancel()
		_ = srv.Close()
		t.Fatalf("grpc server: %v", err)
	}
	go func() { _ = grpcSrv.Serve(grpcLis) }()
	services.GRPCAddr = grpcLis.Addr().String()
	services.HTTPAddr = srv.Addr
	cleanup := func() {
		grpcSrv.GracefulStop()
		_ = srv.Close()
		_ = database.Close()
		cancel()
	}
	return services, cleanup
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestIntegrationEvaluateDenyNotWhitelisted(t *testing.T) {
	skipIfNoDocker(t)
	dsn, dbCleanup := startPostgres(t)
	defer dbCleanup()
	services, cleanup := startService(t, dsn)
	defer cleanup()

	conn, err := grpc.NewClient(services.GRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := policypb.NewPolicyClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.Evaluate(ctx, &policypb.EvaluateRequest{
		UserId: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KytVerdict: "clean", FraudScore: 0.1, KycStatus: "verified",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s", resp.Decision)
	}
	if resp.DecisionId == "" {
		t.Fatal("empty decision id")
	}
}

func TestIntegrationEvaluateAllowWhitelisted(t *testing.T) {
	skipIfNoDocker(t)
	dsn, dbCleanup := startPostgres(t)
	defer dbCleanup()
	services, cleanup := startService(t, dsn)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := services.Whitelist.Add(ctx, "usr_1", "ethereum", "0xabc", "savings"); err != nil {
		t.Fatalf("whitelist add: %v", err)
	}
	if _, err := services.Whitelist.Verify(ctx, "usr_1", "ethereum", "0xabc"); err != nil {
		t.Fatalf("whitelist verify: %v", err)
	}

	conn, err := grpc.NewClient(services.GRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := policypb.NewPolicyClient(conn)
	resp, err := client.Evaluate(ctx, &policypb.EvaluateRequest{
		UserId: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KytVerdict: "clean", FraudScore: 0.1, KycStatus: "verified",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
}

func TestIntegrationReviewQueueLifecycle(t *testing.T) {
	skipIfNoDocker(t)
	dsn, dbCleanup := startPostgres(t)
	defer dbCleanup()
	services, cleanup := startService(t, dsn)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := services.Whitelist.Add(ctx, "usr_1", "ethereum", "0xabc", ""); err != nil {
		t.Fatalf("wl add: %v", err)
	}
	if _, err := services.Whitelist.Verify(ctx, "usr_1", "ethereum", "0xabc"); err != nil {
		t.Fatalf("wl verify: %v", err)
	}
	resp, err := services.Evaluate.Evaluate(ctx, evaluate.Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.6, KYCStatus: "verified",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision != "manual_review" {
		t.Fatalf("decision: %s", resp.Decision)
	}
	item, err := services.Review.Get(ctx, resp.DecisionID)
	if err != nil {
		t.Fatalf("review get: %v", err)
	}
	if item.Status != review.StatusPending {
		t.Fatalf("status: %s", item.Status)
	}
	resolved, err := services.Review.Resolve(ctx, resp.DecisionID, "reviewer_1", review.ResolutionAllow)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Status != review.StatusResolved {
		t.Fatalf("status: %s", resolved.Status)
	}
	_, err = services.Review.Resolve(ctx, resp.DecisionID, "r2", review.ResolutionDeny)
	if err == nil {
		t.Fatal("expected double-resolve to fail")
	}
}

func TestIntegrationRedisCounter(t *testing.T) {
	skipIfNoDocker(t)
	redisURL, redisCleanup := startRedis(t)
	defer redisCleanup()
	addr := strings.TrimPrefix(redisURL, "redis://")
	counter := velocity.NewRedisCounter(addr, "vel")
	defer counter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := counter.Ping(ctx); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	v, err := counter.Increment(ctx, "usr_1", velocity.WindowMinute)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if v != 1 {
		t.Fatalf("first incr: %d", v)
	}
	v, _ = counter.Increment(ctx, "usr_1", velocity.WindowMinute)
	if v != 2 {
		t.Fatalf("second incr: %d", v)
	}
	v, _ = counter.Rollback(ctx, "usr_1", velocity.WindowMinute)
	if v != 1 {
		t.Fatalf("rollback: %d", v)
	}
	got, _ := counter.Get(ctx, "usr_1", velocity.WindowMinute)
	if got != 1 {
		t.Fatalf("get: %d", got)
	}
}

func TestIntegrationRESTEvaluate(t *testing.T) {
	skipIfNoDocker(t)
	dsn, dbCleanup := startPostgres(t)
	defer dbCleanup()
	services, cleanup := startService(t, dsn)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := `{"user_id":"usr_1","amount":"100","currency":"USD","dest_address":"0xabc","dest_chain":"ethereum","kyt_verdict":"clean","fraud_score":0.1,"kyc_status":"verified"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+services.HTTPAddr+"/v1/policy/evaluate", strReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func strReader(s string) *strings.Reader {
	return strings.NewReader(s)
}