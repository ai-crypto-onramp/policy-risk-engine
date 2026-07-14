// Package loadtest provides a load test harness for the gRPC Evaluate path
// that asserts p99 latency < 50ms with an in-process OPA engine + in-memory
// velocity counter (no external deps).
package loadtest

import (
	"context"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/api"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/caps"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/evaluate"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/velocity"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
	policypb "github.com/ai-crypto-onramp/policy-risk-engine/proto/policy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Run exercises the gRPC Evaluate path with N concurrent workers each issuing
// QPS requests, then asserts p99 < threshold. It fails t when the p99 exceeds
// threshold.
func Run(t *testing.T, workers, requestsPerWorker int, threshold time.Duration) {
	t.Helper()
	b, err := engine.LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	eng := engine.NewOPAEngine(b)
	vel := velocity.NewMemoryCounter()
	capsCfg := &caps.Config{DefaultDailyCapUSD: 10000, DefaultTXCapUSD: 2500, NearCapThreshold: 0.9, Rules: caps.SeedRules()}
	wl := whitelist.NewService(whitelist.NewMemoryStore())
	_, _ = wl.Add(context.Background(), "usr_1", "ethereum", "0xabc", "")
	_, _ = wl.Verify(context.Background(), "usr_1", "ethereum", "0xabc")
	rev := review.NewService(review.NewMemoryStore())
	audSvc := audit.NewService(audit.NewSigner(nil), audit.NewMemoryStore(), audit.NewMemorySink(), 1024)
	defer audSvc.Close()
	evalSvc := evaluate.NewService(eng, vel, capsCfg, wl, rev, audSvc)
	evalSvc.SetSessionValidDefault(true)
	services := &api.Services{Evaluate: evalSvc, Whitelist: wl, Review: rev, Audit: audSvc, Engine: eng}

	srv, lis, err := api.NewGRPCServer(services, "0")
	if err != nil {
		t.Fatalf("grpc server: %v", err)
	}
	defer srv.Stop()
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := policypb.NewPolicyClient(conn)

	req := &policypb.EvaluateRequest{
		UserId: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KytVerdict: "clean", FraudScore: 0.1, KycStatus: "verified",
	}

	// Warmup.
	for i := 0; i < 50; i++ {
		_, _ = client.Evaluate(context.Background(), req)
	}

	total := int64(workers * requestsPerWorker)
	var done atomic.Int64
	var wg sync.WaitGroup
	latencies := make([]int64, total)
	var mu sync.Mutex
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < requestsPerWorker; i++ {
				start := time.Now()
				_, err := client.Evaluate(context.Background(), req)
				dur := time.Since(start)
				if err != nil {
					continue
				}
				idx := done.Add(1) - 1
				mu.Lock()
				if int(idx) < len(latencies) {
					latencies[idx] = dur.Nanoseconds()
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	valid := latencies[:done.Load()]
	if len(valid) == 0 {
		t.Fatal("no successful requests")
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i] < valid[j] })
	p50 := time.Duration(valid[len(valid)/2])
	p99Idx := int(math.Ceil(0.99 * float64(len(valid))))
	if p99Idx >= len(valid) {
		p99Idx = len(valid) - 1
	}
	p99 := time.Duration(valid[p99Idx])
	t.Logf("load: workers=%d reqs=%d p50=%s p99=%s threshold=%s", workers, len(valid), p50, p99, threshold)
	if p99 > threshold {
		t.Fatalf("p99 %s exceeded threshold %s", p99, threshold)
	}
}