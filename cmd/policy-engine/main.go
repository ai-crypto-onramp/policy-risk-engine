// Command policy-engine is the policy/risk engine service entrypoint.
// It boots an HTTP server with the evaluate, whitelist, review, rules, and
// metrics endpoints. When DB_URL is unset it runs in a degraded in-memory mode
// suitable for local development.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatalf("policy-engine: %v", err)
	}
}

// run wires all services and runs the HTTP server until ctx is cancelled.
func run(ctx context.Context) error {
	services, err := buildServices(ctx)
	if err != nil {
		return err
	}
	if services.Audit != nil {
		defer services.Audit.Close()
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	grpcPort := os.Getenv("GRPC_PORT")
	if grpcPort == "" {
		grpcPort = "9090"
	}

	srv := api.NewServer(services, ":"+port)

	// gRPC server (mTLS-protected) on the transaction path.
	grpcSrv, grpcLis, grpcErr := api.NewGRPCServer(services, grpcPort)
	if grpcErr != nil {
		log.Printf("grpc: %v (gRPC path disabled)", grpcErr)
	} else {
		go func() {
			log.Printf("policy-engine gRPC listening on :%s", grpcPort)
			if err := grpcSrv.Serve(grpcLis); err != nil {
				log.Printf("grpc serve: %v", err)
			}
		}()
	}

	// Bundle hot-reload poller (Stage 2). Stages new bundles from
	// OPA_BUNDLE_URL without activating; activation is handled by the
	// Stage 8 hot-reload path when POLICY_HOT_RELOAD_INTERVAL is set.
	if bundleURL := os.Getenv("OPA_BUNDLE_URL"); bundleURL != "" {
		if opaEng, ok := services.Engine.(*engine.OPAEngine); ok {
			// When POLICY_HOT_RELOAD_INTERVAL is set, use the HotReloader
			// which stages + validates + atomically swaps. Otherwise use
			// the Stage 2 Poller which only stages.
			hotReloadSec := os.Getenv("POLICY_HOT_RELOAD_INTERVAL")
			if hotReloadSec != "" {
				reloader := engine.NewHotReloader(bundleURL, 0, opaEng)
				reloader.Start(ctx)
				defer reloader.Stop()
			} else {
				poller := engine.NewPoller(bundleURL, 0, opaEng, func(b *engine.Bundle) {
					log.Printf("bundle staged v%s (hot-reload pending activation)", b.Version)
				})
				poller.Start(ctx)
				defer poller.Stop()
			}
		}
	}

	go func() {
		log.Printf("policy-engine listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if grpcSrv != nil {
		grpcSrv.GracefulStop()
	}
	return srv.Shutdown(shutdownCtx)
}

// buildServices constructs the *api.Services. When DB_URL is set it connects to
// Postgres, runs migrations, and uses DB-backed stores; otherwise it uses
// in-memory implementations. REDIS_URL is accepted but velocity remains
// in-memory until a Redis counter implementation exists.
func buildServices(ctx context.Context) (*api.Services, error) {
	bundleDir := envOr("POLICIES_DIR", "policies")
	bundle, err := engine.LoadBundleFromDir(bundleDir)
	if err != nil {
		return nil, err
	}
	eng := engine.NewOPAEngine(bundle)

	capsCfg := caps.DefaultConfig()
	authCfg := api.NewAuthConfig()

	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		return buildInMemoryServices(eng, &capsCfg, authCfg), nil
	}

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	database, err := db.Connect(connectCtx, dsn)
	if err != nil {
		return nil, err
	}

	migrationsDir := envOr("MIGRATIONS_DIR", "migrations")
	if err := db.MigrateUp(dsn, migrationsDir); err != nil {
		_ = database.Close()
		return nil, err
	}

	wlStore := db.NewWhitelistStore(database)
	revStore := db.NewReviewStore(database)
	audStore := db.NewAuditStore(database)
	if err := audStore.EnsurePolicyVersion(eng.Version(), eng.Hash(), "", "policy-engine"); err != nil {
		_ = database.Close()
		return nil, err
	}

	wl := whitelist.NewService(wlStore)
	rev := review.NewService(revStore).WithNotifier(review.NewNotifier())
	// Synchronous persistence ensures the decision row exists before
	// review.Park inserts the FK-referencing review_queue row.
	audSvc := audit.NewService(audit.NewSigner(nil), audStore, audit.NewMemorySink(), 1024).WithSyncPersist()

	vel := velocity.NewMemoryCounter()
	evalSvc := evaluate.NewService(eng, vel, &capsCfg, wl, rev, audSvc)
	if !authCfg.Enabled() {
		evalSvc.SetSessionValidDefault(true)
	}

	return &api.Services{Evaluate: evalSvc, Whitelist: wl, Review: rev, Audit: audSvc, Engine: eng, Auth: authCfg, DB: database}, nil
}

// buildInMemoryServices wires the in-memory implementations used for local
// development and tests.
func buildInMemoryServices(eng engine.Engine, capsCfg *caps.Config, authCfg *api.AuthConfig) *api.Services {
	vel := velocity.NewMemoryCounter()
	wl := whitelist.NewService(whitelist.NewMemoryStore())
	rev := review.NewService(review.NewMemoryStore())
	audSvc := audit.NewService(audit.NewSigner(nil), audit.NewMemoryStore(), audit.NewMemorySink(), 1024)
	evalSvc := evaluate.NewService(eng, vel, capsCfg, wl, rev, audSvc)
	if !authCfg.Enabled() {
		evalSvc.SetSessionValidDefault(true)
	}
	return &api.Services{Evaluate: evalSvc, Whitelist: wl, Review: rev, Audit: audSvc, Engine: eng, Auth: authCfg}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}