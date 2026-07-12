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
	services, err := buildServices()
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
	srv := api.NewServer(services, ":"+port)

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
	return srv.Shutdown(shutdownCtx)
}

// buildServices constructs the *api.Services. When DB_URL/REDIS_URL are unset
// it uses in-memory implementations.
func buildServices() (*api.Services, error) {
	bundleDir := envOr("POLICIES_DIR", "policies")
	bundle, err := engine.LoadBundleFromDir(bundleDir)
	if err != nil {
		return nil, err
	}
	eng := engine.NewOPAEngine(bundle)

	vel := velocity.NewMemoryCounter()
	capsCfg := caps.DefaultConfig()
	wl := whitelist.NewService(whitelist.NewMemoryStore())
	rev := review.NewService(review.NewMemoryStore())
	audSvc := audit.NewService(audit.NewSigner(nil), audit.NewMemoryStore(), audit.NewMemorySink(), 1024)
	evalSvc := evaluate.NewService(eng, vel, &capsCfg, wl, rev, audSvc)

	return &api.Services{Evaluate: evalSvc, Whitelist: wl, Review: rev, Audit: audSvc, Engine: eng}, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}