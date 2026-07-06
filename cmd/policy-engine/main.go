// Command policy-engine is the policy/risk engine service entrypoint.
// It boots an HTTP server and connects to PostgreSQL via DB_URL, logging "db ready"
// once the connection is healthy.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/db"
)

func main() {
	port := envOr("PORT", "8080")
	dsn := os.Getenv("DB_URL")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if dsn == "" {
		log.Printf("warning: %s; running without DB", db.ErrMissingDBURL)
	} else {
		bootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		conn, err := db.Connect(bootCtx, dsn)
		cancel()
		if err != nil {
			log.Fatalf("db: %v", err)
		}
		defer conn.Close()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}