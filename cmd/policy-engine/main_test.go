package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/api"
)

func TestBuildServices(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir("cmd/policy-engine") }()
	svc, err := buildServices(context.Background())
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}
	if svc == nil || svc.Evaluate == nil || svc.Engine == nil {
		t.Fatalf("services incomplete: %+v", svc)
	}
	defer svc.Audit.Close()
}

func TestRunBootsAndShutsDown(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir("cmd/policy-engine") }()
	t.Setenv("PORT", "0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

func TestEnvOr(t *testing.T) {
	if got := envOr("NONEXISTENT_KEY_XYZ", "def"); got != "def" {
		t.Errorf("envOr default: %s", got)
	}
	t.Setenv("NONEXISTENT_KEY_XYZ", "val")
	if got := envOr("NONEXISTENT_KEY_XYZ", "def"); got != "val" {
		t.Errorf("envOr: %s", got)
	}
}

func TestHealthzRoute(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir("cmd/policy-engine") }()
	svc, err := buildServices(context.Background())
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}
	defer svc.Audit.Close()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	api.NewMux(svc).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
}