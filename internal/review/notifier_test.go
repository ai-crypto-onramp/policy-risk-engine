package review

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotifierDisabledByDefault(t *testing.T) {
	n := NewNotifier()
	if n.Enabled() {
		t.Fatal("expected disabled by default")
	}
	if err := n.NotifyResolution(context.Background(), Item{}); err != nil {
		t.Fatalf("no-op notifier returned error: %v", err)
	}
}

func TestNotifierDisabledNil(t *testing.T) {
	var n *Notifier
	if err := n.NotifyResolution(context.Background(), Item{}); err != nil {
		t.Fatalf("nil notifier returned error: %v", err)
	}
}

func TestNotifierPostsResolution(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") != "dec_1" {
			t.Errorf("idempotency key: %q", r.Header.Get("Idempotency-Key"))
		}
		body, _ := io.ReadAll(r.Body)
		var item Item
		_ = json.Unmarshal(body, &item)
		if item.DecisionID != "dec_1" || item.Resolution != "ALLOW" {
			t.Errorf("item: %+v", item)
		}
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("TX_ORCHESTRATOR_WEBHOOK_URL", srv.URL)
	n := NewNotifier()
	if !n.Enabled() {
		t.Fatal("expected enabled")
	}
	now := time.Now()
	item := Item{DecisionID: "dec_1", Status: StatusResolved, Resolution: ResolutionAllow, ResolvedAt: &now}
	if err := n.NotifyResolution(context.Background(), item); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if received.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", received.Load())
	}
}

func TestNotifierRetriesOn5xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("TX_ORCHESTRATOR_WEBHOOK_URL", srv.URL)
	n := NewNotifier()
	n.client.Timeout = 2 * time.Second
	now := time.Now()
	item := Item{DecisionID: "dec_1", Status: StatusResolved, Resolution: ResolutionDeny, ResolvedAt: &now}
	if err := n.NotifyResolution(context.Background(), item); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if attempts.Load() < 3 {
		t.Fatalf("expected retries, got %d attempts", attempts.Load())
	}
}

func TestNotifier4xxNoRetry(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv("TX_ORCHESTRATOR_WEBHOOK_URL", srv.URL)
	n := NewNotifier()
	n.client.Timeout = 2 * time.Second
	now := time.Now()
	item := Item{DecisionID: "dec_1", Status: StatusResolved, Resolution: ResolutionAllow, ResolvedAt: &now}
	if err := n.NotifyResolution(context.Background(), item); err == nil {
		t.Fatal("expected error for 4xx")
	}
	if attempts.Load() != 1 {
		t.Fatalf("expected no retry for 4xx, got %d", attempts.Load())
	}
}

func TestNotifierRejectsUnresolved(t *testing.T) {
	n := &Notifier{url: "http://x", client: http.DefaultClient}
	if err := n.NotifyResolution(context.Background(), Item{Status: StatusPending}); err == nil {
		t.Fatal("expected error for unresolved item")
	}
}

func TestServiceResolveNotifies(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("TX_ORCHESTRATOR_WEBHOOK_URL", srv.URL)
	n := NewNotifier()
	s := NewService(NewMemoryStore()).WithNotifier(n)
	_, _ = s.Park(context.Background(), "dec_1", "")
	if _, err := s.Resolve(context.Background(), "dec_1", "r", ResolutionAllow); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if received.Load() != 1 {
		t.Fatalf("expected 1 webhook, got %d", received.Load())
	}
}