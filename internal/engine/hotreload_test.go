package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHotReloaderSwapsOnNewBundle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "package policy.decisions\n\nallow { input.z }\n")
	}))
	defer srv.Close()

	b, _ := LoadBundleFromDir("../../policies")
	eng := NewOPAEngine(b)
	h := NewHotReloader(srv.URL, 20*time.Millisecond, eng)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	h.Stop()
	if h.Swaps() == 0 {
		t.Fatal("expected at least one swap")
	}
}

func TestHotReloaderSkipsSameHash(t *testing.T) {
	body := "package policy.decisions\n\nallow { input.z }\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	b, _ := LoadBundleFromURL(context.Background(), nil, srv.URL)
	eng := NewOPAEngine(b)
	h := NewHotReloader(srv.URL, 20*time.Millisecond, eng)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	h.Start(ctx)
	time.Sleep(120 * time.Millisecond)
	h.Stop()
	if h.Swaps() != 0 {
		t.Fatalf("expected no swaps for same hash, got %d", h.Swaps())
	}
}

func TestHotReloaderValidationFailsNoSwap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "not rego at all")
	}))
	defer srv.Close()

	b, _ := LoadBundleFromDir("../../policies")
	eng := NewOPAEngine(b)
	h := NewHotReloader(srv.URL, 20*time.Millisecond, eng).WithValidate(func(b *Bundle) error {
		return fmt.Errorf("reject")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	h.Start(ctx)
	time.Sleep(120 * time.Millisecond)
	h.Stop()
	if h.Swaps() != 0 {
		t.Fatalf("expected no swaps on validation failure, got %d", h.Swaps())
	}
}

func TestHotReloaderEmptyURL(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	eng := NewOPAEngine(b)
	h := NewHotReloader("", 20*time.Millisecond, eng)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	h.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	h.Stop()
	if h.Swaps() != 0 {
		t.Fatalf("expected no swaps for empty url, got %d", h.Swaps())
	}
}

func TestHotReloaderStops(t *testing.T) {
	h := NewHotReloader("", 1*time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.Start(ctx)
	h.Stop()
}

func TestDefaultValidateEmptyBundle(t *testing.T) {
	if err := defaultValidate(&Bundle{Source: map[string]string{}}); err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestDefaultValidateCompiles(t *testing.T) {
	if err := defaultValidate(&Bundle{Source: map[string]string{"x.rego": "package p\nallow { true }\n"}}); err != nil {
		t.Fatalf("valid bundle failed: %v", err)
	}
}

func TestDefaultValidateBadRego(t *testing.T) {
	if err := defaultValidate(&Bundle{Source: map[string]string{"x.rego": "not valid rego {"}}); err == nil {
		t.Fatal("expected error for invalid rego")
	}
}

func TestHotReloadIntervalFromEnv(t *testing.T) {
	t.Setenv("POLICY_HOT_RELOAD_INTERVAL", "42")
	if got := hotReloadIntervalFromEnv(); got != 42*time.Second {
		t.Fatalf("interval: %v want 42s", got)
	}
}

func TestHotReloaderAtomicSwapNoInFlightDrop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "package policy.decisions\n\nallow { input.z }\n")
	}))
	defer srv.Close()

	b, _ := LoadBundleFromDir("../../policies")
	eng := NewOPAEngine(b)
	h := NewHotReloader(srv.URL, 10*time.Millisecond, eng)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	h.Start(ctx)
	var done atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = eng.Evaluate(ctx, map[string]any{
				"user_id": "u", "amount_usd": 100.0, "kyt_verdict": "clean",
				"fraud_score": 0.1, "kyc_status": "verified",
				"dest_address": "0xabc", "whitelisted": true, "requires_2fa": false,
			})
			done.Add(1)
		}()
	}
	wg.Wait()
	h.Stop()
	if done.Load() != 50 {
		t.Fatalf("only %d/50 evaluates completed", done.Load())
	}
}