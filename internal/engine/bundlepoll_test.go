package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadBundleFromURLRego(t *testing.T) {
	body := "package policy.decisions\n\nallow { input.x }\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	b, err := LoadBundleFromURL(context.Background(), nil, srv.URL)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.Hash == "" {
		t.Fatal("empty hash")
	}
	if got, ok := b.Source["staged.rego"]; !ok || got != body {
		t.Fatalf("source: %+v", b.Source)
	}
}

func TestLoadBundleFromURLEmpty(t *testing.T) {
	if _, err := LoadBundleFromURL(context.Background(), nil, ""); err == nil {
		t.Fatal("expected error for empty url")
	}
}

func TestLoadBundleFromURLBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := LoadBundleFromURL(context.Background(), nil, srv.URL); err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestPollerStagesNewBundle(t *testing.T) {
	current := "hash-current"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "package policy.decisions\n\nallow { input.y }\n")
	}))
	defer srv.Close()

	eng := &OPAEngine{bundle: &Bundle{Hash: current, Version: current}}
	var staged atomic.Int32
	p := NewPoller(srv.URL, 20*time.Millisecond, eng, func(b *Bundle) {
		if b.Hash != current {
			staged.Add(1)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	time.Sleep(150 * time.Millisecond)
	p.Stop()
	if staged.Load() == 0 {
		t.Fatal("expected at least one staged bundle")
	}
}

func TestPollerSkipsSameHash(t *testing.T) {
	body := "package policy.decisions\n\nallow { input.y }\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	b, _ := LoadBundleFromURL(context.Background(), nil, srv.URL)
	eng := &OPAEngine{bundle: b}
	var staged atomic.Int32
	p := NewPoller(srv.URL, 20*time.Millisecond, eng, func(b2 *Bundle) { staged.Add(1) })
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	p.Start(ctx)
	time.Sleep(120 * time.Millisecond)
	p.Stop()
	if staged.Load() != 0 {
		t.Fatalf("expected no staging for same hash, got %d", staged.Load())
	}
}

func TestPollerStops(t *testing.T) {
	p := NewPoller("", 1*time.Second, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	p.Stop()
}

func TestEnvIntDefault(t *testing.T) {
	if envInt("NOT_SET_VAR_XYZ", 42) != 42 {
		t.Fatal("default not applied")
	}
}

func TestIsRegoContent(t *testing.T) {
	if !isRegoContent("text/plain", []byte("# comment\npackage policy.x\n")) {
		t.Fatal("expected rego detection")
	}
	if isRegoContent("application/gzip", []byte("package")) {
		t.Fatal("unexpected rego detection")
	}
}