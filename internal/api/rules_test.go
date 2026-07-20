package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
)

func TestPublishRulesHandlerEmptyBody(t *testing.T) {
	s := newTestServices(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rules", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishRulesHandlerWhitespaceBody(t *testing.T) {
	s := newTestServices(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rules", bytes.NewBufferString("   \n\t  "))
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}


func TestPublishRulesHandlerInvalidRegoOnActivate(t *testing.T) {
	s := newTestServices(t)
	eng, ok := s.Engine.(*engine.OPAEngine)
	if !ok {
		t.Fatalf("engine is not *OPAEngine: %T", s.Engine)
	}
	before := eng.Hash()
	// publishBundle only hashes the source; the compile failure happens on
	// Swap. With activate=true the handler swaps the bundle, which triggers
	// rebuild(). rebuild() leaves the previous compiler intact on compile
	// failure, so the handler still returns 201.
	body := bytes.NewBufferString("not valid rego {{{")
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rules?activate=true", body)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	// Hash changed because the bundle was swapped (even though rebuild left
	// the old compiler intact).
	if eng.Hash() == before {
		t.Errorf("hash should change after swap even on compile failure")
	}
}

func TestPublishRulesHandlerValidRegoNoActivate(t *testing.T) {
	s := newTestServices(t)
	body := bytes.NewBufferString("package policy.decisions\n\nallow { input.x }\n")
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rules", body)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"activate":false`) {
		t.Errorf("expected activate=false: %s", rec.Body.String())
	}
}

func TestPublishRulesHandlerValidRegoActivate(t *testing.T) {
	s := newTestServices(t)
	eng, ok := s.Engine.(*engine.OPAEngine)
	if !ok {
		t.Fatalf("engine is not *OPAEngine: %T", s.Engine)
	}
	before := eng.Hash()
	body := bytes.NewBufferString("package policy.decisions\n\nallow { input.x }\n")
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rules?activate=true", body)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if eng.Hash() == before {
		t.Errorf("engine hash did not change after activate")
	}
}

func TestPublishRulesHandlerEngineNotOPA(t *testing.T) {
	s := newTestServices(t)
	s.Engine = fakeEngine{}
	body := bytes.NewBufferString("package p\nallow { true }\n")
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/rules", body)
	rec := httptest.NewRecorder()
	NewMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestPublishBundleEmpty(t *testing.T) {
	b, _ := engine.LoadBundleFromDir("../../policies")
	eng := engine.NewOPAEngine(b)
	if _, err := publishBundle(context.Background(), eng, nil); err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestPublishBundleRepublishSameHash(t *testing.T) {
	b, _ := engine.LoadBundleFromDir("../../policies")
	eng := engine.NewOPAEngine(b)
	src := "package policy.decisions\n\nallow { input.x }\n"
	b1, err := publishBundle(context.Background(), eng, []byte(src))
	if err != nil {
		t.Fatalf("publish1: %v", err)
	}
	b2, err := publishBundle(context.Background(), eng, []byte(src))
	if err != nil {
		t.Fatalf("publish2: %v", err)
	}
	if b1.Hash != b2.Hash || b1.Version != b2.Version {
		t.Fatalf("republish should yield same hash/version: %s vs %s", b1.Hash, b2.Hash)
	}
}

func TestPublishBundlePreservesCurrentData(t *testing.T) {
	b, _ := engine.LoadBundleFromDir("../../policies")
	eng := engine.NewOPAEngine(b)
	current := eng.Bundle()
	if current == nil || len(current.Data) == 0 {
		t.Skip("bundle has no data to preserve")
	}
	out, err := publishBundle(context.Background(), eng, []byte("package policy.decisions\n\nallow { input.x }\n"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	for k := range current.Data {
		if _, ok := out.Data[k]; !ok {
			t.Errorf("data key %q not preserved", k)
		}
	}
}

func TestBytesTrim(t *testing.T) {
	if got := bytesTrim([]byte("  \n\thello")); string(got) != "hello" {
		t.Errorf("bytesTrim: %q", got)
	}
	if got := bytesTrim([]byte("hello")); string(got) != "hello" {
		t.Errorf("bytesTrim no-trim: %q", got)
	}
	if len(bytesTrim(nil)) != 0 {
		t.Error("bytesTrim(nil) not empty")
	}
}

type fakeEngine struct{}

func (fakeEngine) Evaluate(context.Context, map[string]any) (engine.Result, error) {
	return engine.Result{}, nil
}
func (fakeEngine) Hash() string    { return "h" }
func (fakeEngine) Version() string  { return "v" }