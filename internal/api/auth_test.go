package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeJWT(t *testing.T, claims Claims) string {
	t.Helper()
	header := map[string]any{"alg": "none", "typ": "JWT", "kid": "test"}
	hB, _ := json.Marshal(header)
	pB, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(hB) + "." +
		base64.RawURLEncoding.EncodeToString(pB) + ".sig"
}

func TestAuthMiddlewareDisabledByDefault(t *testing.T) {
	cfg := &AuthConfig{}
	if cfg.Enabled() {
		t.Fatal("zero config should be disabled")
	}
	called := false
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("handler not called when auth disabled")
	}
}

func TestAuthMiddlewareAdminRequiresBearer(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	called := false
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		c, ok := FromContext(r.Context())
		if !ok || c.Sub != "usr_1" {
			t.Errorf("claims missing: %+v ok=%v", c, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))
	token := makeJWT(t, Claims{Sub: "usr_1", Iss: "test-issuer", Scope: "policy:admin"})
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatalf("handler not called; body: %s", rec.Body.String())
	}
}

func TestAuthMiddlewareMissingScope(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	token := makeJWT(t, Claims{Sub: "usr_1", Iss: "test-issuer", Scope: "other:scope"})
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAuthMiddlewareNonAdminPasses(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	called := false
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/rules", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("GET rules should not require auth")
	}
}

func TestAuthMiddlewareEvaluatePasses(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	called := false
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/evaluate", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("evaluate should not require admin auth")
	}
}

func TestAuthMiddlewareBadIssuer(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "expected", AdminScopes: []string{"policy:admin"}, now: time.Now}
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	token := makeJWT(t, Claims{Sub: "usr_1", Iss: "wrong", Scope: "policy:admin"})
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad issuer, got %d", rec.Code)
	}
}

func TestAuthMiddlewareExpiredToken(t *testing.T) {
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }}
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	token := makeJWT(t, Claims{Sub: "usr_1", Iss: "test-issuer", Scope: "policy:admin", Exp: past.Unix()})
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired, got %d", rec.Code)
	}
}

func TestAuthMiddlewareMalformedToken(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddlewareBadAuthScheme(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "test-issuer", AdminScopes: []string{"policy:admin"}, now: time.Now}
	h := authMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/whitelist", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Basic abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestClaimsHasAnyScope(t *testing.T) {
	c := Claims{Scopes: []string{"a", "b"}}
	if !c.HasAnyScope([]string{"b"}) {
		t.Fatal("expected b match")
	}
	if c.HasAnyScope([]string{"c"}) {
		t.Fatal("c should not match")
	}
	c2 := Claims{Scope: "x y"}
	if !c2.HasAnyScope([]string{"y"}) {
		t.Fatal("expected y from space-delimited scope")
	}
}

func TestIsAdminPath(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/v1/policy/whitelist", true},
		{http.MethodPost, "/v1/policy/rules", true},
		{http.MethodPost, "/v1/policy/whitelist/u1/verify", true},
		{http.MethodPost, "/v1/policy/review/dec_1/resolve", true},
		{http.MethodGet, "/v1/policy/whitelist/u1", false},
		{http.MethodGet, "/v1/policy/rules", false},
		{http.MethodGet, "/v1/policy/review", false},
		{http.MethodPost, "/v1/policy/evaluate", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if got := isAdminPath(req); got != c.want {
			t.Errorf("%s %s: got %v want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestAudienceContains(t *testing.T) {
	if !audienceContains("x", "x") {
		t.Fatal("string match")
	}
	if !audienceContains([]any{"a", "b"}, "b") {
		t.Fatal("array match")
	}
	if audienceContains("x", "y") {
		t.Fatal("no match")
	}
}