package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewAuthConfigDisabled(t *testing.T) {
	t.Setenv("JWT_ISSUER", "")
	cfg := NewAuthConfig()
	if cfg.Enabled() {
		t.Fatal("expected disabled when JWT_ISSUER empty")
	}
}

func TestNewAuthConfigEnabled(t *testing.T) {
	t.Setenv("JWT_ISSUER", "issuer")
	t.Setenv("JWT_AUDIENCE", "aud")
	t.Setenv("JWT_ADMIN_SCOPES", "a b c")
	cfg := NewAuthConfig()
	if !cfg.Enabled() {
		t.Fatal("expected enabled")
	}
	if cfg.JWTIssuer != "issuer" || cfg.JWTAudience != "aud" {
		t.Errorf("iss/aud: %q/%q", cfg.JWTIssuer, cfg.JWTAudience)
	}
	if len(cfg.AdminScopes) != 3 {
		t.Errorf("scopes: %v", cfg.AdminScopes)
	}
}

func TestNewAuthConfigJWKSResolver(t *testing.T) {
	t.Setenv("JWT_ISSUER", "issuer")
	t.Setenv("JWT_JWKS_URL", "http://example.invalid/jwks")
	cfg := NewAuthConfig()
	if cfg.jwksResolver == nil {
		t.Fatal("expected jwks resolver set when JWKSURL configured")
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("OP_TEST_ENV_X", "")
	if got := envOr("OP_TEST_ENV_X", "fallback"); got != "fallback" {
		t.Fatalf("envOr fallback: %q", got)
	}
	t.Setenv("OP_TEST_ENV_X", "set")
	if got := envOr("OP_TEST_ENV_X", "fallback"); got != "set" {
		t.Fatalf("envOr set: %q", got)
	}
}

func TestValidateBearerMissingHeader(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", now: time.Now}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := cfg.validateBearer(req); err == nil {
		t.Fatal("expected error for missing auth header")
	}
}

func TestValidateBearerNonBearer(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", now: time.Now}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic abc")
	if _, err := cfg.validateBearer(req); err == nil {
		t.Fatal("expected error for non-Bearer scheme")
	}
}

func TestValidateBearerEmptyToken(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", now: time.Now}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	if _, err := cfg.validateBearer(req); err == nil {
		t.Fatal("expected error for empty bearer token")
	}
}

func TestParseAndValidateMalformed(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", now: time.Now}
	if _, err := cfg.parseAndValidate("not.a.jwt"); err == nil {
		t.Fatal("expected error for non-3-part token")
	}
	if _, err := cfg.parseAndValidate("a.b.c"); err == nil {
		t.Fatal("expected error for invalid base64 header")
	}
}

func TestParseAndValidateAudienceStringMatch(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", JWTAudience: "aud", now: time.Now}
	claims := Claims{Iss: "iss", Aud: "aud"}
	token := makeJWT(t, claims)
	if _, err := cfg.parseAndValidate(token); err != nil {
		t.Fatalf("aud string match: %v", err)
	}
}

func TestParseAndValidateAudienceStringMismatch(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", JWTAudience: "want", now: time.Now}
	claims := Claims{Iss: "iss", Aud: "other"}
	token := makeJWT(t, claims)
	if _, err := cfg.parseAndValidate(token); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestParseAndValidateAudienceArrayMatch(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", JWTAudience: "b", now: time.Now}
	header := map[string]any{"alg": "none", "typ": "JWT"}
	hB, _ := json.Marshal(header)
	claims := Claims{Iss: "iss", Aud: []any{"a", "b"}}
	pB, _ := json.Marshal(claims)
	tok := base64.RawURLEncoding.EncodeToString(hB) + "." +
		base64.RawURLEncoding.EncodeToString(pB) + ".sig"
	if _, err := cfg.parseAndValidate(tok); err != nil {
		t.Fatalf("aud array match: %v", err)
	}
}

func TestParseAndValidateAudienceStringSliceMatch(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", JWTAudience: "b", now: time.Now}
	header := map[string]any{"alg": "none", "typ": "JWT"}
	hB, _ := json.Marshal(header)
	claims := Claims{Iss: "iss", Aud: []string{"a", "b"}}
	pB, _ := json.Marshal(claims)
	tok := base64.RawURLEncoding.EncodeToString(hB) + "." +
		base64.RawURLEncoding.EncodeToString(pB) + ".sig"
	if _, err := cfg.parseAndValidate(tok); err != nil {
		t.Fatalf("aud []string match: %v", err)
	}
}

func TestParseAndValidateExpiredNotCheckedWhenZero(t *testing.T) {
	cfg := &AuthConfig{JWTIssuer: "iss", now: func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }}
	claims := Claims{Iss: "iss", Exp: 0}
	token := makeJWT(t, claims)
	if _, err := cfg.parseAndValidate(token); err != nil {
		t.Fatalf("exp=0 should not error: %v", err)
	}
}

func TestParseAndValidateWithJWKSResolverHit(t *testing.T) {
	called := false
	cfg := &AuthConfig{
		JWTIssuer:     "iss",
		now:           time.Now,
		jwksResolver:  func(kid string) (any, error) { called = true; return "k", nil },
	}
	claims := Claims{Iss: "iss"}
	token := makeJWT(t, claims)
	if _, err := cfg.parseAndValidate(token); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !called {
		t.Error("jwks resolver not called")
	}
}

func TestParseAndValidateWithJWKSResolverError(t *testing.T) {
	cfg := &AuthConfig{
		JWTIssuer:    "iss",
		now:          time.Now,
		jwksResolver: func(kid string) (any, error) { return nil, errors.New("boom") },
	}
	claims := Claims{Iss: "iss"}
	token := makeJWT(t, claims)
	if _, err := cfg.parseAndValidate(token); err == nil {
		t.Fatal("expected jwks error to surface")
	}
}

func TestFetchJWKSInvalidURL(t *testing.T) {
	r := fetchJWKS("http://127.0.0.1:0/does-not-exist")
	if _, err := r("kid"); err == nil {
		t.Fatal("expected error for unreachable jwks")
	}
}

func TestFetchJWKSEmptyURL(t *testing.T) {
	r := fetchJWKS("")
	if _, err := r("kid"); err == nil {
		t.Fatal("expected error for empty jwks url")
	}
}

func TestFetchJWKSBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := fetchJWKS(srv.URL)
	if _, err := r("kid"); err == nil {
		t.Fatal("expected error for non-2xx jwks")
	}
}

func TestFetchJWKSMissingKID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kid":"a","kty":"OKP"}]}`))
	}))
	defer srv.Close()
	r := fetchJWKS(srv.URL)
	if _, err := r("b"); err == nil {
		t.Fatal("expected error for missing kid")
	}
}

func TestFetchJWKSMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	r := fetchJWKS(srv.URL)
	if _, err := r("b"); err == nil {
		t.Fatal("expected error for malformed jwks json")
	}
}

func TestFetchJWKSKidFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kid":"a","kty":"OKP"},{"kid":"b","kty":"RSA"}]}`))
	}))
	defer srv.Close()
	r := fetchJWKS(srv.URL)
	if _, err := r("b"); err != nil {
		t.Fatalf("expected hit for kid=b: %v", err)
	}
}

func TestAudienceContainsBool(t *testing.T) {
	if audienceContains(true, "x") {
		t.Fatal("bool aud should not match")
	}
}

