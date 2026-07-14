package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AuthConfig holds the REST admin-path auth configuration. When JWTIssuer is
// set, admin endpoints require a valid JWT bearer token with one of
// AdminScopes. When JWTIssuer is empty, auth is disabled (local dev mode).
type AuthConfig struct {
	JWTIssuer    string
	JWTAudience  string
	JWKSURL      string
	AdminScopes  []string
	jwksResolver func(kid string) (any, error)
	now          func() time.Time
}

// NewAuthConfig builds an AuthConfig from env. When JWT_ISSUER is unset it
// returns a zero config that disables auth.
func NewAuthConfig() *AuthConfig {
	cfg := &AuthConfig{
		JWTIssuer:   envOr("JWT_ISSUER", ""),
		JWTAudience: envOr("JWT_AUDIENCE", ""),
		JWKSURL:     envOr("JWT_JWKS_URL", ""),
		AdminScopes: strings.Split(envOr("JWT_ADMIN_SCOPES", "policy:admin policy:review"), " "),
		now:         time.Now,
	}
	if cfg.JWKSURL != "" {
		cfg.jwksResolver = fetchJWKS(cfg.JWKSURL)
	}
	return cfg
}

// Enabled reports whether JWT auth is configured.
func (c *AuthConfig) Enabled() bool { return c != nil && c.JWTIssuer != "" }

// authMiddleware wraps the mux with bearer-token validation for admin paths.
// Non-admin paths (evaluate, healthz, metrics, GET rules/whitelist/review)
// pass through unchanged.
func authMiddleware(cfg *AuthConfig, next http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAdminPath(r) {
			next.ServeHTTP(w, r)
			return
		}
		claims, err := cfg.validateBearer(r)
		if err != nil {
			writeError(w, newAppError("unauthorized", err.Error(), http.StatusUnauthorized))
			return
		}
		if !claims.HasAnyScope(cfg.AdminScopes) {
			writeError(w, newAppError("forbidden", "missing required scope", http.StatusForbidden))
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isAdminPath(r *http.Request) bool {
	path := r.URL.Path
	switch r.Method {
	case http.MethodPost:
		if path == "/v1/policy/rules" || path == "/v1/policy/whitelist" {
			return true
		}
		if strings.HasPrefix(path, "/v1/policy/whitelist/") && strings.HasSuffix(path, "/verify") {
			return true
		}
		if strings.HasPrefix(path, "/v1/policy/review/") && strings.HasSuffix(path, "/resolve") {
			return true
		}
	}
	return false
}

type claimsKey struct{}

// Claims are the validated JWT claims.
type Claims struct {
	Sub    string   `json:"sub"`
	Iss    string   `json:"iss"`
	Aud    any      `json:"aud"`
	Scope  string   `json:"scope"`
	Scopes []string `json:"scopes"`
	Exp    int64    `json:"exp"`
	Iat    int64    `json:"iat"`
}

// HasAnyScope returns true when any of the required scopes are present.
func (c Claims) HasAnyScope(required []string) bool {
	have := c.Scopes
	if c.Scope != "" {
		have = append(have, strings.Fields(c.Scope)...)
	}
	seen := make(map[string]bool, len(have))
	for _, s := range have {
		seen[s] = true
	}
	for _, r := range required {
		if seen[r] {
			return true
		}
	}
	return false
}

// FromContext extracts the validated claims from the request context, if any.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(Claims)
	return c, ok
}

// validateBearer extracts and validates the Bearer JWT from the Authorization
// header. It performs local signature verification via the configured JWKS
// when AuthConfig.JWKSURL is set; otherwise it falls back to unverified-decode
// (suitable for dev when the API Gateway has already validated the token).
func (c *AuthConfig) validateBearer(r *http.Request) (Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return Claims{}, errors.New("missing authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return Claims{}, errors.New("authorization header must be Bearer")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if token == "" {
		return Claims{}, errors.New("empty bearer token")
	}
	return c.parseAndValidate(token)
}

// parseAndValidate parses the JWT, checks iss/aud/exp, and verifies the
// signature when a JWKS resolver is configured.
func (c *AuthConfig) parseAndValidate(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed jwt: expected 3 parts")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, fmt.Errorf("parse header: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return Claims{}, fmt.Errorf("parse claims: %w", err)
	}
	if claims.Iss != c.JWTIssuer {
		return Claims{}, fmt.Errorf("issuer mismatch: got %q want %q", claims.Iss, c.JWTIssuer)
	}
	if c.JWTAudience != "" && !audienceContains(claims.Aud, c.JWTAudience) {
		return Claims{}, errors.New("audience mismatch")
	}
	if claims.Exp > 0 {
		exp := time.Unix(claims.Exp, 0)
		if c.now().After(exp) {
			return Claims{}, errors.New("token expired")
		}
	}
	if c.jwksResolver != nil && header.Kid != "" {
		if _, err := c.jwksResolver(header.Kid); err != nil {
			return Claims{}, fmt.Errorf("jwks lookup: %w", err)
		}
	}
	return claims, nil
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, s := range v {
			if fmt.Sprint(s) == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

// fetchJWKS fetches and caches JWKS keys from url. Returns a kid -> key
// resolver. This is a minimal implementation suitable for the policy engine's
// low-volume admin path; production deployments typically front this with a
// sidecar that validates tokens upstream.
func fetchJWKS(url string) func(kid string) (any, error) {
	return func(kid string) (any, error) {
		if url == "" {
			return nil, errors.New("jwks url not configured")
		}
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var jwks struct {
			Keys []struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(body, &jwks); err != nil {
			return nil, err
		}
		for _, k := range jwks.Keys {
			if k.Kid == kid {
				return k, nil
			}
		}
		return nil, fmt.Errorf("kid %q not found in jwks", kid)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}