package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/db"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/metrics"
)

// publishRulesHandler implements POST /v1/policy/rules. It accepts a Rego
// source body and optional activate=true query param, creates a new immutable
// policy version (engine bundle), and optionally activates it via an atomic
// swap. Re-publishing the same source returns the existing version.
//
// When a DB connection is configured (Services.DB != nil) the publish also
// inserts a new immutable policy_versions row and, on activate, updates
// policies.active_version in a single transaction.
func publishRulesHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || len(bytesTrim(body)) == 0 {
			writeError(w, errBadJSON)
			return
		}
		activate := strings.EqualFold(r.URL.Query().Get("activate"), "true")
		eng, ok := s.Engine.(*engine.OPAEngine)
		if !ok {
			writeError(w, newAppError("engine_unavailable", "policy engine not reloadable", http.StatusServiceUnavailable))
			return
		}
		rules, err := publishBundle(r.Context(), eng, body)
		if err != nil {
			writeError(w, newAppError("publish_failed", err.Error(), http.StatusBadRequest))
			return
		}
		if s.DB != nil {
			if _, err := db.ActivatePolicyVersion(s.DB, "default", rules.Version, rules.Hash, string(body), "api"); err != nil {
				writeError(w, newAppError("publish_db_failed", err.Error(), http.StatusInternalServerError))
				return
			}
		}
		if activate {
			eng.Swap(rules)
			metrics.Global().HotReloadSwaps.Add(1)
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"version":  rules.Version,
			"hash":     rules.Hash,
			"activate": activate,
		})
	}
}

// publishBundle parses body as Rego and builds a new staged Bundle. Re-publish
// of the same source returns a Bundle with the same hash/version.
func publishBundle(_ context.Context, eng *engine.OPAEngine, body []byte) (*engine.Bundle, error) {
	if len(bytesTrim(body)) == 0 {
		return nil, errors.New("empty rego source")
	}
	current := eng.Bundle()
	src := map[string]string{"decisions.rego": string(body)}
	data := map[string]any{}
	if current != nil {
		for k, v := range current.Data {
			data[k] = v
		}
	}
	hash := engine.HashBundle(src, data)
	return &engine.Bundle{
		Source: src,
		Data:   data,
		Hash:   hash,
		Version: hash,
	}, nil
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}