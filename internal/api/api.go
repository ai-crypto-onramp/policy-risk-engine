// Package api exposes the REST API for the policy/risk engine.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/evaluate"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/metrics"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
)

// Services bundles all dependencies used by the HTTP handlers.
type Services struct {
	Evaluate  *evaluate.Service
	Whitelist *whitelist.Service
	Review    *review.Service
	Audit     *audit.Service
	Engine    engine.Engine
}

// NewMux returns the HTTP handler with all routes registered.
func NewMux(s *Services) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/metrics", metrics.Handler())
	mux.HandleFunc("POST /v1/policy/evaluate", evaluateHandler(s))
	mux.HandleFunc("POST /v1/policy/whitelist", addWhitelistHandler(s))
	mux.HandleFunc("GET /v1/policy/whitelist/{user_id}", listWhitelistHandler(s))
	mux.HandleFunc("POST /v1/policy/whitelist/{user_id}/verify", verifyWhitelistHandler(s))
	mux.HandleFunc("POST /v1/policy/review/{decision_id}/resolve", resolveReviewHandler(s))
	mux.HandleFunc("GET /v1/policy/review", listReviewHandler(s))
	mux.HandleFunc("GET /v1/policy/rules", listRulesHandler(s))
	mux.HandleFunc("GET /v1/policy/rules/{version}", getRuleHandler(s))
	return mux
}

// NewServer wires middleware and returns an *http.Server.
func NewServer(s *Services, addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           NewMux(s),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// AppError carries a code and status code.
type AppError struct {
	Code       string
	Message    string
	StatusCode int
}

func (e *AppError) Error() string { return e.Message }

func newAppError(code, msg string, status int) *AppError {
	return &AppError{Code: code, Message: msg, StatusCode: status}
}

var (
	errBadJSON          = newAppError("bad_json", "invalid JSON body", http.StatusBadRequest)
	errMissingUserID    = newAppError("missing_user_id", "user_id is required", http.StatusBadRequest)
	errMissingDecisionID = newAppError("missing_decision_id", "decision_id is required", http.StatusBadRequest)
	errReviewNotFound   = newAppError("review_not_found", "review item not found", http.StatusNotFound)
	errReviewResolved   = newAppError("review_resolved", "review item already resolved", http.StatusConflict)
	errWLNotFound       = newAppError("whitelist_not_found", "whitelist entry not found", http.StatusNotFound)
)

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, err error) {
	ae := toAppError(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ae.StatusCode)
	var env errorEnvelope
	env.Error.Code = ae.Code
	env.Error.Message = ae.Message
	_ = json.NewEncoder(w).Encode(env)
}

func toAppError(err error) *AppError {
	if err == nil {
		return nil
	}
	var ae *AppError
	if errors.As(err, &ae) {
		return ae
	}
	switch {
	case errors.Is(err, review.ErrNotFound):
		return errReviewNotFound
	case errors.Is(err, review.ErrAlreadyResolved):
		return errReviewResolved
	case errors.Is(err, whitelist.ErrNotFound):
		return errWLNotFound
	}
	return newAppError("internal_error", "internal server error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return errBadJSON
	}
	if len(body) == 0 {
		return errBadJSON
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return errBadJSON
	}
	return nil
}

func evaluateHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req evaluate.Request
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		resp, err := s.Evaluate.Evaluate(ctx, req)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

type addWhitelistRequest struct {
	UserID  string `json:"user_id"`
	Chain   string `json:"chain"`
	Address string `json:"address"`
	Label   string `json:"label,omitempty"`
}

func addWhitelistHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req addWhitelistRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, err)
			return
		}
		if req.UserID == "" {
			writeError(w, errMissingUserID)
			return
		}
		entry, err := s.Whitelist.Add(r.Context(), req.UserID, req.Chain, req.Address, req.Label)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, entry)
	}
}

func listWhitelistHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("user_id")
		if userID == "" {
			writeError(w, errMissingUserID)
			return
		}
		entries, err := s.Whitelist.List(r.Context(), userID)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
	}
}

type verifyWhitelistRequest struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

func verifyWhitelistHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("user_id")
		var req verifyWhitelistRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, err)
			return
		}
		entry, err := s.Whitelist.Verify(r.Context(), userID, req.Chain, req.Address)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, entry)
	}
}

type resolveReviewRequest struct {
	Assignee   string `json:"assignee"`
	Resolution string `json:"resolution"`
}

func resolveReviewHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decisionID := r.PathValue("decision_id")
		if decisionID == "" {
			writeError(w, errMissingDecisionID)
			return
		}
		var req resolveReviewRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, err)
			return
		}
		item, err := s.Review.Resolve(r.Context(), decisionID, req.Assignee, req.Resolution)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}
}

func listReviewHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		items, err := s.Review.List(r.Context(), status)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}

func listRulesHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Engine == nil {
			writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version": s.Engine.Version(),
			"hash":    s.Engine.Hash(),
		})
	}
}

func getRuleHandler(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		version := r.PathValue("version")
		if s.Engine == nil || version != s.Engine.Version() {
			writeError(w, newAppError("rule_not_found", "rule version not found", http.StatusNotFound))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version": s.Engine.Version(),
			"hash":    s.Engine.Hash(),
		})
	}
}

// Ensure unused import strings is referenced.
var _ = strings.TrimSpace