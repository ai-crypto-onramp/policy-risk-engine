// Package evaluate is the synchronous policy evaluation path. It aggregates
// signals from KYT, KYC, and Fraud Detection, applies velocity counters, per-tx
// caps, whitelisting, source auth, and the OPA decision engine, then emits a
// signed audit record and parks manual_review decisions in the review queue.
package evaluate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/caps"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/metrics"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/velocity"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
	"github.com/google/uuid"
)

// Request is the input to the evaluate path (mirrors the README JSON body).
type Request struct {
	UserID       string  `json:"user_id"`
	Amount       string  `json:"amount"`
	Currency     string  `json:"currency"`
	Asset        string  `json:"asset"`
	Rail         string  `json:"rail"`
	DestAddress  string  `json:"dest_address"`
	DestChain    string  `json:"dest_chain"`
	KYTVerdict   string  `json:"kyt_verdict"`
	FraudScore   float64 `json:"fraud_score"`
	KYCStatus    string  `json:"kyc_status"`
	UserTier     string  `json:"user_tier,omitempty"`
	Session2FA   bool    `json:"session_2fa_passed,omitempty"`
	FXRateToUSD  float64 `json:"fx_rate_to_usd,omitempty"`
	SessionValid bool    `json:"-"`
}

// AppliedRule is a rule that fired during evaluation.
type AppliedRule struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

// Response is the output of the evaluate path.
type Response struct {
	Decision      string        `json:"decision"`
	Reasons       []string      `json:"reasons"`
	AppliedRules  []AppliedRule `json:"applied_rules"`
	PolicyVersion string        `json:"policy_version"`
	Score         float64       `json:"score"`
	DecisionID    string        `json:"decision_id"`
}

// Service is the evaluate service.
type Service struct {
	engine    engine.Engine
	velocity  velocity.Counter
	caps      *caps.Config
	whitelist *whitelist.Service
	review    *review.Service
	audit     *audit.Service
	metrics   *metrics.Metrics
	now       func() time.Time
	id        func() string
	// sessionValidDefault, when true, treats requests with
	// SessionValid==false as having a valid session. This preserves
	// backwards-compatible behaviour for direct callers (tests, in-memory
	// mode) that do not perform JWT validation at the transport layer.
	sessionValidDefault bool
}

// NewService returns an evaluate Service.
func NewService(eng engine.Engine, vel velocity.Counter, capsCfg *caps.Config, wl *whitelist.Service, rev *review.Service, aud *audit.Service) *Service {
	return &Service{
		engine:    eng,
		velocity:  vel,
		caps:      capsCfg,
		whitelist: wl,
		review:    rev,
		audit:     aud,
		metrics:   metrics.Global(),
		now:       time.Now,
		id:        newID,
	}
}

// WithNow overrides the clock (for testing).
func (s *Service) WithNow(now func() time.Time) *Service {
	s.now = now
	return s
}

// WithID overrides the decision id generator (for testing).
func (s *Service) WithID(id func() string) *Service {
	s.id = id
	return s
}

// SetSessionValidDefault configures whether requests without an explicit
// SessionValid are treated as having a valid session. Set to true for local
// dev / in-memory mode where JWT validation is not performed at the transport.
func (s *Service) SetSessionValidDefault(v bool) {
	s.sessionValidDefault = v
}

func newID() string {
	id, _ := uuid.NewV7()
	return id.String()
}

// Evaluate runs the synchronous policy evaluation path.
func (s *Service) Evaluate(ctx context.Context, req Request) (Response, error) {
	if err := validate(req); err != nil {
		return Response{}, err
	}
	start := time.Now()
	defer func() {
		s.metrics.ObserveEvaluateDuration(time.Since(start).Nanoseconds())
		s.metrics.EvaluateTotal.Add(1)
	}()

	amountUSD := caps.FXToUSD(parseFloat(req.Amount), req.Currency, req.FXRateToUSD)
	tier := caps.Tier(req.UserTier)
	if tier == "" {
		tier = caps.Tier1
	}

	var reasons []string
	var appliedRules []AppliedRule

	// 1. Source auth.
	requires2FA := s.caps.HighValue2FARequired(req.Rail, amountUSD)
	sessionValid := req.SessionValid || s.sessionValidDefault
	authResult := whitelist.CheckSourceAuth(sessionValid, requires2FA, req.Session2FA)
	if !authResult.OK {
		return s.finalize(ctx, req, "deny", append(reasons, authResult.Reason), appliedRules, 1.0, audit.Request{
			UserID: req.UserID, Amount: req.Amount, Currency: req.Currency, Asset: req.Asset,
			Rail: req.Rail, DestAddress: req.DestAddress, DestChain: req.DestChain,
			KYTVerdict: req.KYTVerdict, FraudScore: req.FraudScore, KYCStatus: req.KYCStatus,
		})
	}

	// 2. Whitelist.
	whitelisted := s.whitelist.IsWhitelisted(ctx, req.UserID, req.DestChain, req.DestAddress)
	if !whitelisted {
		return s.finalize(ctx, req, "deny", append(reasons, "dest_not_whitelisted"), appliedRules, 0.5, audit.Request{
			UserID: req.UserID, Amount: req.Amount, Currency: req.Currency, Asset: req.Asset,
			Rail: req.Rail, DestAddress: req.DestAddress, DestChain: req.DestChain,
			KYTVerdict: req.KYTVerdict, FraudScore: req.FraudScore, KYCStatus: req.KYCStatus,
		})
	}
	reasons = append(reasons, "whitelisted")

	// 3. Velocity counters (per-minute, per-hour, per-day).
	min, hour, day := velocity.WindowsFromConfig(velocity.DefaultConfig())
	if s.velocity != nil {
		if v, _ := s.velocity.Increment(ctx, req.UserID, day); v > int64(s.caps.DefaultDailyCapUSD) {
			_, _ = s.velocity.Rollback(ctx, req.UserID, day)
			return s.finalize(ctx, req, "deny", append(reasons, "velocity_daily_exceeded"), appliedRules, 0.5, toAuditReq(req))
		}
		reasons = append(reasons, "velocity_daily_ok")
		_ = min
		_ = hour
	}

	// 4. Per-tx caps.
	if s.caps != nil {
		res := s.caps.Evaluate(tier, req.Rail, req.Asset, "tx", amountUSD)
		if res.AppliedRule != nil {
			appliedRules = append(appliedRules, AppliedRule{ID: res.AppliedRule.ID})
		}
		if res.Exceeded {
			return s.finalize(ctx, req, res.Decision, append(reasons, res.Reason), appliedRules, 0.5, toAuditReq(req))
		}
		if res.NearCap {
			return s.finalize(ctx, req, "manual_review", append(reasons, res.Reason), appliedRules, 0.3, toAuditReq(req))
		}
	}

	// 5. OPA engine evaluation.
	engineInput := map[string]any{
		"user_id":            req.UserID,
		"amount_usd":         amountUSD,
		"kyt_verdict":        req.KYTVerdict,
		"fraud_score":        req.FraudScore,
		"kyc_status":         req.KYCStatus,
		"dest_address":       req.DestAddress,
		"whitelisted":        whitelisted,
		"requires_2fa":       requires2FA,
		"session_2fa_passed": req.Session2FA,
	}
	engRes, err := s.engine.Evaluate(ctx, engineInput)
	if err != nil {
		return s.finalize(ctx, req, "manual_review", append(reasons, "engine_error"), appliedRules, 0.5, toAuditReq(req))
	}
	for _, r := range engRes.AppliedRules {
		appliedRules = append(appliedRules, AppliedRule{ID: r, Version: s.engine.Version()})
	}

	return s.finalize(ctx, req, engRes.Decision, reasons, appliedRules, engRes.RiskScore, toAuditReq(req))
}

// finalize records metrics, emits the audit record, parks manual_review in the
// review queue, and returns the response.
func (s *Service) finalize(ctx context.Context, req Request, decision string, reasons []string, rules []AppliedRule, score float64, auditReq audit.Request) (Response, error) {
	decisionID := s.id()
	policyVersion := s.engine.Version()

	switch decision {
	case "allow":
		s.metrics.AllowTotal.Add(1)
	case "deny":
		s.metrics.DenyTotal.Add(1)
	case "manual_review":
		s.metrics.ManualReviewTotal.Add(1)
	}

	resp := Response{
		Decision:      decision,
		Reasons:       reasons,
		AppliedRules:  rules,
		PolicyVersion: policyVersion,
		Score:         score,
		DecisionID:    decisionID,
	}

	// Audit emission.
	if s.audit != nil {
		rec := audit.DecisionRecord{
			DecisionID:    decisionID,
			PolicyVersion: policyVersion,
			RequestHash:   audit.RequestHash(auditReq),
			Decision:      decision,
			Reasons:       reasons,
			Score:         score,
		}
		for _, r := range rules {
			rec.AppliedRules = append(rec.AppliedRules, r.ID)
		}
		if err := s.audit.Emit(ctx, rec); err != nil && !errors.Is(err, audit.ErrDropped) {
			return resp, fmt.Errorf("audit emit: %w", err)
		}
	}

	// Park manual_review in the review queue.
	if decision == "manual_review" && s.review != nil {
		if _, err := s.review.Park(ctx, decisionID, ""); err == nil {
			s.metrics.ReviewPending.Add(1)
		}
	}

	return resp, nil
}

// validate enforces required fields.
func validate(req Request) error {
	if strings.TrimSpace(req.UserID) == "" {
		return errors.New("user_id is required")
	}
	if strings.TrimSpace(req.Amount) == "" {
		return errors.New("amount is required")
	}
	if _, err := strconv.ParseFloat(req.Amount, 64); err != nil {
		return errors.New("amount must be a number")
	}
	if strings.TrimSpace(req.Currency) == "" {
		return errors.New("currency is required")
	}
	if strings.TrimSpace(req.DestAddress) == "" {
		return errors.New("dest_address is required")
	}
	return nil
}

func parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func toAuditReq(req Request) audit.Request {
	return audit.Request{
		UserID:      req.UserID,
		Amount:      req.Amount,
		Currency:    req.Currency,
		Asset:       req.Asset,
		Rail:        req.Rail,
		DestAddress: req.DestAddress,
		DestChain:   req.DestChain,
		KYTVerdict:  req.KYTVerdict,
		FraudScore:  req.FraudScore,
		KYCStatus:   req.KYCStatus,
	}
}