package evaluate

import (
	"context"
	"errors"
	"testing"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/caps"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/velocity"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
)

func TestSetSessionValidDefault(t *testing.T) {
	s := newTestService(t)
	s.SetSessionValidDefault(true)
	if !s.sessionValidDefault {
		t.Fatal("SetSessionValidDefault did not set field")
	}
	s.SetSessionValidDefault(false)
	if s.sessionValidDefault {
		t.Fatal("SetSessionValidDefault(false) did not clear")
	}
}

func TestNewIDReturnsNonEmpty(t *testing.T) {
	if id := newID(); id == "" {
		t.Fatal("newID returned empty string")
	}
	// Should produce different ids.
	if id1, id2 := newID(), newID(); id1 == id2 {
		t.Errorf("newID not unique: %s == %s", id1, id2)
	}
}

func TestEvaluateUsesNewIDByDefault(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// Override id back to default (newID) by clearing it via WithID.
	s.WithID(newID)
	resp, err := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.DecisionID == "" {
		t.Fatal("expected non-empty default decision id")
	}
}

func TestEvaluateDenyInvalidSession(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// Disable the session-valid default to exercise the invalid_session branch.
	s.sessionValidDefault = false
	resp, err := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected deny for invalid session, got %s", resp.Decision)
	}
	if len(resp.Reasons) == 0 || resp.Reasons[0] != "invalid_session" {
		t.Errorf("reasons: %v", resp.Reasons)
	}
}

func TestEvaluateDeny2FARequiredReason(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "1500", Currency: "USD", Rail: "card",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "deny" {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if len(resp.Reasons) == 0 || resp.Reasons[0] != "2fa_required" {
		t.Errorf("reasons: %v", resp.Reasons)
	}
}

func TestEvaluateDenyDestNotWhitelistedReason(t *testing.T) {
	s := newTestService(t) // no whitelist entries
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "deny" {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if len(resp.Reasons) == 0 || resp.Reasons[0] != "dest_not_whitelisted" {
		t.Errorf("reasons: %v", resp.Reasons)
	}
}

func TestEvaluateEngineErrorManualReview(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	s.engine = errEngine{}
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "manual_review" {
		t.Fatalf("expected manual_review on engine error, got %s", resp.Decision)
	}
}

func TestEvaluateNilVelocitySkipped(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	s.velocity = nil
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "allow" {
		t.Fatalf("expected allow with nil velocity, got %s reasons=%v", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateNilCapsSkipped(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// Replace caps with a zero-Rules config so HighValue2FARequired returns
	// false and the per-tx caps block is skipped (no rules match).
	s.caps = &caps.Config{DefaultDailyCapUSD: 10000, DefaultTXCapUSD: 2500, NearCapThreshold: 0.9, Rules: nil}
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "allow" {
		t.Fatalf("expected allow with empty caps rules, got %s", resp.Decision)
	}
}

func TestEvaluateNilAuditSkipped(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	s.audit = nil
	resp, err := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow with nil audit, got %s", resp.Decision)
	}
}

func TestEvaluateNilReviewSkipped(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	s.review = nil
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.6, KYCStatus: "verified",
	})
	if resp.Decision != "manual_review" {
		t.Fatalf("expected manual_review with nil review, got %s", resp.Decision)
	}
}

func TestEvaluateAuditEmitErrorReturnsError(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// Replace audit with a service backed by a failing store so Emit returns
	// a non-ErrDropped error.
	signer := audit.NewSigner(nil)
	failingStore := &failStore{}
	sink := audit.NewMemorySink()
	failingAud := audit.NewService(signer, failingStore, sink, 16)
	t.Cleanup(failingAud.Close)
	failingAud.WithSyncPersist()
	s.audit = failingAud
	_, err := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD",
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if err == nil {
		t.Fatal("expected error when audit emit fails synchronously")
	}
}

func TestValidateRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     Request
		wantErr bool
	}{
		{"empty user", Request{Amount: "1", Currency: "USD", DestAddress: "0x1"}, true},
		{"empty amount", Request{UserID: "u", Currency: "USD", DestAddress: "0x1"}, true},
		{"non-numeric amount", Request{UserID: "u", Amount: "abc", Currency: "USD", DestAddress: "0x1"}, true},
		{"empty currency", Request{UserID: "u", Amount: "1", DestAddress: "0x1"}, true},
		{"empty dest", Request{UserID: "u", Amount: "1", Currency: "USD"}, true},
		{"whitespace user", Request{UserID: "   ", Amount: "1", Currency: "USD", DestAddress: "0x1"}, true},
		{"valid", Request{UserID: "u", Amount: "1", Currency: "USD", DestAddress: "0x1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validate(c.req)
			if (err != nil) != c.wantErr {
				t.Fatalf("validate: err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestParseFloat(t *testing.T) {
	if got := parseFloat("1.5"); got != 1.5 {
		t.Errorf("parseFloat 1.5: %v", got)
	}
	if got := parseFloat("not a number"); got != 0 {
		t.Errorf("parseFloat non-number: %v", got)
	}
}

func TestToAuditReq(t *testing.T) {
	req := Request{
		UserID: "u", Amount: "1", Currency: "USD", Asset: "USDC", Rail: "ach",
		DestAddress: "0x1", DestChain: "eth", KYTVerdict: "clean",
		FraudScore: 0.5, KYCStatus: "verified",
	}
	got := toAuditReq(req)
	if got.UserID != "u" || got.Amount != "1" || got.Currency != "USD" || got.Asset != "USDC" {
		t.Errorf("toAuditReq: %+v", got)
	}
	if got.Rail != "ach" || got.DestAddress != "0x1" || got.DestChain != "eth" {
		t.Errorf("toAuditReq rails/dest: %+v", got)
	}
	if got.KYTVerdict != "clean" || got.FraudScore != 0.5 || got.KYCStatus != "verified" {
		t.Errorf("toAuditReq kyt/fraud/kyc: %+v", got)
	}
}

func TestNewServiceDefaults(t *testing.T) {
	eng := engine.NewOPAEngine(mustLoadBundle(t))
	vel := velocity.NewMemoryCounter()
	capsCfg := &caps.Config{DefaultDailyCapUSD: 10000, DefaultTXCapUSD: 2500, Rules: caps.SeedRules()}
	wl := whitelist.NewService(whitelist.NewMemoryStore())
	rev := review.NewService(review.NewMemoryStore())
	aud := audit.NewService(audit.NewSigner(nil), audit.NewMemoryStore(), audit.NewMemorySink(), 8)
	t.Cleanup(aud.Close)
	s := NewService(eng, vel, capsCfg, wl, rev, aud)
	if s == nil {
		t.Fatal("nil service")
	}
	if s.metrics == nil {
		t.Error("metrics not initialized")
	}
	if s.id == nil {
		t.Error("id not initialized")
	}
}

type errEngine struct{}

func (errEngine) Evaluate(context.Context, map[string]any) (engine.Result, error) {
	return engine.Result{}, errors.New("boom")
}
func (errEngine) Hash() string    { return "h" }
func (errEngine) Version() string { return "v" }

func mustLoadBundle(t *testing.T) *engine.Bundle {
	t.Helper()
	b, err := engine.LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	return b
}

type failStore struct{}

func (failStore) Put(audit.DecisionRecord) error {
	return errors.New("persist failed")
}
func (failStore) Get(string) (audit.DecisionRecord, bool, error) {
	return audit.DecisionRecord{}, false, errors.New("get failed")
}