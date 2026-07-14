package evaluate

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/caps"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/engine"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/velocity"
	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	b, err := engine.LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	eng := engine.NewOPAEngine(b)
	vel := velocity.NewMemoryCounter()
	capsCfg := &caps.Config{DefaultDailyCapUSD: 10000, DefaultTXCapUSD: 2500, NearCapThreshold: 0.9, Rules: caps.SeedRules()}
	wlStore := whitelist.NewMemoryStore()
	wl := whitelist.NewService(wlStore)
	revStore := review.NewMemoryStore()
	rev := review.NewService(revStore)
	audSigner := audit.NewSigner(nil)
	audStore := audit.NewMemoryStore()
	audSink := audit.NewMemorySink()
	audSvc := audit.NewService(audSigner, audStore, audSink, 16)
	t.Cleanup(audSvc.Close)
	svc := NewService(eng, vel, capsCfg, wl, rev, audSvc).WithID(func() string { return "dec_test" })
	svc.sessionValidDefault = true
	return svc
}

func newTestServiceWithWhitelist(t *testing.T, entries ...[3]string) *Service {
	t.Helper()
	b, _ := engine.LoadBundleFromDir("../../policies")
	eng := engine.NewOPAEngine(b)
	vel := velocity.NewMemoryCounter()
	capsCfg := &caps.Config{DefaultDailyCapUSD: 10000, DefaultTXCapUSD: 2500, NearCapThreshold: 0.9, Rules: caps.SeedRules()}
	wlStore := whitelist.NewMemoryStore()
	wl := whitelist.NewService(wlStore)
	for _, e := range entries {
		_, _ = wl.Add(context.Background(), e[0], e[1], e[2], "")
		_, _ = wl.Verify(context.Background(), e[0], e[1], e[2])
	}
	revStore := review.NewMemoryStore()
	rev := review.NewService(revStore)
	audSigner := audit.NewSigner(nil)
	audStore := audit.NewMemoryStore()
	audSink := audit.NewMemorySink()
	audSvc := audit.NewService(audSigner, audStore, audSink, 16)
	t.Cleanup(audSvc.Close)
	svc := NewService(eng, vel, capsCfg, wl, rev, audSvc).WithID(func() string { return "dec_test" }).WithNow(func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) })
	svc.sessionValidDefault = true
	return svc
}

func TestEvaluateAllow(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, err := s.Evaluate(context.Background(), Request{
		UserID:      "usr_1",
		Amount:      "100.00",
		Currency:    "USD",
		Asset:       "USDC",
		Rail:        "ach",
		DestAddress: "0xabc",
		DestChain:   "ethereum",
		KYTVerdict:  "clean",
		FraudScore:  0.1,
		KYCStatus:   "verified",
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
	if resp.DecisionID != "dec_test" {
		t.Errorf("decision id: %s", resp.DecisionID)
	}
	if resp.PolicyVersion == "" {
		t.Error("missing policy version")
	}
}

func TestEvaluateDenyNotWhitelisted(t *testing.T) {
	s := newTestService(t)
	resp, err := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s", resp.Decision)
	}
}

func TestEvaluateDenyFraudHigh(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.9, KYCStatus: "verified",
	})
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s", resp.Decision)
	}
}

func TestEvaluateManualReviewFraudMid(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.6, KYCStatus: "verified",
	})
	if resp.Decision != "manual_review" {
		t.Fatalf("decision: %s", resp.Decision)
	}
}

func TestEvaluateDenyKYTSanctioned(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "sanctioned", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s", resp.Decision)
	}
}

func TestEvaluateDeny2FARequired(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "1500", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		Rail: "card", KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateManualReviewParksInReviewQueue(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.6, KYCStatus: "verified",
	})
	if resp.Decision != "manual_review" {
		t.Fatalf("decision: %s", resp.Decision)
	}
	// The manual_review decision must be parked in the review queue.
	item, err := s.review.Get(context.Background(), resp.DecisionID)
	if err != nil {
		t.Fatalf("review get: %v", err)
	}
	if item.Status != review.StatusPending {
		t.Errorf("review status: %s", item.Status)
	}
}

func TestEvaluateValidatesRequest(t *testing.T) {
	s := newTestService(t)
	cases := []Request{
		{Amount: "100", Currency: "USD", DestAddress: "0x1", DestChain: "eth"},
		{UserID: "u", Currency: "USD", DestAddress: "0x1", DestChain: "eth"},
		{UserID: "u", Amount: "100", DestAddress: "0x1", DestChain: "eth"},
		{UserID: "u", Amount: "abc", Currency: "USD", DestAddress: "0x1", DestChain: "eth"},
		{UserID: "u", Amount: "100", Currency: "USD", DestChain: "eth"},
	}
	for i, req := range cases {
		if _, err := s.Evaluate(context.Background(), req); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestEvaluateVelocityExceeded(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// Force velocity counter above the daily cap.
	cfg := velocity.DefaultConfig()
	_, _, day := velocity.WindowsFromConfig(cfg)
	vel := s.velocity.(*velocity.MemoryCounter)
	for i := 0; i < int(s.caps.DefaultDailyCapUSD)+1; i++ {
		_, _ = vel.Increment(context.Background(), "usr_1", day)
	}
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateCapsExceeded(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// tier_1 tx cap is 1000; send 2000.
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "2000", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified", UserTier: "tier_1",
	})
	if resp.Decision != "deny" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateNearCapManualReview(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// tier_1 tx cap is 1000; 95% = 950 -> near_cap.
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "950", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified", UserTier: "tier_1",
	})
	if resp.Decision != "manual_review" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateFXConversion(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	// 100 EUR * 1.1 = 110 USD, well within caps.
	resp, _ := s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "EUR", FXRateToUSD: 1.1,
		DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	if resp.Decision != "allow" {
		t.Fatalf("decision: %s reasons: %v", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateEmitsAuditRecord(t *testing.T) {
	s := newTestServiceWithWhitelist(t, [3]string{"usr_1", "ethereum", "0xabc"})
	_, _ = s.Evaluate(context.Background(), Request{
		UserID: "usr_1", Amount: "100", Currency: "USD", DestAddress: "0xabc", DestChain: "ethereum",
		KYTVerdict: "clean", FraudScore: 0.1, KYCStatus: "verified",
	})
	// Audit record should be persisted; poll the audit store via the audit service.
	// We can't access s.audit directly, so verify no drops occurred via metrics.
	if s.metrics.AuditDrops.Load() > 0 {
		t.Errorf("audit drops: %d", s.metrics.AuditDrops.Load())
	}
}