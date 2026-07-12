package engine

import (
	"context"
	"testing"
)

func TestLoadBundleFromDir(t *testing.T) {
	b, err := LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.Hash == "" {
		t.Error("empty hash")
	}
	if len(b.Source) == 0 {
		t.Error("no source")
	}
	if b.Data == nil {
		t.Error("no data")
	}
}

func TestBundleHashDeterministic(t *testing.T) {
	b1, err := LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load1: %v", err)
	}
	b2, err := LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load2: %v", err)
	}
	if b1.Hash != b2.Hash {
		t.Fatalf("hash not deterministic: %s != %s", b1.Hash, b2.Hash)
	}
}

func TestLoadBundleMissingDir(t *testing.T) {
	_, err := LoadBundleFromDir("../../does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestLoadBundleNoRegoFiles(t *testing.T) {
	_, err := LoadBundleFromDir("..")
	if err == nil {
		t.Fatal("expected error when no .rego files")
	}
}

func TestOPAEngineEvaluateAllow(t *testing.T) {
	b, err := LoadBundleFromDir("../../policies")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":            "usr_1",
		"amount_usd":         100.0,
		"kyt_verdict":        "clean",
		"fraud_score":        0.1,
		"kyc_status":         "verified",
		"dest_address":       "0xabc",
		"whitelisted":        true,
		"requires_2fa":       false,
		"session_2fa_passed": false,
	}
	res, err := e.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if res.Decision != "allow" {
		t.Fatalf("expected allow, got %s (allow=%v mr=%v deny=%v)", res.Decision, res.Allow, res.ManualReview, res.Deny)
	}
}

func TestOPAEngineEvaluateDenyNotWhitelisted(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":      "usr_1",
		"amount_usd":   100.0,
		"kyt_verdict":  "clean",
		"fraud_score":  0.1,
		"kyc_status":   "verified",
		"dest_address": "0xabc",
		"whitelisted":  false,
		"requires_2fa": false,
	}
	res, _ := e.Evaluate(context.Background(), input)
	if res.Decision != "deny" {
		t.Fatalf("expected deny (not whitelisted), got %s", res.Decision)
	}
}

func TestOPAEngineEvaluateDenyFraudHigh(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":      "usr_1",
		"amount_usd":   100.0,
		"kyt_verdict":  "clean",
		"fraud_score":  0.9,
		"kyc_status":   "verified",
		"dest_address": "0xabc",
		"whitelisted":  true,
		"requires_2fa": false,
	}
	res, err := e.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if res.Decision != "deny" {
		t.Fatalf("expected deny for fraud 0.9, got %s", res.Decision)
	}
}

func TestOPAEngineEvaluateManualReviewFraudMid(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":      "usr_1",
		"amount_usd":   100.0,
		"kyt_verdict":  "clean",
		"fraud_score":  0.6,
		"kyc_status":   "verified",
		"dest_address": "0xabc",
		"whitelisted":  true,
		"requires_2fa": false,
	}
	res, err := e.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if res.Decision != "manual_review" {
		t.Fatalf("expected manual_review for fraud 0.6, got %s (deny=%v mr=%v)", res.Decision, res.Deny, res.ManualReview)
	}
}

func TestOPAEngineEvaluateDenyKYTSanctioned(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":      "usr_1",
		"amount_usd":   100.0,
		"kyt_verdict":  "sanctioned",
		"fraud_score":  0.1,
		"kyc_status":   "verified",
		"dest_address": "0xabc",
		"whitelisted":  true,
		"requires_2fa": false,
	}
	res, _ := e.Evaluate(context.Background(), input)
	if res.Decision != "deny" {
		t.Fatalf("expected deny for sanctioned KYT, got %s", res.Decision)
	}
}

func TestOPAEngineEvaluateDeny2FARequired(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":            "usr_1",
		"amount_usd":         1500.0,
		"kyt_verdict":        "clean",
		"fraud_score":        0.1,
		"kyc_status":         "verified",
		"dest_address":       "0xabc",
		"whitelisted":        true,
		"requires_2fa":       true,
		"session_2fa_passed": false,
	}
	res, _ := e.Evaluate(context.Background(), input)
	if res.Decision != "deny" {
		t.Fatalf("expected deny for 2fa required-not-passed, got %s", res.Decision)
	}
}

func TestOPAEngineSwap(t *testing.T) {
	b1, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b1)
	h1 := e.Hash()
	// Build a second bundle with modified source so the hash changes.
	b2, _ := LoadBundleFromDir("../../policies")
	b2.Source["decisions.rego"] = b2.Source["decisions.rego"] + "\n# swapped\n"
	b2.Hash = hashBundle(b2.Source, b2.Data)
	b2.Version = b2.Hash
	e.Swap(b2)
	if e.Hash() == h1 {
		t.Fatal("hash did not change after swap")
	}
}

func TestOPAEngineVersion(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	if e.Version() != e.Hash() {
		t.Error("version should equal hash")
	}
}

func TestOPAEngineBundle(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	if e.Bundle() == nil || e.Bundle().Hash != b.Hash {
		t.Error("bundle mismatch")
	}
}

func TestRiskScoreComputed(t *testing.T) {
	b, _ := LoadBundleFromDir("../../policies")
	e := NewOPAEngine(b)
	input := map[string]any{
		"user_id":      "usr_1",
		"amount_usd":   100.0,
		"kyt_verdict":  "high_risk",
		"fraud_score":  0.3,
		"kyc_status":   "verified",
		"dest_address": "0xabc",
		"whitelisted":  true,
		"requires_2fa": false,
	}
	res, err := e.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	// kyt_weight("high_risk")=0.5, fraud=0.3, kyc_weight("verified")=0.0
	// score = (0.5 + 0.3 + 0.0) / 3.0 = 0.266...
	if res.RiskScore <= 0 {
		t.Fatalf("risk_score should be positive, got %v", res.RiskScore)
	}
	expected := (0.5 + 0.3 + 0.0) / 3.0
	if (res.RiskScore - expected) > 0.01 || (expected - res.RiskScore) > 0.01 {
		t.Errorf("risk_score: got %v want ~%v", res.RiskScore, expected)
	}
}

func TestTruthyDefault(t *testing.T) {
	// truthy with nil returns false.
	if truthy(nil) {
		t.Error("nil should be false")
	}
}