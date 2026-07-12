package caps

import (
	"testing"
)

func TestEvaluateTier2DailyExceed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DefaultDailyCapUSD = 10000
	// tier_2 daily cap is 25000 from seed rules.
	res := cfg.Evaluate(Tier2, "", "", "1d", 30000)
	if !res.Exceeded || res.Decision != "deny" {
		t.Fatalf("res: %+v", res)
	}
	if res.AppliedRule == nil || res.AppliedRule.ID != "cap.daily.tier_2" {
		t.Fatalf("applied rule: %+v", res.AppliedRule)
	}
}

func TestEvaluateTier2TXWithinCap(t *testing.T) {
	cfg := DefaultConfig()
	res := cfg.Evaluate(Tier2, "", "", "tx", 4000)
	if res.Exceeded || res.Decision != "" {
		t.Fatalf("res: %+v", res)
	}
}

func TestEvaluateNearCap(t *testing.T) {
	cfg := DefaultConfig()
	// tier_2 tx cap is 5000; 95% = 4750 -> near_cap -> manual_review.
	res := cfg.Evaluate(Tier2, "", "", "tx", 4750)
	if !res.NearCap || res.Decision != "manual_review" {
		t.Fatalf("res: %+v", res)
	}
}

func TestEvaluateDefaultFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DefaultTXCapUSD = 2500
	// unknown tier falls back to default tx cap.
	res := cfg.Evaluate(Tier("unknown"), "", "", "tx", 3000)
	if !res.Exceeded || res.Decision != "deny" {
		t.Fatalf("res: %+v", res)
	}
}

func TestEvaluateCardHighValue2FA(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.HighValue2FARequired("card", 1500) {
		t.Error("expected 2FA required for card 1500")
	}
	if cfg.HighValue2FARequired("card", 500) {
		t.Error("expected no 2FA for card 500")
	}
	if cfg.HighValue2FARequired("ach", 50000) {
		t.Error("expected no 2FA for ach")
	}
}

func TestFXToUSD(t *testing.T) {
	if got := FXToUSD(100, "USD", 1.0); got != 100 {
		t.Errorf("USD: %v", got)
	}
	got := FXToUSD(100, "EUR", 1.1)
	if got < 109.9 || got > 110.1 {
		t.Errorf("EUR->USD: %v", got)
	}
	if got := FXToUSD(100, "EUR", 0); got != 100 {
		t.Errorf("rate 0 should be 1.0: %v", got)
	}
}

func TestDefaultConfigFromEnv(t *testing.T) {
	t.Setenv("DEFAULT_DAILY_CAP_USD", "50000")
	t.Setenv("DEFAULT_TX_CAP_USD", "5000")
	cfg := DefaultConfig()
	if cfg.DefaultDailyCapUSD != 50000 {
		t.Errorf("daily: %v", cfg.DefaultDailyCapUSD)
	}
	if cfg.DefaultTXCapUSD != 5000 {
		t.Errorf("tx: %v", cfg.DefaultTXCapUSD)
	}
}

func TestEvaluateNoCapApplies(t *testing.T) {
	cfg := DefaultConfig()
	res := cfg.Evaluate(Tier2, "", "", "weird-window", 1000)
	if res.Decision != "" {
		t.Fatalf("expected no decision for unknown window, got %+v", res)
	}
}