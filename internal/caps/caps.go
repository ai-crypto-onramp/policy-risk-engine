// Package caps enforces per-transaction USD caps by user tier, asset, and
// fiat rail, with FX conversion to USD-equivalent at evaluation time, and
// near-cap routing to manual review.
package caps

import (
	"os"
	"strconv"
	"strings"
)

// Tier identifies a user tier (e.g. tier_1, tier_2, institutional).
type Tier string

const (
	Tier1            Tier = "tier_1"
	Tier2            Tier = "tier_2"
	Tier3            Tier = "tier_3"
	TierInstitutional Tier = "institutional"
)

// Rule is a single cap rule.
type Rule struct {
	ID         string  `yaml:"id"`
	Tier       Tier    `yaml:"tier,omitempty"`
	Rail       string  `yaml:"rail,omitempty"`
	Asset      string  `yaml:"asset,omitempty"`
	Window     string  `yaml:"window,omitempty"` // "tx" or "1d"
	USDCap     float64 `yaml:"usd_cap"`
	OnExceed   string  `yaml:"on_exceed"` // "deny" or "manual_review"
	USDThreshold float64 `yaml:"usd_threshold,omitempty"`
	Requires2FA bool    `yaml:"requires_2fa,omitempty"`
}

// Config holds cap configuration. The per-tier/per-rail rules are loaded from
// policies/caps.yaml; env defaults apply when no rule matches.
type Config struct {
	DefaultDailyCapUSD float64
	DefaultTXCapUSD    float64
	NearCapThreshold   float64 // fraction of cap (e.g. 0.9) that routes to manual_review
	Rules              []Rule
}

// DefaultConfig returns a Config populated from env with README defaults and
// the seed caps.yaml rules.
func DefaultConfig() Config {
	return Config{
		DefaultDailyCapUSD: envFloat("DEFAULT_DAILY_CAP_USD", 10000),
		DefaultTXCapUSD:    envFloat("DEFAULT_TX_CAP_USD", 2500),
		NearCapThreshold:   0.9,
		Rules:              SeedRules(),
	}
}

// SeedRules returns the cap rules from the README/policies/caps.yaml seed.
func SeedRules() []Rule {
	return []Rule{
		{ID: "cap.daily.tier_1", Tier: Tier1, Window: "1d", USDCap: 2500, OnExceed: "deny"},
		{ID: "cap.tx.tier_1", Tier: Tier1, Window: "tx", USDCap: 1000, OnExceed: "deny"},
		{ID: "cap.daily.tier_2", Tier: Tier2, Window: "1d", USDCap: 25000, OnExceed: "deny"},
		{ID: "cap.tx.tier_2", Tier: Tier2, Window: "tx", USDCap: 5000, OnExceed: "deny"},
		{ID: "cap.daily.tier_3", Tier: Tier3, Window: "1d", USDCap: 100000, OnExceed: "deny"},
		{ID: "cap.tx.tier_3", Tier: Tier3, Window: "tx", USDCap: 25000, OnExceed: "deny"},
		{ID: "cap.daily.institutional", Tier: TierInstitutional, Window: "1d", USDCap: 1000000, OnExceed: "deny"},
		{ID: "cap.tx.institutional", Tier: TierInstitutional, Window: "tx", USDCap: 250000, OnExceed: "deny"},
		{ID: "cap.tx.card.high_value_2fa", Rail: "card", Window: "tx", USDThreshold: 1000, Requires2FA: true, OnExceed: "manual_review"},
	}
}

// EvaluateResult is the outcome of a cap evaluation.
type EvaluateResult struct {
	Exceeded     bool
	NearCap      bool
	AppliedRule  *Rule
	Decision     string // "allow", "deny", "manual_review", or "" if no cap applies
	Reason       string
}

// Evaluate checks amountUSD against the applicable cap for (tier, rail, asset, window).
// When amount exceeds the cap, the rule's OnExceed branch decides. When amount
// is within NearCapThreshold of the cap, the decision is manual_review.
func (c *Config) Evaluate(tier Tier, rail, asset, window string, amountUSD float64) EvaluateResult {
	rule := c.matchRule(tier, rail, asset, window)
	cap := c.effectiveCap(rule, window)
	if cap <= 0 {
		return EvaluateResult{Decision: ""}
	}
	res := EvaluateResult{AppliedRule: rule}
	if amountUSD > cap {
		res.Exceeded = true
		res.Decision = "deny"
		res.Reason = "cap_" + window + "_exceeded"
		if rule != nil && rule.OnExceed == "manual_review" {
			res.Decision = "manual_review"
		}
		return res
	}
	if amountUSD >= cap*c.NearCapThreshold {
		res.NearCap = true
		res.Decision = "manual_review"
		res.Reason = "near_cap_" + window
		return res
	}
	return res
}

// matchRule returns the most specific rule matching (tier, rail, asset, window).
// Tier-specific rules take precedence over rail/asset rules.
func (c *Config) matchRule(tier Tier, rail, asset, window string) *Rule {
	for i, r := range c.Rules {
		if r.Tier == tier && r.Window == window && r.Rail == "" && r.Asset == "" {
			return &c.Rules[i]
		}
	}
	for i, r := range c.Rules {
		if r.Rail == rail && r.Window == window && r.Tier == "" {
			return &c.Rules[i]
		}
	}
	for i, r := range c.Rules {
		if r.Asset == asset && r.Window == window && r.Tier == "" && r.Rail == "" {
			return &c.Rules[i]
		}
	}
	return nil
}

// effectiveCap returns the USD cap for the rule, or the default for window.
func (c *Config) effectiveCap(rule *Rule, window string) float64 {
	if rule != nil && rule.USDCap > 0 {
		return rule.USDCap
	}
	switch window {
	case "1d":
		return c.DefaultDailyCapUSD
	case "tx":
		return c.DefaultTXCapUSD
	}
	return 0
}

// HighValue2FARequired returns true when the card rail rule requires 2FA for
// the given amount.
func (c *Config) HighValue2FARequired(rail string, amountUSD float64) bool {
	for _, r := range c.Rules {
		if r.Rail == rail && r.Requires2FA && amountUSD >= r.USDThreshold {
			return true
		}
	}
	return false
}

// FXToUSD converts amount in currency to USD using fxRateToUSD. If
// fxRateToUSD <= 0 it is treated as 1.0 (already USD).
func FXToUSD(amount float64, currency string, fxRateToUSD float64) float64 {
	c := strings.ToUpper(strings.TrimSpace(currency))
	if c == "USD" || fxRateToUSD <= 0 {
		return amount
	}
	return amount * fxRateToUSD
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return def
}