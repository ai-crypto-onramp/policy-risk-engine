package db

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
)

// skipIfNoDB skips tests requiring a live Postgres. Set DB_URL to enable.
func skipIfNoDB(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping live Postgres test")
	}
	return dsn
}

// freshDB connects, applies migrations, and truncates all tables so each test
// starts from a clean slate.
func freshDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := skipIfNoDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := MigrateUp(dsn, "../../migrations"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	for _, tbl := range []string{"review_queue", "policy_decisions", "policy_versions", "policies", "whitelist_addresses"} {
		if _, err := database.ExecContext(ctx, `DELETE FROM `+tbl); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
	}
	return database
}

// TestAuditStorePutNilSlices is a regression test for the 500 returned by
// POST /v1/policy/evaluate on the early-deny paths (e.g. dest_not_whitelisted,
// 2fa_required). Those paths build an audit.DecisionRecord with nil Reasons /
// AppliedRules. pq.Array of a nil slice yields SQL NULL, which violates the
// NOT NULL constraint on policy_decisions.reasons / applied_rules. The store
// must coerce nil to an empty array before inserting.
func TestAuditStorePutNilSlices(t *testing.T) {
	database := freshDB(t)
	defer database.Close()

	s := NewAuditStore(database)
	if err := s.EnsurePolicyVersion("v1", "hash1", "", "test"); err != nil {
		t.Fatalf("ensure policy version: %v", err)
	}

	rec := audit.DecisionRecord{
		DecisionID:    "dec_nil_slices",
		PolicyVersion: "v1",
		RequestHash:   "hash",
		Decision:      "deny",
		Reasons:       nil, // regression trigger
		AppliedRules:  nil, // regression trigger
		Score:         0.5,
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.Put(rec); err != nil {
		t.Fatalf("Put with nil slices failed: %v", err)
	}

	got, ok, err := s.Get("dec_nil_slices")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("record not found after Put")
	}
	if got.Decision != "deny" {
		t.Errorf("Decision: %q want deny", got.Decision)
	}
	if len(got.Reasons) != 0 {
		t.Errorf("Reasons: %v want empty", got.Reasons)
	}
	if len(got.AppliedRules) != 0 {
		t.Errorf("AppliedRules: %v want empty", got.AppliedRules)
	}
}

// TestAuditStorePutPopulatedSlices confirms the happy path still persists both
// arrays verbatim.
func TestAuditStorePutPopulatedSlices(t *testing.T) {
	database := freshDB(t)
	defer database.Close()

	s := NewAuditStore(database)
	if err := s.EnsurePolicyVersion("v2", "hash2", "", "test"); err != nil {
		t.Fatalf("ensure policy version: %v", err)
	}

	rec := audit.DecisionRecord{
		DecisionID:    "dec_pop",
		PolicyVersion: "v2",
		RequestHash:   "hash",
		Decision:      "manual_review",
		Reasons:       []string{"whitelisted", "velocity_daily_ok"},
		AppliedRules:  []string{"cap.tx.tier_1", "manual_review.fraud_mid"},
		Score:         0.2,
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.Put(rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := s.Get("dec_pop")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if len(got.Reasons) != 2 || len(got.AppliedRules) != 2 {
		t.Errorf("slices not round-tripped: reasons=%v rules=%v", got.Reasons, got.AppliedRules)
	}
}