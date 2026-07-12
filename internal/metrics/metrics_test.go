package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderIncludesAllMetricNames(t *testing.T) {
	m := Global()
	m.EvaluateTotal.Add(5)
	m.AllowTotal.Add(3)
	m.DenyTotal.Add(1)
	m.ManualReviewTotal.Add(1)
	m.VelocityRollbacks.Add(2)
	m.HotReloadSwaps.Add(1)
	m.AuditDrops.Add(1)
	m.ReviewPending.Store(4)
	m.ObserveEvaluateDuration(1_000_000)

	out := render(m)
	want := []string{
		"policy_evaluate_total",
		"policy_evaluate_duration_seconds_sum",
		"policy_evaluate_duration_seconds_count",
		"policy_allow_total",
		"policy_deny_total",
		"policy_manual_review_total",
		"policy_velocity_rollbacks_total",
		"policy_hot_reload_swaps_total",
		"policy_audit_drops_total",
		"policy_review_pending",
	}
	for _, s := range want {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in:\n%s", s, out)
		}
	}
}

func TestHandlerServesMetrics(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	Handler()(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "policy_evaluate_total") {
		t.Errorf("body: %s", rec.Body.String())
	}
}