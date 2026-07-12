// Package metrics exposes Prometheus-compatible metrics for the policy engine.
package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics is the metrics container.
type Metrics struct {
	EvaluateTotal       atomic.Int64
	EvaluateDurationSum atomic.Int64
	EvaluateDurationCount atomic.Int64
	AllowTotal          atomic.Int64
	DenyTotal           atomic.Int64
	ManualReviewTotal   atomic.Int64
	VelocityRollbacks   atomic.Int64
	HotReloadSwaps      atomic.Int64
	AuditDrops          atomic.Int64
	ReviewPending       atomic.Int64
}

var (
	globalOnce sync.Once
	global     *Metrics
)

// Global returns the process-wide Metrics instance.
func Global() *Metrics {
	globalOnce.Do(func() { global = &Metrics{} })
	return global
}

// ObserveEvaluateDuration records an evaluate latency in nanoseconds.
func (m *Metrics) ObserveEvaluateDuration(nanos int64) {
	m.EvaluateDurationSum.Add(nanos)
	m.EvaluateDurationCount.Add(1)
}

// Handler serves Prometheus-formatted metrics on /metrics.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(render(Global())))
	}
}

func render(m *Metrics) string {
	var b strings.Builder
	writeCounter(&b, "policy_evaluate_total", m.EvaluateTotal.Load())
	writeHistogram(&b, "policy_evaluate_duration_seconds", m.EvaluateDurationSum.Load(), m.EvaluateDurationCount.Load())
	writeCounter(&b, "policy_allow_total", m.AllowTotal.Load())
	writeCounter(&b, "policy_deny_total", m.DenyTotal.Load())
	writeCounter(&b, "policy_manual_review_total", m.ManualReviewTotal.Load())
	writeCounter(&b, "policy_velocity_rollbacks_total", m.VelocityRollbacks.Load())
	writeCounter(&b, "policy_hot_reload_swaps_total", m.HotReloadSwaps.Load())
	writeCounter(&b, "policy_audit_drops_total", m.AuditDrops.Load())
	writeGauge(&b, "policy_review_pending", m.ReviewPending.Load())
	return b.String()
}

func writeCounter(b *strings.Builder, name string, v int64) {
	fmt.Fprintf(b, "# TYPE %s counter\n%s %d\n", name, name, v)
}

func writeGauge(b *strings.Builder, name string, v int64) {
	fmt.Fprintf(b, "# TYPE %s gauge\n%s %d\n", name, name, v)
}

func writeHistogram(b *strings.Builder, name string, sum, count int64) {
	fmt.Fprintf(b, "# TYPE %s histogram\n%s_sum %d\n%s_count %d\n", name, name, sum, name, count)
}