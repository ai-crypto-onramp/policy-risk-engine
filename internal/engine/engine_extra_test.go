package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

func TestScoreFloatInt64(t *testing.T) {
	results := rego.ResultSet{
		{Expressions: []*rego.ExpressionValue{{Value: int64(7)}}},
	}
	if got := scoreFloat(results); got != 7 {
		t.Errorf("int64: %v", got)
	}
}

func TestScoreFloatJSONNumber(t *testing.T) {
	n := json.Number("3.5")
	results := rego.ResultSet{
		{Expressions: []*rego.ExpressionValue{{Value: n}}},
	}
	if got := scoreFloat(results); got != 3.5 {
		t.Errorf("json.Number: %v", got)
	}
}

func TestScoreFloatOtherType(t *testing.T) {
	results := rego.ResultSet{
		{Expressions: []*rego.ExpressionValue{{Value: "not a number"}}},
	}
	if got := scoreFloat(results); got != 0 {
		t.Errorf("string: %v", got)
	}
}

func TestScoreFloatEmptyResults(t *testing.T) {
	if got := scoreFloat(rego.ResultSet{}); got != 0 {
		t.Errorf("empty: %v", got)
	}
	if got := scoreFloat(rego.ResultSet{{}}); got != 0 {
		t.Errorf("empty exprs: %v", got)
	}
}

func TestTruthyBoolTrue(t *testing.T) {
	results := rego.ResultSet{
		{Expressions: []*rego.ExpressionValue{{Value: true}}},
	}
	if !truthy(results) {
		t.Error("bool true should be truthy")
	}
}

func TestTruthyBoolFalse(t *testing.T) {
	results := rego.ResultSet{
		{Expressions: []*rego.ExpressionValue{{Value: false}}},
	}
	if truthy(results) {
		t.Error("bool false should not be truthy")
	}
}

func TestTruthyNonBool(t *testing.T) {
	results := rego.ResultSet{
		{Expressions: []*rego.ExpressionValue{{Value: "string"}}},
	}
	if !truthy(results) {
		t.Error("non-nil non-bool should be truthy")
	}
}

func TestTruthyEmpty(t *testing.T) {
	if truthy(rego.ResultSet{}) {
		t.Error("empty result set should be false")
	}
	if truthy(rego.ResultSet{{}}) {
		t.Error("empty exprs should be false")
	}
}

func TestTrimLeftSpace(t *testing.T) {
	if got := string(trimLeftSpace([]byte("   x"))); got != "x" {
		t.Errorf("trim spaces: %q", got)
	}
	if got := string(trimLeftSpace([]byte("\t\tx"))); got != "x" {
		t.Errorf("trim tabs: %q", got)
	}
	if got := string(trimLeftSpace([]byte("\r\tx"))); got != "x" {
		t.Errorf("trim cr/tab: %q", got)
	}
	if len(trimLeftSpace(nil)) != 0 {
		t.Error("nil not empty")
	}
}

func TestStartsWith(t *testing.T) {
	if !startsWith([]byte("package x"), "package ") {
		t.Error("expected prefix match")
	}
	if startsWith([]byte("pack"), "package ") {
		t.Error("expected prefix too short to not match")
	}
	if startsWith([]byte("x"), "package ") {
		t.Error("single char should not match long prefix")
	}
}

func TestSplitLines(t *testing.T) {
	got := splitLines([]byte("a\nb\nc"))
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("split: %v", got)
	}
	got = splitLines([]byte("a\nb\n"))
	if len(got) != 2 {
		t.Errorf("trailing newline: %v", got)
	}
	got = splitLines([]byte(""))
	if len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
}

func TestIsRegoContentCommentOnly(t *testing.T) {
	if isRegoContent("text/plain", []byte("# just a comment\n# another\n")) {
		t.Error("comment-only should not be rego")
	}
	if isRegoContent("text/plain", []byte("package policy.x\n")) {
		// first non-comment line is "package policy.x"
	}
	if !isRegoContent("text/plain", []byte("# c\npackage policy.x\n")) {
		t.Error("comment then package should be rego")
	}
	if isRegoContent("application/octet-stream", []byte("x = 1\n")) {
		t.Error("non-package first line should not be rego")
	}
	if isRegoContent("application/gzip", []byte("package")) {
		t.Error("gzip content type should not be rego")
	}
}

func TestMin(t *testing.T) {
	if min(1, 2) != 1 {
		t.Error("min(1,2) != 1")
	}
	if min(2, 1) != 1 {
		t.Error("min(2,1) != 1")
	}
	if min(5, 5) != 5 {
		t.Error("min(5,5) != 5")
	}
}

func TestNewPollerDefaultIntervalFromEnv(t *testing.T) {
	t.Setenv("OPA_BUNDLE_POLL_INTERVAL", "5")
	p := NewPoller("http://x", 0, nil, nil)
	if p.interval != 5*time.Second {
		t.Fatalf("interval: %v want 5s", p.interval)
	}
	if p.url != "http://x" {
		t.Errorf("url: %q", p.url)
	}
}

func TestNewPollerExplicitInterval(t *testing.T) {
	p := NewPoller("http://x", 100*time.Millisecond, nil, nil)
	if p.interval != 100*time.Millisecond {
		t.Errorf("interval: %v", p.interval)
	}
}

func TestNewHotReloaderDefaultIntervalFromEnv(t *testing.T) {
	t.Setenv("POLICY_HOT_RELOAD_INTERVAL", "7")
	h := NewHotReloader("http://x", 0, nil)
	if h.interval != 7*time.Second {
		t.Fatalf("interval: %v want 7s", h.interval)
	}
	if h.validate == nil {
		t.Error("default validate not set")
	}
}

func TestNewHotReloaderExplicitInterval(t *testing.T) {
	h := NewHotReloader("http://x", 250*time.Millisecond, nil)
	if h.interval != 250*time.Millisecond {
		t.Errorf("interval: %v", h.interval)
	}
}

func TestHotReloaderWithValidate(t *testing.T) {
	called := false
	h := NewHotReloader("", 1*time.Second, nil).WithValidate(func(b *Bundle) error {
		called = true
		return nil
	})
	if h.validate == nil {
		t.Fatal("validate not set")
	}
	_ = h.validate(&Bundle{Source: map[string]string{"x.rego": "package p\nallow { true }\n"}})
	if !called {
		t.Error("validate not called")
	}
}

func TestPollerStopsViaContextCancel(t *testing.T) {
	p := NewPoller("", 1*time.Second, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	cancel()
	p.Stop()
}

func TestHotReloaderStopsViaContextCancel(t *testing.T) {
	h := NewHotReloader("", 1*time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	h.Start(ctx)
	cancel()
	h.Stop()
}

func TestLoadBundleFromDirJSONData(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "decisions.rego"), []byte("package policy.decisions\nallow { true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"k":"v"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundleFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v, ok := b.Data["k"]; !ok || v != "v" {
		t.Errorf("data: %+v", b.Data)
	}
}

func TestLoadBundleFromDirYAMLData(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "decisions.rego"), []byte("package policy.decisions\nallow { true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.yaml"), []byte("k: v\nnum: 42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundleFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v, ok := b.Data["k"]; !ok || v != "v" {
		t.Errorf("k: %+v", b.Data)
	}
	if v, ok := b.Data["num"]; !ok || v != 42 {
		t.Errorf("num: %+v", b.Data)
	}
}

func TestLoadBundleFromDirBadJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "decisions.rego"), []byte("package policy.decisions\nallow { true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundleFromDir(dir); err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestLoadBundleFromDirBadYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "decisions.rego"), []byte("package policy.decisions\nallow { true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.yaml"), []byte("k: : : invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundleFromDir(dir); err == nil {
		t.Fatal("expected error for bad YAML")
	}
}

func TestParseYAMLError(t *testing.T) {
	if _, err := parseYAML([]byte("k: : : invalid")); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestNormalizeData(t *testing.T) {
	in := map[string]any{"k": 1}
	out := normalizeData(in)
	if out["k"] != 1 {
		t.Errorf("normalizeData: %+v", out)
	}
}

func TestHashBundleEmpty(t *testing.T) {
	h := HashBundle(nil, nil)
	if h == "" {
		t.Fatal("empty hash")
	}
}

func TestHashBundleDeterministic(t *testing.T) {
	src := map[string]string{"a.rego": "package a\n", "b.rego": "package b\n"}
	data := map[string]any{"x": 1}
	h1 := HashBundle(src, data)
	h2 := HashBundle(src, data)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
	// Different key order shouldn't matter — function sorts keys.
	h3 := HashBundle(map[string]string{"b.rego": "package b\n", "a.rego": "package a\n"}, data)
	if h1 != h3 {
		t.Fatalf("hash order-dependent: %s != %s", h1, h3)
	}
}