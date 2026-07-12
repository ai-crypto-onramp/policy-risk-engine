// Package engine wraps OPA as an in-process library, loads Rego policies from
// a bundle, and exposes a minimal Evaluate(input) -> result entry point.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"gopkg.in/yaml.v3"
)

// Result is the output of a policy evaluation.
type Result struct {
	Allow         bool    `json:"allow"`
	ManualReview  bool    `json:"manual_review"`
	Deny          bool    `json:"deny"`
	RiskScore     float64 `json:"risk_score"`
	Decision      string  `json:"decision"`
	AppliedRules  []string `json:"applied_rules,omitempty"`
}

// Engine is the swappable decision engine interface. Implementations must be
// safe for concurrent use.
type Engine interface {
	Evaluate(ctx context.Context, input map[string]any) (Result, error)
	Hash() string
	Version() string
}

// Bundle is a loaded Rego bundle: source, hash, and version.
type Bundle struct {
	Version  string
	Hash     string
	Source   map[string]string // filename -> source
	Data     map[string]any
	loadedAt time.Time
}

// LoadBundleFromDir reads all .rego and .yaml/.json data files from dir and
// returns a Bundle with a deterministic SHA-256 hash of the canonical source.
func LoadBundleFromDir(dir string) (*Bundle, error) {
	src := make(map[string]string)
	data := make(map[string]any)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", path, rerr)
		}
		rel, _ := filepath.Rel(dir, path)
		switch ext := filepath.Ext(path); ext {
		case ".rego":
			src[rel] = string(body)
		case ".json":
			var v map[string]any
			if err := json.Unmarshal(body, &v); err != nil {
				return fmt.Errorf("parse json %s: %w", path, err)
			}
			mergeData(data, v)
		case ".yaml", ".yml":
			v, err := parseYAML(body)
			if err != nil {
				return fmt.Errorf("parse yaml %s: %w", path, err)
			}
			if m, ok := v.(map[string]any); ok {
				mergeData(data, m)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(src) == 0 {
		return nil, errors.New("no .rego files found in bundle dir")
	}
	return &Bundle{
		Version:  hashBundle(src, data),
		Hash:     hashBundle(src, data),
		Source:   src,
		Data:     data,
		loadedAt: time.Now(),
	}, nil
}

// mergeData merges src into dst (shallow).
func mergeData(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

// hashBundle returns the deterministic SHA-256 hash of the bundle source.
func hashBundle(src map[string]string, data map[string]any) string {
	h := sha256.New()
	// Keys are sorted for determinism.
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(src[k]))
		_, _ = h.Write([]byte{0})
	}
	dkeys := make([]string, 0, len(data))
	for k := range data {
		dkeys = append(dkeys, k)
	}
	sortStrings(dkeys)
	for _, k := range dkeys {
		body, _ := json.Marshal(data[k])
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(body)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// OPAEngine is an OPA-backed DecisionEngine.
type OPAEngine struct {
	bundle *Bundle
	mu     sync.RWMutex
}

// NewOPAEngine returns an OPAEngine backed by bundle.
func NewOPAEngine(bundle *Bundle) *OPAEngine {
	return &OPAEngine{bundle: bundle}
}

// Hash returns the bundle hash.
func (e *OPAEngine) Hash() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bundle.Hash
}

// Version returns the bundle version (currently equal to the hash).
func (e *OPAEngine) Version() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bundle.Version
}

// Bundle returns the current bundle (thread-safe).
func (e *OPAEngine) Bundle() *Bundle {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bundle
}

// Swap atomically replaces the active bundle. In-flight Evaluate calls
// continue against the previous bundle until they complete.
func (e *OPAEngine) Swap(b *Bundle) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bundle = b
}

// Evaluate runs the Rego policy against input and returns the decision.
func (e *OPAEngine) Evaluate(ctx context.Context, input map[string]any) (Result, error) {
	e.mu.RLock()
	bundle := e.bundle
	e.mu.RUnlock()

	compiler, err := compileModules(bundle.Source)
	if err != nil {
		return Result{}, fmt.Errorf("compile: %w", err)
	}
	store := inmem.NewFromObject(normalizeData(bundle.Data))

	allow, err := evalBool(ctx, compiler, store, input, "data.policy.decisions.allow")
	if err != nil {
		return Result{}, fmt.Errorf("eval allow: %w", err)
	}
	mr, err := evalBool(ctx, compiler, store, input, "data.policy.decisions.manual_review")
	if err != nil {
		return Result{}, fmt.Errorf("eval manual_review: %w", err)
	}
	deny, err := evalBool(ctx, compiler, store, input, "data.policy.decisions.deny")
	if err != nil {
		return Result{}, fmt.Errorf("eval deny: %w", err)
	}
	score, errScore := evalFloat(ctx, compiler, store, input, "data.policy.decisions.risk_score")
	if errScore != nil {
		// Non-fatal: default to 0.
		score = 0
	}

	return e.decide(allow, mr, deny, score, appliedRules(allow, mr, deny)), nil
}

// compileModules parses and compiles Rego source files into an ast.Compiler.
func compileModules(src map[string]string) (*ast.Compiler, error) {
	modules := make(map[string]*ast.Module, len(src))
	for name, body := range src {
		mod, err := ast.ParseModule(name, body)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		modules[name] = mod
	}
	c := ast.NewCompiler()
	c.Compile(modules)
	if c.Failed() {
		return nil, fmt.Errorf("compile: %v", c.Errors)
	}
	return c, nil
}

// evalBool evaluates a boolean query.
func evalBool(ctx context.Context, c *ast.Compiler, s storageStore, input map[string]any, query string) (bool, error) {
	r := rego.New(rego.Compiler(c), rego.Store(s), rego.Input(input), rego.Query(query))
	results, err := r.Eval(ctx)
	if err != nil {
		return false, err
	}
	return truthy(results), nil
}

// evalFloat evaluates a float query.
func evalFloat(ctx context.Context, c *ast.Compiler, s storageStore, input map[string]any, query string) (float64, error) {
	r := rego.New(rego.Compiler(c), rego.Store(s), rego.Input(input), rego.Query(query))
	results, err := r.Eval(ctx)
	if err != nil {
		return 0, err
	}
	return scoreFloat(results), nil
}

// storageStore is the OPA storage.Store interface.
type storageStore = storage.Store

// normalizeData ensures data values are in a form OPA storage accepts.
func normalizeData(data map[string]any) map[string]any {
	// YAML decodes numbers as int or float64; OPA expects these. Just return.
	return data
}

// decide maps the boolean flags into a Result with a single decision field.
// Precedence: deny > manual_review > allow.
func (e *OPAEngine) decide(allow, mr, deny bool, score float64, rules []string) Result {
	decision := "manual_review"
	switch {
	case deny:
		decision = "deny"
	case mr:
		decision = "manual_review"
	case allow:
		decision = "allow"
	}
	return Result{
		Allow:        allow,
		ManualReview: mr,
		Deny:         deny,
		RiskScore:    score,
		Decision:     decision,
		AppliedRules: rules,
	}
}

// truthy returns true if the Rego result set expresses a truthy value.
func truthy(results rego.ResultSet) bool {
	if len(results) == 0 {
		return false
	}
	if len(results[0].Expressions) == 0 {
		return false
	}
	v := results[0].Expressions[0].Value
	switch x := v.(type) {
	case bool:
		return x
	case nil:
		return false
	default:
		return true
	}
}

// scoreFloat extracts a float from the risk_score result set.
func scoreFloat(results rego.ResultSet) float64 {
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return 0
	}
	switch x := results[0].Expressions[0].Value.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return 0
}

// appliedRules derives the list of rule ids that fired for the decision.
func appliedRules(allow, mr, deny bool) []string {
	var rules []string
	if deny {
		rules = append(rules, "deny.fraud_high", "deny.kyt_sanctioned", "deny.daily_cap_exceeded", "deny.dest_not_whitelisted", "deny.kyc_not_verified")
	}
	if mr {
		rules = append(rules, "manual_review.fraud_mid", "manual_review.near_cap")
	}
	if allow {
		rules = append(rules, "allow.clean")
	}
	return rules
}

// sortStrings sorts a slice in place.
func sortStrings(s []string) { sort.Strings(s) }

// parseYAML parses a YAML document into a generic value.
func parseYAML(body []byte) (any, error) {
	var v any
	if err := yaml.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	return v, nil
}