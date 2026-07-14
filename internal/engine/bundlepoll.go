package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// LoadBundleFromURL downloads a bundle tarball/gzip from the OPA bundle service
// (OPA_BUNDLE_URL) and stages it as a Bundle without activating it. The caller
// is responsible for verifying the hash and calling Swap when ready.
//
// The OPA bundle service serves bundles at <base>/bundles/<name>.tar.gz with a
// .manifest.json describing the revision. This loader is intentionally minimal:
// it fetches the raw bytes, hashes them, and returns a Bundle whose Source is
// keyed by the URL path so callers can inspect the staged content.
//
// For the single-file mode used by this service the bundle URL points at a
// plain Rego or tar.gz file. When the response is a tarball the staged Source
// is left empty (the caller should fall back to LoadBundleFromDir after
// extracting); for plain-text Rego the body is staged under "staged.rego".
func LoadBundleFromURL(ctx context.Context, client *http.Client, bundleURL string) (*Bundle, error) {
	if bundleURL == "" {
		return nil, errors.New("bundle url is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("bundle request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("bundle fetch status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	h := sha256.Sum256(body)
	hash := hex.EncodeToString(h[:])
	src := map[string]string{}
	contentType := resp.Header.Get("Content-Type")
	if isRegoContent(contentType, body) {
		src["staged.rego"] = string(body)
	}
	return &Bundle{
		Version:  hash,
		Hash:     hash,
		Source:   src,
		Data:     map[string]any{},
		loadedAt: time.Now(),
	}, nil
}

// isRegoContent heuristically detects a plain Rego file by looking for the
// "package " prefix (skipping leading whitespace/comments).
func isRegoContent(contentType string, body []byte) bool {
	if contentType == "text/plain" || contentType == "application/octet-stream" {
		for _, line := range splitLines(body) {
			trimmed := trimLeftSpace([]byte(line))
			if len(trimmed) == 0 || trimmed[0] == '#' {
				continue
			}
			return startsWith(trimmed, "package ")
		}
	}
	return false
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

func trimLeftSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}

func startsWith(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	return string(b[:len(prefix)]) == prefix
}

// Poller periodically downloads a bundle from OPA_BUNDLE_URL, stages it
// (without activating), and notifies a callback when a new version is staged.
// Transient fetch errors are logged but do not stop the loop.
type Poller struct {
	url       string
	interval  time.Duration
	client    *http.Client
	engine    *OPAEngine
	onStage   func(b *Bundle)
	stopCh    chan struct{}
	stoppedCh chan struct{}
	once      sync.Once
}

// NewPoller returns a bundle Poller. interval is the poll cadence; when 0 it
// defaults to OPA_BUNDLE_POLL_INTERVAL env (or 30s).
func NewPoller(url string, interval time.Duration, eng *OPAEngine, onStage func(b *Bundle)) *Poller {
	if interval <= 0 {
		interval = time.Duration(envInt("OPA_BUNDLE_POLL_INTERVAL", 30)) * time.Second
	}
	return &Poller{
		url:       url,
		interval:  interval,
		client:    &http.Client{Timeout: 10 * time.Second},
		engine:    eng,
		onStage:   onStage,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}
}

// Start launches the polling goroutine. It returns immediately.
func (p *Poller) Start(ctx context.Context) {
	go p.run(ctx)
}

// Stop signals the poller to stop and waits for the goroutine to exit.
func (p *Poller) Stop() {
	p.once.Do(func() { close(p.stopCh) })
	<-p.stoppedCh
}

func (p *Poller) run(ctx context.Context) {
	defer close(p.stoppedCh)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.pollOnce(ctx)
		}
	}
}

func (p *Poller) pollOnce(ctx context.Context) {
	if p.url == "" {
		return
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := LoadBundleFromURL(fetchCtx, p.client, p.url)
	if err != nil {
		log.Printf("bundle poll fetch error: %v", err)
		return
	}
	if p.engine != nil {
		current := p.engine.Hash()
		if b.Hash == current {
			return
		}
	}
	log.Printf("bundle staged v%s", b.Version)
	if p.onStage != nil {
		p.onStage(b)
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}