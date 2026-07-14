package engine

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HotReloader polls the OPA bundle service on POLICY_HOT_RELOAD_INTERVAL,
// stages a downloaded bundle, validates its hash, and atomically swaps the
// in-memory decision engine. In-flight Evaluate calls continue against the
// previous bundle until they complete (the OPAEngine.Swap is atomic).
//
// Unlike the Stage 2 Poller (which only stages), the HotReloader activates
// the bundle when it differs from the active hash.
type HotReloader struct {
	url      string
	interval time.Duration
	client   *http.Client
	engine   *OPAEngine
	stopCh   chan struct{}
	stoppedCh chan struct{}
	once     sync.Once
	swaps    atomic.Int64
	// validate, when non-nil, is called before swapping to validate the staged
	// bundle. Returning an error aborts the swap.
	validate func(b *Bundle) error
}

// NewHotReloader returns a HotReloader. interval defaults to
// POLICY_HOT_RELOAD_INTERVAL env (or 30s).
func NewHotReloader(url string, interval time.Duration, eng *OPAEngine) *HotReloader {
	if interval <= 0 {
		interval = time.Duration(envInt("POLICY_HOT_RELOAD_INTERVAL", 30)) * time.Second
	}
	return &HotReloader{
		url:       url,
		interval:  interval,
		client:    &http.Client{Timeout: 10 * time.Second},
		engine:    eng,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
		validate:  defaultValidate,
	}
}

// WithValidate overrides the bundle validation hook.
func (h *HotReloader) WithValidate(fn func(b *Bundle) error) *HotReloader {
	h.validate = fn
	return h
}

// Swaps returns the number of successful hot-reload swaps performed.
func (h *HotReloader) Swaps() int64 { return h.swaps.Load() }

// Start launches the hot-reload goroutine. It returns immediately.
func (h *HotReloader) Start(ctx context.Context) {
	go h.run(ctx)
}

// Stop signals the reloader to stop and waits for the goroutine to exit.
func (h *HotReloader) Stop() {
	h.once.Do(func() { close(h.stopCh) })
	<-h.stoppedCh
}

func (h *HotReloader) run(ctx context.Context) {
	defer close(h.stoppedCh)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.reloadOnce(ctx)
		}
	}
}

func (h *HotReloader) reloadOnce(ctx context.Context) {
	if h.url == "" {
		return
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := LoadBundleFromURL(fetchCtx, h.client, h.url)
	if err != nil {
		log.Printf("hot-reload fetch error: %v", err)
		return
	}
	if h.engine != nil && b.Hash == h.engine.Hash() {
		return
	}
	if h.validate != nil {
		if err := h.validate(b); err != nil {
			log.Printf("hot-reload validation failed: %v", err)
			return
		}
	}
	if h.engine != nil {
		h.engine.Swap(b)
		h.swaps.Add(1)
		log.Printf("hot-reload swapped to v%s (hash=%s)", b.Version, b.Hash[:min(8, len(b.Hash))])
	}
}

// defaultValidate ensures the staged bundle has at least one Rego module and
// that the source compiles.
func defaultValidate(b *Bundle) error {
	if len(b.Source) == 0 {
		return errors.New("bundle has no rego source")
	}
	if _, err := compileModules(b.Source); err != nil {
		return err
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// hotReloadIntervalFromEnv is exported for tests.
func hotReloadIntervalFromEnv() time.Duration {
	return time.Duration(envInt("POLICY_HOT_RELOAD_INTERVAL", 30)) * time.Second
}