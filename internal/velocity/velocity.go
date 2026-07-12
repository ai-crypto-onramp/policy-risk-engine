// Package velocity implements per-minute / per-hour / per-day velocity
// counters using atomic increment with TTL equal to the window length. The
// production Redis implementation wraps go-redis; an in-memory implementation
// is provided for tests and DB-less mode.
package velocity

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Counter is the velocity counter abstraction. Increment is called on the
// evaluate path; Rollback is the compensating decrement invoked when a tx
// fails downstream.
type Counter interface {
	Increment(ctx context.Context, userID string, window Window) (int64, error)
	Rollback(ctx context.Context, userID string, window Window) (int64, error)
	Get(ctx context.Context, userID string, window Window) (int64, error)
}

// Window identifies a velocity window length.
type Window time.Duration

const (
	// WindowMinute is the per-minute rolling window.
	WindowMinute = Window(60 * time.Second)
	// WindowHour is the per-hour rolling window.
	WindowHour = Window(time.Hour)
	// WindowDay is the per-day rolling window.
	WindowDay = Window(24 * time.Hour)
)

// String returns a human-readable window name (e.g. "60s", "1h0m0s").
func (w Window) String() string { return time.Duration(w).String() }

// Suffix returns the key suffix used for the window (e.g. "60s", "1h", "1d").
func (w Window) Suffix() string {
	switch w {
	case WindowMinute:
		return "60s"
	case WindowHour:
		return "1h"
	case WindowDay:
		return "1d"
	}
	return time.Duration(w).String()
}

// Config holds velocity counter configuration read from the environment.
type Config struct {
	WindowMinSec  int
	WindowHourSec int
	WindowDaySec  int
}

// DefaultConfig returns a Config populated from env with README defaults.
func DefaultConfig() Config {
	return Config{
		WindowMinSec:  envInt("VELOCITY_WINDOW_MIN_SEC", 60),
		WindowHourSec: envInt("VELOCITY_WINDOW_HOUR_SEC", 3600),
		WindowDaySec:  envInt("VELOCITY_WINDOW_DAY_SEC", 86400),
	}
}

// WindowsFromConfig returns the three canonical windows derived from cfg.
func WindowsFromConfig(cfg Config) (Window, Window, Window) {
	return Window(time.Duration(cfg.WindowMinSec) * time.Second),
		Window(time.Duration(cfg.WindowHourSec) * time.Second),
		Window(time.Duration(cfg.WindowDaySec) * time.Second)
}

// key returns the redis-style key for a user + window.
func key(userID string, w Window) string {
	return fmt.Sprintf("vel:%s:%s", userID, w.Suffix())
}

// ErrNegativeCounter is returned when a rollback would produce a negative
// counter; the counter is left at zero instead.
var ErrNegativeCounter = errors.New("velocity counter would be negative")

// MemoryCounter is an in-memory Counter used for tests and DB-less mode.
// Each counter has a TTL equal to its window length; entries expire
// automatically.
type MemoryCounter struct {
	mu   sync.Mutex
	mem  map[string]*memEntry
	now  func() time.Time
}

type memEntry struct {
	value     int64
	expiresAt time.Time
}

// NewMemoryCounter returns a fresh in-memory velocity counter.
func NewMemoryCounter() *MemoryCounter {
	return &MemoryCounter{mem: make(map[string]*memEntry), now: time.Now}
}

// WithNow overrides the clock (for testing).
func (c *MemoryCounter) WithNow(now func() time.Time) *MemoryCounter {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
	return c
}

// Increment atomically increments the counter for (userID, window) and
// (re)sets the TTL to the window length. Returns the new value.
func (c *MemoryCounter) Increment(_ context.Context, userID string, w Window) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(userID, w)
	e, ok := c.mem[k]
	now := c.now()
	if !ok || now.After(e.expiresAt) {
		e = &memEntry{value: 0, expiresAt: now.Add(time.Duration(w))}
		c.mem[k] = e
	}
	e.value++
	e.expiresAt = now.Add(time.Duration(w))
	return e.value, nil
}

// Rollback atomically decrements the counter. If the counter would become
// negative it is set to 0 and ErrNegativeCounter is returned (the call still
// succeeds in leaving the counter at 0).
func (c *MemoryCounter) Rollback(_ context.Context, userID string, w Window) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(userID, w)
	e, ok := c.mem[k]
	now := c.now()
	if !ok || now.After(e.expiresAt) {
		return 0, nil
	}
	e.value--
	if e.value < 0 {
		e.value = 0
		return 0, ErrNegativeCounter
	}
	return e.value, nil
}

// Get returns the current counter value (0 if expired or absent).
func (c *MemoryCounter) Get(_ context.Context, userID string, w Window) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(userID, w)
	e, ok := c.mem[k]
	if !ok || c.now().After(e.expiresAt) {
		return 0, nil
	}
	return e.value, nil
}

// Len returns the number of tracked counters.
func (c *MemoryCounter) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.mem)
}

func envInt(key string, def int) int {
	if v := getEnv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}