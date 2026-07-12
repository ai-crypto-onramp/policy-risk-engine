package velocity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWindowSuffix(t *testing.T) {
	cases := map[Window]string{
		WindowMinute: "60s",
		WindowHour:   "1h",
		WindowDay:    "1d",
	}
	for w, want := range cases {
		if got := w.Suffix(); got != want {
			t.Errorf("window %v suffix: %q want %q", w, got, want)
		}
	}
}

func TestDefaultConfigFromEnv(t *testing.T) {
	t.Setenv("VELOCITY_WINDOW_MIN_SEC", "30")
	t.Setenv("VELOCITY_WINDOW_HOUR_SEC", "1800")
	t.Setenv("VELOCITY_WINDOW_DAY_SEC", "43200")
	cfg := DefaultConfig()
	if cfg.WindowMinSec != 30 || cfg.WindowHourSec != 1800 || cfg.WindowDaySec != 43200 {
		t.Fatalf("cfg: %+v", cfg)
	}
	min, hour, day := WindowsFromConfig(cfg)
	if min != Window(30*time.Second) || hour != Window(1800*time.Second) || day != Window(43200*time.Second) {
		t.Fatalf("windows: %v %v %v", min, hour, day)
	}
}

func TestMemoryCounterIncrement(t *testing.T) {
	c := NewMemoryCounter()
	for i := int64(1); i <= 5; i++ {
		v, err := c.Increment(context.Background(), "usr_1", WindowMinute)
		if err != nil {
			t.Fatalf("incr: %v", err)
		}
		if v != i {
			t.Errorf("incr %d: got %d", i, v)
		}
	}
}

func TestMemoryCounterRollback(t *testing.T) {
	c := NewMemoryCounter()
	for i := 0; i < 3; i++ {
		_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	}
	v, err := c.Rollback(context.Background(), "usr_1", WindowMinute)
	if err != nil || v != 2 {
		t.Fatalf("rollback: v=%d err=%v", v, err)
	}
}

func TestMemoryCounterRollbackToZero(t *testing.T) {
	c := NewMemoryCounter()
	_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	_, _ = c.Rollback(context.Background(), "usr_1", WindowMinute)
	_, err := c.Rollback(context.Background(), "usr_1", WindowMinute)
	if !errors.Is(err, ErrNegativeCounter) {
		t.Fatalf("expected ErrNegativeCounter, got %v", err)
	}
	v, _ := c.Get(context.Background(), "usr_1", WindowMinute)
	if v != 0 {
		t.Errorf("counter should be 0, got %d", v)
	}
}

func TestMemoryCounterRollbackExpired(t *testing.T) {
	c := NewMemoryCounter()
	now := time.Now()
	c.WithNow(func() time.Time { return now })
	_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	// Advance past TTL.
	c.WithNow(func() time.Time { return now.Add(2 * time.Minute) })
	v, err := c.Rollback(context.Background(), "usr_1", WindowMinute)
	if err != nil || v != 0 {
		t.Fatalf("rollback expired: v=%d err=%v", v, err)
	}
}

func TestMemoryCounterExpiresAfterTTL(t *testing.T) {
	c := NewMemoryCounter()
	now := time.Now()
	c.WithNow(func() time.Time { return now })
	_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	c.WithNow(func() time.Time { return now.Add(2 * time.Minute) })
	v, _ := c.Get(context.Background(), "usr_1", WindowMinute)
	if v != 0 {
		t.Errorf("expired counter: got %d, want 0", v)
	}
}

func TestMemoryCounterIncrementAfterExpiryResets(t *testing.T) {
	c := NewMemoryCounter()
	now := time.Now()
	c.WithNow(func() time.Time { return now })
	_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	c.WithNow(func() time.Time { return now.Add(2 * time.Minute) })
	v, _ := c.Increment(context.Background(), "usr_1", WindowMinute)
	if v != 1 {
		t.Errorf("after expiry increment should reset to 1, got %d", v)
	}
}

func TestMemoryCounterGetAbsent(t *testing.T) {
	c := NewMemoryCounter()
	v, err := c.Get(context.Background(), "nope", WindowMinute)
	if err != nil || v != 0 {
		t.Fatalf("get absent: v=%d err=%v", v, err)
	}
}

func TestMemoryCounterConcurrentIncrements(t *testing.T) {
	c := NewMemoryCounter()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
		}()
	}
	wg.Wait()
	v, _ := c.Get(context.Background(), "usr_1", WindowMinute)
	if v != 100 {
		t.Errorf("concurrent increments: got %d, want 100", v)
	}
}

func TestMemoryCounterLen(t *testing.T) {
	c := NewMemoryCounter()
	if c.Len() != 0 {
		t.Errorf("initial len: %d", c.Len())
	}
	_, _ = c.Increment(context.Background(), "usr_1", WindowMinute)
	_, _ = c.Increment(context.Background(), "usr_1", WindowHour)
	if c.Len() != 2 {
		t.Errorf("len after 2 windows: %d", c.Len())
	}
}