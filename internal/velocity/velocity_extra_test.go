package velocity

import (
	"context"
	"errors"
	"testing"
)

func TestWindowString(t *testing.T) {
	if got := WindowMinute.String(); got != "1m0s" {
		t.Errorf("minute string: %q", got)
	}
	if got := WindowHour.String(); got != "1h0m0s" {
		t.Errorf("hour string: %q", got)
	}
	if got := WindowDay.String(); got != "24h0m0s" {
		t.Errorf("day string: %q", got)
	}
}

func TestWindowSuffixUnknown(t *testing.T) {
	w := Window(42)
	if got := w.Suffix(); got != "42ns" {
		t.Errorf("unknown suffix: %q want 42ns", got)
	}
}

func TestEnvIntInvalid(t *testing.T) {
	t.Setenv("VELOCITY_TEST_INT", "not-a-number")
	if got := envInt("VELOCITY_TEST_INT", 7); got != 7 {
		t.Errorf("envInt invalid: %d", got)
	}
	t.Setenv("VELOCITY_TEST_INT", "12")
	if got := envInt("VELOCITY_TEST_INT", 7); got != 12 {
		t.Errorf("envInt valid: %d", got)
	}
}

func TestWindowsFromConfigDefaults(t *testing.T) {
	min, hour, day := WindowsFromConfig(Config{WindowMinSec: 60, WindowHourSec: 3600, WindowDaySec: 86400})
	if min != WindowMinute || hour != WindowHour || day != WindowDay {
		t.Errorf("windows: %v %v %v", min, hour, day)
	}
}

func TestNewRedisCounterDefaultPrefix(t *testing.T) {
	c := NewRedisCounter("localhost:6379", "")
	if c.prefix != "vel" {
		t.Errorf("default prefix: %q", c.prefix)
	}
	if c.client == nil {
		t.Error("nil client")
	}
	_ = c.Close()
}

func TestNewRedisCounterExplicitPrefix(t *testing.T) {
	c := NewRedisCounter("localhost:6379", "myprefix")
	if c.prefix != "myprefix" {
		t.Errorf("prefix: %q", c.prefix)
	}
	_ = c.Close()
}

func TestNewRedisCounterFromClientDefaultPrefix(t *testing.T) {
	c := NewRedisCounterFromClient(nil, "")
	if c.prefix != "vel" {
		t.Errorf("default prefix: %q", c.prefix)
	}
}

func TestRedisCounterKey(t *testing.T) {
	c := NewRedisCounter("localhost:6379", "vel")
	if got := c.k("usr_1", WindowMinute); got != "vel:usr_1:60s" {
		t.Errorf("key: %q", got)
	}
	if got := c.k("usr_1", WindowHour); got != "vel:usr_1:1h" {
		t.Errorf("key: %q", got)
	}
	if got := c.k("usr_1", WindowDay); got != "vel:usr_1:1d" {
		t.Errorf("key: %q", got)
	}
	_ = c.Close()
}

func TestRedisCounterPingFailsOffline(t *testing.T) {
	c := NewRedisCounter("127.0.0.1:1", "vel")
	defer c.Close()
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected ping error for unreachable redis")
	}
}

func TestRedisCounterGetIncrementFailsOffline(t *testing.T) {
	c := NewRedisCounter("127.0.0.1:1", "vel")
	defer c.Close()
	if _, err := c.Increment(context.Background(), "u", WindowMinute); err == nil {
		t.Fatal("expected increment error for unreachable redis")
	}
}

func TestRedisCounterRollbackFailsOffline(t *testing.T) {
	c := NewRedisCounter("127.0.0.1:1", "vel")
	defer c.Close()
	if _, err := c.Rollback(context.Background(), "u", WindowMinute); err == nil {
		t.Fatal("expected rollback error for unreachable redis")
	}
}

func TestRedisCounterGetFailsOffline(t *testing.T) {
	c := NewRedisCounter("127.0.0.1:1", "vel")
	defer c.Close()
	_, err := c.Get(context.Background(), "u", WindowMinute)
	if err == nil {
		t.Fatal("expected get error for unreachable redis")
	}
	if !errors.Is(err, err) {
		t.Errorf("errors.Is self: %v", err)
	}
}