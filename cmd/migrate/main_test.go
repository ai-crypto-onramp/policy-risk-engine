package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/db"
)

func TestRunNoArgs(t *testing.T) {
	if err := run([]string{"migrate"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("err: %v", err)
	}
}

func TestRunMissingDBURL(t *testing.T) {
	t.Setenv("DB_URL", "")
	if err := run([]string{"migrate", "up"}); !errors.Is(err, db.ErrMissingDBURL) {
		t.Fatalf("err: %v", err)
	}
}

func TestRunUnknownDirection(t *testing.T) {
	t.Setenv("DB_URL", "postgres://x")
	if err := run([]string{"migrate", "sideways"}); err == nil || !strings.Contains(err.Error(), "unknown direction") {
		t.Fatalf("err: %v", err)
	}
}

func TestRunMigrateUpBadDB(t *testing.T) {
	t.Setenv("DB_URL", "postgres://nobody:nopass@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	if err := run([]string{"migrate", "up"}); err == nil {
		t.Fatal("expected error for unreachable DB")
	}
	_ = os.Args
}