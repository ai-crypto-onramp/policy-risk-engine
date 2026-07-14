package db

import (
	"testing"
)

func TestActivatePolicyVersionNilDB(t *testing.T) {
	if _, err := ActivatePolicyVersion(nil, "default", "v1", "h", "", "test"); err == nil {
		t.Fatal("expected error for nil db")
	}
}

func TestActivatePolicyVersionEmptyVersion(t *testing.T) {
	if _, err := ActivatePolicyVersion(nil, "default", "", "h", "", "test"); err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestGetActiveVersionNilDB(t *testing.T) {
	if _, _, err := GetActiveVersion(nil, "default"); err == nil {
		t.Fatal("expected error for nil db")
	}
}

func TestParseVersionInt(t *testing.T) {
	if parseVersionInt("42") != 42 {
		t.Fatal("numeric parse failed")
	}
	if parseVersionInt("abc") <= 0 {
		t.Fatal("hash-derived version should be positive")
	}
}

func TestErrNoActiveVersion(t *testing.T) {
	if ErrNoActiveVersion == nil {
		t.Fatal("ErrNoActiveVersion should be non-nil")
	}
}