package db

import (
	"context"
	"testing"
)

func TestActivatePolicyVersionLive(t *testing.T) {
	database := freshDB(t)
	defer database.Close()

	vid, err := ActivatePolicyVersion(database, "default", "v-activate-1", "hash-1", "rego-src-1", "test")
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if vid <= 0 {
		t.Fatalf("version id: %d", vid)
	}

	// Activating the same version again should be idempotent (return same id).
	vid2, err := ActivatePolicyVersion(database, "default", "v-activate-1", "hash-1", "rego-src-1", "test")
	if err != nil {
		t.Fatalf("activate 2: %v", err)
	}
	if vid2 != vid {
		t.Fatalf("idempotent activate: got %d want %d", vid2, vid)
	}

	// GetActiveVersion should return the active version.
	_, hash, err := GetActiveVersion(database, "default")
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if hash != "hash-1" {
		t.Fatalf("active hash: %q want hash-1", hash)
	}

	// Activate a new version; active should switch.
	_, err = ActivatePolicyVersion(database, "default", "v-activate-2", "hash-2", "rego-src-2", "test")
	if err != nil {
		t.Fatalf("activate 3: %v", err)
	}
	_, hash2, err := GetActiveVersion(database, "default")
	if err != nil {
		t.Fatalf("get active 2: %v", err)
	}
	if hash2 != "hash-2" {
		t.Fatalf("active hash after swap: %q want hash-2", hash2)
	}

	// Verify the active_version points to the new row in a single query.
	var activeID int64
	row := database.QueryRowContext(context.Background(),
		`SELECT active_version FROM policies WHERE scope = 'default'`)
	if err := row.Scan(&activeID); err != nil {
		t.Fatalf("query active_version: %v", err)
	}
	var activeHash string
	row = database.QueryRowContext(context.Background(),
		`SELECT rego_hash FROM policy_versions WHERE id = $1`, activeID)
	if err := row.Scan(&activeHash); err != nil {
		t.Fatalf("query active version hash: %v", err)
	}
	if activeHash != "hash-2" {
		t.Fatalf("active_version FK: %q want hash-2", activeHash)
	}
}

func TestGetActiveVersionNoRow(t *testing.T) {
	database := freshDB(t)
	defer database.Close()
	_, _, err := GetActiveVersion(database, "nonexistent-scope")
	if err == nil {
		t.Fatal("expected error for missing scope")
	}
}