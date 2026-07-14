package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// ActivatePolicyVersion creates a new immutable policy_versions row (or returns
// the existing one when (policy_id, version) already exists) and updates
// policies.active_version to point at it, all within a single transaction.
//
// version is the human-readable version string (e.g. bundle hash); it is
// mapped to an integer via versionToInt for the policy_versions.version
// column. regoHash / regoSource / createdBy are stored on the version row.
//
// Returns the policy_versions.id of the activated version.
func ActivatePolicyVersion(database *sql.DB, scope, version, regoHash, regoSource, createdBy string) (int64, error) {
	if database == nil {
		return 0, errors.New("db is required")
	}
	if version == "" {
		return 0, errors.New("version is required")
	}
	ctx := context.Background()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policyID, err := ensurePolicy(ctx, tx, scope)
	if err != nil {
		return 0, err
	}
	vid, err := ensurePolicyVersion(ctx, tx, policyID, version, regoHash, regoSource, createdBy)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE policies SET active_version = $1 WHERE id = $2`, vid, policyID); err != nil {
		return 0, fmt.Errorf("set active_version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return vid, nil
}

// GetActiveVersion returns the currently active policy_versions row for scope.
func GetActiveVersion(database *sql.DB, scope string) (version string, regoHash string, err error) {
	if database == nil {
		return "", "", errors.New("db is required")
	}
	row := database.QueryRowContext(context.Background(),
		`SELECT v.version::text, v.rego_hash
		 FROM policies p
		 JOIN policy_versions v ON v.id = p.active_version
		 WHERE p.scope = $1`, scope)
	v := ""
	h := ""
	if err := row.Scan(&v, &h); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNoActiveVersion
		}
		return "", "", fmt.Errorf("get active version: %w", err)
	}
	return strconv.Itoa(parseVersionInt(v)), h, nil
}

// ErrNoActiveVersion is returned when no active version is set for the scope.
var ErrNoActiveVersion = errors.New("no active policy version")

// parseVersionInt parses a version column value (stored as INTEGER) read back
// via ::text cast. Non-numeric values fall back to the FNV derivation in
// versionToInt so the returned value matches what was inserted.
func parseVersionInt(s string) int {
	n, err := strconv.Atoi(s)
	if err == nil {
		return n
	}
	v, _ := versionToInt(s)
	return v
}