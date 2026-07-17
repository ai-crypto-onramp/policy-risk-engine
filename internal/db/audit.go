package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/audit"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// AuditStore is a DB-backed audit.Store backed by policy_decisions.
// PolicyVersion is the active policy version string (e.g. the bundle hash);
// policyVersionID is the resolved policy_versions.id used for inserts.
type AuditStore struct {
	db              *sql.DB
	policyVersionID uuid.UUID
}

// NewAuditStore returns a DB-backed audit store. EnsurePolicyVersion must be
// called before Put to resolve policyVersionID.
func NewAuditStore(db *sql.DB) *AuditStore {
	return &AuditStore{db: db}
}

var _ audit.Store = (*AuditStore)(nil)

// EnsurePolicyVersion resolves version string to a policy_versions.id,
// creating policies + policy_versions rows on first use. Must be called
// before Put (e.g. at boot with the active engine version).
func (s *AuditStore) EnsurePolicyVersion(version, regoHash, regoSource, createdBy string) error {
	if version == "" {
		return errors.New("policy version is required")
	}
	if s.policyVersionID != uuid.Nil {
		return nil
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policyID, err := ensurePolicy(ctx, tx, "default")
	if err != nil {
		return err
	}
	vid, err := ensurePolicyVersion(ctx, tx, policyID, version, regoHash, regoSource, createdBy)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	s.policyVersionID = vid
	return nil
}

func ensurePolicy(ctx context.Context, tx *sql.Tx, scope string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM policies WHERE scope = $1`, scope).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("lookup policy: %w", err)
	}
	id, _ = uuid.NewV7()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO policies (id, scope) VALUES ($1, $2)`, id, scope,
	); err != nil {
		return uuid.Nil, fmt.Errorf("insert policy: %w", err)
	}
	return id, nil
}

func ensurePolicyVersion(ctx context.Context, tx *sql.Tx, policyID uuid.UUID, version, regoHash, regoSource, createdBy string) (uuid.UUID, error) {
	versionInt, err := versionToInt(version)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse version %q: %w", version, err)
	}
	id, _ := uuid.NewV7()
	var existingID uuid.UUID
	err = tx.QueryRowContext(ctx,
		`INSERT INTO policy_versions (id, policy_id, version, rego_hash, rego_source, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (policy_id, version) DO UPDATE SET rego_hash = EXCLUDED.rego_hash
		 RETURNING id`,
		id, policyID, versionInt, regoHash, regoSource, createdBy,
	).Scan(&existingID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("ensure policy_version: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE policies SET active_version = $1, updated_at = now() WHERE id = $2`, existingID, policyID); err != nil {
		return uuid.Nil, fmt.Errorf("set active_version: %w", err)
	}
	return existingID, nil
}

func versionToInt(version string) (int, error) {
	n, err := strconv.Atoi(version)
	if err == nil {
		return n, nil
	}
	// version is a hash; derive a stable positive integer via FNV-1a.
	h := uint32(2166136261)
	for i := 0; i < len(version); i++ {
		h ^= uint32(version[i])
		h *= 16777619
	}
	return int(h%9000000) + 1000000, nil
}

// Put persists rec. If the decision_id already exists, returns audit.ErrDuplicateDecision.
func (s *AuditStore) Put(rec audit.DecisionRecord) error {
	if rec.DecisionID == "" {
		return errors.New("decision_id required")
	}
	if s.policyVersionID == uuid.Nil {
		return errors.New("EnsurePolicyVersion must be called before Put")
	}
	// reasons and applied_rules are NOT NULL DEFAULT '{}' in policy_decisions.
	// pq.Array of a nil slice yields SQL NULL (which violates the constraint),
	// so coerce nil to an empty slice to let the column default / array literal apply.
	reasons := rec.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	appliedRules := rec.AppliedRules
	if appliedRules == nil {
		appliedRules = []string{}
	}
	var sigBytes []byte
	if rec.Signature != "" {
		sigBytes = []byte(rec.Signature)
	}
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO policy_decisions (decision_id, policy_version, request_hash, decision, reasons, applied_rules, score, signature, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		rec.DecisionID, s.policyVersionID, rec.RequestHash, rec.Decision,
		pq.Array(reasons), pq.Array(appliedRules),
		rec.Score, sigBytes, rec.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return audit.ErrDuplicateDecision
		}
		return err
	}
	return nil
}

// Get returns the record by decisionID.
func (s *AuditStore) Get(decisionID string) (audit.DecisionRecord, bool, error) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT d.decision_id, v.version::text, d.request_hash, d.decision, d.reasons, d.applied_rules, d.score, d.signature, d.created_at
		 FROM policy_decisions d
		 JOIN policy_versions v ON v.id = d.policy_version
		 WHERE d.decision_id = $1`, decisionID)
	rec, err := scanDecisionRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.DecisionRecord{}, false, nil
	}
	if err != nil {
		return audit.DecisionRecord{}, false, err
	}
	return rec, true, nil
}

func scanDecisionRow(r interface {
	Scan(dest ...any) error
}) (audit.DecisionRecord, error) {
	var rec audit.DecisionRecord
	var reasons, appliedRules pq.StringArray
	var sigBytes []byte
	err := r.Scan(&rec.DecisionID, &rec.PolicyVersion, &rec.RequestHash, &rec.Decision,
		&reasons, &appliedRules, &rec.Score, &sigBytes, &rec.CreatedAt)
	if err != nil {
		return audit.DecisionRecord{}, err
	}
	rec.Reasons = reasons
	rec.AppliedRules = appliedRules
	rec.Signature = string(sigBytes)
	return rec, nil
}