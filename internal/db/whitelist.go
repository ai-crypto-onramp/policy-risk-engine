package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/whitelist"
)

// WhitelistStore is a DB-backed whitelist.Store backed by whitelist_addresses.
type WhitelistStore struct {
	db *sql.DB
}

// NewWhitelistStore returns a DB-backed whitelist store.
func NewWhitelistStore(db *sql.DB) *WhitelistStore {
	return &WhitelistStore{db: db}
}

var _ whitelist.Store = (*WhitelistStore)(nil)

// Add inserts e; returns whitelist.ErrDuplicate on (user_id, chain, address) conflict.
func (s *WhitelistStore) Add(e whitelist.Entry) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO whitelist_addresses (user_id, chain, address, label, verified_at, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.UserID, e.Chain, e.Address, nullableText(e.Label),
		nullableTime(e.VerifiedAt), e.Status, e.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return whitelist.ErrDuplicate
		}
		return err
	}
	return nil
}

// List returns entries for userID.
func (s *WhitelistStore) List(userID string) ([]whitelist.Entry, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT user_id, chain, address, label, verified_at, status, created_at
		 FROM whitelist_addresses WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWhitelistRows(rows)
}

// Get returns the entry for (userID, chain, address).
func (s *WhitelistStore) Get(userID, chain, address string) (whitelist.Entry, bool, error) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT user_id, chain, address, label, verified_at, status, created_at
		 FROM whitelist_addresses WHERE user_id = $1 AND chain = $2 AND address = $3`,
		userID, chain, address)
	e, err := scanWhitelistRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return whitelist.Entry{}, false, nil
	}
	if err != nil {
		return whitelist.Entry{}, false, err
	}
	return e, true, nil
}

// Update overwrites the stored entry; returns whitelist.ErrNotFound if no row exists.
func (s *WhitelistStore) Update(e whitelist.Entry) error {
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE whitelist_addresses
		 SET label = $1, verified_at = $2, status = $3
		 WHERE user_id = $4 AND chain = $5 AND address = $6`,
		nullableText(e.Label), nullableTime(e.VerifiedAt), e.Status,
		e.UserID, e.Chain, e.Address,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return whitelist.ErrNotFound
	}
	return nil
}

func scanWhitelistRows(rows *sql.Rows) ([]whitelist.Entry, error) {
	var out []whitelist.Entry
	for rows.Next() {
		e, err := scanWhitelistRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanWhitelistRow(r interface {
	Scan(dest ...any) error
}) (whitelist.Entry, error) {
	var e whitelist.Entry
	var label sql.NullString
	var verifiedAt sql.NullTime
	err := r.Scan(&e.UserID, &e.Chain, &e.Address, &label, &verifiedAt, &e.Status, &e.CreatedAt)
	if err != nil {
		return whitelist.Entry{}, err
	}
	e.Label = label.String
	if verifiedAt.Valid {
		e.VerifiedAt = verifiedAt.Time
	}
	return e, nil
}

func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}