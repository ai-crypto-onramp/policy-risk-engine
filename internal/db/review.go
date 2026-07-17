package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ai-crypto-onramp/policy-risk-engine/internal/review"
	"github.com/google/uuid"
)

// ReviewStore is a DB-backed review.Store backed by review_queue.
type ReviewStore struct {
	db *sql.DB
}

// NewReviewStore returns a DB-backed review store.
func NewReviewStore(db *sql.DB) *ReviewStore {
	return &ReviewStore{db: db}
}

var _ review.Store = (*ReviewStore)(nil)

// Put inserts item; returns review.ErrDuplicate on conflict.
func (s *ReviewStore) Put(item review.Item) error {
	id, _ := uuid.NewV7()
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO review_queue (id, decision_id, tx_id, status, assigned_to, created_at, resolved_at, resolution)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, item.DecisionID, nullableText(item.TxID), item.Status,
		nullableText(item.AssignedTo), item.CreatedAt,
		nullableTimePtr(item.ResolvedAt), nullableText(item.Resolution),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return review.ErrDuplicate
		}
		return err
	}
	return nil
}

// Get returns the item by decisionID.
func (s *ReviewStore) Get(decisionID string) (review.Item, bool, error) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT decision_id, tx_id, status, assigned_to, created_at, resolved_at, resolution
		 FROM review_queue WHERE decision_id = $1`, decisionID)
	item, err := scanReviewRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return review.Item{}, false, nil
	}
	if err != nil {
		return review.Item{}, false, err
	}
	return item, true, nil
}

// List returns items filtered by status (empty = all).
func (s *ReviewStore) List(status string) ([]review.Item, error) {
	var rows *sql.Rows
	var err error
	if status == "" {
		rows, err = s.db.QueryContext(context.Background(),
			`SELECT decision_id, tx_id, status, assigned_to, created_at, resolved_at, resolution
			 FROM review_queue ORDER BY created_at`)
	} else {
		rows, err = s.db.QueryContext(context.Background(),
			`SELECT decision_id, tx_id, status, assigned_to, created_at, resolved_at, resolution
			 FROM review_queue WHERE status = $1 ORDER BY created_at`, status)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []review.Item
	for rows.Next() {
		item, err := scanReviewRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Update overwrites the stored item; returns review.ErrNotFound if no row exists.
func (s *ReviewStore) Update(item review.Item) error {
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE review_queue
		 SET status = $1, assigned_to = $2, resolved_at = $3, resolution = $4, updated_at = now()
		 WHERE decision_id = $5`,
		item.Status, nullableText(item.AssignedTo),
		nullableTimePtr(item.ResolvedAt), nullableText(item.Resolution),
		item.DecisionID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return review.ErrNotFound
	}
	return nil
}

func scanReviewRow(r interface {
	Scan(dest ...any) error
}) (review.Item, error) {
	var item review.Item
	var txID, assignedTo, resolution sql.NullString
	var resolvedAt sql.NullTime
	err := r.Scan(&item.DecisionID, &txID, &item.Status, &assignedTo, &item.CreatedAt, &resolvedAt, &resolution)
	if err != nil {
		return review.Item{}, err
	}
	item.TxID = txID.String
	item.AssignedTo = assignedTo.String
	item.Resolution = resolution.String
	if resolvedAt.Valid {
		t := resolvedAt.Time
		item.ResolvedAt = &t
	}
	return item, nil
}