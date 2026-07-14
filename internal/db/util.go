package db

import (
	"errors"
	"time"

	"github.com/lib/pq"
)

const pgUniqueViolation = "23505"

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == pgUniqueViolation
	}
	return false
}

func nullableTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return *t
}