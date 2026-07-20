package db

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestVersionToIntNumeric(t *testing.T) {
	n, err := versionToInt("42")
	if err != nil || n != 42 {
		t.Fatalf("versionToInt 42: %d err=%v", n, err)
	}
}

func TestVersionToIntHashStable(t *testing.T) {
	a, _ := versionToInt("abc123hash")
	b, _ := versionToInt("abc123hash")
	if a != b {
		t.Fatalf("hash version not stable: %d vs %d", a, b)
	}
	if a < 1000000 || a >= 1000000+9000000 {
		t.Fatalf("hash version out of range: %d", a)
	}
}

func TestVersionToIntDifferentHashesDiffer(t *testing.T) {
	a, _ := versionToInt("hash_a")
	b, _ := versionToInt("hash_b")
	if a == b {
		t.Fatal("expected different hashes to map to different ints")
	}
}

func TestParseVersionIntHashFallback(t *testing.T) {
	v := parseVersionInt("nonnumeric")
	if v <= 0 {
		t.Fatalf("hash fallback parse: %d", v)
	}
	v2, _ := versionToInt("nonnumeric")
	if v != v2 {
		t.Fatalf("parseVersionInt != versionToInt for hash: %d vs %d", v, v2)
	}
}

func TestIsUniqueViolationPQMatch(t *testing.T) {
	err := &pq.Error{Code: pgUniqueViolation}
	if !isUniqueViolation(err) {
		t.Fatal("expected pq unique violation to be detected")
	}
}

func TestIsUniqueViolationPQOther(t *testing.T) {
	err := &pq.Error{Code: "12345"}
	if isUniqueViolation(err) {
		t.Fatal("expected non-23505 pq error to not be unique violation")
	}
}

func TestIsUniqueViolationNonPQ(t *testing.T) {
	if isUniqueViolation(errors.New("not pq")) {
		t.Fatal("non-pq error should not be unique violation")
	}
	if isUniqueViolation(nil) {
		t.Fatal("nil should not be unique violation")
	}
}

func TestNullableText(t *testing.T) {
	if nullableText("") != nil {
		t.Error("empty string should be nil")
	}
	if nullableText("x") != "x" {
		t.Error("non-empty should pass through")
	}
}

func TestNullableTime(t *testing.T) {
	if nullableTime(time.Time{}) != nil {
		t.Error("zero time should be nil")
	}
	now := time.Now()
	if v := nullableTime(now); v != now {
		t.Errorf("non-zero time: %v", v)
	}
}

func TestNullableTimePtr(t *testing.T) {
	if nullableTimePtr(nil) != nil {
		t.Error("nil ptr should be nil")
	}
	zero := time.Time{}
	if nullableTimePtr(&zero) != nil {
		t.Error("zero time ptr should be nil")
	}
	now := time.Now()
	if v := nullableTimePtr(&now); v != now {
		t.Errorf("non-zero ptr: %v", v)
	}
}

func TestErrMissingDBURLNonNil(t *testing.T) {
	if ErrMissingDBURL == nil {
		t.Fatal("ErrMissingDBURL should not be nil")
	}
}

func TestScanReviewRowHandlesNulls(t *testing.T) {
	// Verify scanReviewRow maps null columns correctly via a fake scanner.
	row := &fakeRow{
		values: []any{
			"dec_1", nil, "PENDING", nil, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), nil, nil,
		},
	}
	item, err := scanReviewRow(row)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if item.DecisionID != "dec_1" || item.Status != "PENDING" {
		t.Errorf("item: %+v", item)
	}
	if item.TxID != "" || item.AssignedTo != "" || item.Resolution != "" {
		t.Errorf("null fields should be empty: %+v", item)
	}
	if item.ResolvedAt != nil {
		t.Errorf("resolved_at should be nil: %v", item.ResolvedAt)
	}
}

func TestScanReviewRowWithValues(t *testing.T) {
	now := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	row := &fakeRow{
		values: []any{
			"dec_2", "tx_1", "RESOLVED", "r1", now, now, "ALLOW",
		},
	}
	item, err := scanReviewRow(row)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if item.TxID != "tx_1" || item.AssignedTo != "r1" || item.Resolution != "ALLOW" {
		t.Errorf("item: %+v", item)
	}
	if item.ResolvedAt == nil || !item.ResolvedAt.Equal(now) {
		t.Errorf("resolved_at: %v want %v", item.ResolvedAt, now)
	}
}

func TestScanWhitelistRow(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	row := &fakeRow{
		values: []any{"u1", "eth", "0x1", "label", now, "VERIFIED", now},
	}
	e, err := scanWhitelistRow(row)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if e.UserID != "u1" || e.Chain != "eth" || e.Address != "0x1" {
		t.Errorf("entry: %+v", e)
	}
	if e.Label != "label" {
		t.Errorf("label: %q", e.Label)
	}
	if e.Status != "VERIFIED" {
		t.Errorf("status: %q", e.Status)
	}
	if !e.VerifiedAt.Equal(now) || !e.CreatedAt.Equal(now) {
		t.Errorf("times: verified=%v created=%v", e.VerifiedAt, e.CreatedAt)
	}
}

func TestScanWhitelistRowNulls(t *testing.T) {
	row := &fakeRow{
		values: []any{"u1", "eth", "0x1", nil, nil, "PENDING", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	e, err := scanWhitelistRow(row)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if e.Label != "" {
		t.Errorf("label should be empty: %q", e.Label)
	}
	if !e.VerifiedAt.IsZero() {
		t.Errorf("verified_at should be zero: %v", e.VerifiedAt)
	}
}

func TestScanDecisionRowScanError(t *testing.T) {
	row := &fakeRow{err: errors.New("scan boom")}
	if _, err := scanDecisionRow(row); err == nil {
		t.Fatal("expected scan error to surface")
	}
}

func TestScanReviewRowScanError(t *testing.T) {
	row := &fakeRow{err: errors.New("scan boom")}
	if _, err := scanReviewRow(row); err == nil {
		t.Fatal("expected scan error to surface")
	}
}

func TestScanWhitelistRowScanError(t *testing.T) {
	row := &fakeRow{err: errors.New("scan boom")}
	if _, err := scanWhitelistRow(row); err == nil {
		t.Fatal("expected scan error to surface")
	}
}

// fakeRow implements the Scan interface used by scan*Row.
type fakeRow struct {
	values []any
	err    error
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("column count mismatch")
	}
	for i, v := range r.values {
		switch d := dest[i].(type) {
		case *string:
			switch vv := v.(type) {
			case string:
				*d = vv
			case []byte:
				*d = string(vv)
			case sql.NullString:
				if vv.Valid {
					*d = vv.String
				}
			}
		case *[]byte:
			if vv, ok := v.([]byte); ok {
				*d = vv
			}
		case *sql.NullString:
			switch vv := v.(type) {
			case string:
				*d = sql.NullString{String: vv, Valid: true}
			case []byte:
				*d = sql.NullString{String: string(vv), Valid: true}
			case sql.NullString:
				*d = vv
			}
		case *sql.NullTime:
			switch vv := v.(type) {
			case time.Time:
				*d = sql.NullTime{Time: vv, Valid: !vv.IsZero()}
			case sql.NullTime:
				*d = vv
			}
		case *time.Time:
			if vv, ok := v.(time.Time); ok {
				*d = vv
			}
		case *float64:
			if f, ok := v.(float64); ok {
				*d = f
			}
		case *pq.StringArray:
			// pq.StringArray.Scan expects the wire format; not supported in
			// this fake. Tests that need array scanning use real scan paths.
		}
	}
	return nil
}