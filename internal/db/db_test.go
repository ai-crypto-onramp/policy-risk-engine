package db

import (
	"context"
	"testing"
)

func TestConnect_MissingDSN(t *testing.T) {
	if _, err := Connect(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty DSN")
	} else if err != ErrMissingDBURL {
		t.Fatalf("expected ErrMissingDBURL, got %v", err)
	}
}