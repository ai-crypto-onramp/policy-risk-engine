package review

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceParkAndResolve(t *testing.T) {
	s := NewService(NewMemoryStore()).WithNow(func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) })
	item, err := s.Park(context.Background(), "dec_1", "tx_1")
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	if item.Status != StatusPending {
		t.Fatalf("status: %s", item.Status)
	}
	resolved, err := s.Resolve(context.Background(), "dec_1", "reviewer_1", ResolutionAllow)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Status != StatusResolved || resolved.Resolution != ResolutionAllow || resolved.AssignedTo != "reviewer_1" {
		t.Fatalf("resolved: %+v", resolved)
	}
	if resolved.ResolvedAt == nil {
		t.Error("missing resolved_at")
	}
}

func TestServiceParkEmptyDecisionID(t *testing.T) {
	s := NewService(NewMemoryStore())
	if _, err := s.Park(context.Background(), "", "tx"); err == nil {
		t.Fatal("expected error for empty decision id")
	}
}

func TestServiceResolveNotFound(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, err := s.Resolve(context.Background(), "nope", "r", ResolutionAllow)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err: %v", err)
	}
}

func TestServiceResolveAlreadyResolved(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, _ = s.Park(context.Background(), "dec_1", "")
	_, _ = s.Resolve(context.Background(), "dec_1", "r", ResolutionAllow)
	_, err := s.Resolve(context.Background(), "dec_1", "r", ResolutionDeny)
	if !errors.Is(err, ErrAlreadyResolved) {
		t.Fatalf("err: %v", err)
	}
}

func TestServiceResolveInvalidResolution(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, _ = s.Park(context.Background(), "dec_1", "")
	_, err := s.Resolve(context.Background(), "dec_1", "r", "maybe")
	if !errors.Is(err, ErrInvalidResolution) {
		t.Fatalf("err: %v", err)
	}
}

func TestServiceGet(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, _ = s.Park(context.Background(), "dec_1", "tx")
	item, err := s.Get(context.Background(), "dec_1")
	if err != nil || item.DecisionID != "dec_1" {
		t.Fatalf("get: %v %+v", err, item)
	}
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err: %v", err)
	}
}

func TestServiceListByStatus(t *testing.T) {
	store := NewMemoryStore()
	s := NewService(store)
	_, _ = s.Park(context.Background(), "dec_1", "")
	_, _ = s.Park(context.Background(), "dec_2", "")
	_, _ = s.Resolve(context.Background(), "dec_1", "r", ResolutionDeny)
	pending, _ := s.List(context.Background(), StatusPending)
	if len(pending) != 1 {
		t.Fatalf("pending: %d", len(pending))
	}
	resolved, _ := s.List(context.Background(), StatusResolved)
	if len(resolved) != 1 {
		t.Fatalf("resolved: %d", len(resolved))
	}
	all, _ := s.List(context.Background(), "")
	if len(all) != 2 {
		t.Fatalf("all: %d", len(all))
	}
}

func TestMemoryStoreDuplicate(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Put(Item{DecisionID: "d"})
	if err := store.Put(Item{DecisionID: "d"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err: %v", err)
	}
}

func TestMemoryStoreUpdateNotFound(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Update(Item{DecisionID: "d"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err: %v", err)
	}
}

func TestMemoryStorePutEmptyID(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Put(Item{}); err == nil {
		t.Fatal("expected error for empty id")
	}
}