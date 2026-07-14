// Package review parks manual_review decisions in a review_queue and lets
// reviewers resolve them into allow / deny, emitting a follow-up audit record.
package review

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Status values for a review queue item.
const (
	StatusPending  = "pending"
	StatusResolved = "resolved"
)

// Resolution values for a resolved review.
const (
	ResolutionAllow = "allow"
	ResolutionDeny  = "deny"
)

// Item is a review_queue row.
type Item struct {
	DecisionID string     `json:"decision_id"`
	TxID       string     `json:"tx_id,omitempty"`
	Status     string     `json:"status"`
	AssignedTo string     `json:"assigned_to,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Resolution string     `json:"resolution,omitempty"`
}

// Store persists review queue items.
type Store interface {
	Put(item Item) error
	Get(decisionID string) (Item, bool, error)
	List(status string) ([]Item, error)
	Update(item Item) error
}

// Service is the review queue service.
type Service struct {
	store    Store
	notifier *Notifier
	now      func() time.Time
	mu       sync.Mutex
}

// NewService returns a review queue Service.
func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

// WithNotifier attaches a Notifier so that Resolve posts the resolved item to
// the Transaction Orchestrator webhook.
func (s *Service) WithNotifier(n *Notifier) *Service {
	s.notifier = n
	return s
}

// WithNow overrides the clock (for testing).
func (s *Service) WithNow(now func() time.Time) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
	return s
}

// Park inserts a new pending review_queue row for decisionID.
func (s *Service) Park(ctx context.Context, decisionID, txID string) (Item, error) {
	if decisionID == "" {
		return Item{}, errors.New("decision_id is required")
	}
	s.mu.Lock()
	now := s.now()
	s.mu.Unlock()
	item := Item{
		DecisionID: decisionID,
		TxID:       txID,
		Status:     StatusPending,
		CreatedAt:  now,
	}
	if err := s.store.Put(item); err != nil {
		return Item{}, err
	}
	return item, nil
}

// Resolve transitions a pending item to resolved with the given resolution.
// Re-resolving an already-resolved item returns ErrAlreadyResolved. When a
// Notifier is configured, the resolved item is posted to the Transaction
// Orchestrator webhook so the saga can resume.
func (s *Service) Resolve(ctx context.Context, decisionID, assignee, resolution string) (Item, error) {
	if resolution != ResolutionAllow && resolution != ResolutionDeny {
		return Item{}, ErrInvalidResolution
	}
	item, ok, err := s.store.Get(decisionID)
	if err != nil {
		return Item{}, err
	}
	if !ok {
		return Item{}, ErrNotFound
	}
	if item.Status == StatusResolved {
		return Item{}, ErrAlreadyResolved
	}
	s.mu.Lock()
	now := s.now()
	s.mu.Unlock()
	item.Status = StatusResolved
	item.AssignedTo = assignee
	item.Resolution = resolution
	item.ResolvedAt = &now
	if err := s.store.Update(item); err != nil {
		return Item{}, err
	}
	if s.notifier != nil && s.notifier.Enabled() {
		_ = s.notifier.NotifyResolution(ctx, item)
	}
	return item, nil
}

// Get returns the review item for decisionID.
func (s *Service) Get(ctx context.Context, decisionID string) (Item, error) {
	item, ok, err := s.store.Get(decisionID)
	if err != nil {
		return Item{}, err
	}
	if !ok {
		return Item{}, ErrNotFound
	}
	return item, nil
}

// List returns items filtered by status (empty = all).
func (s *Service) List(ctx context.Context, status string) ([]Item, error) {
	return s.store.List(status)
}

// ErrNotFound is returned when a review item does not exist.
var ErrNotFound = errors.New("review item not found")

// ErrAlreadyResolved is returned when resolving an already-resolved item.
var ErrAlreadyResolved = errors.New("review item already resolved")

// ErrInvalidResolution is returned when the resolution is not allow or deny.
var ErrInvalidResolution = errors.New("invalid resolution; must be allow or deny")

// MemoryStore is an in-memory Store.
type MemoryStore struct {
	mu    sync.Mutex
	mem   map[string]Item
	order []string
}

// NewMemoryStore returns a fresh in-memory review store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{mem: make(map[string]Item)}
}

// Put stores item.
func (s *MemoryStore) Put(item Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if item.DecisionID == "" {
		return errors.New("decision_id required")
	}
	if _, exists := s.mem[item.DecisionID]; exists {
		return ErrDuplicate
	}
	s.mem[item.DecisionID] = item
	s.order = append(s.order, item.DecisionID)
	return nil
}

// Get returns the item by decisionID.
func (s *MemoryStore) Get(decisionID string) (Item, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.mem[decisionID]
	return item, ok, nil
}

// List returns items filtered by status (empty = all).
func (s *MemoryStore) List(status string) ([]Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Item
	for _, id := range s.order {
		item := s.mem[id]
		if status == "" || item.Status == status {
			out = append(out, item)
		}
	}
	return out, nil
}

// Update overwrites the stored item.
func (s *MemoryStore) Update(item Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mem[item.DecisionID]; !ok {
		return ErrNotFound
	}
	s.mem[item.DecisionID] = item
	return nil
}

// ErrDuplicate is returned when an item with the same decision_id already exists.
var ErrDuplicate = errors.New("review item already exists")