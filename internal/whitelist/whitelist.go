// Package whitelist enforces destination address whitelisting (with
// verification flow) and source authentication (valid session + 2FA for
// high-value tx).
package whitelist

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Status values for a whitelist entry.
const (
	StatusPending  = "PENDING"
	StatusVerified = "VERIFIED"
)

// Entry is a whitelisted destination address.
type Entry struct {
	UserID     string    `json:"user_id"`
	Chain      string    `json:"chain"`
	Address    string    `json:"address"`
	Label      string    `json:"label,omitempty"`
	Status     string    `json:"status"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Store persists whitelist entries.
type Store interface {
	Add(e Entry) error
	List(userID string) ([]Entry, error)
	Get(userID, chain, address string) (Entry, bool, error)
	Update(e Entry) error
}

// Service is the whitelisting service.
type Service struct {
	store Store
	now   func() time.Time
	mu    sync.Mutex
}

// NewService returns a whitelist Service backed by store.
func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

// WithNow overrides the clock (for testing).
func (s *Service) WithNow(now func() time.Time) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
	return s
}

// Add adds a new destination address to a user's allowlist in pending status,
// awaiting verification.
func (s *Service) Add(ctx context.Context, userID, chain, address, label string) (Entry, error) {
	if userID == "" || chain == "" || address == "" {
		return Entry{}, errors.New("user_id, chain, and address are required")
	}
	s.mu.Lock()
	now := s.now()
	s.mu.Unlock()
	e := Entry{
		UserID:    userID,
		Chain:     chain,
		Address:   address,
		Label:     label,
		Status:    StatusPending,
		CreatedAt: now,
	}
	if err := s.store.Add(e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// List returns the whitelist for a user.
func (s *Service) List(ctx context.Context, userID string) ([]Entry, error) {
	return s.store.List(userID)
}

// Verify transitions a pending entry to verified (after micro-transfer or
// signed message confirmation).
func (s *Service) Verify(ctx context.Context, userID, chain, address string) (Entry, error) {
	e, ok, err := s.store.Get(userID, chain, address)
	if err != nil {
		return Entry{}, err
	}
	if !ok {
		return Entry{}, ErrNotFound
	}
	if e.Status == StatusVerified {
		return e, ErrAlreadyVerified
	}
	s.mu.Lock()
	e.Status = StatusVerified
	e.VerifiedAt = s.now()
	s.mu.Unlock()
	if err := s.store.Update(e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// IsWhitelisted returns true when (userID, chain, address) is verified.
func (s *Service) IsWhitelisted(ctx context.Context, userID, chain, address string) bool {
	e, ok, _ := s.store.Get(userID, chain, address)
	return ok && e.Status == StatusVerified
}

// ErrNotFound is returned when a whitelist entry does not exist.
var ErrNotFound = errors.New("whitelist entry not found")

// ErrAlreadyVerified is returned when Verify is called on an already-verified entry.
var ErrAlreadyVerified = errors.New("whitelist entry already verified")

// MemoryStore is an in-memory Store.
type MemoryStore struct {
	mu  sync.Mutex
	mem map[string]Entry
}

// NewMemoryStore returns a fresh in-memory whitelist store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{mem: make(map[string]Entry)}
}

func key(userID, chain, address string) string { return userID + "|" + chain + "|" + address }

// Add stores e.
func (s *MemoryStore) Add(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.mem[key(e.UserID, e.Chain, e.Address)]; exists {
		return ErrDuplicate
	}
	s.mem[key(e.UserID, e.Chain, e.Address)] = e
	return nil
}

// List returns entries for userID.
func (s *MemoryStore) List(userID string) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	for _, e := range s.mem {
		if e.UserID == userID {
			out = append(out, e)
		}
	}
	return out, nil
}

// Get returns the entry for (userID, chain, address).
func (s *MemoryStore) Get(userID, chain, address string) (Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.mem[key(userID, chain, address)]
	return e, ok, nil
}

// Update overwrites the stored entry.
func (s *MemoryStore) Update(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mem[key(e.UserID, e.Chain, e.Address)]; !ok {
		return ErrNotFound
	}
	s.mem[key(e.UserID, e.Chain, e.Address)] = e
	return nil
}

// ErrDuplicate is returned when an entry already exists.
var ErrDuplicate = errors.New("whitelist entry already exists")

// SourceAuthResult is the outcome of source authentication checks.
type SourceAuthResult struct {
	OK            bool
	Reason        string
	Requires2FA   bool
	TwoFAPassed   bool
}

// CheckSourceAuth validates the session and 2FA requirements for a tx.
// sessionValid must be true (JWT issued by Identity & Auth). When
// requires2FA is true, twoFAPassed must also be true.
func CheckSourceAuth(sessionValid, requires2FA, twoFAPassed bool) SourceAuthResult {
	if !sessionValid {
		return SourceAuthResult{Reason: "invalid_session"}
	}
	if requires2FA && !twoFAPassed {
		return SourceAuthResult{Requires2FA: true, TwoFAPassed: false, Reason: "2fa_required"}
	}
	return SourceAuthResult{OK: true, Requires2FA: requires2FA, TwoFAPassed: twoFAPassed}
}