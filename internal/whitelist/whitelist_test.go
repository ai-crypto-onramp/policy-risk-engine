package whitelist

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceAddAndList(t *testing.T) {
	s := NewService(NewMemoryStore())
	e, err := s.Add(context.Background(), "usr_1", "ethereum", "0xabc", "savings")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if e.Status != StatusPending {
		t.Errorf("status: %s", e.Status)
	}
	list, err := s.List(context.Background(), "usr_1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len: %d", len(list))
	}
}

func TestServiceAddValidation(t *testing.T) {
	s := NewService(NewMemoryStore())
	if _, err := s.Add(context.Background(), "", "ethereum", "0x1", ""); err == nil {
		t.Fatal("expected error for empty user")
	}
	if _, err := s.Add(context.Background(), "usr_1", "", "0x1", ""); err == nil {
		t.Fatal("expected error for empty chain")
	}
	if _, err := s.Add(context.Background(), "usr_1", "ethereum", "", ""); err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestServiceVerify(t *testing.T) {
	s := NewService(NewMemoryStore()).WithNow(func() time.Time { return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC) })
	_, _ = s.Add(context.Background(), "usr_1", "ethereum", "0xabc", "")
	e, err := s.Verify(context.Background(), "usr_1", "ethereum", "0xabc")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if e.Status != StatusVerified || e.VerifiedAt.IsZero() {
		t.Fatalf("entry: %+v", e)
	}
	if !s.IsWhitelisted(context.Background(), "usr_1", "ethereum", "0xabc") {
		t.Error("expected whitelisted after verify")
	}
}

func TestServiceVerifyNotFound(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, err := s.Verify(context.Background(), "nope", "ethereum", "0x1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err: %v", err)
	}
}

func TestServiceVerifyAlreadyVerified(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, _ = s.Add(context.Background(), "usr_1", "ethereum", "0x1", "")
	_, _ = s.Verify(context.Background(), "usr_1", "ethereum", "0x1")
	_, err := s.Verify(context.Background(), "usr_1", "ethereum", "0x1")
	if !errors.Is(err, ErrAlreadyVerified) {
		t.Fatalf("err: %v", err)
	}
}

func TestIsWhitelistedPendingNotVerified(t *testing.T) {
	s := NewService(NewMemoryStore())
	_, _ = s.Add(context.Background(), "usr_1", "ethereum", "0x1", "")
	if s.IsWhitelisted(context.Background(), "usr_1", "ethereum", "0x1") {
		t.Error("pending entry should not be whitelisted")
	}
}

func TestMemoryStoreDuplicate(t *testing.T) {
	store := NewMemoryStore()
	_ = store.Add(Entry{UserID: "u", Chain: "c", Address: "a"})
	if err := store.Add(Entry{UserID: "u", Chain: "c", Address: "a"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err: %v", err)
	}
}

func TestMemoryStoreUpdateNotFound(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Update(Entry{UserID: "u", Chain: "c", Address: "a"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err: %v", err)
	}
}

func TestCheckSourceAuth(t *testing.T) {
	if r := CheckSourceAuth(false, false, false); r.OK || r.Reason != "invalid_session" {
		t.Fatalf("invalid session: %+v", r)
	}
	if r := CheckSourceAuth(true, true, false); r.OK || r.Reason != "2fa_required" {
		t.Fatalf("2fa required: %+v", r)
	}
	if r := CheckSourceAuth(true, true, true); !r.OK || !r.Requires2FA || !r.TwoFAPassed {
		t.Fatalf("2fa passed: %+v", r)
	}
	if r := CheckSourceAuth(true, false, false); !r.OK {
		t.Fatalf("no 2fa needed: %+v", r)
	}
}