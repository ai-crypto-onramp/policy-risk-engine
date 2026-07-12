package audit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignerSignAndVerify(t *testing.T) {
	signer := NewSigner(nil)
	rec := DecisionRecord{DecisionID: "dec_1", PolicyVersion: "v1", Decision: "allow"}
	sig, err := signer.Sign(rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}
	rec.Signature = sig
	if err := signer.Verify(rec); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignerVerifyTampered(t *testing.T) {
	signer := NewSigner(nil)
	rec := DecisionRecord{DecisionID: "dec_1", Decision: "allow"}
	sig, _ := signer.Sign(rec)
	rec.Signature = sig
	rec.Decision = "deny"
	if err := signer.Verify(rec); err == nil {
		t.Fatal("expected verification failure for tampered record")
	}
}

func TestSignerVerifyMissingSig(t *testing.T) {
	signer := NewSigner(nil)
	if err := signer.Verify(DecisionRecord{}); err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestSignerVerifyInvalidHex(t *testing.T) {
	signer := NewSigner(nil)
	if err := signer.Verify(DecisionRecord{Signature: "nothex"}); err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestSignerDeterministicForSameRecord(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	s1 := NewSigner(priv)
	s2 := NewSigner(priv)
	rec := DecisionRecord{DecisionID: "dec_1", Decision: "allow"}
	sig1, _ := s1.Sign(rec)
	sig2, _ := s2.Sign(rec)
	if sig1 != sig2 {
		t.Fatal("signatures differ for same key + record")
	}
}

func TestSignerPublicKeyHex(t *testing.T) {
	s := NewSigner(nil)
	if s.PublicKeyHex() == "" {
		t.Error("empty public key hex")
	}
}

func TestRequestHashDeterministic(t *testing.T) {
	req := Request{UserID: "u1", Amount: "100", Currency: "USD"}
	h1 := RequestHash(req)
	h2 := RequestHash(req)
	if h1 != h2 {
		t.Fatal("request hash not deterministic")
	}
	req2 := req
	req2.Amount = "200"
	if RequestHash(req2) == h1 {
		t.Fatal("hash should differ for different requests")
	}
}

func TestServiceEmitPersistsAndPublishes(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	sink := NewMemorySink()
	svc := NewService(signer, store, sink, 16)
	defer svc.Close()

	rec := DecisionRecord{DecisionID: "dec_1", PolicyVersion: "v1", Decision: "allow"}
	if err := svc.Emit(context.Background(), rec); err != nil {
		t.Fatalf("emit: %v", err)
	}
	waitFor(store, 1)
	if store.Len() != 1 {
		t.Fatalf("store len: %d", store.Len())
	}
	if len(sink.Records()) != 1 {
		t.Fatalf("sink records: %d", len(sink.Records()))
	}
	if svc.Drops() != 0 {
		t.Errorf("drops: %d", svc.Drops())
	}
}

func TestServiceEmitSetsCreatedAt(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	sink := NewMemorySink()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := NewService(signer, store, sink, 16).WithNow(func() time.Time { return now })
	defer svc.Close()
	_ = svc.Emit(context.Background(), DecisionRecord{DecisionID: "d"})
	waitFor(store, 1)
	got, _, _ := store.Get("d")
	if !got.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt: %v want %v", got.CreatedAt, now)
	}
}

func TestServiceDropsOnOverflow(t *testing.T) {
	signer := NewSigner(nil)
	sink := &blockingSink{}
	svc := NewService(signer, nil, sink, 2)
	defer svc.Close()
	var drops int
	for i := 0; i < 10; i++ {
		if err := svc.Emit(context.Background(), DecisionRecord{DecisionID: "d"}); err != nil {
			if errors.Is(err, ErrDropped) {
				drops++
			}
		}
	}
	if drops == 0 {
		t.Fatal("expected drops on overflow")
	}
}

type blockingSink struct{}

func (blockingSink) Publish(ctx context.Context, rec DecisionRecord) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestServiceDropsOnSinkFailure(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	sink := NewMemorySink()
	sink.SetFail(true)
	svc := NewService(signer, store, sink, 4)
	defer svc.Close()
	_ = svc.Emit(context.Background(), DecisionRecord{DecisionID: "d"})
	waitForDrops(svc, 1)
	if svc.Drops() == 0 {
		t.Fatal("expected drops on sink failure")
	}
}

func TestServiceEmitSignsRecord(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	svc := NewService(signer, store, NewMemorySink(), 4)
	defer svc.Close()
	_ = svc.Emit(context.Background(), DecisionRecord{DecisionID: "d", Decision: "allow"})
	waitFor(store, 1)
	got, _, _ := store.Get("d")
	if got.Signature == "" {
		t.Error("missing signature on stored record")
	}
	if err := signer.Verify(got); err != nil {
		t.Errorf("verify stored: %v", err)
	}
}

func TestMemoryStorePutEmptyID(t *testing.T) {
	if err := NewMemoryStore().Put(DecisionRecord{}); err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestMemoryStoreGetMiss(t *testing.T) {
	_, ok, err := NewMemoryStore().Get("nope")
	if ok || err != nil {
		t.Fatalf("miss: ok=%v err=%v", ok, err)
	}
}

func TestMemorySinkSetFail(t *testing.T) {
	s := NewMemorySink()
	s.SetFail(true)
	if err := s.Publish(context.Background(), DecisionRecord{}); err == nil {
		t.Fatal("expected error")
	}
}

func waitFor(store *MemoryStore, n int) {
	deadline := time.After(2 * time.Second)
	for {
		if store.Len() >= n {
			return
		}
		select {
		case <-deadline:
			return
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func waitForDrops(s *Service, n int64) {
	deadline := time.After(2 * time.Second)
	for {
		if s.Drops() >= n {
			return
		}
		select {
		case <-deadline:
			return
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}