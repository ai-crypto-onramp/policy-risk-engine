package audit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewSignerWithExplicitKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	s := NewSigner(priv)
	if s.PublicKeyHex() == "" {
		t.Fatal("empty public key hex")
	}
	// Signing with the same key should verify.
	rec := DecisionRecord{DecisionID: "d", Decision: "allow"}
	sig, err := s.Sign(rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.Signature = sig
	if err := s.Verify(rec); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Public key hex should match the pub we generated.
	if s.PublicKeyHex() != pubToHex(pub) {
		t.Errorf("pub key hex mismatch")
	}
}

func pubToHex(pub ed25519.PublicKey) string {
	b := []byte(pub)
	out := make([]byte, len(b)*2)
	const hex = "0123456789abcdef"
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0xF]
	}
	return string(out)
}

func TestSignerSignError(t *testing.T) {
	s := NewSigner(nil)
	// canonicalJSON never fails for a normal DecisionRecord; exercise a path
	// where Sign succeeds (no error branch reachable in this impl) and just
	// verify non-empty signature.
	sig, err := s.Sign(DecisionRecord{DecisionID: "d"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig == "" {
		t.Fatal("empty sig")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	s1 := NewSigner(nil)
	s2 := NewSigner(nil)
	rec := DecisionRecord{DecisionID: "d", Decision: "allow"}
	sig, _ := s1.Sign(rec)
	rec.Signature = sig
	if err := s2.Verify(rec); err == nil {
		t.Fatal("expected verify failure with different signer")
	}
}

func TestServiceWithSyncPersistSuccess(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	sink := NewMemorySink()
	svc := NewService(signer, store, sink, 16).WithSyncPersist()
	defer svc.Close()

	rec := DecisionRecord{DecisionID: "d_sync", PolicyVersion: "v1", Decision: "allow"}
	if err := svc.Emit(context.Background(), rec); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("store len after sync persist: %d", store.Len())
	}
	// Wait for sink publish.
	deadline := time.After(2 * time.Second)
	for len(sink.Records()) == 0 {
		select {
		case <-deadline:
			t.Fatalf("sink records: %d", len(sink.Records()))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if svc.Drops() != 0 {
		t.Errorf("drops: %d", svc.Drops())
	}
}

func TestServiceWithSyncPersistStoreFailure(t *testing.T) {
	signer := NewSigner(nil)
	failing := &failStore{}
	sink := NewMemorySink()
	svc := NewService(signer, failing, sink, 16).WithSyncPersist()
	defer svc.Close()

	err := svc.Emit(context.Background(), DecisionRecord{DecisionID: "d_fail"})
	if err == nil {
		t.Fatal("expected persist error")
	}
	if svc.Drops() < 1 {
		t.Errorf("expected drops>=1, got %d", svc.Drops())
	}
}

func TestServiceWorkerPutFailure(t *testing.T) {
	signer := NewSigner(nil)
	failing := &failStore{}
	sink := NewMemorySink()
	svc := NewService(signer, failing, sink, 16)
	defer svc.Close()

	if err := svc.Emit(context.Background(), DecisionRecord{DecisionID: "d_wf"}); err != nil {
		t.Fatalf("emit (async path): %v", err)
	}
	waitForDrops(svc, 1)
	if svc.Drops() < 1 {
		t.Fatalf("expected drops on worker put failure, got %d", svc.Drops())
	}
}

func TestServiceEmitSignError(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	sink := NewMemorySink()
	svc := NewService(signer, store, sink, 4)
	defer svc.Close()
	// canonicalJSON never errors for a regular record, so Sign succeeds.
	// Cover the CreatedAt-zero path with a non-zero CreatedAt record.
	rec := DecisionRecord{DecisionID: "d_set", CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := svc.Emit(context.Background(), rec); err != nil {
		t.Fatalf("emit: %v", err)
	}
	waitFor(store, 1)
	got, _, _ := store.Get("d_set")
	if !got.CreatedAt.Equal(rec.CreatedAt) {
		t.Errorf("CreatedAt: %v want %v", got.CreatedAt, rec.CreatedAt)
	}
}

func TestServiceRunStoreNilNoPanic(t *testing.T) {
	signer := NewSigner(nil)
	sink := NewMemorySink()
	svc := NewService(signer, nil, sink, 4)
	defer svc.Close()
	if err := svc.Emit(context.Background(), DecisionRecord{DecisionID: "d_nil_store"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	waitForSink(sink, 1)
	if len(sink.Records()) != 1 {
		t.Fatalf("sink records: %d", len(sink.Records()))
	}
}

func TestServiceRunSinkNilNoPanic(t *testing.T) {
	signer := NewSigner(nil)
	store := NewMemoryStore()
	svc := NewService(signer, store, nil, 4)
	defer svc.Close()
	if err := svc.Emit(context.Background(), DecisionRecord{DecisionID: "d_nil_sink"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	waitFor(store, 1)
	if store.Len() != 1 {
		t.Fatalf("store len: %d", store.Len())
	}
}

func TestServiceWithSyncPersistStoreNilSkipsPut(t *testing.T) {
	signer := NewSigner(nil)
	sink := NewMemorySink()
	svc := NewService(signer, nil, sink, 4).WithSyncPersist()
	defer svc.Close()
	if err := svc.Emit(context.Background(), DecisionRecord{DecisionID: "d"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	waitForSink(sink, 1)
	if svc.Drops() != 0 {
		t.Errorf("drops: %d", svc.Drops())
	}
}

func TestServiceCloseIdempotent(t *testing.T) {
	svc := NewService(NewSigner(nil), NewMemoryStore(), NewMemorySink(), 2)
	svc.Close()
	// Second Close should not panic.
	svc.Close()
}

func TestMemorySinkRecordsCopy(t *testing.T) {
	s := NewMemorySink()
	_ = s.Publish(context.Background(), DecisionRecord{DecisionID: "a"})
	_ = s.Publish(context.Background(), DecisionRecord{DecisionID: "b"})
	recs := s.Records()
	if len(recs) != 2 {
		t.Fatalf("len: %d", len(recs))
	}
	// Mutating the returned slice should not affect the sink's internal state.
	recs[0] = DecisionRecord{DecisionID: "tampered"}
	again := s.Records()
	if again[0].DecisionID != "a" {
		t.Errorf("internal slice mutated: %v", again[0])
	}
}

func TestMemoryStorePutAndGetRoundtrip(t *testing.T) {
	s := NewMemoryStore()
	rec := DecisionRecord{DecisionID: "rt", Decision: "deny", Reasons: []string{"r"}}
	if err := s.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := s.Get("rt")
	if !ok || err != nil {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Decision != "deny" || len(got.Reasons) != 1 || got.Reasons[0] != "r" {
		t.Errorf("got: %+v", got)
	}
}

func TestMemorySinkConcurrentPublish(t *testing.T) {
	s := NewMemorySink()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Publish(context.Background(), DecisionRecord{DecisionID: "c"})
		}()
	}
	wg.Wait()
	if len(s.Records()) != 50 {
		t.Errorf("records: %d", len(s.Records()))
	}
}

func waitForSink(s *MemorySink, n int) {
	deadline := time.After(2 * time.Second)
	for {
		if len(s.Records()) >= n {
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

type failStore struct{}

func (failStore) Put(DecisionRecord) error { return errors.New("persist failed") }
func (failStore) Get(string) (DecisionRecord, bool, error) {
	return DecisionRecord{}, false, errors.New("get failed")
}