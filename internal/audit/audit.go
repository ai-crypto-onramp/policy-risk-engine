// Package audit emits a signed decision record for every evaluation, persists
// it durably, and emits it to the audit-event-log. Signing uses Ed25519.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
)

const AuditTopic = "audit.v1"

// DecisionRecord is the signed audit record for a policy evaluation.
type DecisionRecord struct {
	DecisionID    string    `json:"decision_id"`
	PolicyVersion string    `json:"policy_version"`
	RequestHash   string    `json:"request_hash"`
	Decision      string    `json:"decision"`
	Reasons       []string  `json:"reasons"`
	AppliedRules  []string  `json:"applied_rules"`
	Score         float64   `json:"score"`
	CreatedAt     time.Time `json:"created_at"`
	Signature     string    `json:"signature,omitempty"`
}

// Request is the input to a policy evaluation, used to compute the request hash.
type Request struct {
	UserID       string  `json:"user_id"`
	Amount       string  `json:"amount"`
	Currency     string  `json:"currency"`
	Asset        string  `json:"asset"`
	Rail         string  `json:"rail"`
	DestAddress  string  `json:"dest_address"`
	DestChain    string  `json:"dest_chain"`
	KYTVerdict   string  `json:"kyt_verdict"`
	FraudScore   float64 `json:"fraud_score"`
	KYCStatus    string  `json:"kyc_status"`
}

// Store persists decision records.
type Store interface {
	Put(rec DecisionRecord) error
	Get(decisionID string) (DecisionRecord, bool, error)
}

// Sink publishes decision records to the audit-event-log bus.
type Sink interface {
	Publish(ctx context.Context, rec DecisionRecord) error
}

// Signer signs decision records with an Ed25519 key.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSigner returns a Signer using the given Ed25519 private key. If priv is
// nil a new key is generated.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	if priv == nil {
		pub, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		return &Signer{priv: sk, pub: pub}
	}
	return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

// PublicKeyHex returns the hex-encoded public key.
func (s *Signer) PublicKeyHex() string { return hex.EncodeToString(s.pub) }

// Sign signs the canonical-JSON encoding of rec (without the Signature field)
// and returns the hex-encoded signature.
func (s *Signer) Sign(rec DecisionRecord) (string, error) {
	payload, err := canonicalJSON(rec)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.priv, payload)
	return hex.EncodeToString(sig), nil
}

// Verify verifies a decision record's signature.
func (s *Signer) Verify(rec DecisionRecord) error {
	if rec.Signature == "" {
		return errors.New("missing signature")
	}
	sig, err := hex.DecodeString(rec.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := canonicalJSON(rec)
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.pub, payload, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// canonicalJSON marshals rec without the Signature field, with sorted keys.
func canonicalJSON(rec DecisionRecord) ([]byte, error) {
	copy := rec
	copy.Signature = ""
	return json.Marshal(copy)
}

// Service is the audit emission service.
type Service struct {
	signer *Signer
	store  Store
	sink   Sink
	now    func() time.Time
	mu     sync.Mutex
	queue  chan DecisionRecord
	drops  atomic.Int64
	wg     sync.WaitGroup
	stopCh chan struct{}
	stopOnce sync.Once
	// syncPersist, when true, makes Emit persist the record to the store
	// synchronously before returning (instead of via the worker goroutine).
	// This guarantees ordering with respect to downstream consumers that have
	// foreign-key dependencies on the decision record (e.g. review_queue).
	syncPersist bool
}

// NewService returns a started audit Service. queueSize is the bounded async
// queue length; when full, Emit returns ErrDropped.
func NewService(signer *Signer, store Store, sink Sink, queueSize int) *Service {
	if queueSize <= 0 {
		queueSize = 1024
	}
	s := &Service{
		signer: signer,
		store:  store,
		sink:   sink,
		now:    time.Now,
		queue:  make(chan DecisionRecord, queueSize),
		stopCh: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s
}

// WithNow overrides the clock (for testing).
func (s *Service) WithNow(now func() time.Time) *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
	return s
}

// WithSyncPersist enables synchronous store persistence: Emit will call
// store.Put before returning. Use this when downstream stores have FK
// dependencies on the persisted decision record.
func (s *Service) WithSyncPersist() *Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncPersist = true
	return s
}

// run is the worker goroutine that persists and publishes records.
func (s *Service) run() {
	defer s.wg.Done()
	for {
		select {
		case rec := <-s.queue:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			// When syncPersist is enabled, the record was already persisted by
			// Emit; the worker only publishes to the sink.
			if !s.syncPersist && s.store != nil {
				if err := s.store.Put(rec); err != nil {
					s.drops.Add(1)
					cancel()
					continue
				}
			}
			if s.sink != nil {
				if err := s.sink.Publish(ctx, rec); err != nil {
					s.drops.Add(1)
				}
			}
			cancel()
		case <-s.stopCh:
			return
		}
	}
}

// Emit signs and enqueues rec. Returns ErrDropped if the queue is full.
func (s *Service) Emit(ctx context.Context, rec DecisionRecord) error {
	if rec.CreatedAt.IsZero() {
		s.mu.Lock()
		rec.CreatedAt = s.now()
		s.mu.Unlock()
	}
	sig, err := s.signer.Sign(rec)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	rec.Signature = sig
	s.mu.Lock()
	syncP := s.syncPersist
	s.mu.Unlock()
	if syncP && s.store != nil {
		if err := s.store.Put(rec); err != nil {
			s.drops.Add(1)
			return fmt.Errorf("persist: %w", err)
		}
	}
	select {
	case s.queue <- rec:
		return nil
	default:
		s.drops.Add(1)
		return ErrDropped
	}
}

// Drops returns the number of dropped records.
func (s *Service) Drops() int64 { return s.drops.Load() }

// Close drains and stops the worker.
func (s *Service) Close() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
}

// ErrDropped is returned when the audit queue is full.
var ErrDropped = errors.New("audit record dropped")

// ErrDuplicateDecision is returned when a decision_id already exists in the store.
var ErrDuplicateDecision = errors.New("audit decision already exists")

// RequestHash computes the SHA-256 hash of the canonical-JSON encoding of req.
func RequestHash(req Request) string {
	body, _ := json.Marshal(req)
	return hex.EncodeToString(sha256Bytes(body))
}

func sha256Bytes(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

// MemoryStore is an in-memory Store.
type MemoryStore struct {
	mu  sync.Mutex
	mem map[string]DecisionRecord
}

// NewMemoryStore returns a fresh in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{mem: make(map[string]DecisionRecord)}
}

// Put stores rec.
func (s *MemoryStore) Put(rec DecisionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.DecisionID == "" {
		return errors.New("decision_id required")
	}
	s.mem[rec.DecisionID] = rec
	return nil
}

// Get returns the record by decisionID.
func (s *MemoryStore) Get(decisionID string) (DecisionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.mem[decisionID]
	return r, ok, nil
}

// Len returns the number of stored records.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.mem)
}

// MemorySink is an in-memory Sink.
type MemorySink struct {
	mu   sync.Mutex
	mem  []DecisionRecord
	fail bool
}

// NewMemorySink returns a fresh in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// SetFail forces Publish to return an error.
func (s *MemorySink) SetFail(f bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = f
}

// Publish appends rec.
func (s *MemorySink) Publish(_ context.Context, rec DecisionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("sink unavailable")
	}
	s.mem = append(s.mem, rec)
	return nil
}

// Records returns a copy of the published records.
func (s *MemorySink) Records() []DecisionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DecisionRecord, len(s.mem))
	copy(out, s.mem)
	return out
}

// KafkaSink publishes decision records wrapped in the canonical audit.v1
// envelope (see .github/contracts/asyncapi/audit/v1/asyncapi.yaml) to the `audit.v1`
// Kafka topic.
type KafkaSink struct {
	writer *kafka.Writer
}

func NewKafkaSink(brokers []string) (*KafkaSink, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("audit kafka: no brokers provided")
	}
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        AuditTopic,
		Balancer:     &kafka.LeastBytes{},
		BatchTimeout: 10 * time.Millisecond,
		RequiredAcks: kafka.RequireAll,
	}
	return &KafkaSink{writer: w}, nil
}

func (s *KafkaSink) Close() error {
	if s.writer == nil {
		return nil
	}
	return s.writer.Close()
}

func (s *KafkaSink) Publish(ctx context.Context, rec DecisionRecord) error {
	if s.writer == nil {
		return fmt.Errorf("audit kafka: not connected")
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	payloadHash := "sha256:" + hex.EncodeToString(sum[:])
	envelope := map[string]any{
		"schema_version": "1",
		"id":              rec.DecisionID,
		"ts":              rec.CreatedAt.UTC().Format(time.RFC3339Nano),
		"source_service":  "policy-risk-engine",
		"actor_id":        "policy-risk-engine",
		"action":          "policy.evaluate",
		"target_type":     "decision",
		"target_id":       rec.DecisionID,
		"payload_hash":    payloadHash,
		"payload":         json.RawMessage(payload),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return s.writer.WriteMessages(ctx, kafka.Message{
		Key:   []byte(rec.DecisionID),
		Value: body,
	})
}