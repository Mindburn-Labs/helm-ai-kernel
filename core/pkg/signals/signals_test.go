package signals

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interfaces"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// inMemoryEventRepo is a minimal EventRepository for testing.
type inMemoryEventRepo struct {
	events []interfaces.Event
	seq    int64
}

func (r *inMemoryEventRepo) Append(_ context.Context, eventType, actorID string, payload interface{}) (*interfaces.Event, error) {
	r.seq++
	e := &interfaces.Event{
		SequenceID: r.seq,
		EventType:  eventType,
		Timestamp:  time.Now(),
		ActorID:    actorID,
		Payload:    payload,
	}
	r.events = append(r.events, *e)
	return e, nil
}

func (r *inMemoryEventRepo) ReadFrom(_ context.Context, startSequenceID int64, limit int) ([]interfaces.Event, error) {
	var result []interfaces.Event
	for _, e := range r.events {
		if e.SequenceID >= startSequenceID {
			result = append(result, e)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func makeTestEnvelope() *SignalEnvelope {
	return &SignalEnvelope{
		SignalID: "sig-001",
		Class:    SignalClassEmail,
		Source: SignalSource{
			SourceID:    "gmail-workspace-acme",
			SourceType:  "gmail",
			PrincipalID: "principal-123",
			ConnectorID: "gmail-v1",
			TrustLevel:  "VERIFIED",
		},
		Sensitivity: SensitivityInternal,
		RawPayload:  json.RawMessage(`{"from":"alice@acme.com","subject":"Q2 Planning","body":"Let's meet Thursday."}`),
		ExternalID:  "msg-ext-001",
		Provenance: SignalProvenance{
			IngestedBy: "gmail-v1",
		},
	}
}

func TestSignalClassValid(t *testing.T) {
	if !SignalClassEmail.IsValid() {
		t.Error("EMAIL should be valid")
	}
	if SignalClass("UNKNOWN").IsValid() {
		t.Error("UNKNOWN should not be valid")
	}
}

func TestSensitivityValid(t *testing.T) {
	if !SensitivityConfidential.IsValid() {
		t.Error("CONFIDENTIAL should be valid")
	}
	if SensitivityTag("SECRET").IsValid() {
		t.Error("SECRET should not be valid")
	}
}

func TestSensitivityRequiresEncryption(t *testing.T) {
	if SensitivityPublic.RequiresEncryption() {
		t.Error("PUBLIC should not require encryption")
	}
	if !SensitivityRestricted.RequiresEncryption() {
		t.Error("RESTRICTED should require encryption")
	}
}

func TestDefaultNormalizer(t *testing.T) {
	norm := NewDefaultNormalizer()
	env := makeTestEnvelope()

	if err := norm.Normalize(env); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	// ContentHash should be set
	if env.ContentHash == "" {
		t.Error("content_hash should be set")
	}
	if !strings.HasPrefix(env.ContentHash, "sha256:") {
		t.Errorf("content_hash should have sha256: prefix, got %s", env.ContentHash)
	}

	// IdempotencyKey should be set
	if env.IdempotencyKey == "" {
		t.Error("idempotency_key should be set")
	}

	// ReceivedAt should be set
	if env.ReceivedAt.IsZero() {
		t.Error("received_at should be set")
	}

	// Provenance should be complete
	if env.Provenance.NormalizedAt.IsZero() {
		t.Error("provenance.normalized_at should be set")
	}
}

func TestNormalizerRejectsInvalidClass(t *testing.T) {
	norm := NewDefaultNormalizer()
	env := makeTestEnvelope()
	env.Class = "BOGUS"

	if err := norm.Normalize(env); err == nil {
		t.Error("expected error for invalid class")
	}
}

func TestNormalizerRejectsEmptyPayload(t *testing.T) {
	norm := NewDefaultNormalizer()
	env := makeTestEnvelope()
	env.RawPayload = nil

	if err := norm.Normalize(env); err == nil {
		t.Error("expected error for empty payload")
	}
}

func TestNormalizerRejectsMissingSource(t *testing.T) {
	norm := NewDefaultNormalizer()
	env := makeTestEnvelope()
	env.Source.SourceID = ""

	if err := norm.Normalize(env); err == nil {
		t.Error("expected error for missing source_id")
	}
}

func TestDedupStore(t *testing.T) {
	store := NewInMemoryDedupStore()

	if store.HasSeen("key-1") {
		t.Error("key-1 should not be seen yet")
	}

	if err := store.Record("key-1"); err != nil {
		t.Fatalf("record failed: %v", err)
	}

	if !store.HasSeen("key-1") {
		t.Error("key-1 should be seen after recording")
	}

	if store.HasSeen("key-2") {
		t.Error("key-2 should not be seen")
	}
}

func TestSignalEmitter(t *testing.T) {
	repo := &inMemoryEventRepo{}
	graph := proofgraph.NewGraph()
	dedup := NewInMemoryDedupStore()

	emitter, err := NewSignalEmitter(EmitterConfig{
		Events: repo,
		Graph:  graph,
		Dedup:  dedup,
	})
	if err != nil {
		t.Fatalf("new emitter: %v", err)
	}

	env := makeTestEnvelope()
	result, err := emitter.Emit(context.Background(), env)
	if err != nil {
		t.Fatalf("emit failed: %v", err)
	}

	if result.Duplicate {
		t.Error("first emit should not be a duplicate")
	}
	if result.ProofNodeHash == "" {
		t.Error("proof node hash should be set")
	}

	// Verify event was written
	if len(repo.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(repo.events))
	}
	if repo.events[0].EventType != EventTypeSignalIngested {
		t.Errorf("expected event type %s, got %s", EventTypeSignalIngested, repo.events[0].EventType)
	}

	// Verify ProofGraph node exists
	node, ok := graph.Get(result.ProofNodeHash)
	if !ok {
		t.Fatal("proof node not found in graph")
	}
	if node.Kind != proofgraph.NodeTypeIntent {
		t.Errorf("expected node type INTENT, got %s", node.Kind)
	}
}

func TestSignalEmitterDeduplicate(t *testing.T) {
	repo := &inMemoryEventRepo{}
	graph := proofgraph.NewGraph()

	emitter, err := NewSignalEmitter(EmitterConfig{
		Events: repo,
		Graph:  graph,
	})
	if err != nil {
		t.Fatalf("new emitter: %v", err)
	}

	env := makeTestEnvelope()

	// First emit
	result1, err := emitter.Emit(context.Background(), env)
	if err != nil {
		t.Fatalf("first emit: %v", err)
	}
	if result1.Duplicate {
		t.Error("first emit should not be duplicate")
	}

	// Second emit with same content
	env2 := makeTestEnvelope()
	result2, err := emitter.Emit(context.Background(), env2)
	if err != nil {
		t.Fatalf("second emit: %v", err)
	}
	if !result2.Duplicate {
		t.Error("second emit should be duplicate")
	}

	// Only one event should be written
	if len(repo.events) != 1 {
		t.Errorf("expected 1 event (deduped), got %d", len(repo.events))
	}
}

func TestSignalEmitterRejectsNilPayload(t *testing.T) {
	repo := &inMemoryEventRepo{}
	graph := proofgraph.NewGraph()

	emitter, err := NewSignalEmitter(EmitterConfig{
		Events: repo,
		Graph:  graph,
	})
	if err != nil {
		t.Fatalf("new emitter: %v", err)
	}

	env := makeTestEnvelope()
	env.RawPayload = nil

	_, err = emitter.Emit(context.Background(), env)
	if err == nil {
		t.Error("expected error for nil payload")
	}
}

func TestLookupSignalType(t *testing.T) {
	entry := LookupSignalType(SignalClassEmail)
	if entry == nil {
		t.Fatal("EMAIL should be in catalog")
	}
	if entry.Name != "Email" {
		t.Errorf("expected name 'Email', got %q", entry.Name)
	}
	if !entry.SupportsThreading {
		t.Error("EMAIL should support threading")
	}

	if LookupSignalType("UNKNOWN") != nil {
		t.Error("UNKNOWN should not be in catalog")
	}
}

func TestContentHashDeterminism(t *testing.T) {
	norm := NewDefaultNormalizer()
	fixedTime := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	norm.Clock = func() time.Time { return fixedTime }

	env1 := makeTestEnvelope()
	env2 := makeTestEnvelope()

	if err := norm.Normalize(env1); err != nil {
		t.Fatal(err)
	}
	if err := norm.Normalize(env2); err != nil {
		t.Fatal(err)
	}

	if env1.ContentHash != env2.ContentHash {
		t.Errorf("same payload should produce same content hash: %s vs %s", env1.ContentHash, env2.ContentHash)
	}

	if env1.IdempotencyKey != env2.IdempotencyKey {
		t.Errorf("same payload should produce same idempotency key")
	}
}
