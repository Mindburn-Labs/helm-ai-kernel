package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func binaryHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func testRelease(id string) ConnectorRelease {
	binData := []byte("connector-bin-" + id)
	return ConnectorRelease{
		ConnectorID:    id,
		Name:           "test-connector-" + id,
		Version:        "1.0.0",
		State:          ConnectorCandidate,
		SchemaRefs:     []string{"schema://input", "schema://output"},
		ExecutorKind:   ExecDigital,
		SandboxProfile: "default",
		DriftPolicyRef: "policy://drift",
		BinaryHash:     binaryHash(binData),
		SignatureRef:   "sig://xyz789",
	}
}

// --- Store tests ---

func TestInMemoryConnectorStore_PutAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()
	r := testRelease("c1")

	err := store.Put(ctx, r)
	require.NoError(t, err)

	got, err := store.Get(ctx, "c1")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.ConnectorID)
	assert.Equal(t, "test-connector-c1", got.Name)
}

func TestInMemoryConnectorStore_PutEmptyID(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	err := store.Put(ctx, ConnectorRelease{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector_id is required")
}

func TestInMemoryConnectorStore_GetNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	_, err := store.Get(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectorNotFound)
}

func TestInMemoryConnectorStore_List(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	_ = store.Put(ctx, testRelease("a"))
	_ = store.Put(ctx, testRelease("b"))

	all, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestInMemoryConnectorStore_ListByState(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	r1 := testRelease("a")
	r1.State = ConnectorCandidate
	r2 := testRelease("b")
	r2.State = ConnectorCertified
	r3 := testRelease("c")
	r3.State = ConnectorCandidate

	_ = store.Put(ctx, r1)
	_ = store.Put(ctx, r2)
	_ = store.Put(ctx, r3)

	candidates, err := store.ListByState(ctx, ConnectorCandidate)
	require.NoError(t, err)
	assert.Len(t, candidates, 2)

	certified, err := store.ListByState(ctx, ConnectorCertified)
	require.NoError(t, err)
	assert.Len(t, certified, 1)

	revoked, err := store.ListByState(ctx, ConnectorRevoked)
	require.NoError(t, err)
	assert.Len(t, revoked, 0)
}

func TestInMemoryConnectorStore_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	_ = store.Put(ctx, testRelease("d"))

	err := store.Delete(ctx, "d")
	require.NoError(t, err)

	_, err = store.Get(ctx, "d")
	assert.ErrorIs(t, err, ErrConnectorNotFound)
}

func TestInMemoryConnectorStore_DeleteNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	err := store.Delete(ctx, "ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectorNotFound)
}

// --- VerifyRelease tests ---

func TestVerifyRelease_Success(t *testing.T) {
	data := []byte("connector-binary")
	r := ConnectorRelease{
		ConnectorID:  "vr1",
		BinaryHash:   binaryHash(data),
		SignatureRef: "sig://ok",
	}

	err := VerifyRelease(r, data)
	require.NoError(t, err)
}

func TestVerifyRelease_HashMismatch(t *testing.T) {
	r := ConnectorRelease{
		ConnectorID:  "vr2",
		BinaryHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		SignatureRef: "sig://ok",
	}

	err := VerifyRelease(r, []byte("real-data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestVerifyRelease_EmptyHash(t *testing.T) {
	r := ConnectorRelease{ConnectorID: "vr3", SignatureRef: "sig://ok"}
	err := VerifyRelease(r, []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binary_hash is empty")
}

func TestVerifyRelease_EmptySignatureRef(t *testing.T) {
	r := ConnectorRelease{ConnectorID: "vr4", BinaryHash: "abc"}
	err := VerifyRelease(r, []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature_ref is empty")
}

func TestVerifyRelease_EmptyData(t *testing.T) {
	r := ConnectorRelease{ConnectorID: "vr5", BinaryHash: "abc", SignatureRef: "sig://ok"}
	err := VerifyRelease(r, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binary data is empty")
}

func TestVerifyRelease_EmptyConnectorID(t *testing.T) {
	r := ConnectorRelease{BinaryHash: "abc", SignatureRef: "sig://ok"}
	err := VerifyRelease(r, []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector_id is empty")
}

// --- Lifecycle / Transition tests ---

func TestTransition_CandidateToCertified(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()
	r := testRelease("lt1")
	r.State = ConnectorCandidate
	_ = store.Put(ctx, r)

	err := Transition(ctx, store, "lt1", ConnectorCertified)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lt1")
	assert.Equal(t, ConnectorCertified, got.State)
}

func TestTransition_CandidateToRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()
	r := testRelease("lt2")
	r.State = ConnectorCandidate
	_ = store.Put(ctx, r)

	err := Transition(ctx, store, "lt2", ConnectorRevoked)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lt2")
	assert.Equal(t, ConnectorRevoked, got.State)
}

func TestTransition_CertifiedToRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()
	r := testRelease("lt3")
	r.State = ConnectorCertified
	_ = store.Put(ctx, r)

	err := Transition(ctx, store, "lt3", ConnectorRevoked)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lt3")
	assert.Equal(t, ConnectorRevoked, got.State)
}

func TestTransition_InvalidCertifiedToCandidate(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()
	r := testRelease("lt4")
	r.State = ConnectorCertified
	_ = store.Put(ctx, r)

	err := Transition(ctx, store, "lt4", ConnectorCandidate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transition")
}

func TestTransition_InvalidRevokedToAnything(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()
	r := testRelease("lt5")
	r.State = ConnectorRevoked
	_ = store.Put(ctx, r)

	err := Transition(ctx, store, "lt5", ConnectorCandidate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transition")

	err = Transition(ctx, store, "lt5", ConnectorCertified)
	require.Error(t, err)
}

func TestTransition_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryConnectorStore()

	err := Transition(ctx, store, "ghost", ConnectorCertified)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectorNotFound)
}

func TestTransition_NilStore(t *testing.T) {
	err := Transition(context.Background(), nil, "x", ConnectorCertified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is nil")
}

// --- Type constant tests ---

func TestConnectorExecutorKindValues(t *testing.T) {
	assert.Equal(t, ConnectorExecutorKind("digital"), ExecDigital)
	assert.Equal(t, ConnectorExecutorKind("analog"), ExecAnalog)
}

func TestConnectorReleaseStateValues(t *testing.T) {
	assert.Equal(t, ConnectorReleaseState("candidate"), ConnectorCandidate)
	assert.Equal(t, ConnectorReleaseState("certified"), ConnectorCertified)
	assert.Equal(t, ConnectorReleaseState("revoked"), ConnectorRevoked)
}
