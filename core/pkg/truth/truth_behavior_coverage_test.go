package truth_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/truth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruthRegistryRegisterAndGet(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	obj := &truth.TruthObject{ObjectID: "o1", Type: truth.TruthTypePolicy, Name: "pol-1"}
	require.NoError(t, r.Register(obj))
	got, err := r.Get("o1")
	require.NoError(t, err)
	assert.Equal(t, "pol-1", got.Name)
}

func TestTruthRegistryDuplicateRegister(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	_ = r.Register(&truth.TruthObject{ObjectID: "o1"})
	err := r.Register(&truth.TruthObject{ObjectID: "o1"})
	assert.Error(t, err)
}

func TestTruthRegistryGetNotFound(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	got, err := r.Get("missing")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestTruthRegistryGetLatest(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	_ = r.Register(&truth.TruthObject{ObjectID: "o1", Type: truth.TruthTypeSchema, Name: "s", RegisteredAt: time.Unix(1, 0)})
	_ = r.Register(&truth.TruthObject{ObjectID: "o2", Type: truth.TruthTypeSchema, Name: "s", RegisteredAt: time.Unix(2, 0)})
	got, _ := r.GetLatest(truth.TruthTypeSchema, "s")
	assert.Equal(t, "o2", got.ObjectID)
}

func TestTruthRegistryListByType(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	_ = r.Register(&truth.TruthObject{ObjectID: "o1", Type: truth.TruthTypePolicy})
	_ = r.Register(&truth.TruthObject{ObjectID: "o2", Type: truth.TruthTypeSchema})
	list, _ := r.List(truth.TruthTypePolicy)
	assert.Len(t, list, 1)
}

func TestTruthRegistryGetAtEpoch(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	_ = r.Register(&truth.TruthObject{ObjectID: "o1", Type: truth.TruthTypePolicy, Name: "p", Version: truth.VersionScope{Epoch: "e1"}})
	got, _ := r.GetAtEpoch(truth.TruthTypePolicy, "p", "e1")
	require.NotNil(t, got)
	assert.Equal(t, "o1", got.ObjectID)
}

func TestTruthRegistryGetAtEpochNotFound(t *testing.T) {
	r := truth.NewInMemoryRegistry()
	got, _ := r.GetAtEpoch(truth.TruthTypePolicy, "p", "e99")
	assert.Nil(t, got)
}

func TestVersionScopeString(t *testing.T) {
	v := truth.VersionScope{Major: 1, Minor: 2, Patch: 3, Epoch: "e1", Label: "rc"}
	assert.Equal(t, "e1:1.2.3-rc", v.String())
}

func TestVersionScopeStringNoEpochNoLabel(t *testing.T) {
	v := truth.VersionScope{Major: 0, Minor: 1, Patch: 0}
	assert.Equal(t, "0.1.0", v.String())
}

func TestClaimRegistryWithClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := truth.NewInMemoryClaimRegistry().WithClock(func() time.Time { return fixed })
	_ = r.Register(&truth.ClaimRecord{ClaimID: "c1", Statement: "s"})
	got, _ := r.Get("c1")
	assert.Equal(t, fixed, got.RegisteredAt)
}

func TestUnknownRegistryListBlockingNoMatch(t *testing.T) {
	r := truth.NewInMemoryUnknownRegistry()
	_ = r.Register(&contracts.Unknown{ID: "u1", Impact: contracts.UnknownImpactBlocking, BlockingStepIDs: []string{"s1"}})
	blocking, _ := r.ListBlocking("s99")
	assert.Empty(t, blocking)
}

func TestUnknownRegistryResolveTimestamp(t *testing.T) {
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	r := truth.NewInMemoryUnknownRegistry().WithClock(func() time.Time { return fixed })
	_ = r.Register(&contracts.Unknown{ID: "u1", Impact: contracts.UnknownImpactBlocking})
	_ = r.Resolve("u1", "done")
	got, _ := r.Get("u1")
	assert.Equal(t, fixed, got.ResolvedAt)
}

func TestDuplicateObjectErrorMessage(t *testing.T) {
	e := &truth.DuplicateObjectError{ObjectID: "abc"}
	assert.Contains(t, e.Error(), "abc")
}

func TestClaimRegistryListAllEmpty(t *testing.T) {
	r := truth.NewInMemoryClaimRegistry()
	all, err := r.ListAll()
	require.NoError(t, err)
	assert.Empty(t, all)
}
