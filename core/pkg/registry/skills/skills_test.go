package skills

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func bundleHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func testManifest(id string) SkillManifest {
	bundleData := []byte("test-bundle-" + id)
	return SkillManifest{
		ID:             id,
		Name:           "test-skill-" + id,
		Version:        "1.0.0",
		Description:    "A test skill",
		EntryPoint:     "main.wasm",
		State:          SkillBundleStateCandidate,
		SelfModClass:   "none",
		RiskClass:      "low",
		SandboxProfile: "default",
		Capabilities:   []SkillCapability{CapReadFiles, CapNetworkOutbound},
		Compatibility: SkillCompatibility{
			RuntimeSpecVersion: "1.0.0",
			MinKernelVersion:   "2.0.0",
			MaxKernelVersion:   "3.0.0",
			RequiredPacks:      []string{"pack-a"},
			RequiredConnectors: []string{"conn-x"},
		},
		Inputs: []SkillInputContract{
			{Name: "query", SchemaRef: "schema://query", TrustClass: "user", Required: true},
		},
		Outputs: []SkillOutputContract{
			{Name: "result", SchemaRef: "schema://result", TrustClass: "skill", Promotable: true},
		},
		PolicyProfileRef: "policy://default",
		BundleHash:       bundleHash(bundleData),
		SignatureRef:     "sig://abc123",
	}
}

// --- Store tests ---

func TestInMemorySkillStore_PutAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("s1")

	err := store.Put(ctx, m)
	require.NoError(t, err)

	got, err := store.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "s1", got.ID)
	assert.Equal(t, "test-skill-s1", got.Name)
}

func TestInMemorySkillStore_PutEmptyID(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := SkillManifest{}

	err := store.Put(ctx, m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ID is required")
}

func TestInMemorySkillStore_GetNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()

	_, err := store.Get(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSkillNotFound)
}

func TestInMemorySkillStore_List(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()

	_ = store.Put(ctx, testManifest("a"))
	_ = store.Put(ctx, testManifest("b"))

	all, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestInMemorySkillStore_ListByState(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()

	m1 := testManifest("a")
	m1.State = SkillBundleStateCandidate
	m2 := testManifest("b")
	m2.State = SkillBundleStateCertified
	m3 := testManifest("c")
	m3.State = SkillBundleStateCandidate

	_ = store.Put(ctx, m1)
	_ = store.Put(ctx, m2)
	_ = store.Put(ctx, m3)

	candidates, err := store.ListByState(ctx, SkillBundleStateCandidate)
	require.NoError(t, err)
	assert.Len(t, candidates, 2)

	certified, err := store.ListByState(ctx, SkillBundleStateCertified)
	require.NoError(t, err)
	assert.Len(t, certified, 1)

	revoked, err := store.ListByState(ctx, SkillBundleStateRevoked)
	require.NoError(t, err)
	assert.Len(t, revoked, 0)
}

func TestInMemorySkillStore_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()

	_ = store.Put(ctx, testManifest("d"))

	err := store.Delete(ctx, "d")
	require.NoError(t, err)

	_, err = store.Get(ctx, "d")
	assert.ErrorIs(t, err, ErrSkillNotFound)
}

func TestInMemorySkillStore_DeleteNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()

	err := store.Delete(ctx, "ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSkillNotFound)
}

// --- Install tests ---

func TestInstall_Success(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	bundleData := []byte("test-bundle-inst")
	m := testManifest("inst")
	m.BundleHash = bundleHash(bundleData)
	m.State = SkillBundleStateCertified // should be overridden to candidate

	err := Install(ctx, store, m, bundleData)
	require.NoError(t, err)

	got, err := store.Get(ctx, "inst")
	require.NoError(t, err)
	assert.Equal(t, SkillBundleStateCandidate, got.State, "install must force state to candidate")
}

func TestInstall_HashMismatch(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("bad-hash")
	m.BundleHash = "0000000000000000000000000000000000000000000000000000000000000000"

	err := Install(ctx, store, m, []byte("test-bundle-bad-hash"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestInstall_EmptySignatureRef(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	bundleData := []byte("test-bundle-nosig")
	m := testManifest("nosig")
	m.BundleHash = bundleHash(bundleData)
	m.SignatureRef = ""

	err := Install(ctx, store, m, bundleData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature_ref is required")
}

func TestInstall_EmptyBundleData(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("empty")

	err := Install(ctx, store, m, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle data is empty")
}

func TestInstall_NilStore(t *testing.T) {
	err := Install(context.Background(), nil, testManifest("x"), []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is nil")
}

// --- VerifyBundle tests ---

func TestVerifyBundle_Success(t *testing.T) {
	data := []byte("hello-bundle")
	m := SkillManifest{
		ID:         "v1",
		BundleHash: bundleHash(data),
	}

	err := VerifyBundle(m, data)
	require.NoError(t, err)
}

func TestVerifyBundle_Mismatch(t *testing.T) {
	m := SkillManifest{
		ID:         "v2",
		BundleHash: "deadbeef",
	}

	err := VerifyBundle(m, []byte("something"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestVerifyBundle_EmptyHash(t *testing.T) {
	m := SkillManifest{ID: "v3"}
	err := VerifyBundle(m, []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle_hash is empty")
}

func TestVerifyBundle_EmptyData(t *testing.T) {
	m := SkillManifest{ID: "v4", BundleHash: "abc"}
	err := VerifyBundle(m, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bundle data is empty")
}

// --- VerifyCompatibility tests ---

func TestVerifyCompatibility_Success(t *testing.T) {
	m := testManifest("vc1")
	err := VerifyCompatibility(m, "1.0.0", "2.5.0")
	require.NoError(t, err)
}

func TestVerifyCompatibility_KernelTooLow(t *testing.T) {
	m := testManifest("vc2")
	err := VerifyCompatibility(m, "1.0.0", "1.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestVerifyCompatibility_KernelTooHigh(t *testing.T) {
	m := testManifest("vc3")
	err := VerifyCompatibility(m, "1.0.0", "4.0.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestVerifyCompatibility_RuntimeMismatch(t *testing.T) {
	m := testManifest("vc4")
	err := VerifyCompatibility(m, "2.0.0", "2.5.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match required")
}

func TestVerifyCompatibility_NoMaxKernel(t *testing.T) {
	m := testManifest("vc5")
	m.Compatibility.MaxKernelVersion = ""
	err := VerifyCompatibility(m, "1.0.0", "99.0.0")
	require.NoError(t, err, "no max kernel means no upper bound")
}

func TestVerifyCompatibility_InvalidSemver(t *testing.T) {
	m := testManifest("vc6")
	err := VerifyCompatibility(m, "not-semver", "2.5.0")
	require.Error(t, err)
}

func TestVerifyCompatibility_EmptyRuntimeSpec(t *testing.T) {
	m := testManifest("vc7")
	m.Compatibility.RuntimeSpecVersion = ""
	err := VerifyCompatibility(m, "1.0.0", "2.5.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runtime_spec_version is empty")
}

func TestVerifyCompatibility_EmptyMinKernel(t *testing.T) {
	m := testManifest("vc8")
	m.Compatibility.MinKernelVersion = ""
	err := VerifyCompatibility(m, "1.0.0", "2.5.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_kernel_version is empty")
}

// --- Lifecycle / Transition tests ---

func TestTransition_CandidateToCertified(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc1")
	m.State = SkillBundleStateCandidate
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc1", SkillBundleStateCertified)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lc1")
	assert.Equal(t, SkillBundleStateCertified, got.State)
}

func TestTransition_CertifiedToDeprecated(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc2")
	m.State = SkillBundleStateCertified
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc2", SkillBundleStateDeprecated)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lc2")
	assert.Equal(t, SkillBundleStateDeprecated, got.State)
}

func TestTransition_CertifiedToRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc3")
	m.State = SkillBundleStateCertified
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc3", SkillBundleStateRevoked)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lc3")
	assert.Equal(t, SkillBundleStateRevoked, got.State)
}

func TestTransition_DeprecatedToRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc4")
	m.State = SkillBundleStateDeprecated
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc4", SkillBundleStateRevoked)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lc4")
	assert.Equal(t, SkillBundleStateRevoked, got.State)
}

func TestTransition_CandidateToRevoked(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc5")
	m.State = SkillBundleStateCandidate
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc5", SkillBundleStateRevoked)
	require.NoError(t, err)

	got, _ := store.Get(ctx, "lc5")
	assert.Equal(t, SkillBundleStateRevoked, got.State)
}

func TestTransition_InvalidCandidateToDeprecated(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc6")
	m.State = SkillBundleStateCandidate
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc6", SkillBundleStateDeprecated)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transition")
}

func TestTransition_InvalidRevokedToAnything(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()
	m := testManifest("lc7")
	m.State = SkillBundleStateRevoked
	_ = store.Put(ctx, m)

	err := Transition(ctx, store, "lc7", SkillBundleStateCandidate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transition")

	err = Transition(ctx, store, "lc7", SkillBundleStateCertified)
	require.Error(t, err)
}

func TestTransition_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewInMemorySkillStore()

	err := Transition(ctx, store, "ghost", SkillBundleStateCertified)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSkillNotFound)
}

func TestTransition_NilStore(t *testing.T) {
	err := Transition(context.Background(), nil, "x", SkillBundleStateCertified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is nil")
}

// --- CheckCompatibility tests ---

func TestCheckCompatibility_Success(t *testing.T) {
	m := testManifest("cc1")

	err := CheckCompatibility(m, "1.0.0", "2.5.0", []string{"pack-a", "pack-b"}, []string{"conn-x", "conn-y"})
	require.NoError(t, err)
}

func TestCheckCompatibility_MissingPack(t *testing.T) {
	m := testManifest("cc2")

	err := CheckCompatibility(m, "1.0.0", "2.5.0", []string{"pack-b"}, []string{"conn-x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required pack")
	assert.Contains(t, err.Error(), "pack-a")
}

func TestCheckCompatibility_MissingConnector(t *testing.T) {
	m := testManifest("cc3")

	err := CheckCompatibility(m, "1.0.0", "2.5.0", []string{"pack-a"}, []string{"conn-z"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required connector")
	assert.Contains(t, err.Error(), "conn-x")
}

func TestCheckCompatibility_KernelBelowMin(t *testing.T) {
	m := testManifest("cc4")

	err := CheckCompatibility(m, "1.0.0", "1.0.0", []string{"pack-a"}, []string{"conn-x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestCheckCompatibility_KernelAboveMax(t *testing.T) {
	m := testManifest("cc5")

	err := CheckCompatibility(m, "1.0.0", "4.0.0", []string{"pack-a"}, []string{"conn-x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestCheckCompatibility_NoRequiredDeps(t *testing.T) {
	m := testManifest("cc6")
	m.Compatibility.RequiredPacks = nil
	m.Compatibility.RequiredConnectors = nil

	err := CheckCompatibility(m, "1.0.0", "2.5.0", nil, nil)
	require.NoError(t, err)
}

func TestCheckCompatibility_EmptyMinKernel(t *testing.T) {
	m := testManifest("cc7")
	m.Compatibility.MinKernelVersion = ""

	err := CheckCompatibility(m, "1.0.0", "2.5.0", []string{"pack-a"}, []string{"conn-x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_kernel_version is empty")
}

func TestCheckCompatibility_KernelExactlyAtMin(t *testing.T) {
	m := testManifest("cc8")
	// min=2.0.0, max=3.0.0 — kernel exactly at min should pass
	err := CheckCompatibility(m, "1.0.0", "2.0.0", []string{"pack-a"}, []string{"conn-x"})
	require.NoError(t, err)
}

func TestCheckCompatibility_KernelExactlyAtMax(t *testing.T) {
	m := testManifest("cc9")
	// min=2.0.0, max=3.0.0 — kernel exactly at max should pass
	err := CheckCompatibility(m, "1.0.0", "3.0.0", []string{"pack-a"}, []string{"conn-x"})
	require.NoError(t, err)
}
