package cases

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust/registry"
)

func TestRegisterAllCasesAndRunSuccess(t *testing.T) {
	restore := replaceCaseHooks(t)
	conformanceNow = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	defer restore()

	suite := conformance.NewSuite()
	RegisterAllCases(suite)

	tests := suite.TestsForLevel(conformance.LevelL3)
	if len(tests) != 8 {
		t.Fatalf("registered tests = %d, want 8: %#v", len(tests), tests)
	}

	seen := map[string]bool{}
	for _, tc := range tests {
		if tc.ID == "" || tc.Level == "" || tc.Category == "" || tc.Name == "" || tc.Description == "" || tc.Run == nil {
			t.Fatalf("incomplete test case: %#v", tc)
		}
		seen[tc.ID] = true
	}
	for _, id := range []string{
		"L1-PACK-002",
		"L1-PACK-003",
		"L1-PACK-004",
		"L1-TRUST-002",
		"L2-TRUST-002",
		"L3-SIGPACK-EP-001",
		"L3-SIGPACK-EP-002",
		"L3-TRUST-REG-001",
	} {
		if !seen[id] {
			t.Fatalf("missing registered case %s in %#v", id, tests)
		}
	}

	results := suite.Run(conformance.LevelL3)
	for _, result := range results {
		if !result.Passed {
			t.Fatalf("case %s failed unexpectedly: %#v", result.TestID, result)
		}
	}
}

func TestEvidencePackCaseErrorAndFailureBranches(t *testing.T) {
	t.Run("deterministic archive first error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			return nil, errors.New("archive failed")
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-002")
		assertErrContains(t, err, "first archive")
	})

	t.Run("deterministic archive second error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("second failed")
			}
			return []byte("archive"), nil
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-002")
		assertErrContains(t, err, "second archive")
	})

	t.Run("deterministic archive mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			calls++
			return []byte{byte(calls)}, nil
		}
		defer restore()

		ctx, err := runCase(t, "L1-PACK-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "archive hashes differ")
	})

	t.Run("builder add receipt error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{addErrAt: map[int]error{1: errors.New("add failed")}}
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-003")
		assertErrContains(t, err, "add failed")
	})

	t.Run("builder build error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{buildErr: errors.New("build failed")}
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-003")
		assertErrContains(t, err, "build")
	})

	t.Run("builder recompute error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{manifest: &evidencepack.Manifest{ManifestHash: "sha256:old"}}
		}
		computeManifestHash = func(*evidencepack.Manifest) (string, error) {
			return "", errors.New("compute failed")
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-003")
		assertErrContains(t, err, "recompute hash")
	})

	t.Run("builder manifest mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{manifest: &evidencepack.Manifest{ManifestHash: "sha256:old"}}
		}
		computeManifestHash = func(*evidencepack.Manifest) (string, error) {
			return "sha256:new", nil
		}
		defer restore()

		ctx, err := runCase(t, "L1-PACK-003")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "manifest hash mismatch")
	})

	t.Run("round trip archive error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			return nil, errors.New("archive failed")
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-004")
		assertErrContains(t, err, "archive failed")
	})

	t.Run("round trip unarchive error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		unarchiveEvidencePack = func([]byte) (map[string][]byte, error) {
			return nil, errors.New("unarchive failed")
		}
		defer restore()

		_, err := runCase(t, "L1-PACK-004")
		assertErrContains(t, err, "unarchive failed")
	})

	t.Run("round trip content mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		unarchiveEvidencePack = func([]byte) (map[string][]byte, error) {
			return map[string][]byte{"a.json": []byte("wrong"), "b.txt": []byte("hello world")}, nil
		}
		defer restore()

		ctx, err := runCase(t, "L1-PACK-004")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "content mismatch")
	})
}

func TestSignedEvidenceCaseErrorAndFailureBranches(t *testing.T) {
	t.Run("first receipt error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{addErrAt: map[int]error{1: errors.New("first add failed")}}
		}
		defer restore()

		_, err := runCase(t, "L3-SIGPACK-EP-001")
		assertErrContains(t, err, "first add failed")
	})

	t.Run("second receipt error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{addErrAt: map[int]error{2: errors.New("second add failed")}}
		}
		defer restore()

		_, err := runCase(t, "L3-SIGPACK-EP-001")
		assertErrContains(t, err, "second add failed")
	})

	t.Run("build error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{buildErr: errors.New("build failed")}
		}
		defer restore()

		_, err := runCase(t, "L3-SIGPACK-EP-001")
		assertErrContains(t, err, "build")
	})

	t.Run("empty manifest hash", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{manifest: &evidencepack.Manifest{}}
		}
		defer restore()

		ctx, err := runCase(t, "L3-SIGPACK-EP-001")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "manifest hash is empty")
	})

	t.Run("recompute error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{manifest: &evidencepack.Manifest{ManifestHash: "sha256:old"}}
		}
		computeManifestHash = func(*evidencepack.Manifest) (string, error) {
			return "", errors.New("compute failed")
		}
		defer restore()

		_, err := runCase(t, "L3-SIGPACK-EP-001")
		assertErrContains(t, err, "recompute")
	})

	t.Run("manifest mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		newEvidencePackBuilder = func(string, string, string, string, time.Time) evidencePackBuilder {
			return &fakeEvidenceBuilder{manifest: &evidencepack.Manifest{ManifestHash: "sha256:old"}}
		}
		computeManifestHash = func(*evidencepack.Manifest) (string, error) {
			return "sha256:new", nil
		}
		defer restore()

		ctx, err := runCase(t, "L3-SIGPACK-EP-001")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "manifest hash not deterministic")
	})

	t.Run("archive first error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			return nil, errors.New("archive failed")
		}
		defer restore()

		_, err := runCase(t, "L3-SIGPACK-EP-002")
		assertErrContains(t, err, "first archive")
	})

	t.Run("archive second error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			calls++
			if calls == 2 {
				return nil, errors.New("second archive failed")
			}
			return []byte("archive"), nil
		}
		defer restore()

		_, err := runCase(t, "L3-SIGPACK-EP-002")
		assertErrContains(t, err, "second archive")
	})

	t.Run("archive mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		archiveEvidencePack = func(map[string][]byte) ([]byte, error) {
			calls++
			return []byte{byte(calls)}, nil
		}
		defer restore()

		ctx, err := runCase(t, "L3-SIGPACK-EP-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "archive not deterministic")
	})
}

func TestTrustRegistryCaseErrorAndFailureBranches(t *testing.T) {
	t.Run("deterministic reducer first state apply error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		applyTrustEvent = func(*registry.TrustState, *registry.TrustEvent) error {
			return errors.New("apply failed")
		}
		defer restore()

		_, err := runCase(t, "L1-TRUST-002")
		assertErrContains(t, err, "apply event e1")
	})

	t.Run("deterministic reducer second state apply error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if calls == 3 {
				return errors.New("second state failed")
			}
			return state.Apply(event)
		}
		defer restore()

		_, err := runCase(t, "L1-TRUST-002")
		assertErrContains(t, err, "second state failed")
	})

	t.Run("deterministic reducer lamport mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 4 {
				state.Lamport++
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L1-TRUST-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "lamport mismatch")
	})

	t.Run("deterministic reducer key count mismatch", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 4 {
				state.Keys["extra"] = registry.KeyEntry{KID: "extra"}
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L1-TRUST-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "key count mismatch")
	})

	t.Run("revoked key registration apply error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		applyTrustEvent = func(*registry.TrustState, *registry.TrustEvent) error {
			return errors.New("registration failed")
		}
		defer restore()

		_, err := runCase(t, "L2-TRUST-002")
		assertErrContains(t, err, "registration failed")
	})

	t.Run("revoked key missing after registration", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			state.Lamport = event.Lamport
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L2-TRUST-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "key not found")
	})

	t.Run("revoked key inactive after registration", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			if err := state.Apply(event); err != nil {
				return err
			}
			lamport := uint64(1)
			key := state.Keys["key-001"]
			key.RevokedAtLamport = &lamport
			state.Keys["key-001"] = key
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L2-TRUST-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "should be active")
	})

	t.Run("revoked key revoke apply error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if calls == 2 {
				return errors.New("revoke failed")
			}
			return state.Apply(event)
		}
		defer restore()

		_, err := runCase(t, "L2-TRUST-002")
		assertErrContains(t, err, "revoke failed")
	})

	t.Run("revoked key missing after revocation", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 2 {
				delete(state.Keys, "key-001")
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L2-TRUST-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "key missing after revocation")
	})

	t.Run("revoked key remains active", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if calls == 2 {
				state.Lamport = event.Lamport
				return nil
			}
			return state.Apply(event)
		}
		defer restore()

		ctx, err := runCase(t, "L2-TRUST-002")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "should NOT be active")
	})
}

func TestL3TrustRegistryCaseErrorAndFailureBranches(t *testing.T) {
	t.Run("register old key error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		applyTrustEvent = func(*registry.TrustState, *registry.TrustEvent) error {
			return errors.New("register failed")
		}
		defer restore()

		_, err := runCase(t, "L3-TRUST-REG-001")
		assertErrContains(t, err, "register failed")
	})

	t.Run("revoke old key error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if calls == 2 {
				return errors.New("revoke failed")
			}
			return state.Apply(event)
		}
		defer restore()

		_, err := runCase(t, "L3-TRUST-REG-001")
		assertErrContains(t, err, "revoke failed")
	})

	t.Run("register new key error", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if calls == 3 {
				return errors.New("new key failed")
			}
			return state.Apply(event)
		}
		defer restore()

		_, err := runCase(t, "L3-TRUST-REG-001")
		assertErrContains(t, err, "new key failed")
	})

	t.Run("old key missing", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 3 {
				delete(state.Keys, "key-v1")
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L3-TRUST-REG-001")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "old key should still exist")
	})

	t.Run("old key still active", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 3 {
				key := state.Keys["key-v1"]
				key.RevokedAtLamport = nil
				state.Keys["key-v1"] = key
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L3-TRUST-REG-001")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "old key should not be active")
	})

	t.Run("new key missing", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 3 {
				delete(state.Keys, "key-v2")
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L3-TRUST-REG-001")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "new key should exist")
	})

	t.Run("new key inactive", func(t *testing.T) {
		restore := replaceCaseHooks(t)
		calls := 0
		applyTrustEvent = func(state *registry.TrustState, event *registry.TrustEvent) error {
			calls++
			if err := state.Apply(event); err != nil {
				return err
			}
			if calls == 3 {
				lamport := uint64(6)
				key := state.Keys["key-v2"]
				key.RevokedAtLamport = &lamport
				state.Keys["key-v2"] = key
			}
			return nil
		}
		defer restore()

		ctx, err := runCase(t, "L3-TRUST-REG-001")
		assertNoErr(t, err)
		assertFailedContains(t, ctx, "new key should be active")
	})
}

func runCase(t *testing.T, id string) (*conformance.TestContext, error) {
	t.Helper()

	tc := findCase(t, id)
	ctx := &conformance.TestContext{
		Level:    tc.Level,
		Category: tc.Category,
	}
	return ctx, tc.Run(ctx)
}

func findCase(t *testing.T, id string) conformance.TestCase {
	t.Helper()

	suite := conformance.NewSuite()
	RegisterAllCases(suite)
	for _, tc := range suite.TestsForLevel(conformance.LevelL3) {
		if tc.ID == id {
			return tc
		}
	}
	t.Fatalf("case %s not registered", id)
	return conformance.TestCase{}
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}

func assertNoErr(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertFailedContains(t *testing.T, ctx *conformance.TestContext, want string) {
	t.Helper()

	if !ctx.Failed() {
		t.Fatalf("context did not fail, want %q", want)
	}
	for _, msg := range ctx.Errors {
		if strings.Contains(msg, want) {
			return
		}
	}
	t.Fatalf("context errors = %#v, want substring %q", ctx.Errors, want)
}

func replaceCaseHooks(t *testing.T) func() {
	t.Helper()

	oldArchive := archiveEvidencePack
	oldUnarchive := unarchiveEvidencePack
	oldCompute := computeManifestHash
	oldBuilder := newEvidencePackBuilder
	oldNewTrustState := newTrustState
	oldApplyTrustEvent := applyTrustEvent
	oldNow := conformanceNow
	restored := false

	restore := func() {
		if restored {
			return
		}
		archiveEvidencePack = oldArchive
		unarchiveEvidencePack = oldUnarchive
		computeManifestHash = oldCompute
		newEvidencePackBuilder = oldBuilder
		newTrustState = oldNewTrustState
		applyTrustEvent = oldApplyTrustEvent
		conformanceNow = oldNow
		restored = true
	}
	t.Cleanup(restore)
	return restore
}

type fakeEvidenceBuilder struct {
	addCalls int
	addErrAt map[int]error
	buildErr error
	manifest *evidencepack.Manifest
}

func (b *fakeEvidenceBuilder) AddReceipt(string, interface{}) error {
	b.addCalls++
	if err := b.addErrAt[b.addCalls]; err != nil {
		return err
	}
	return nil
}

func (b *fakeEvidenceBuilder) Build() (*evidencepack.Manifest, map[string][]byte, error) {
	if b.buildErr != nil {
		return nil, nil, b.buildErr
	}
	if b.manifest != nil {
		return b.manifest, map[string][]byte{"manifest.json": []byte("{}")}, nil
	}
	return &evidencepack.Manifest{ManifestHash: "sha256:manifest"}, map[string][]byte{"manifest.json": []byte("{}")}, nil
}
