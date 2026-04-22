package skills_conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry/connectors"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry/skills"
)

// bundleHash computes SHA-256 of data and returns the hex string.
func bundleHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// newTestManifest builds a minimal valid SkillManifest for use in conformance tests.
func newTestManifest(id string, bundleData []byte) skills.SkillManifest {
	return skills.SkillManifest{
		ID:             id,
		Name:           "conformance-skill-" + id,
		Version:        "1.0.0",
		Description:    "Conformance test skill",
		EntryPoint:     "main.wasm",
		State:          skills.SkillBundleStateCandidate,
		SelfModClass:   "none",
		RiskClass:      "low",
		SandboxProfile: "default",
		Capabilities:   []skills.SkillCapability{skills.CapReadFiles},
		Compatibility: skills.SkillCompatibility{
			RuntimeSpecVersion: "1.0.0",
			MinKernelVersion:   "2.0.0",
			MaxKernelVersion:   "5.0.0",
			RequiredPacks:      []string{"pack-a"},
			RequiredConnectors: []string{"conn-x"},
		},
		Inputs: []skills.SkillInputContract{
			{Name: "query", SchemaRef: "schema://query", TrustClass: "user", Required: true},
		},
		Outputs: []skills.SkillOutputContract{
			{Name: "result", SchemaRef: "schema://result", TrustClass: "skill", Promotable: true},
		},
		PolicyProfileRef: "policy://default",
		BundleHash:       bundleHash(bundleData),
		SignatureRef:     "sig://conformance-test",
	}
}

// TestSkillBundleLifecycle_InstallStartsAsCandidate verifies that Install forces state to candidate.
func TestSkillBundleLifecycle_InstallStartsAsCandidate(t *testing.T) {
	ctx := context.Background()
	store := skills.NewInMemorySkillStore()
	bundleData := []byte("conformance-bundle-v1")
	m := newTestManifest("lc-001", bundleData)
	m.State = skills.SkillBundleStateCertified // intentionally wrong — Install must override

	t.Run("install_forces_candidate_state", func(t *testing.T) {
		err := skills.Install(ctx, store, m, bundleData)
		require.NoError(t, err)

		got, err := store.Get(ctx, "lc-001")
		require.NoError(t, err)
		assert.Equal(t, skills.SkillBundleStateCandidate, got.State,
			"Install must force initial state to candidate regardless of the supplied state field")
	})
}

// TestSkillBundleLifecycle_CandidateToCertified verifies the candidate → certified transition.
func TestSkillBundleLifecycle_CandidateToCertified(t *testing.T) {
	ctx := context.Background()
	store := skills.NewInMemorySkillStore()
	bundleData := []byte("conformance-bundle-v2")
	m := newTestManifest("lc-002", bundleData)

	require.NoError(t, skills.Install(ctx, store, m, bundleData))

	t.Run("candidate_to_certified", func(t *testing.T) {
		err := skills.Transition(ctx, store, "lc-002", skills.SkillBundleStateCertified)
		require.NoError(t, err)

		got, err := store.Get(ctx, "lc-002")
		require.NoError(t, err)
		assert.Equal(t, skills.SkillBundleStateCertified, got.State)
	})
}

// TestSkillBundleLifecycle_CertifiedSkillsAreDiscoverable verifies ListByState for certified.
func TestSkillBundleLifecycle_CertifiedSkillsAreDiscoverable(t *testing.T) {
	ctx := context.Background()
	store := skills.NewInMemorySkillStore()

	// Install two skills and certify only one.
	dataA := []byte("conformance-bundle-a")
	dataB := []byte("conformance-bundle-b")
	mA := newTestManifest("lc-disc-a", dataA)
	mB := newTestManifest("lc-disc-b", dataB)

	require.NoError(t, skills.Install(ctx, store, mA, dataA))
	require.NoError(t, skills.Install(ctx, store, mB, dataB))
	require.NoError(t, skills.Transition(ctx, store, "lc-disc-a", skills.SkillBundleStateCertified))

	t.Run("certified_skills_are_discoverable", func(t *testing.T) {
		certified, err := store.ListByState(ctx, skills.SkillBundleStateCertified)
		require.NoError(t, err)
		require.Len(t, certified, 1)
		assert.Equal(t, "lc-disc-a", certified[0].ID)
	})
}

// TestSkillBundleLifecycle_DeprecatedSkillsRemainAccessible verifies deprecated skills are still readable.
func TestSkillBundleLifecycle_DeprecatedSkillsRemainAccessible(t *testing.T) {
	ctx := context.Background()
	store := skills.NewInMemorySkillStore()
	bundleData := []byte("conformance-bundle-dep")
	m := newTestManifest("lc-dep", bundleData)

	require.NoError(t, skills.Install(ctx, store, m, bundleData))
	require.NoError(t, skills.Transition(ctx, store, "lc-dep", skills.SkillBundleStateCertified))

	t.Run("transition_to_deprecated", func(t *testing.T) {
		err := skills.Transition(ctx, store, "lc-dep", skills.SkillBundleStateDeprecated)
		require.NoError(t, err)

		got, err := store.Get(ctx, "lc-dep")
		require.NoError(t, err)
		assert.Equal(t, skills.SkillBundleStateDeprecated, got.State,
			"deprecated skill must still be accessible via Get")
	})
}

// TestSkillBundleLifecycle_RevokedSkillsAreNotReinstallable verifies that a revoked skill cannot
// be installed again under the same ID via the store (state machine is terminal).
func TestSkillBundleLifecycle_RevokedSkillsAreNotReinstallable(t *testing.T) {
	ctx := context.Background()
	store := skills.NewInMemorySkillStore()
	bundleData := []byte("conformance-bundle-rev")
	m := newTestManifest("lc-rev", bundleData)

	require.NoError(t, skills.Install(ctx, store, m, bundleData))
	require.NoError(t, skills.Transition(ctx, store, "lc-rev", skills.SkillBundleStateRevoked))

	t.Run("revoked_skill_is_inaccessible_to_new_transitions", func(t *testing.T) {
		// Revoked is a terminal state; any further transition must be rejected.
		err := skills.Transition(ctx, store, "lc-rev", skills.SkillBundleStateCandidate)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid transition")
	})

	t.Run("revoked_skill_is_still_readable", func(t *testing.T) {
		got, err := store.Get(ctx, "lc-rev")
		require.NoError(t, err)
		assert.Equal(t, skills.SkillBundleStateRevoked, got.State)
	})
}

// TestSkillBundleLifecycle_InvalidTransitionsAreRejected verifies the fail-closed state machine.
func TestSkillBundleLifecycle_InvalidTransitionsAreRejected(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		from  skills.SkillBundleState
		to    skills.SkillBundleState
	}{
		{"candidate_to_deprecated_is_invalid", skills.SkillBundleStateCandidate, skills.SkillBundleStateDeprecated},
		{"deprecated_to_certified_is_invalid", skills.SkillBundleStateDeprecated, skills.SkillBundleStateCertified},
		{"deprecated_to_candidate_is_invalid", skills.SkillBundleStateDeprecated, skills.SkillBundleStateCandidate},
		{"revoked_to_candidate_is_invalid", skills.SkillBundleStateRevoked, skills.SkillBundleStateCandidate},
		{"revoked_to_certified_is_invalid", skills.SkillBundleStateRevoked, skills.SkillBundleStateCertified},
		{"revoked_to_deprecated_is_invalid", skills.SkillBundleStateRevoked, skills.SkillBundleStateDeprecated},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := skills.NewInMemorySkillStore()
			bundleData := []byte("bundle-for-" + tc.name)
			m := newTestManifest("inv-"+tc.name, bundleData)
			m.State = tc.from
			require.NoError(t, store.Put(ctx, m))

			err := skills.Transition(ctx, store, "inv-"+tc.name, tc.to)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid transition")
		})
	}
}

// TestSkillBundleLifecycle_BundleHashVerificationCatchesTampering verifies VerifyBundle.
func TestSkillBundleLifecycle_BundleHashVerificationCatchesTampering(t *testing.T) {
	originalData := []byte("authentic-bundle-payload")
	tamperedData := []byte("tampered-bundle-payload!")

	m := skills.SkillManifest{
		ID:         "tamper-check",
		BundleHash: bundleHash(originalData),
	}

	t.Run("correct_data_passes_verification", func(t *testing.T) {
		err := skills.VerifyBundle(m, originalData)
		require.NoError(t, err)
	})

	t.Run("tampered_data_fails_verification", func(t *testing.T) {
		err := skills.VerifyBundle(m, tamperedData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash mismatch")
	})
}

// TestSkillBundleLifecycle_CapabilityValidation verifies that capabilities are recorded correctly.
func TestSkillBundleLifecycle_CapabilityValidation(t *testing.T) {
	ctx := context.Background()
	store := skills.NewInMemorySkillStore()
	bundleData := []byte("capability-bundle")
	m := newTestManifest("cap-001", bundleData)
	m.Capabilities = []skills.SkillCapability{
		skills.CapReadFiles,
		skills.CapNetworkOutbound,
		skills.CapChannelSend,
	}

	require.NoError(t, skills.Install(ctx, store, m, bundleData))

	t.Run("capabilities_are_stored_and_readable", func(t *testing.T) {
		got, err := store.Get(ctx, "cap-001")
		require.NoError(t, err)
		assert.Len(t, got.Capabilities, 3)
		assert.Contains(t, got.Capabilities, skills.CapReadFiles)
		assert.Contains(t, got.Capabilities, skills.CapNetworkOutbound)
		assert.Contains(t, got.Capabilities, skills.CapChannelSend)
	})
}

// TestSkillBundleLifecycle_CompatibilityChecks verifies kernel version and dependency checks.
func TestSkillBundleLifecycle_CompatibilityChecks(t *testing.T) {
	bundleData := []byte("compat-bundle")
	m := newTestManifest("compat-001", bundleData)
	// manifest has MinKernel=2.0.0, MaxKernel=5.0.0, RequiredPacks=[pack-a], RequiredConnectors=[conn-x]

	t.Run("valid_environment_passes", func(t *testing.T) {
		err := skills.CheckCompatibility(m, "1.0.0", "3.0.0", []string{"pack-a"}, []string{"conn-x"})
		require.NoError(t, err)
	})

	t.Run("kernel_below_minimum_fails", func(t *testing.T) {
		err := skills.CheckCompatibility(m, "1.0.0", "1.5.0", []string{"pack-a"}, []string{"conn-x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "below minimum")
	})

	t.Run("kernel_above_maximum_fails", func(t *testing.T) {
		err := skills.CheckCompatibility(m, "1.0.0", "6.0.0", []string{"pack-a"}, []string{"conn-x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("missing_required_pack_fails", func(t *testing.T) {
		err := skills.CheckCompatibility(m, "1.0.0", "3.0.0", []string{"pack-z"}, []string{"conn-x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required pack")
	})

	t.Run("missing_required_connector_fails", func(t *testing.T) {
		err := skills.CheckCompatibility(m, "1.0.0", "3.0.0", []string{"pack-a"}, []string{"conn-z"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required connector")
	})
}

// TestConnectorRegistry_BasicLifecycle validates connector store operations alongside skills.
// This exercises the connectors package (imported alongside skills per the task spec).
func TestConnectorRegistry_BasicLifecycle(t *testing.T) {
	ctx := context.Background()
	store := connectors.NewInMemoryConnectorStore()

	binaryData := []byte("connector-binary-v1")
	h := sha256.Sum256(binaryData)
	release := connectors.ConnectorRelease{
		ConnectorID:    "conn-conformance-01",
		Name:           "conformance-connector",
		Version:        "1.0.0",
		State:          connectors.ConnectorCandidate,
		ExecutorKind:   connectors.ExecDigital,
		SandboxProfile: "default",
		DriftPolicyRef: "policy://drift-default",
		BinaryHash:     hex.EncodeToString(h[:]),
		SignatureRef:   "sig://conformance-connector",
	}

	t.Run("register_connector_as_candidate", func(t *testing.T) {
		err := store.Put(ctx, release)
		require.NoError(t, err)

		got, err := store.Get(ctx, "conn-conformance-01")
		require.NoError(t, err)
		assert.Equal(t, connectors.ConnectorCandidate, got.State)
	})

	t.Run("transition_connector_to_certified", func(t *testing.T) {
		err := connectors.Transition(ctx, store, "conn-conformance-01", connectors.ConnectorCertified)
		require.NoError(t, err)

		got, err := store.Get(ctx, "conn-conformance-01")
		require.NoError(t, err)
		assert.Equal(t, connectors.ConnectorCertified, got.State)
	})

	t.Run("certified_connectors_are_discoverable", func(t *testing.T) {
		certified, err := store.ListByState(ctx, connectors.ConnectorCertified)
		require.NoError(t, err)
		require.Len(t, certified, 1)
		assert.Equal(t, "conn-conformance-01", certified[0].ConnectorID)
	})

	t.Run("transition_connector_to_revoked", func(t *testing.T) {
		err := connectors.Transition(ctx, store, "conn-conformance-01", connectors.ConnectorRevoked)
		require.NoError(t, err)

		got, err := store.Get(ctx, "conn-conformance-01")
		require.NoError(t, err)
		assert.Equal(t, connectors.ConnectorRevoked, got.State)
	})

	t.Run("invalid_transition_from_revoked_is_rejected", func(t *testing.T) {
		err := connectors.Transition(ctx, store, "conn-conformance-01", connectors.ConnectorCandidate)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid transition")
	})

	t.Run("binary_hash_verification_catches_tampering", func(t *testing.T) {
		err := connectors.VerifyRelease(release, binaryData)
		require.NoError(t, err)

		err = connectors.VerifyRelease(release, []byte("tampered!"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash mismatch")
	})
}
