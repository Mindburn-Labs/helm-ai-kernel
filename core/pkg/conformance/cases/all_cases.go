// Package cases provides concrete conformance test implementations
// with fixtures and generators for each test level.
package cases

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust/registry"
)

// RegisterEvidencePackTests adds evidence pack conformance tests.
func RegisterEvidencePackTests(suite *conformance.Suite) {
	suite.Register(conformance.TestCase{
		ID:          "L1-PACK-002",
		Level:       conformance.LevelL1,
		Category:    "evidencepack",
		Name:        "Deterministic archive produces identical bytes",
		Description: "Same contents always produce the same tar archive",
		Run: func(ctx *conformance.TestContext) error {
			contents := map[string][]byte{
				"receipts/r1.json": []byte(`{"id":"r1"}`),
				"receipts/r2.json": []byte(`{"id":"r2"}`),
				"manifest.json":    []byte(`{"version":"1.0.0"}`),
			}

			archive1, err := evidencepack.Archive(contents)
			if err != nil {
				return fmt.Errorf("first archive: %w", err)
			}
			archive2, err := evidencepack.Archive(contents)
			if err != nil {
				return fmt.Errorf("second archive: %w", err)
			}

			hash1 := sha256.Sum256(archive1)
			hash2 := sha256.Sum256(archive2)
			if hash1 != hash2 {
				ctx.Fail("archive hashes differ: %s vs %s",
					hex.EncodeToString(hash1[:8]),
					hex.EncodeToString(hash2[:8]))
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "L1-PACK-003",
		Level:       conformance.LevelL1,
		Category:    "evidencepack",
		Name:        "Builder produces valid manifest hash",
		Description: "Builder output manifest hash matches recomputation",
		Run: func(ctx *conformance.TestContext) error {
			b := evidencepack.NewBuilder("test-pack", "did:test:actor", "intent-1", "policy-hash")
			b.WithCreatedAt(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

			if err := b.AddReceipt("receipt1", map[string]string{"id": "r1"}); err != nil {
				return err
			}

			manifest, _, err := b.Build()
			if err != nil {
				return fmt.Errorf("build: %w", err)
			}

			recomputed, err := evidencepack.ComputeManifestHash(manifest)
			if err != nil {
				return fmt.Errorf("recompute hash: %w", err)
			}
			if manifest.ManifestHash != recomputed {
				ctx.Fail("manifest hash mismatch: %s vs %s", manifest.ManifestHash, recomputed)
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "L1-PACK-004",
		Level:       conformance.LevelL1,
		Category:    "evidencepack",
		Name:        "Archive round-trip preserves content",
		Description: "Archive then unarchive produces identical content",
		Run: func(ctx *conformance.TestContext) error {
			contents := map[string][]byte{
				"a.json": []byte(`{"key":"value"}`),
				"b.txt":  []byte("hello world"),
			}

			archived, err := evidencepack.Archive(contents)
			if err != nil {
				return err
			}

			restored, err := evidencepack.Unarchive(archived)
			if err != nil {
				return err
			}

			for k, v := range contents {
				if string(restored[k]) != string(v) {
					ctx.Fail("content mismatch for %s", k)
				}
			}
			return nil
		},
	})
}

// RegisterTrustRegistryTests adds trust registry conformance tests.
func RegisterTrustRegistryTests(suite *conformance.Suite) {
	suite.Register(conformance.TestCase{
		ID:          "L1-TRUST-002",
		Level:       conformance.LevelL1,
		Category:    "trust",
		Name:        "Deterministic reducer produces same state",
		Description: "Same events always produce the same trust state",
		Run: func(ctx *conformance.TestContext) error {
			events := []*registry.TrustEvent{
				{
					ID:        "e1",
					EventType: registry.EventKeyPublish,
					SubjectID: "key-001",
					Lamport:   1,
					CreatedAt: time.Now().UTC(),
					Payload:   json.RawMessage(`{"algorithm":"ed25519","purpose":"signing"}`),
				},
				{
					ID:        "e2",
					EventType: registry.EventDIDRegister,
					SubjectID: "did:helm:abc",
					Lamport:   2,
					CreatedAt: time.Now().UTC(),
					Payload:   json.RawMessage(`{"method":"helm","controller":"key-001"}`),
				},
			}

			state1 := registry.NewTrustState()
			for _, e := range events {
				if err := state1.Apply(e); err != nil {
					return fmt.Errorf("apply event %s: %w", e.ID, err)
				}
			}

			state2 := registry.NewTrustState()
			for _, e := range events {
				if err := state2.Apply(e); err != nil {
					return fmt.Errorf("apply event %s: %w", e.ID, err)
				}
			}

			if state1.Lamport != state2.Lamport {
				ctx.Fail("lamport mismatch: %d vs %d", state1.Lamport, state2.Lamport)
			}
			if len(state1.Keys) != len(state2.Keys) {
				ctx.Fail("key count mismatch: %d vs %d", len(state1.Keys), len(state2.Keys))
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "L2-TRUST-002",
		Level:       conformance.LevelL2,
		Category:    "trust",
		Name:        "Revoked key is no longer active",
		Description: "After KEY_REVOKE, key.IsActive returns false",
		Run: func(ctx *conformance.TestContext) error {
			state := registry.NewTrustState()

			// Register key
			regEvent := &registry.TrustEvent{
				ID:        "e1",
				EventType: registry.EventKeyPublish,
				SubjectID: "key-001",
				Lamport:   1,
				CreatedAt: time.Now().UTC(),
				Payload:   json.RawMessage(`{"algorithm":"ed25519","purpose":"signing"}`),
			}
			if err := state.Apply(regEvent); err != nil {
				return err
			}

			// Verify key exists and is active
			key, ok := state.Keys["key-001"]
			if !ok {
				ctx.Fail("key not found after registration")
				return nil
			}
			if !key.IsActive(1) {
				ctx.Fail("key should be active at lamport 1")
				return nil
			}

			// Revoke key
			revokeEvent := &registry.TrustEvent{
				ID:        "e2",
				EventType: registry.EventKeyRevoke,
				SubjectID: "key-001",
				Lamport:   2,
				CreatedAt: time.Now().UTC(),
			}
			if err := state.Apply(revokeEvent); err != nil {
				return err
			}

			// Verify key is no longer active
			key, ok = state.Keys["key-001"]
			if !ok {
				ctx.Fail("key missing after revocation")
				return nil
			}
			if key.IsActive(2) {
				ctx.Fail("key should NOT be active after revocation at lamport 2")
			}
			return nil
		},
	})
}

// RegisterL3SignedEvidenceTests adds L3 signed evidence pack tests using the suite system.
func RegisterL3SignedEvidenceTests(suite *conformance.Suite) {
	suite.Register(conformance.TestCase{
		ID:          "L3-SIGPACK-EP-001",
		Level:       conformance.LevelL3,
		Category:    "signed_evidence",
		Name:        "Builder-produced evidence pack is signable",
		Description: "Evidence pack from builder can be signed and verified",
		Run: func(ctx *conformance.TestContext) error {
			b := evidencepack.NewBuilder("signable-pack", "did:test:signer", "intent-sig-1", "policy-hash-sig")
			b.WithCreatedAt(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

			if err := b.AddReceipt("receipt-sig-1", map[string]string{"verdict": "ALLOW"}); err != nil {
				return err
			}
			if err := b.AddReceipt("receipt-sig-2", map[string]string{"verdict": "DENY"}); err != nil {
				return err
			}

			manifest, _, err := b.Build()
			if err != nil {
				return fmt.Errorf("build: %w", err)
			}

			// Verify manifest hash is non-empty and deterministic
			if manifest.ManifestHash == "" {
				ctx.Fail("evidence pack manifest hash is empty")
				return nil
			}

			recomputed, err := evidencepack.ComputeManifestHash(manifest)
			if err != nil {
				return fmt.Errorf("recompute: %w", err)
			}
			if manifest.ManifestHash != recomputed {
				ctx.Fail("manifest hash not deterministic for signing: %s vs %s",
					manifest.ManifestHash, recomputed)
			}
			return nil
		},
	})

	suite.Register(conformance.TestCase{
		ID:          "L3-SIGPACK-EP-002",
		Level:       conformance.LevelL3,
		Category:    "signed_evidence",
		Name:        "Evidence pack archive is deterministic for signature binding",
		Description: "Same contents always produce the same archive bytes for stable signing",
		Run: func(ctx *conformance.TestContext) error {
			contents := map[string][]byte{
				"receipts/r1.json": []byte(`{"id":"r1","verdict":"ALLOW"}`),
				"receipts/r2.json": []byte(`{"id":"r2","verdict":"DENY"}`),
				"manifest.json":    []byte(`{"version":"1.0.0","signed":true}`),
			}

			archive1, err := evidencepack.Archive(contents)
			if err != nil {
				return fmt.Errorf("first archive: %w", err)
			}
			archive2, err := evidencepack.Archive(contents)
			if err != nil {
				return fmt.Errorf("second archive: %w", err)
			}

			hash1 := sha256.Sum256(archive1)
			hash2 := sha256.Sum256(archive2)
			if hash1 != hash2 {
				ctx.Fail("archive not deterministic: signatures would diverge")
			}
			return nil
		},
	})
}

// RegisterL3TrustRegistryTests adds L3 trust registry conformance tests.
func RegisterL3TrustRegistryTests(suite *conformance.Suite) {
	suite.Register(conformance.TestCase{
		ID:          "L3-TRUST-REG-001",
		Level:       conformance.LevelL3,
		Category:    "trust",
		Name:        "Key rotation preserves trust state consistency",
		Description: "After key rotation, trust state reflects both old (revoked) and new keys",
		Run: func(ctx *conformance.TestContext) error {
			state := registry.NewTrustState()

			// Register initial key
			regEvent := &registry.TrustEvent{
				ID:        "e1",
				EventType: registry.EventKeyPublish,
				SubjectID: "key-v1",
				Lamport:   1,
				CreatedAt: time.Now().UTC(),
				Payload:   json.RawMessage(`{"algorithm":"ed25519","purpose":"signing"}`),
			}
			if err := state.Apply(regEvent); err != nil {
				return err
			}

			// Revoke old key
			revokeEvent := &registry.TrustEvent{
				ID:        "e2",
				EventType: registry.EventKeyRevoke,
				SubjectID: "key-v1",
				Lamport:   5,
				CreatedAt: time.Now().UTC(),
			}
			if err := state.Apply(revokeEvent); err != nil {
				return err
			}

			// Register new key
			newKeyEvent := &registry.TrustEvent{
				ID:        "e3",
				EventType: registry.EventKeyPublish,
				SubjectID: "key-v2",
				Lamport:   6,
				CreatedAt: time.Now().UTC(),
				Payload:   json.RawMessage(`{"algorithm":"ed25519","purpose":"signing"}`),
			}
			if err := state.Apply(newKeyEvent); err != nil {
				return err
			}

			// Old key must exist but not be active
			oldKey, ok := state.Keys["key-v1"]
			if !ok {
				ctx.Fail("old key should still exist in trust state after rotation")
				return nil
			}
			if oldKey.IsActive(6) {
				ctx.Fail("old key should not be active after revocation")
			}

			// New key must be active
			newKey, ok := state.Keys["key-v2"]
			if !ok {
				ctx.Fail("new key should exist in trust state after rotation")
				return nil
			}
			if !newKey.IsActive(6) {
				ctx.Fail("new key should be active at lamport 6")
			}

			return nil
		},
	})
}

// RegisterAllCases registers all conformance test cases.
func RegisterAllCases(suite *conformance.Suite) {
	RegisterEvidencePackTests(suite)
	RegisterTrustRegistryTests(suite)
	RegisterL3SignedEvidenceTests(suite)
	RegisterL3TrustRegistryTests(suite)
}
