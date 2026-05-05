package contracts

import (
	"testing"
	"time"
)

func TestSandboxGrantSealBindsAuthority(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	grant := SandboxGrant{
		GrantID:        "grant-1",
		Runtime:        "wazero",
		RuntimeVersion: "1.9.0",
		Profile:        "deny-by-default",
		ImageDigest:    "sha256:image",
		FilesystemPreopens: []FilesystemPreopen{
			{Path: "/workspace", Mode: "ro", ContentHash: "sha256:workspace"},
		},
		Env: EnvExposurePolicy{Mode: "allowlist", Names: []string{"PATH"}},
		Network: NetworkGrant{
			Mode:  "allowlist",
			CIDRs: []string{"10.0.0.0/24"},
		},
		DeclaredAt:  now,
		PolicyEpoch: "epoch-42",
	}

	sealed, err := grant.Seal()
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}
	resealed, err := grant.Seal()
	if err != nil {
		t.Fatalf("reseal grant: %v", err)
	}
	if sealed.GrantHash == "" {
		t.Fatal("grant hash was not set")
	}
	if sealed.GrantHash != resealed.GrantHash {
		t.Fatalf("grant hash is not deterministic: %s != %s", sealed.GrantHash, resealed.GrantHash)
	}

	grant.Network.Mode = "deny-all"
	grant.Network.CIDRs = nil
	changed, err := grant.Seal()
	if err != nil {
		t.Fatalf("seal changed grant: %v", err)
	}
	if changed.GrantHash == sealed.GrantHash {
		t.Fatal("grant hash did not bind network authority")
	}
}

func TestSandboxGrantRejectsOverbroadNetwork(t *testing.T) {
	_, err := SandboxGrant{
		GrantID:    "grant-1",
		Runtime:    "wasmtime",
		Profile:    "native-code",
		Env:        EnvExposurePolicy{Mode: "deny-all"},
		Network:    NetworkGrant{Mode: "open"},
		DeclaredAt: time.Now().UTC(),
	}.Seal()
	if err == nil {
		t.Fatal("expected open network mode to be rejected")
	}
}

func TestAuthzSnapshotSealBindsRelationshipState(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	snapshot := AuthzSnapshot{
		SnapshotID:       "snap-1",
		Resolver:         "openfga-compatible",
		ModelID:          "model-a",
		RelationshipHash: "sha256:tuples-a",
		Subject:          "user:alice",
		Object:           "tool:deploy",
		Relation:         "can_call",
		Decision:         true,
		CheckedAt:        now,
	}
	sealed, err := snapshot.Seal()
	if err != nil {
		t.Fatalf("seal snapshot: %v", err)
	}
	snapshot.Stale = true
	stale, err := snapshot.Seal()
	if err != nil {
		t.Fatalf("seal stale snapshot: %v", err)
	}
	if sealed.SnapshotHash == stale.SnapshotHash {
		t.Fatal("snapshot hash did not bind stale state")
	}
}

func TestExecutionBoundaryRecordRequiresReasonForDeny(t *testing.T) {
	_, err := ExecutionBoundaryRecord{
		RecordID:    "ebr-1",
		Verdict:     VerdictDeny,
		PolicyEpoch: "epoch-42",
		CreatedAt:   time.Now().UTC(),
	}.Seal()
	if err == nil {
		t.Fatal("expected deny without reason code to fail")
	}
}

func TestExecutionBoundaryRecordBindsGrantAndSnapshotHashes(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	record := ExecutionBoundaryRecord{
		RecordID:          "ebr-1",
		Verdict:           VerdictDeny,
		ReasonCode:        ReasonPDPError,
		ToolName:          "deploy",
		ArgsHash:          "sha256:args",
		PolicyEpoch:       "epoch-42",
		SandboxGrantHash:  "sha256:grant-a",
		AuthzSnapshotHash: "sha256:snapshot-a",
		CreatedAt:         now,
	}
	sealed, err := record.Seal()
	if err != nil {
		t.Fatalf("seal record: %v", err)
	}
	record.SandboxGrantHash = "sha256:grant-b"
	changed, err := record.Seal()
	if err != nil {
		t.Fatalf("seal changed record: %v", err)
	}
	if sealed.RecordHash == changed.RecordHash {
		t.Fatal("record hash did not bind sandbox grant hash")
	}
}

func TestEvidenceEnvelopeManifestKeepsNativeAuthority(t *testing.T) {
	manifest := EvidenceEnvelopeManifest{
		ManifestID:         "env-1",
		Envelope:           "dsse",
		NativeEvidenceHash: "sha256:evidence",
		NativeAuthority:    true,
		CreatedAt:          time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC),
	}
	sealed, err := manifest.Seal()
	if err != nil {
		t.Fatalf("seal manifest: %v", err)
	}
	if sealed.ManifestHash == "" {
		t.Fatal("manifest hash was not set")
	}

	manifest.NativeAuthority = false
	if _, err := manifest.Seal(); err == nil {
		t.Fatal("expected non-native authority export to fail closed")
	}
}
