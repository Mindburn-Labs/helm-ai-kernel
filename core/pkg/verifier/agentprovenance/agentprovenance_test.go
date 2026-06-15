package agentprovenance

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

func TestVerifyPackValidCryptoConformantAdvisory(t *testing.T) {
	dir, trusted := writeTestPack(t, false)
	report, err := VerifyPack(dir, trusted, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified || report.Classification != ClassCryptoConformantAdvisory {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Classification == "helm_native" || report.Classification == "helm_native_receipt" {
		t.Fatal("agent provenance must never classify as HELM native")
	}
}

func TestVerifyPackTamperedObjectFailsHash(t *testing.T) {
	dir, trusted := writeTestPack(t, false)
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(m.Objects[0].Path)), []byte(`{"tampered":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyPack(dir, trusted, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != ClassUnverified || report.HashesValid {
		t.Fatalf("tampered object should fail hashes: %#v", report)
	}
}

func TestVerifyPackWithoutTrustedKeyIsHashConformantOnly(t *testing.T) {
	dir, _ := writeTestPack(t, false)
	report, err := VerifyPack(dir, nil, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != ClassHashConformant || report.SignatureValid {
		t.Fatalf("expected hash_conformant without trusted key: %#v", report)
	}
}

func TestVerifyPackHELMBindingIsStillAdvisory(t *testing.T) {
	dir, trusted := writeTestPack(t, true)
	report, err := VerifyPack(dir, trusted, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != ClassHELMBoundAdvisory || !report.HELMBound {
		t.Fatalf("expected helm_bound_advisory: %#v", report)
	}
}

func TestVerifyPackRedactionFailureFailsClosed(t *testing.T) {
	dir, trusted := writeTestPack(t, false)
	manifestRaw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var m manifest
	_ = json.Unmarshal(manifestRaw, &m)
	raw := mustJCS(t, map[string]any{"version": "redaction_report.v1", "status": "redaction_failed", "profile": "hash_only"})
	redactionHash := hashBytes(raw)
	redactionPath := filepath.Join(dir, "objects", redactionHash[:2], redactionHash)
	if err := os.MkdirAll(filepath.Dir(redactionPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(redactionPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	m.RedactionReport = manifestObject{Kind: "redaction_report", Path: filepath.ToSlash(filepath.Join("objects", redactionHash[:2], redactionHash)), Hash: redactionHash, Size: int64(len(raw))}
	rootHash, err := manifestRootHash(m.Objects, m.RedactionReport, m.AgentRunReceipt)
	if err != nil {
		t.Fatal(err)
	}
	resignManifest(t, dir, &m, rootHash)
	report, err := VerifyPack(dir, trusted, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.RedactionValid || report.Classification != ClassHashConformant {
		t.Fatalf("redaction failure should prevent crypto advisory classification: %#v", report)
	}
}

func writeTestPack(t *testing.T, helmBound bool) (string, TrustedKeySet) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("k", 128)))
	if err != nil {
		t.Fatal(err)
	}
	writeObject := func(kind string, value any) manifestObject {
		raw := mustJCS(t, value)
		hash := hashBytes(raw)
		path := filepath.Join(dir, "objects", hash[:2], hash)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return manifestObject{Kind: kind, Path: filepath.ToSlash(filepath.Join("objects", hash[:2], hash)), Hash: hash, Size: int64(len(raw))}
	}
	sessionObj := writeObject("agent_session", map[string]any{
		"version": "agent_session.v1", "origin": "codex", "external_session_id": "s1",
		"canonical_session_id": "codex-s1", "repo_target": "repo", "workspace_path": "/tmp/repo",
		"capture_profile": "hash_only", "started_at": "2026-06-15T00:00:00Z", "last_seen_at": "2026-06-15T00:00:01Z",
	})
	turnObj := writeObject("agent_turn", map[string]any{
		"version": "agent_turn.v1", "session_id": "codex-s1", "turn_id": "t1", "turn_hash": strings.Repeat("a", 64),
		"prompt_hash": strings.Repeat("b", 64), "tool_action_refs": []any{}, "file_effect_refs": []any{},
		"validation_refs": []any{}, "commit_binding_refs": []any{}, "capture_status": "captured", "created_at": "2026-06-15T00:00:00Z",
	})
	redactionObj := writeObject("redaction_report", map[string]any{"version": "redaction_report.v1", "status": "ok", "profile": "hash_only"})
	objects := []manifestObject{sessionObj, turnObj}
	contentRoot, err := manifestRootHash(objects, redactionObj, nil)
	if err != nil {
		t.Fatal(err)
	}
	refs := []any{"agent-provenance://" + contentRoot}
	if helmBound {
		refs = append(refs, "evidence-pack://pack-123")
	}
	receipt := map[string]any{
		"receipt_version": "agent_run_receipt.v1", "receipt_id": "r1", "run_id": "run1", "goal": "test",
		"actor":         map[string]any{"actor_id": "mb-agent", "actor_type": "agent"},
		"workspace":     map[string]any{"workspace_id": "local"},
		"agent_surface": "codex", "policy_profile": "agent-provenance-advisory",
		"artifact_hashes": map[string]any{"agent_provenance_root": contentRoot},
		"tool_actions":    []any{}, "changed_files": []any{}, "validation_results": []any{},
		"memory_effects": []any{}, "recurring_loop_effects": []any{}, "denied_effects": []any{},
		"proofgraph_refs": []any{}, "evidence_pack_refs": refs,
		"provenance_pack_ref": "agent-provenance://" + contentRoot, "provenance_root_hash": contentRoot,
		"capture_profile": "hash_only", "turn_count": 1, "created_at": "2026-06-15T00:00:00Z",
		"receipt_hash": "", "signature": "", "signer_key_id": "test-key",
	}
	unsigned := mustJCS(t, receipt)
	receipt["receipt_hash"] = hashBytes(unsigned)
	receipt["signature"] = hex.EncodeToString(ed25519.Sign(priv, unsigned))
	receiptObj := writeObject("agent_run_receipt", receipt)
	rootHash, err := manifestRootHash(objects, redactionObj, &receiptObj)
	if err != nil {
		t.Fatal(err)
	}
	m := manifest{
		Version: "agent_provenance_pack.v1", PackID: "pack-" + rootHash[:16], RootHash: rootHash,
		CaptureProfile: "hash_only", CreatedAt: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC),
		ObjectHashAlg: "sha256", CanonicalJSON: "jcs-rfc8785", Objects: objects,
		RedactionReport: redactionObj, AgentRunReceipt: &receiptObj,
		Signing:     signingMetadata{SignerKeyID: "test-key", PublicKeyHex: hex.EncodeToString(pub), SignedAt: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)},
		Limitations: []string{"agent authoring provenance; advisory unless bound to HELM verdict receipts"},
	}
	resignManifest(t, dir, &m, rootHash)
	return dir, TrustedKeySet{"test-key": pub}
}

func resignManifest(t *testing.T, dir string, m *manifest, rootHash string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("k", 128)))
	if err != nil {
		t.Fatal(err)
	}
	m.RootHash = rootHash
	m.PackID = "pack-" + rootHash[:16]
	payload := mustJCS(t, map[string]any{"pack_id": m.PackID, "root_hash": m.RootHash, "version": PackVersion, "capture_profile": m.CaptureProfile})
	m.Signing.SignatureHex = hex.EncodeToString(ed25519.Sign(priv, payload))
	raw := mustJCS(t, m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustJCS(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicalize.JCS(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
