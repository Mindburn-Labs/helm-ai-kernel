package crypto

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestShardedCacheEvictsBoundedShard(t *testing.T) {
	cache := NewShardedCache()
	for i := 0; i < maxEntriesPerShard; i++ {
		var key [32]byte
		key[0] = 0
		key[1] = byte(i >> 8)
		key[2] = byte(i)
		cache.Store(key, true)
	}
	var extra [32]byte
	extra[0] = 0
	extra[1] = 0xff
	extra[2] = 0xff
	cache.Store(extra, false)
	if len(cache.shards[0].items) > maxEntriesPerShard {
		t.Fatalf("shard exceeded max entries: %d", len(cache.shards[0].items))
	}
	if got, ok := cache.Lookup(extra); !ok || got {
		t.Fatalf("extra cache entry = %v/%v, want false/true", got, ok)
	}
}

func TestAuditLogErrorAndMalformedEntryBranches(t *testing.T) {
	if _, err := NewFileAuditLog(filepath.Join(t.TempDir(), "missing", "audit.jsonl")); err == nil {
		t.Fatal("audit log in missing parent directory should fail")
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewFileAuditLog(path)
	if err != nil {
		t.Fatalf("NewFileAuditLog: %v", err)
	}
	if err := log.Append("actor", "bad-payload", map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("file audit log should reject non-canonical payload")
	}

	log.filePath = t.TempDir()
	if err := log.Append("actor", "directory-target", map[string]string{"ok": "true"}); err == nil {
		t.Fatal("file audit append to directory path should fail")
	}

	missingLog := &FileAuditLog{filePath: filepath.Join(t.TempDir(), "missing.jsonl")}
	if entries := missingLog.Entries(); len(entries) != 0 {
		t.Fatalf("missing audit log entries = %#v", entries)
	}

	malformedPath := filepath.Join(t.TempDir(), "malformed.jsonl")
	if err := os.WriteFile(malformedPath, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformedLog := &FileAuditLog{filePath: malformedPath}
	if entries := malformedLog.Entries(); len(entries) != 0 {
		t.Fatalf("malformed audit log should skip bad entries, got %#v", entries)
	}

	memoryLog := NewMemoryAuditLog()
	if err := memoryLog.Append("actor", "bad-payload", map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("memory audit log should reject non-canonical payload")
	}
}

func TestVerifierKeyringAndHasherErrorBranches(t *testing.T) {
	if _, err := CanonicalMarshal(map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("CanonicalMarshal should fail on non-canonical input")
	}
	if _, err := NewCanonicalHasher().Hash(map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("CanonicalHasher should fail on non-canonical input")
	}

	signer, err := NewEd25519Signer("kid")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	if _, err := Verify("not-hex", "00", []byte("payload")); err == nil || !strings.Contains(err.Error(), "invalid public key hex") {
		t.Fatalf("invalid public key hex error = %v", err)
	}
	if _, err := Verify(hex.EncodeToString([]byte("short")), "00", []byte("payload")); err == nil || !strings.Contains(err.Error(), "invalid public key size") {
		t.Fatalf("invalid public key size error = %v", err)
	}
	if _, err := Verify(signer.PublicKey(), "not-hex", []byte("payload")); err == nil || !strings.Contains(err.Error(), "invalid signature hex") {
		t.Fatalf("invalid signature hex error = %v", err)
	}

	verifier, err := NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}
	if _, err := verifier.VerifyDecision(&contracts.DecisionRecord{}); err == nil {
		t.Fatal("verifier decision without signature should fail")
	}
	if _, err := verifier.VerifyDecision(&contracts.DecisionRecord{Signature: "not-hex"}); err == nil {
		t.Fatal("verifier decision with bad signature hex should fail")
	}
	if _, err := verifier.VerifyIntent(&contracts.AuthorizedExecutionIntent{}); err == nil {
		t.Fatal("verifier intent without signature should fail")
	}
	if _, err := verifier.VerifyIntent(&contracts.AuthorizedExecutionIntent{Signature: "not-hex"}); err == nil {
		t.Fatal("verifier intent with bad signature hex should fail")
	}
	if _, err := verifier.VerifyReceipt(&contracts.Receipt{}); err == nil {
		t.Fatal("verifier receipt without signature should fail")
	}
	if _, err := verifier.VerifyReceipt(&contracts.Receipt{Signature: "not-hex"}); err == nil {
		t.Fatal("verifier receipt with bad signature hex should fail")
	}

	intent := &contracts.AuthorizedExecutionIntent{ID: "intent", DecisionID: "decision", AllowedTool: "tool"}
	if err := signer.SignIntent(intent); err != nil {
		t.Fatalf("SignIntent: %v", err)
	}
	intent.SignatureType = SigPrefixEd25519 + SigSeparator + "missing"
	keyring := NewKeyRing()
	keyring.AddKey(signer)
	if _, err := keyring.VerifyIntent(intent); err == nil || !strings.Contains(err.Error(), "unknown or revoked key") {
		t.Fatalf("keyring unknown intent key error = %v", err)
	}

	intent.SignatureType = "malformed"
	emptyKeyring := NewKeyRing()
	if _, err := emptyKeyring.VerifyIntent(intent); err == nil || !strings.Contains(err.Error(), "no key verified") {
		t.Fatalf("empty keyring fallback error = %v", err)
	}
	if verified := emptyKeyring.Verify([]byte("payload"), []byte("sig")); verified {
		t.Fatal("empty keyring raw verify should fail")
	}
	if _, err := emptyKeyring.VerifyReceipt(&contracts.Receipt{Signature: intent.Signature}); err == nil || !strings.Contains(err.Error(), "no key verified") {
		t.Fatalf("empty keyring receipt error = %v", err)
	}
}
