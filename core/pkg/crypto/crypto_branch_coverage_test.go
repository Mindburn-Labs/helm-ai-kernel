package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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
		t.Fatalf("malformed audit log should fail closed, got %#v", entries)
	}
	if _, err := malformedLog.VerifiedEntries(); err == nil || !strings.Contains(err.Error(), "malformed entry") {
		t.Fatalf("malformed audit log verification error = %v", err)
	}

	memoryLog := NewMemoryAuditLog()
	if err := memoryLog.Append("actor", "bad-payload", map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("memory audit log should reject non-canonical payload")
	}
}

func TestFileAuditLogEntriesReadsLargeJSONLRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-audit.jsonl")
	log, err := NewFileAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append("guardian", "DECISION_MADE", map[string]any{"blob": strings.Repeat("x", 70*1024)}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append("guardian", "FOLLOWUP", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}

	entries := log.Entries()
	if len(entries) != 2 {
		t.Fatalf("large JSONL entries = %d, want 2", len(entries))
	}
	if entries[0].Action != "DECISION_MADE" || entries[1].Action != "FOLLOWUP" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestFileAuditLogVerifiedEntriesRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, log *FileAuditLog, lines [][]byte)
	}{
		{
			name: "edited content",
			mutate: func(t *testing.T, log *FileAuditLog, lines [][]byte) {
				event := decodeAuditLine(t, lines[0])
				event.Action = "TAMPERED"
				lines[0] = encodeAuditLine(t, event)
				writeAuditLines(t, log.filePath, lines)
			},
		},
		{
			name: "recomputed row hash",
			mutate: func(t *testing.T, log *FileAuditLog, lines [][]byte) {
				event := decodeAuditLine(t, lines[0])
				event.Action = "TAMPERED"
				hash, err := hashAuditEvent(NewCanonicalHasher(), event)
				if err != nil {
					t.Fatal(err)
				}
				event.Hash = hash
				lines[0] = encodeAuditLine(t, event)
				writeAuditLines(t, log.filePath, lines)
			},
		},
		{
			name: "reordered entries",
			mutate: func(t *testing.T, log *FileAuditLog, lines [][]byte) {
				lines[0], lines[1] = lines[1], lines[0]
				writeAuditLines(t, log.filePath, lines)
			},
		},
		{
			name: "deleted tail",
			mutate: func(t *testing.T, log *FileAuditLog, lines [][]byte) {
				writeAuditLines(t, log.filePath, lines[:2])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, lines := seededFileAuditLog(t)
			tt.mutate(t, log, lines)

			if entries := log.Entries(); entries != nil {
				t.Fatalf("Entries() = %#v, want fail-closed nil", entries)
			}
			if _, err := log.VerifiedEntries(); err == nil {
				t.Fatal("VerifiedEntries() error = nil, want tamper rejection")
			}
		})
	}
}

func seededFileAuditLog(t *testing.T) (*FileAuditLog, [][]byte) {
	t.Helper()
	log, err := NewFileAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"FIRST", "SECOND", "THIRD"} {
		if err := log.Append("actor", action, map[string]any{"action": action}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(log.filePath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("seeded lines = %d, want 3", len(lines))
	}
	return log, lines
}

func decodeAuditLine(t *testing.T, line []byte) AuditEvent {
	t.Helper()
	var event AuditEvent
	if err := json.Unmarshal(line, &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func encodeAuditLine(t *testing.T, event AuditEvent) []byte {
	t.Helper()
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func writeAuditLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	data := bytes.Join(lines, []byte("\n"))
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
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

	intent := executableIntentFixture("intent", "decision", "sha256:effect-intent", "tool")
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
	if _, err := emptyKeyring.VerifyIntent(intent); err == nil || !strings.Contains(err.Error(), "invalid signature type format") {
		t.Fatalf("malformed intent signature type error = %v", err)
	}
	if verified := emptyKeyring.Verify([]byte("payload"), []byte("sig")); verified {
		t.Fatal("empty keyring raw verify should fail")
	}
	if _, err := emptyKeyring.VerifyReceipt(&contracts.Receipt{Signature: intent.Signature}); err == nil || !strings.Contains(err.Error(), "no key verified") {
		t.Fatalf("empty keyring receipt error = %v", err)
	}
}
