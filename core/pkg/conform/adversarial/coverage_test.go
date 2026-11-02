package adversarial

// quantum_posture: fixtures exercise deterministic classical Ed25519 keys and
// do not represent post-quantum assurance.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

func writeCoverageIndex(t *testing.T, dir string) {
	t.Helper()
	entries := make([]map[string]string, 0)
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "00_INDEX.json" || rel == evidence.EvidencePackSealPath {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		entries = append(entries, map[string]string{"path": rel, "sha256": hex.EncodeToString(digest[:])})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i]["path"] < entries[j]["path"] })
	data, err := json.MarshalIndent(map[string]any{"version": "1.0.0", "entries": entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func campaignTestKey() (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("helm-adversarial-campaign-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey, hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

const (
	testCampaignID    = "campaign:test-clean-room"
	testCampaignRunID = "run:test-001"
)

func writeTestMutationJSON(path string, value map[string]interface{}) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return false
	}
	return os.WriteFile(path, data, 0o600) == nil
}

func signCampaignDocument(t *testing.T, document map[string]any, field, domain string, privateKey ed25519.PrivateKey) map[string]any {
	t.Helper()
	payload := make(map[string]any, len(document))
	for key, value := range document {
		if key != field {
			payload[key] = value
		}
	}
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		t.Fatal(err)
	}
	signedMessage := []byte(domain)
	signedMessage = append(signedMessage, 0)
	signedMessage = append(signedMessage, canonical...)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	payload[field] = []any{map[string]any{
		"algorithm": "ed25519",
		"key_id":    "sha256:" + hex.EncodeToString(keyHash[:]),
		"signature": hex.EncodeToString(ed25519.Sign(privateKey, signedMessage)),
	}}
	return payload
}
