// Package conformance provides L3 test fixtures for adversarial resilience testing.
// These fixtures simulate HSM key operations, policy bundle signing, and proof
// condensation scenarios used by L3 conformance vectors.
package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// ── HSM Key Management Fixtures (G13) ────────────────────────

// hsmKey represents a hardware-backed signing key with ceremony lifecycle.
type hsmKey struct {
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	CreatedAt   time.Time `json:"created_at"`
	RevokedAt   uint64    `json:"revoked_at,omitempty"` // Lamport height of revocation
	RotatedToID string    `json:"rotated_to_id,omitempty"`
	Active      bool      `json:"active"`
}

// IsValidAt returns whether this key was active at the given lamport height.
func (k *hsmKey) IsValidAt(lamport uint64) bool {
	if !k.Active {
		return false
	}
	if k.RevokedAt > 0 && lamport >= k.RevokedAt {
		return false
	}
	return true
}

// hsmKeyring simulates a hardware security module with ceremony-based rotation.
type hsmKeyring struct {
	keys    map[string]*hsmKey
	current string // active key ID
}

func newHSMKeyring() *hsmKeyring {
	return &hsmKeyring{keys: make(map[string]*hsmKey)}
}

func (kr *hsmKeyring) register(key *hsmKey) {
	kr.keys[key.KeyID] = key
	if key.Active {
		kr.current = key.KeyID
	}
}

func (kr *hsmKeyring) currentKey() *hsmKey {
	return kr.keys[kr.current]
}

func (kr *hsmKeyring) rotateKey(oldID, newID string, rotationLamport uint64) error {
	old, ok := kr.keys[oldID]
	if !ok {
		return fmt.Errorf("key %s not found", oldID)
	}
	old.Active = false
	old.RevokedAt = rotationLamport
	old.RotatedToID = newID

	newKey := &hsmKey{
		KeyID:     newID,
		Algorithm: old.Algorithm,
		CreatedAt: time.Now().UTC(),
		Active:    true,
	}
	kr.keys[newID] = newKey
	kr.current = newID
	return nil
}

func (kr *hsmKeyring) revokeKey(keyID string, lamport uint64) error {
	key, ok := kr.keys[keyID]
	if !ok {
		return fmt.Errorf("key %s not found", keyID)
	}
	key.Active = false
	key.RevokedAt = lamport
	return nil
}

// signWithKey simulates HSM signing: returns a content hash bound to key ID.
func signWithKey(key *hsmKey, content []byte) string {
	h := sha256.New()
	h.Write([]byte("helm:hsm:sign:v1\x00"))
	h.Write([]byte(key.KeyID))
	h.Write([]byte("\x00"))
	h.Write(content)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// verifyKeySignature verifies that a signature was produced by the given key.
func verifyKeySignature(key *hsmKey, content []byte, signature string) bool {
	expected := signWithKey(key, content)
	return signature == expected
}

// sampleHSMKeyring returns a keyring with 2 keys: one active, one rotated.
func sampleHSMKeyring() *hsmKeyring {
	kr := newHSMKeyring()
	kr.register(&hsmKey{
		KeyID:       "hsm-key-001",
		Algorithm:   "ed25519",
		CreatedAt:   time.Now().Add(-48 * time.Hour),
		RevokedAt:   10,
		RotatedToID: "hsm-key-002",
		Active:      false,
	})
	kr.register(&hsmKey{
		KeyID:     "hsm-key-002",
		Algorithm: "ed25519",
		CreatedAt: time.Now().Add(-1 * time.Hour),
		Active:    true,
	})
	return kr
}

// ── Policy Bundle Integrity Fixtures (G14) ───────────────────

// policyBundle represents a signed, content-addressed policy bundle.
type policyBundle struct {
	BundleID    string       `json:"bundle_id"`
	Version     int          `json:"version"`
	Epoch       uint64       `json:"epoch"` // Deployment epoch
	Rules       []policyRule `json:"rules"`
	ContentHash string       `json:"content_hash"`
	Signature   string       `json:"signature"`
	SignerKeyID string       `json:"signer_key_id"`
	Provenance  bundleProvenance `json:"provenance"`
}

type policyRule struct {
	RuleID    string `json:"rule_id"`
	Effect    string `json:"effect"` // "ALLOW" or "DENY"
	Condition string `json:"condition"`
}

type bundleProvenance struct {
	CompileHash string `json:"compile_hash"`
	SignHash    string `json:"sign_hash"`
	DeployHash  string `json:"deploy_hash"`
}

// computeBundleHash computes the content-addressed hash of a bundle's rules.
func computeBundleHash(rules []policyRule) string {
	// Sort rules by ID for deterministic hashing
	sorted := make([]policyRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RuleID < sorted[j].RuleID
	})
	data, _ := json.Marshal(sorted)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// signBundle signs a bundle with an HSM key.
func signBundle(bundle *policyBundle, key *hsmKey) {
	bundle.ContentHash = computeBundleHash(bundle.Rules)
	bundle.Signature = signWithKey(key, []byte(bundle.ContentHash))
	bundle.SignerKeyID = key.KeyID
}

// verifyBundle checks bundle integrity: hash match + signature validity.
func verifyBundle(bundle *policyBundle, key *hsmKey) (bool, string) {
	// 1. Verify content hash matches rules
	expectedHash := computeBundleHash(bundle.Rules)
	if bundle.ContentHash != expectedHash {
		return false, "content_hash_mismatch"
	}
	// 2. Verify signature
	if !verifyKeySignature(key, []byte(bundle.ContentHash), bundle.Signature) {
		return false, "signature_invalid"
	}
	return true, ""
}

// samplePolicyBundle returns a valid, signed policy bundle.
func samplePolicyBundle(key *hsmKey) *policyBundle {
	bundle := &policyBundle{
		BundleID: "bundle-001",
		Version:  1,
		Epoch:    1,
		Rules: []policyRule{
			{RuleID: "rule-001", Effect: "ALLOW", Condition: "effect.class == 'E0'"},
			{RuleID: "rule-002", Effect: "DENY", Condition: "effect.class == 'E4'"},
			{RuleID: "rule-003", Effect: "ALLOW", Condition: "budget.remaining > 0"},
		},
		Provenance: bundleProvenance{
			CompileHash: "sha256:compile_abc",
			SignHash:    "sha256:sign_def",
			DeployHash:  "sha256:deploy_ghi",
		},
	}
	signBundle(bundle, key)
	return bundle
}

// ── Proof Condensation Fixtures (G15) ────────────────────────

// condensationCheckpoint represents a Merkle checkpoint over a receipt window.
type condensationCheckpoint struct {
	CheckpointID string   `json:"checkpoint_id"`
	MerkleRoot   string   `json:"merkle_root"`
	StartLamport uint64   `json:"start_lamport"`
	EndLamport   uint64   `json:"end_lamport"`
	ReceiptCount int      `json:"receipt_count"`
	LeafHashes   []string `json:"leaf_hashes"`
	PrevCheckpointID string `json:"prev_checkpoint_id,omitempty"`
}

// condensableReceipt is a receipt with risk tier for condensation routing.
type condensableReceipt struct {
	Hash     string `json:"hash"`
	Lamport  uint64 `json:"lamport"`
	RiskTier string `json:"risk_tier"` // "T1" (low), "T2" (medium), "T3+" (high)
}

// buildCheckpoint creates a Merkle checkpoint from a window of receipts.
func buildCheckpoint(id string, receipts []condensableReceipt, prevCheckpointID string) *condensationCheckpoint {
	if len(receipts) == 0 {
		return nil
	}

	leafHashes := make([]string, len(receipts))
	for i, r := range receipts {
		leafHashes[i] = r.Hash
	}

	merkleRoot := computeMerkleRoot(leafHashes)

	return &condensationCheckpoint{
		CheckpointID:     id,
		MerkleRoot:       merkleRoot,
		StartLamport:     receipts[0].Lamport,
		EndLamport:       receipts[len(receipts)-1].Lamport,
		ReceiptCount:     len(receipts),
		LeafHashes:       leafHashes,
		PrevCheckpointID: prevCheckpointID,
	}
}

// computeMerkleRoot builds a Merkle tree root from leaf hashes.
func computeMerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	current := make([]string, len(leaves))
	copy(current, leaves)

	for len(current) > 1 {
		if len(current)%2 != 0 {
			current = append(current, current[len(current)-1])
		}
		next := make([]string, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			h := sha256.New()
			h.Write([]byte("helm:condense:node:v1\x00"))
			h.Write([]byte(current[i]))
			h.Write([]byte(current[i+1]))
			next[i/2] = "sha256:" + hex.EncodeToString(h.Sum(nil))
		}
		current = next
	}
	return current[0]
}

// verifyInclusionProof checks that a receipt hash is included in a checkpoint.
func verifyInclusionProof(checkpoint *condensationCheckpoint, receiptHash string) bool {
	for _, leaf := range checkpoint.LeafHashes {
		if leaf == receiptHash {
			return true
		}
	}
	return false
}

// sampleCondensableReceipts returns a window of receipts with mixed risk tiers.
func sampleCondensableReceipts(count int) []condensableReceipt {
	receipts := make([]condensableReceipt, count)
	for i := 0; i < count; i++ {
		tier := "T1"
		if i%5 == 0 {
			tier = "T3+"
		} else if i%3 == 0 {
			tier = "T2"
		}
		data := fmt.Sprintf("receipt-condense-%d", i)
		h := sha256.Sum256([]byte(data))
		receipts[i] = condensableReceipt{
			Hash:     "sha256:" + hex.EncodeToString(h[:]),
			Lamport:  uint64(i + 1),
			RiskTier: tier,
		}
	}
	return receipts
}
