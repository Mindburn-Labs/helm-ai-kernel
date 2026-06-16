package adapters

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

// agtChainFile is the top-level structure of an AGT receipt export.
type agtChainFile struct {
	Receipts []agtReceipt `json:"receipts"`
}

// agtReceipt mirrors the AGT GovernanceReceipt dataclass.
type agtReceipt struct {
	ReceiptID         string  `json:"receipt_id"`
	ToolName          string  `json:"tool_name"`
	AgentDID          string  `json:"agent_did"`
	CedarPolicyID     string  `json:"cedar_policy_id"`
	CedarDecision     string  `json:"cedar_decision"`
	ArgsHash          string  `json:"args_hash"`
	Timestamp         float64 `json:"timestamp"`
	SessionID         *string `json:"session_id"`
	ParentReceiptHash *string `json:"parent_receipt_hash"`
	PayloadHash       string  `json:"payload_hash"`
	Signature         string  `json:"signature"`
	SignerPublicKey   string  `json:"signer_public_key"`
	Error             *string `json:"error"`
}

// agtCanonicalPayload reproduces AGT's canonical_payload() method in Go.
// Python: json.dumps({...fields...}, sort_keys=True, separators=(",",":")).
// Signed fields: agent_did, args_hash, cedar_decision, cedar_policy_id,
//
//	receipt_id, timestamp, tool_name — and optionally parent_receipt_hash,
//	session_id when non-nil.
func agtCanonicalPayload(r agtReceipt) ([]byte, error) {
	m := map[string]interface{}{
		"agent_did":       r.AgentDID,
		"args_hash":       r.ArgsHash,
		"cedar_decision":  r.CedarDecision,
		"cedar_policy_id": r.CedarPolicyID,
		"receipt_id":      r.ReceiptID,
		"timestamp":       r.Timestamp,
		"tool_name":       r.ToolName,
	}
	if r.ParentReceiptHash != nil {
		m["parent_receipt_hash"] = *r.ParentReceiptHash
	}
	if r.SessionID != nil {
		m["session_id"] = *r.SessionID
	}
	return agtSortedCompactJSON(m)
}

// agtSortedCompactJSON marshals a map to compact JSON with alphabetically sorted keys.
// Matches Python json.dumps(sort_keys=True, separators=(",",":")):
//   - string values → JSON strings
//   - float64 values → JSON numbers (Go marshals 1749988800.0 as 1.74998880e+09 unless
//     the value is within safe-integer range; we use json.Marshal which handles this)
//   - nil values → "null"
func agtSortedCompactJSON(m map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)

	buf := make([]byte, 0, 256)
	buf = append(buf, '{')
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf = append(buf, kb...)
		buf = append(buf, ':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return buf, nil
}

// sortStrings sorts a string slice in ascending order (insertion sort).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// AGTToExternalReceiptChain converts an AGT receipt-chain JSON export into a
// HELM ExternalReceiptChain. Each AGT GovernanceReceipt becomes one
// ExternalHostReceipt with EventKind=action_effect.
//
// The adapter performs a BINDING CHECK: after constructing ActionEvent, it
// re-parses the canonical payload bytes and asserts that tool_name, args_hash,
// and agent_did match what was put into ActionEvent. An error is returned on mismatch.
//
// AGT signing scope: Ed25519 over agtCanonicalPayload() bytes (Python sort_keys JSON).
// Public key format: hex (32 bytes = 64 hex chars).
// Signature format: hex (64 bytes = 128 hex chars).
// Hash chain: parent_receipt_hash = sha256hex(canonical_payload_of_previous_receipt).
func AGTToExternalReceiptChain(raw []byte) (*contracts.ExternalReceiptChain, error) {
	var file agtChainFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("agt: parse chain file: %w", err)
	}
	if len(file.Receipts) == 0 {
		return nil, fmt.Errorf("agt: chain file contains no receipts")
	}

	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		SourceVendor:  "microsoft-agt",
		SourceProfile: "agt-cedar-v1",
	}

	issuerPubKeyHex := strings.TrimSpace(file.Receipts[0].SignerPublicKey)
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "agt-issuer",
		Algorithm:    "Ed25519",
		PublicKeyHex: issuerPubKeyHex,
	}}

	var prevReceiptHash string
	receiptHashes := make([]string, 0, len(file.Receipts))

	for i, r := range file.Receipts {
		receipt, hash, err := agtReceiptToHELM(r, prevReceiptHash, i)
		if err != nil {
			return nil, fmt.Errorf("agt: receipt[%d] id=%s: %w", i, r.ReceiptID, err)
		}
		chain.Receipts = append(chain.Receipts, receipt)
		receiptHashes = append(receiptHashes, hash)
		prevReceiptHash = hash
	}

	chain.ReceiptChainHash = externalhost.ComputeChainHash(receiptHashes)
	return chain, nil
}

// agtReceiptToHELM converts one AGT GovernanceReceipt into an ExternalHostReceipt.
func agtReceiptToHELM(r agtReceipt, prevHelmReceiptHash string, idx int) (contracts.ExternalHostReceipt, string, error) {
	signedBytes, err := agtCanonicalPayload(r)
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("compute canonical payload: %w", err)
	}

	// Verify that the embedded payload_hash matches our reconstruction.
	computedPayloadHash := fmt.Sprintf("%x", sha256.Sum256(signedBytes))
	if r.PayloadHash != "" && r.PayloadHash != computedPayloadHash {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf(
			"payload_hash mismatch: embedded=%q computed=%q — signed payload reconstruction failed",
			r.PayloadHash, computedPayloadHash,
		)
	}

	// Decode signature (hex).
	sigBytes, err := hex.DecodeString(strings.TrimSpace(r.Signature))
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("decode signature hex: %w", err)
	}

	ts := time.Unix(int64(r.Timestamp), 0).UTC()

	actionEvent := &contracts.ActionEffectEvent{
		ActionID:   r.ReceiptID,
		ToolName:   r.ToolName,
		TargetRef:  r.AgentDID,
		ParamsHash: "sha256:" + r.ArgsHash,
		Decision:   r.CedarDecision,
		Timestamp:  ts,
	}

	// BINDING CHECK: parse signedBytes back and assert tool_name, args_hash,
	// and agent_did match those in ActionEvent.
	if err := agtBindingCheck(signedBytes, actionEvent, r.AgentDID, r.ArgsHash); err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("binding check failed: %w", err)
	}

	meta := map[string]string{
		"cedar_policy_id": r.CedarPolicyID,
		"cedar_decision":  r.CedarDecision,
		"agt_receipt_id":  r.ReceiptID,
	}
	if r.SessionID != nil {
		meta["session_id"] = *r.SessionID
	}
	if r.ParentReceiptHash != nil {
		meta["agt_parent_receipt_hash"] = *r.ParentReceiptHash
	}

	receipt := contracts.ExternalHostReceipt{
		SchemaVersion:      contracts.ExternalHostReceiptVersion,
		ReceiptID:          r.ReceiptID,
		HostID:             r.AgentDID,
		AgentID:            r.AgentDID,
		ProcessIdentity:    r.AgentDID,
		EventKind:          contracts.EventKindActionEffect,
		ActionEvent:        actionEvent,
		SignedPayloadB64:   base64.StdEncoding.EncodeToString(signedBytes),
		Signature:          hex.EncodeToString(sigBytes),
		SignatureAlgorithm: "Ed25519",
		PublicKeyRef:       r.SignerPublicKey,
		SourceVendor:       "microsoft-agt",
		SourceProfile:      "agt-cedar-v1",
		PrevReceiptHash:    prevHelmReceiptHash,
		VerifierProfile:    "cedar_policy_id=" + r.CedarPolicyID,
		Metadata:           meta,
	}

	hash, err := externalhost.ComputeReceiptHash(receipt)
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("compute receipt hash: %w", err)
	}
	receipt.ReceiptHash = hash

	return receipt, hash, nil
}

// agtBindingCheck parses the canonical payload JSON and asserts that tool_name,
// args_hash, and agent_did match those in ActionEvent / the adapter's local values.
func agtBindingCheck(signedBytes []byte, actionEvent *contracts.ActionEffectEvent, agentDID, argsHash string) error {
	var parsed map[string]interface{}
	if err := json.Unmarshal(signedBytes, &parsed); err != nil {
		return fmt.Errorf("parse signed payload: %w", err)
	}
	if v, ok := parsed["tool_name"].(string); !ok || v != actionEvent.ToolName {
		return fmt.Errorf("tool_name mismatch: signed=%q actionEvent=%q", parsed["tool_name"], actionEvent.ToolName)
	}
	if v, ok := parsed["args_hash"].(string); !ok || v != argsHash {
		return fmt.Errorf("args_hash mismatch: signed=%q adapter=%q", parsed["args_hash"], argsHash)
	}
	if v, ok := parsed["agent_did"].(string); !ok || v != agentDID {
		return fmt.Errorf("agent_did mismatch: signed=%q adapter=%q", parsed["agent_did"], agentDID)
	}
	return nil
}
