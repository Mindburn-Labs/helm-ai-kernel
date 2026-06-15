// Package adapters converts vendor-specific receipt formats into HELM
// ExternalReceiptChain for import into EvidencePacks.
package adapters

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

// signetAuditFile is the top-level structure of a Signet audit export.
type signetAuditFile struct {
	AuditRecords []signetAuditRecord `json:"audit_records"`
}

// signetAuditRecord wraps one Signet receipt with hash-chain fields.
type signetAuditRecord struct {
	PrevHash   string        `json:"prev_hash"`
	Receipt    signetReceipt `json:"receipt"`
	RecordHash string        `json:"record_hash"`
}

// signetReceipt is the Signet v1/v4 signed receipt (Rust struct Receipt).
type signetReceipt struct {
	V      int           `json:"v"`
	ID     string        `json:"id"`
	Action signetAction  `json:"action"`
	Signer signetSigner  `json:"signer"`
	Policy *signetPolicy `json:"policy,omitempty"`
	Ts     string        `json:"ts"`
	Nonce  string        `json:"nonce"`
	Sig    string        `json:"sig"`
}

// signetAction mirrors Signet's Action struct.
type signetAction struct {
	Tool            string          `json:"tool"`
	Params          json.RawMessage `json:"params,omitempty"`
	ParamsHash      string          `json:"params_hash,omitempty"`
	Target          string          `json:"target,omitempty"`
	Transport       string          `json:"transport,omitempty"`
	Session         string          `json:"session,omitempty"`
	CallID          string          `json:"call_id,omitempty"`
	ResponseHash    string          `json:"response_hash,omitempty"`
	TraceID         string          `json:"trace_id,omitempty"`
	ParentReceiptID string          `json:"parent_receipt_id,omitempty"`
}

// signetSigner mirrors Signet's Signer struct.
type signetSigner struct {
	Pubkey string `json:"pubkey"`
	Name   string `json:"name"`
	Owner  string `json:"owner"`
}

// signetPolicy mirrors Signet's PolicyAttestation struct.
type signetPolicy struct {
	PolicyHash   string   `json:"policy_hash"`
	PolicyName   string   `json:"policy_name"`
	MatchedRules []string `json:"matched_rules"`
	Decision     string   `json:"decision"`
	Reason       string   `json:"reason"`
}

// signetSignable is the exact struct Signet feeds into RFC 8785 JCS before signing.
// Fields: v, action, signer, ts, nonce, and optionally policy.
// The `id` and `sig` fields are NOT included in the signed payload.
type signetSignable struct {
	V      int           `json:"v"`
	Action signetAction  `json:"action"`
	Policy *signetPolicy `json:"policy,omitempty"`
	Signer signetSigner  `json:"signer"`
	Ts     string        `json:"ts"`
	Nonce  string        `json:"nonce"`
}

// SignetToExternalReceiptChain converts a Signet audit-file JSON export into a
// HELM ExternalReceiptChain. Each Signet AuditRecord becomes one ExternalHostReceipt
// with EventKind=action_effect. The SignedPayloadB64 field carries the exact bytes
// Signet signed (JCS of the receipt body minus id/sig), preserving the vendor's
// original signature scope.
//
// The adapter performs a BINDING CHECK: after constructing ActionEvent from the
// action fields, it re-parses the signed payload and asserts that tool, params_hash,
// and target match what was put in ActionEvent. An error is returned on mismatch.
func SignetToExternalReceiptChain(raw []byte) (*contracts.ExternalReceiptChain, error) {
	var file signetAuditFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("signet: parse audit file: %w", err)
	}
	if len(file.AuditRecords) == 0 {
		return nil, fmt.Errorf("signet: audit file contains no audit_records")
	}

	chain := &contracts.ExternalReceiptChain{
		SchemaVersion: contracts.ExternalReceiptChainVersion,
		SourceVendor:  "signet",
		SourceProfile: "signet-v4",
	}

	// Extract the issuer public key from the first receipt's signer.pubkey.
	// Format: "ed25519:<base64>".
	issuerPubKeyHex, err := signetDecodePublicKeyToHex(file.AuditRecords[0].Receipt.Signer.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("signet: decode issuer public key: %w", err)
	}
	chain.PublicKeys = []contracts.ExternalVerifierKey{{
		KeyID:        "signet-issuer",
		Algorithm:    "Ed25519",
		PublicKeyHex: issuerPubKeyHex,
	}}

	var prevReceiptHash string
	receiptHashes := make([]string, 0, len(file.AuditRecords))

	for i, record := range file.AuditRecords {
		r := record.Receipt
		receipt, hash, err := signetRecordToHELM(r, record.PrevHash, prevReceiptHash, i)
		if err != nil {
			return nil, fmt.Errorf("signet: record[%d] id=%s: %w", i, r.ID, err)
		}
		chain.Receipts = append(chain.Receipts, receipt)
		receiptHashes = append(receiptHashes, hash)
		prevReceiptHash = hash
	}

	chain.ReceiptChainHash = externalhost.ComputeChainHash(receiptHashes)
	return chain, nil
}

// signetRecordToHELM converts one Signet AuditRecord into an ExternalHostReceipt.
// prevHelmReceiptHash is the HELM receipt_hash of the immediately preceding receipt
// (empty string for the first receipt).
func signetRecordToHELM(r signetReceipt, signetPrevHash, prevHelmReceiptHash string, idx int) (contracts.ExternalHostReceipt, string, error) {
	// Reconstruct the exact signed payload bytes (JCS of signable, minus id/sig).
	signable := signetSignable{
		V:      r.V,
		Action: r.Action,
		Signer: r.Signer,
		Ts:     r.Ts,
		Nonce:  r.Nonce,
		Policy: r.Policy,
	}
	signedBytes, err := canonicalize.JCS(signable)
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("canonicalize signed payload: %w", err)
	}

	// Decode the Signet signature ("ed25519:<base64>") to raw bytes, then re-encode
	// as hex for ExternalHostReceipt.Signature (which accepts both hex and base64).
	sigStr := strings.TrimPrefix(strings.TrimSpace(r.Sig), "ed25519:")
	sigBytes, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("decode sig base64: %w", err)
	}

	pubKeyHex, err := signetDecodePublicKeyToHex(r.Signer.Pubkey)
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("decode signer pubkey: %w", err)
	}

	ts, err := time.Parse(time.RFC3339Nano, r.Ts)
	if err != nil {
		ts = time.Time{}
	}

	// Build ActionEffectEvent from Signet action fields.
	actionEvent := &contracts.ActionEffectEvent{
		ActionID:   r.ID,
		ToolName:   r.Action.Tool,
		TargetRef:  r.Action.Target,
		Transport:  r.Action.Transport,
		ParamsHash: r.Action.ParamsHash,
		Timestamp:  ts,
	}
	if r.Policy != nil {
		actionEvent.Decision = r.Policy.Decision
	}

	// BINDING CHECK: parse signedBytes back and assert tool/params_hash/target
	// match those in ActionEvent. Fail-closed: error on any mismatch.
	if err := signetBindingCheck(signedBytes, actionEvent); err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("binding check failed: %w", err)
	}

	agentID := r.Signer.Name
	if r.Signer.Owner != "" {
		agentID = r.Signer.Owner + "/" + r.Signer.Name
	}

	meta := map[string]string{
		"signet_receipt_id": r.ID,
		"signet_nonce":      r.Nonce,
		"signet_prev_hash":  signetPrevHash,
	}
	if r.Policy != nil {
		meta["signet_policy_hash"] = r.Policy.PolicyHash
		meta["signet_policy_name"] = r.Policy.PolicyName
		meta["signet_rule_id"] = strings.Join(r.Policy.MatchedRules, ",")
	}

	receipt := contracts.ExternalHostReceipt{
		SchemaVersion:      contracts.ExternalHostReceiptVersion,
		ReceiptID:          r.ID,
		HostID:             r.Signer.Name,
		AgentID:            agentID,
		ProcessIdentity:    r.Signer.Name,
		EventKind:          contracts.EventKindActionEffect,
		ActionEvent:        actionEvent,
		SignedPayloadB64:   base64.StdEncoding.EncodeToString(signedBytes),
		Signature:          fmt.Sprintf("%x", sigBytes),
		SignatureAlgorithm: "Ed25519",
		PublicKeyRef:       pubKeyHex,
		SourceVendor:       "signet",
		SourceProfile:      "signet-v4",
		PrevReceiptHash:    prevHelmReceiptHash,
		Metadata:           meta,
	}

	hash, err := externalhost.ComputeReceiptHash(receipt)
	if err != nil {
		return contracts.ExternalHostReceipt{}, "", fmt.Errorf("compute receipt hash: %w", err)
	}
	receipt.ReceiptHash = hash

	return receipt, hash, nil
}

// signetBindingCheck parses the JCS-encoded signed payload and asserts that the
// tool, params_hash, and target fields match those in actionEvent.
func signetBindingCheck(signedBytes []byte, actionEvent *contracts.ActionEffectEvent) error {
	var parsed signetSignable
	if err := json.Unmarshal(signedBytes, &parsed); err != nil {
		return fmt.Errorf("parse signed payload: %w", err)
	}
	if parsed.Action.Tool != actionEvent.ToolName {
		return fmt.Errorf("tool mismatch: signed=%q actionEvent=%q", parsed.Action.Tool, actionEvent.ToolName)
	}
	if parsed.Action.ParamsHash != actionEvent.ParamsHash {
		return fmt.Errorf("params_hash mismatch: signed=%q actionEvent=%q", parsed.Action.ParamsHash, actionEvent.ParamsHash)
	}
	if parsed.Action.Target != actionEvent.TargetRef {
		return fmt.Errorf("target mismatch: signed=%q actionEvent=%q", parsed.Action.Target, actionEvent.TargetRef)
	}
	return nil
}

// signetDecodePublicKeyToHex decodes a Signet public key string ("ed25519:<base64>")
// to lowercase hex. Returns an error if the format is unexpected.
func signetDecodePublicKeyToHex(pubkey string) (string, error) {
	s := strings.TrimPrefix(strings.TrimSpace(pubkey), "ed25519:")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decode pubkey %q: %w", pubkey, err)
	}
	return fmt.Sprintf("%x", b), nil
}
