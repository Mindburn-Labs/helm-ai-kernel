// Package externalhost parses and verifies vendor-neutral host evidence chains.
package externalhost

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type VerifyOptions struct {
	PublicKeyHex string
	RequireKey   bool
}

type CheckResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type VerificationReport struct {
	Verified      bool          `json:"verified"`
	ChainID       string        `json:"chain_id,omitempty"`
	ChainHash     string        `json:"chain_hash,omitempty"`
	ReceiptCount  int           `json:"receipt_count"`
	PublicKeyUsed string        `json:"public_key_used,omitempty"`
	Checks        []CheckResult `json:"checks"`
}

func ParseFile(path string) (*contracts.ExternalReceiptChain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*contracts.ExternalReceiptChain, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("external host evidence is empty")
	}

	var chain contracts.ExternalReceiptChain
	if err := json.Unmarshal(trimmed, &chain); err == nil && len(chain.Receipts) > 0 {
		normalizeChain(&chain)
		return &chain, nil
	}

	var receipts []contracts.ExternalHostReceipt
	if err := json.Unmarshal(trimmed, &receipts); err == nil && len(receipts) > 0 {
		chain = contracts.ExternalReceiptChain{SchemaVersion: contracts.ExternalReceiptChainVersion, Receipts: receipts}
		normalizeChain(&chain)
		return &chain, nil
	}

	var receipt contracts.ExternalHostReceipt
	if err := json.Unmarshal(trimmed, &receipt); err == nil && receipt.ReceiptID != "" {
		chain = contracts.ExternalReceiptChain{SchemaVersion: contracts.ExternalReceiptChainVersion, Receipts: []contracts.ExternalHostReceipt{receipt}}
		normalizeChain(&chain)
		return &chain, nil
	}

	parsed, err := parseJSONL(trimmed)
	if err != nil {
		return nil, err
	}
	normalizeChain(parsed)
	return parsed, nil
}

func VerifyFile(path string, opts VerifyOptions) (*VerificationReport, error) {
	chain, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	return VerifyChain(chain, opts)
}

func VerifyChain(chain *contracts.ExternalReceiptChain, opts VerifyOptions) (*VerificationReport, error) {
	report := &VerificationReport{Verified: true, Checks: []CheckResult{}}
	if chain == nil {
		report.add(CheckResult{Name: "external_host:parse", Pass: false, Reason: "chain is nil"})
		report.finalize()
		return report, nil
	}
	normalizeChain(chain)
	report.ChainID = chain.ChainID
	report.ReceiptCount = len(chain.Receipts)

	if len(chain.Receipts) == 0 {
		report.add(CheckResult{Name: "external_host:receipts", Pass: false, Reason: "chain contains no receipts"})
		report.finalize()
		return report, nil
	}
	report.add(CheckResult{Name: "external_host:receipts", Pass: true, Detail: fmt.Sprintf("%d host receipts", len(chain.Receipts))})

	explicitKeyHex := strings.TrimSpace(opts.PublicKeyHex)
	if explicitKeyHex == "" && opts.RequireKey {
		report.add(CheckResult{Name: "external_host:public_key", Pass: false, Reason: "missing Ed25519 public key"})
	}
	if explicitKeyHex != "" {
		report.PublicKeyUsed = explicitKeyHex
	}

	receiptHashes := make([]string, 0, len(chain.Receipts))
	var prevHash string
	for i := range chain.Receipts {
		r := &chain.Receipts[i]

		// Resolve the key for this receipt.
		// RequireKey+explicit key: always use the caller-supplied key (chain embedded keys stay untrusted).
		// No RequireKey + no explicit key: select from chain by the receipt's algorithm.
		keyHex := explicitKeyHex
		if keyHex == "" && !opts.RequireKey {
			keyHex = selectChainPublicKey(chain, r.SignatureAlgorithm)
			if keyHex != "" && report.PublicKeyUsed == "" {
				report.PublicKeyUsed = keyHex
			}
		}

		if err := validateReceipt(r); err != nil {
			report.add(CheckResult{Name: "external_host:receipt_schema", Pass: false, Reason: fmt.Sprintf("%s: %v", r.ReceiptID, err)})
			continue
		}
		report.add(CheckResult{Name: "external_host:receipt_schema", Pass: true, Detail: r.ReceiptID})

		computed, err := ComputeReceiptHash(*r)
		if err != nil {
			report.add(CheckResult{Name: "external_host:receipt_hash", Pass: false, Reason: fmt.Sprintf("%s: %v", r.ReceiptID, err)})
			continue
		}
		receiptHashes = append(receiptHashes, computed)
		if r.ReceiptHash != computed {
			report.add(CheckResult{Name: "external_host:receipt_hash", Pass: false, Reason: fmt.Sprintf("%s hash mismatch: expected %s, computed %s", r.ReceiptID, r.ReceiptHash, computed)})
		} else {
			report.add(CheckResult{Name: "external_host:receipt_hash", Pass: true, Detail: fmt.Sprintf("%s %s", r.ReceiptID, computed)})
		}

		if i > 0 {
			if prevHash == "" {
				report.add(CheckResult{Name: "external_host:prev_hash", Pass: false, Reason: fmt.Sprintf("%s previous receipt hash unavailable", r.ReceiptID)})
			} else if r.PrevReceiptHash != prevHash {
				report.add(CheckResult{Name: "external_host:prev_hash", Pass: false, Reason: fmt.Sprintf("%s prev_receipt_hash=%q, want %q", r.ReceiptID, r.PrevReceiptHash, prevHash)})
			} else {
				report.add(CheckResult{Name: "external_host:prev_hash", Pass: true, Detail: r.ReceiptID})
			}
		}
		prevHash = computed

		report.add(verifySignatureCheck(*r, keyHex, opts.RequireKey || keyHex != ""))
		report.add(verifyHardwareRootCheck(*r))
	}

	chainHash := ComputeChainHash(receiptHashes)
	report.ChainHash = chainHash
	if chain.ReceiptChainHash != "" {
		if chain.ReceiptChainHash != chainHash {
			report.add(CheckResult{Name: "external_host:chain_hash", Pass: false, Reason: fmt.Sprintf("receipt_chain_hash=%q, computed %q", chain.ReceiptChainHash, chainHash)})
		} else {
			report.add(CheckResult{Name: "external_host:chain_hash", Pass: true, Detail: chainHash})
		}
	} else {
		report.add(CheckResult{Name: "external_host:chain_hash", Pass: true, Detail: chainHash})
	}

	report.finalize()
	return report, nil
}

func ComputeReceiptHash(receipt contracts.ExternalHostReceipt) (string, error) {
	hashable := receipt
	hashable.ReceiptHash = ""
	hashable.Signature = ""
	data, err := CanonicalReceiptBytes(hashable)
	if err != nil {
		return "", err
	}
	return "sha256:" + canonicalize.HashBytes(data), nil
}

func CanonicalReceiptBytes(receipt contracts.ExternalHostReceipt) ([]byte, error) {
	return canonicalize.JCS(receipt)
}

// signedBytesFor returns the exact bytes a signature is verified against:
// the vendor's preserved original bytes when present, else HELM's JCS canonicalization.
func signedBytesFor(receipt contracts.ExternalHostReceipt) ([]byte, error) {
	if strings.TrimSpace(receipt.SignedPayloadB64) != "" {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(receipt.SignedPayloadB64))
	}
	hashable := receipt
	hashable.Signature = ""
	return CanonicalReceiptBytes(hashable)
}

func SignReceipt(receipt contracts.ExternalHostReceipt, privateKey ed25519.PrivateKey) (contracts.ExternalHostReceipt, error) {
	if receipt.SignatureAlgorithm == "" {
		receipt.SignatureAlgorithm = "Ed25519"
	}
	hash, err := ComputeReceiptHash(receipt)
	if err != nil {
		return receipt, err
	}
	receipt.ReceiptHash = hash
	hashable := receipt
	hashable.Signature = ""
	data, err := CanonicalReceiptBytes(hashable)
	if err != nil {
		return receipt, err
	}
	receipt.Signature = hex.EncodeToString(ed25519.Sign(privateKey, data))
	return receipt, nil
}

func ComputeChainHash(receiptHashes []string) string {
	return "sha256:" + canonicalize.HashBytes([]byte(strings.Join(receiptHashes, "\n")))
}

func parseJSONL(data []byte) (*contracts.ExternalReceiptChain, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var receipts []contracts.ExternalHostReceipt
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var receipt contracts.ExternalHostReceipt
		if err := json.Unmarshal(line, &receipt); err != nil {
			return nil, fmt.Errorf("parse JSONL line %d: %w", lineNo, err)
		}
		receipts = append(receipts, receipt)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(receipts) == 0 {
		return nil, fmt.Errorf("no JSONL host receipts found")
	}
	return &contracts.ExternalReceiptChain{SchemaVersion: contracts.ExternalReceiptChainVersion, Receipts: receipts}, nil
}

func normalizeChain(chain *contracts.ExternalReceiptChain) {
	if chain.SchemaVersion == "" {
		chain.SchemaVersion = contracts.ExternalReceiptChainVersion
	}
	for i := range chain.Receipts {
		if chain.Receipts[i].SchemaVersion == "" {
			chain.Receipts[i].SchemaVersion = contracts.ExternalHostReceiptVersion
		}
		if chain.Receipts[i].SourceVendor == "" {
			chain.Receipts[i].SourceVendor = chain.SourceVendor
		}
		if chain.Receipts[i].SourceProfile == "" {
			chain.Receipts[i].SourceProfile = chain.SourceProfile
		}
	}
}

func validateReceipt(r *contracts.ExternalHostReceipt) error {
	if r.ReceiptID == "" {
		return fmt.Errorf("receipt_id is required")
	}
	if r.HostID == "" {
		return fmt.Errorf("host_id is required")
	}
	if r.ReceiptHash == "" {
		return fmt.Errorf("receipt_hash is required")
	}
	switch r.EventKind {
	case "", contracts.EventKindNetworkEgress:
		return validateNetworkEgressEvent(&r.Event)
	case contracts.EventKindActionEffect:
		return validateActionEffectEvent(r.ActionEvent)
	default:
		return fmt.Errorf("unsupported event_kind %q", r.EventKind)
	}
}

func validateNetworkEgressEvent(e *contracts.NetworkEgressEvent) error {
	switch {
	case e.DestinationIP == "" && e.DestinationHost == "":
		return fmt.Errorf("event destination is required")
	case e.DestinationPort <= 0:
		return fmt.Errorf("event.destination_port must be positive")
	case strings.TrimSpace(e.Protocol) == "":
		return fmt.Errorf("event.protocol is required")
	case e.Timestamp.IsZero():
		return fmt.Errorf("event.timestamp is required")
	}
	return nil
}

func validateActionEffectEvent(e *contracts.ActionEffectEvent) error {
	if e == nil {
		return fmt.Errorf("action_event is required when event_kind=%q", contracts.EventKindActionEffect)
	}
	if strings.TrimSpace(e.ActionID) == "" {
		return fmt.Errorf("action_event.action_id is required")
	}
	if strings.TrimSpace(e.ToolName) == "" {
		return fmt.Errorf("action_event.tool_name is required")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("action_event.timestamp is required")
	}
	return nil
}

func verifySignatureCheck(receipt contracts.ExternalHostReceipt, keyHex string, require bool) CheckResult {
	if strings.TrimSpace(receipt.Signature) == "" {
		if require {
			return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s missing signature", receipt.ReceiptID)}
		}
		return CheckResult{Name: "external_host:signature", Pass: true, Detail: fmt.Sprintf("%s unsigned; signature verification skipped", receipt.ReceiptID)}
	}
	if keyHex == "" {
		return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s has signature but no public key", receipt.ReceiptID)}
	}
	alg := strings.TrimSpace(receipt.SignatureAlgorithm)
	if alg == "" {
		alg = "Ed25519"
	}
	data, err := signedBytesFor(receipt)
	if err != nil {
		return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s payload decode failed: %v", receipt.ReceiptID, err)}
	}
	sig, err := decodeSignature(receipt.Signature)
	if err != nil {
		return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s invalid signature encoding: %v", receipt.ReceiptID, err)}
	}
	switch {
	case strings.EqualFold(alg, "Ed25519"):
		pub, err := hex.DecodeString(strings.TrimPrefix(keyHex, "ed25519:"))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return CheckResult{Name: "external_host:signature", Pass: false, Reason: "invalid Ed25519 public key"}
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
			return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s Ed25519 signature mismatch", receipt.ReceiptID)}
		}
	case strings.EqualFold(alg, "ECDSA-P256") || strings.EqualFold(alg, "ES256"):
		ok, verr := verifyECDSAP256(keyHex, data, sig)
		if verr != nil {
			return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s ECDSA-P256 key/sig error: %v", receipt.ReceiptID, verr)}
		}
		if !ok {
			return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s ECDSA-P256 signature mismatch", receipt.ReceiptID)}
		}
	default:
		return CheckResult{Name: "external_host:signature", Pass: false, Reason: fmt.Sprintf("%s unsupported signature_algorithm=%q", receipt.ReceiptID, alg)}
	}
	return CheckResult{Name: "external_host:signature", Pass: true, Detail: receipt.ReceiptID}
}

func verifyHardwareRootCheck(receipt contracts.ExternalHostReceipt) CheckResult {
	if receipt.HardwareRoot == nil || strings.TrimSpace(receipt.HardwareRoot.HardwareRootType) == "" {
		return CheckResult{Name: "external_host:hardware_root", Pass: true, Detail: fmt.Sprintf("%s no hardware root claim", receipt.ReceiptID)}
	}
	rootType := strings.ToUpper(strings.TrimSpace(receipt.HardwareRoot.HardwareRootType))
	switch rootType {
	case "TPM2", "AWS_NITRO", "AMD_SEV_SNP", "INTEL_TDX", "APPLE_SEP", "OTHER":
	default:
		return CheckResult{Name: "external_host:hardware_root", Pass: false, Reason: fmt.Sprintf("%s unsupported hardware_root_type=%q", receipt.ReceiptID, receipt.HardwareRoot.HardwareRootType)}
	}
	if receipt.HardwareRoot.QuoteBlobB64 != "" {
		if _, err := base64.StdEncoding.DecodeString(receipt.HardwareRoot.QuoteBlobB64); err != nil {
			return CheckResult{Name: "external_host:hardware_root", Pass: false, Reason: fmt.Sprintf("%s invalid quote_blob_b64: %v", receipt.ReceiptID, err)}
		}
	}
	return CheckResult{
		Name:   "external_host:hardware_root",
		Pass:   false,
		Reason: fmt.Sprintf("%s hardware root %s structurally present but not cryptographically verified in this verifier", receipt.ReceiptID, rootType),
	}
}

func decodeSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

// selectChainPublicKey returns the first public key from the chain whose
// Algorithm matches alg (empty Algorithm is treated as Ed25519).
func selectChainPublicKey(chain *contracts.ExternalReceiptChain, alg string) string {
	if alg == "" {
		alg = "Ed25519"
	}
	for _, key := range chain.PublicKeys {
		keyAlg := key.Algorithm
		if keyAlg == "" {
			keyAlg = "Ed25519"
		}
		if key.PublicKeyHex != "" && strings.EqualFold(keyAlg, alg) {
			return key.PublicKeyHex
		}
	}
	return ""
}

// firstChainPublicKey is a thin wrapper for backward compatibility with
// existing callers that only need an Ed25519 key.
func firstChainPublicKey(chain *contracts.ExternalReceiptChain) string {
	return selectChainPublicKey(chain, "Ed25519")
}

// verifyECDSAP256 verifies an ASN.1 DER ECDSA-P256 signature over sha256(data).
// keyHex may be an uncompressed (04...) or compressed (02.../03...) P-256 point
// encoded as hex (with optional "ecdsa-p256:" or "0x" prefix), or a
// hex-encoded SubjectPublicKeyInfo DER blob. Returns (false, err) on any parse
// failure — fail-closed.
func verifyECDSAP256(keyHex string, data, sig []byte) (bool, error) {
	raw := strings.TrimPrefix(strings.TrimPrefix(keyHex, "ecdsa-p256:"), "0x")
	keyBytes, err := hex.DecodeString(raw)
	if err != nil {
		return false, fmt.Errorf("hex decode public key: %w", err)
	}
	var pub *ecdsa.PublicKey
	// Try uncompressed (04 || X || Y) or compressed (02/03 || X) EC point first.
	if len(keyBytes) > 0 && (keyBytes[0] == 0x04 || keyBytes[0] == 0x02 || keyBytes[0] == 0x03) {
		x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
		if x == nil {
			// Try compressed
			x, y = elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
		}
		if x == nil {
			return false, fmt.Errorf("failed to unmarshal P-256 point")
		}
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	} else {
		// Fall back to SubjectPublicKeyInfo DER.
		iface, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return false, fmt.Errorf("parse SubjectPublicKeyInfo: %w", err)
		}
		var ok bool
		pub, ok = iface.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not ECDSA")
		}
		if pub.Curve != elliptic.P256() {
			return false, fmt.Errorf("key curve is not P-256")
		}
	}
	h := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pub, h[:], sig), nil
}

func (r *VerificationReport) add(check CheckResult) {
	r.Checks = append(r.Checks, check)
}

func (r *VerificationReport) finalize() {
	r.Verified = true
	for _, check := range r.Checks {
		if !check.Pass {
			r.Verified = false
			return
		}
	}
}
