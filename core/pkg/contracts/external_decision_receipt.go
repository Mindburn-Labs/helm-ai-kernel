package contracts

import "time"

const (
	// ExternalDecisionReceiptVersion is the schema version for a single
	// normalized external decision receipt imported into HELM.
	ExternalDecisionReceiptVersion = "external_decision_receipt.v1"
	// ExternalDecisionReceiptBundleVersion is the on-disk chain envelope version.
	ExternalDecisionReceiptBundleVersion = "external_decision_receipt_bundle.v1"
)

// ExternalReceiptKind is the top-level taxonomy discriminator for any receipt
// HELM is asked to reason about. It deliberately separates HELM-native receipts
// (which carry a fail-closed policy verdict bound to an effect permit) from
// external receipts (which, at best, carry a decision-level claim).
type ExternalReceiptKind string

const (
	// KindHELMNative is reserved for receipts that bind a HELM policy verdict to
	// an effect permit + policy hash. No external-format adapter may emit it.
	KindHELMNative ExternalReceiptKind = "helm_native_receipt"
	// KindExternalDecision is a third-party decision receipt (e.g. AAR, ACTA):
	// decision-level proof only, not execution proof.
	KindExternalDecision ExternalReceiptKind = "external_decision_receipt"
	// KindExternalScan is a third-party scan/proxy receipt (e.g. Pipelock egress).
	KindExternalScan ExternalReceiptKind = "external_scan_receipt"
)

// ExternalReceiptClassification is the trust level the verifier assigns to an
// external receipt. It is never promoted to HELM-native authority: an external
// decision receipt lacks a verdict-bound effect permit, so the strongest level
// it can reach is crypto_conformant (cryptographically sound, decision-level).
type ExternalReceiptClassification string

const (
	// ClassCryptoConformant: signature verified against an externally trusted key
	// and (if a chain is present) the chain links. Decision-level proof.
	ClassCryptoConformant ExternalReceiptClassification = "crypto_conformant"
	// ClassCryptoCompatibleNonConformant: cryptographically well-formed and the
	// signature verifies, but only against a key disclosed inside the bundle
	// (self-consistency, not authenticity) or a HELM binding is absent.
	ClassCryptoCompatibleNonConformant ExternalReceiptClassification = "crypto_compatible_non_conformant"
	// ClassUnverified: no trusted key, invalid signature, or hash mismatch.
	ClassUnverified ExternalReceiptClassification = "unverified"
)

// ExternalDecisionReceipt is the HELM-internal normalized representation that
// every external decision-receipt format (AAR, ACTA, Pipelock, …) maps into via
// its FormatAdapter. The Classification, ReceiptHash, OriginalDigest and
// Limitations fields are assigned by HELM during verification/import and are
// excluded from the bytes the producer signed.
type ExternalDecisionReceipt struct {
	SchemaVersion  string                        `json:"schema_version"`
	Kind           ExternalReceiptKind           `json:"kind"`
	FormatID       string                        `json:"format_id"`
	FormatVersion  string                        `json:"format_version,omitempty"`
	Classification ExternalReceiptClassification `json:"classification,omitempty"`

	ReceiptID       string `json:"receipt_id"`
	PrevReceiptHash string `json:"prev_receipt_hash,omitempty"`
	ReceiptHash     string `json:"receipt_hash,omitempty"` // "sha256:" + hex over canonical signed bytes

	Action       string    `json:"action,omitempty"`
	Verdict      string    `json:"verdict,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	ArgsHash     string    `json:"args_hash,omitempty"`
	DecisionTime time.Time `json:"decision_time,omitempty"`

	SignatureAlgorithm string `json:"signature_algorithm,omitempty"` // "Ed25519"
	Signature          string `json:"signature,omitempty"`           // hex or base64
	SigningKeyID       string `json:"signing_key_id,omitempty"`

	SourceVendor   string            `json:"source_vendor,omitempty"`
	Limitations    []string          `json:"limitations,omitempty"`
	OriginalDigest string            `json:"original_digest,omitempty"` // sha256 of verbatim source bytes
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ExternalDecisionReceiptBundle is the on-disk envelope for one or more external
// decision receipts. PublicKeys are local-only and never fetched over the
// network during verification (same invariant as ExternalVerifierKey).
type ExternalDecisionReceiptBundle struct {
	SchemaVersion string                    `json:"schema_version"`
	FormatID      string                    `json:"format_id,omitempty"`
	SourceVendor  string                    `json:"source_vendor,omitempty"`
	PublicKeys    []ExternalVerifierKey     `json:"public_keys,omitempty"`
	Receipts      []ExternalDecisionReceipt `json:"receipts"`
}
