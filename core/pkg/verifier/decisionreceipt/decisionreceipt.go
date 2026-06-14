// Package decisionreceipt verifies external decision receipts against HELM's
// neutral classification ladder and normalizes them into
// contracts.ExternalDecisionReceipt for import into EvidencePacks. Target formats
// (AAR, ACTA, Pipelock) plug in as FormatAdapters; this release ships the
// helm_external.v1 reference adapter only.
//
// HELM verifies external receipts; it does NOT promote them to HELM-native
// authority. The strongest level an external decision receipt can reach is
// crypto_conformant (decision-level proof). Execution proof requires a HELM
// verdict-bound effect permit, which these formats do not carry.
package decisionreceipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// FormatAdapter is implemented once per external decision-receipt format. It
// owns detection, parsing, and — most importantly — reproducing the exact bytes
// the producer signed (CanonicalSignedBytes), so HELM verifies the signature
// without re-canonicalizing differently from the producer.
type FormatAdapter interface {
	FormatID() string
	Kind() contracts.ExternalReceiptKind
	// Detect cheaply reports whether raw bytes plausibly match this format.
	Detect(raw []byte) bool
	// Parse decodes vendor bytes into one or more normalized receipts. It must
	// set Kind and FormatID and must not verify signatures.
	Parse(raw []byte) ([]contracts.ExternalDecisionReceipt, error)
	// CanonicalSignedBytes returns the exact bytes that were signed for r.
	CanonicalSignedBytes(r contracts.ExternalDecisionReceipt) ([]byte, error)
}

// Registry maps format IDs to adapters.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]FormatAdapter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{adapters: map[string]FormatAdapter{}} }

var defaultRegistry = NewRegistry()

// Register adds an adapter to the default registry. It panics if the adapter
// declares the reserved helm_native kind (no external adapter may claim
// HELM-native authority).
func Register(a FormatAdapter) { defaultRegistry.Register(a) }

// Default returns the process-wide registry that built-in adapters register into.
func Default() *Registry { return defaultRegistry }

// Register adds an adapter. It panics on a reserved helm_native kind.
func (r *Registry) Register(a FormatAdapter) {
	if a.Kind() == contracts.KindHELMNative {
		panic(fmt.Sprintf("decisionreceipt: adapter %q may not declare helm_native kind", a.FormatID()))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[a.FormatID()] = a
}

// Get returns the adapter registered for formatID.
func (r *Registry) Get(formatID string) (FormatAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[formatID]
	return a, ok
}

// DetectAdapter returns the first adapter (in deterministic id order) whose
// Detect matches raw.
func (r *Registry) DetectAdapter(raw []byte) (FormatAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.adapters))
	for id := range r.adapters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if r.adapters[id].Detect(raw) {
			return r.adapters[id], true
		}
	}
	return nil, false
}

// DecisionCheck is a single named verification result.
type DecisionCheck struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// DecisionReport is the aggregate verification outcome for an input.
type DecisionReport struct {
	Verified       bool                                    `json:"verified"`
	FormatID       string                                  `json:"format_id"`
	Kind           contracts.ExternalReceiptKind           `json:"kind"`
	Classification contracts.ExternalReceiptClassification `json:"classification"`
	ReceiptCount   int                                     `json:"receipt_count"`
	Checks         []DecisionCheck                         `json:"checks"`
	Receipts       []contracts.ExternalDecisionReceipt     `json:"receipts,omitempty"`
}

// ComputeReceiptHash returns "sha256:" + hex over the adapter's canonical signed
// bytes for r.
func ComputeReceiptHash(a FormatAdapter, r contracts.ExternalDecisionReceipt) (string, error) {
	data, err := a.CanonicalSignedBytes(r)
	if err != nil {
		return "", err
	}
	return "sha256:" + canonicalize.HashBytes(data), nil
}

// VerifyReceipt verifies one receipt and returns its classification + checks.
func VerifyReceipt(a FormatAdapter, r contracts.ExternalDecisionReceipt, bundleKeys []contracts.ExternalVerifierKey, trustedKeyHex string) (contracts.ExternalReceiptClassification, []DecisionCheck) {
	var checks []DecisionCheck
	id := r.ReceiptID

	data, err := a.CanonicalSignedBytes(r)
	if err != nil {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":hash", Pass: false, Reason: "canonicalization failed: " + err.Error()})
		return contracts.ClassUnverified, checks
	}
	computed := "sha256:" + canonicalize.HashBytes(data)
	switch {
	case r.ReceiptHash == "":
		// No producer-supplied hash; the signature below is the authoritative
		// check. Record this honestly rather than implying a stored hash matched.
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":hash", Pass: true, Detail: "no stored receipt_hash (computed " + computed + ")"})
	case r.ReceiptHash != computed:
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":hash", Pass: false, Reason: fmt.Sprintf("receipt_hash=%q computed=%q", r.ReceiptHash, computed)})
		return contracts.ClassUnverified, checks
	default:
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":hash", Pass: true, Detail: computed})
	}

	if strings.TrimSpace(r.Signature) == "" {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":signature", Pass: false, Reason: "missing signature"})
		return contracts.ClassUnverified, checks
	}
	if alg := strings.TrimSpace(r.SignatureAlgorithm); alg != "" && !strings.EqualFold(alg, "Ed25519") {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":signature", Pass: false, Reason: "unsupported signature_algorithm=" + alg})
		return contracts.ClassUnverified, checks
	}

	pub, trusted, keyErr := resolveKey(r, bundleKeys, trustedKeyHex)
	if keyErr != nil {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":key", Pass: false, Reason: keyErr.Error()})
		return contracts.ClassUnverified, checks
	}
	if pub == nil {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":key", Pass: false, Reason: "no trusted or disclosed public key for signature"})
		return contracts.ClassUnverified, checks
	}

	sig, err := decodeSignature(r.Signature)
	if err != nil {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":signature", Pass: false, Reason: "invalid signature encoding: " + err.Error()})
		return contracts.ClassUnverified, checks
	}
	if !ed25519.Verify(pub, data, sig) {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":signature", Pass: false, Reason: "Ed25519 signature mismatch"})
		return contracts.ClassUnverified, checks
	}
	checks = append(checks, DecisionCheck{Name: "decision:" + id + ":signature", Pass: true, Detail: "Ed25519 verified"})

	if trusted {
		checks = append(checks, DecisionCheck{Name: "decision:" + id + ":classification", Pass: true, Detail: string(contracts.ClassCryptoConformant)})
		return contracts.ClassCryptoConformant, checks
	}
	checks = append(checks, DecisionCheck{Name: "decision:" + id + ":classification", Pass: true, Detail: string(contracts.ClassCryptoCompatibleNonConformant) + " (verified against bundle-disclosed key only; decision-level proof, not execution proof)"})
	return contracts.ClassCryptoCompatibleNonConformant, checks
}

// VerifyBundle parses raw using the registry (explicit formatID or auto-detect),
// verifies every receipt, links the chain, and returns an aggregate report whose
// Classification is the weakest of any receipt.
func (r *Registry) VerifyBundle(raw []byte, formatID, trustedKeyHex string) (DecisionReport, error) {
	var adapter FormatAdapter
	var ok bool
	if formatID != "" {
		if adapter, ok = r.Get(formatID); !ok {
			return DecisionReport{}, fmt.Errorf("unknown format_id %q", formatID)
		}
	} else if adapter, ok = r.DetectAdapter(raw); !ok {
		return DecisionReport{}, fmt.Errorf("no registered adapter matched the input")
	}
	if adapter.Kind() == contracts.KindHELMNative {
		return DecisionReport{}, fmt.Errorf("adapter %q must not declare helm_native kind", adapter.FormatID())
	}

	receipts, err := adapter.Parse(raw)
	if err != nil {
		return DecisionReport{}, fmt.Errorf("parse: %w", err)
	}
	report := DecisionReport{FormatID: adapter.FormatID(), Kind: adapter.Kind(), ReceiptCount: len(receipts), Verified: true, Classification: contracts.ClassCryptoConformant}
	if len(receipts) == 0 {
		report.Verified = false
		report.Classification = contracts.ClassUnverified
		report.Checks = append(report.Checks, DecisionCheck{Name: "decision:bundle", Pass: false, Reason: "no receipts in input"})
		return report, nil
	}

	bundleKeys := extractBundleKeys(raw)
	weakest := contracts.ClassCryptoConformant
	var prevHash string
	for i := range receipts {
		if receipts[i].Kind == contracts.KindHELMNative {
			report.Verified = false
			report.Checks = append(report.Checks, DecisionCheck{Name: "decision:" + receipts[i].ReceiptID + ":kind", Pass: false, Reason: "external receipt must not claim helm_native kind"})
			weakest = contracts.ClassUnverified
			prevHash = ""
			continue
		}
		class, checks := VerifyReceipt(adapter, receipts[i], bundleKeys, trustedKeyHex)
		report.Checks = append(report.Checks, checks...)
		receipts[i].Classification = class
		if class == contracts.ClassUnverified {
			report.Verified = false
		}
		weakest = weaker(weakest, class)

		if i > 0 {
			// prevHash == "" means the previous receipt was skipped/uncomputable
			// (e.g. it forged a helm_native kind); the chain is broken there.
			if prevHash == "" || receipts[i].PrevReceiptHash != prevHash {
				report.Verified = false
				weakest = contracts.ClassUnverified
				report.Checks = append(report.Checks, DecisionCheck{Name: "decision:" + receipts[i].ReceiptID + ":chain", Pass: false, Reason: fmt.Sprintf("prev_receipt_hash=%q expected %q", receipts[i].PrevReceiptHash, prevHash)})
			} else {
				report.Checks = append(report.Checks, DecisionCheck{Name: "decision:" + receipts[i].ReceiptID + ":chain", Pass: true})
			}
		}
		if h, herr := ComputeReceiptHash(adapter, receipts[i]); herr == nil {
			prevHash = h
		} else {
			prevHash = ""
		}
	}
	report.Classification = weakest
	report.Receipts = receipts
	return report, nil
}

func weaker(a, b contracts.ExternalReceiptClassification) contracts.ExternalReceiptClassification {
	rank := map[contracts.ExternalReceiptClassification]int{
		contracts.ClassUnverified:                    0,
		contracts.ClassCryptoCompatibleNonConformant: 1,
		contracts.ClassCryptoConformant:              2,
	}
	if rank[b] < rank[a] {
		return b
	}
	return a
}

func resolveKey(r contracts.ExternalDecisionReceipt, bundleKeys []contracts.ExternalVerifierKey, trustedKeyHex string) (ed25519.PublicKey, bool, error) {
	if strings.TrimSpace(trustedKeyHex) != "" {
		pub, err := decodePublicKey(trustedKeyHex)
		if err != nil {
			return nil, false, err
		}
		return pub, true, nil
	}
	for _, k := range bundleKeys {
		if r.SigningKeyID == "" || k.KeyID == r.SigningKeyID {
			if pub, err := decodePublicKey(k.PublicKeyHex); err == nil {
				return pub, false, nil
			}
		}
	}
	return nil, false, nil
}

// extractBundleKeys best-effort recovers public keys disclosed in a bundle
// envelope. Disclosed keys prove self-consistency only, never authenticity.
func extractBundleKeys(raw []byte) []contracts.ExternalVerifierKey {
	var bundle contracts.ExternalDecisionReceiptBundle
	if err := json.Unmarshal(raw, &bundle); err == nil && len(bundle.PublicKeys) > 0 {
		return bundle.PublicKeys
	}
	return nil
}

func decodeSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("signature is neither valid hex nor base64")
}

func decodePublicKey(keyHex string) (ed25519.PublicKey, error) {
	pub, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(keyHex), "ed25519:"))
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(pub))
	}
	return ed25519.PublicKey(pub), nil
}
