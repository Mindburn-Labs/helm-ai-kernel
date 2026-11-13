// quantum_posture: export verifies classical Ed25519 receipt signatures (the
// budget-verdict seal and the detached signature over the JCS canonicalization
// of every record) against a pinned public key, and re-derives SHA-256 content
// hashes offline; no post-quantum primitives are used in this file.

package spendproxy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// ExportOptions configures ExportEvidencePacks.
type ExportOptions struct {
	ReceiptsDir string
	OutDir      string
	// IntentFilter, when non-empty, exports only that spend intent.
	IntentFilter string
	// PublicKey is the issuer's Ed25519 public key, taken from outside the
	// receipts directory (--public-key). The directory's own key registry is
	// written by the process whose receipts it would vouch for, so it is never
	// used to verify them. Without a key no signature is checked, and none is
	// reported verified.
	PublicKey ed25519.PublicKey
	// PublicKeys are more issuer keys, for a log signed by more than one: a
	// reconcile after the seed was lost or changed signs with the new key for
	// a dispatch the old one journalled (helm-tracker#313 r3, finding 2). Each
	// signature is checked against the pinned key its key id names.
	PublicKeys []ed25519.PublicKey
}

// ExportResult summarizes one exported spend EvidencePack.
type ExportResult struct {
	SpendIntentID    string   `json:"spend_intent_id"`
	PackID           string   `json:"pack_id"`
	ManifestHash     string   `json:"manifest_hash"`
	ReceiptsVerified []string `json:"receipts_verified"`
	OfflineVerified  bool     `json:"offline_verified"`
	// SignatureVerified is true only when a pinned public key was given and
	// every signature in SignaturesChecked verified against it, the
	// budget-verdict seal included.
	SignatureVerified bool `json:"signature_verified"`
	// SignaturesChecked names each signature that was checked: the detached
	// signature of every record of the intent, by record kind, and
	// "budget_verdict_seal". Empty when no key was pinned.
	SignaturesChecked []string `json:"signatures_checked"`
	// SignatureKeyID is the pinned key's id when one key is pinned; with more,
	// the id of the one key that signed what was checked, empty when several
	// did. SignatureKeyIDs lists every pinned key that signed what was checked.
	SignatureKeyID  string   `json:"signature_key_id,omitempty"`
	SignatureKeyIDs []string `json:"signature_key_ids,omitempty"`
	OutputDir       string   `json:"output_dir"`
}

// IssuerKeyID is the key id the spend proxy's issuer writes into receipts for
// an Ed25519 public key.
func IssuerKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "spend-proxy-" + hex.EncodeToString(sum[:6])
}

// ParsePublicKey reads an Ed25519 public key written as hex, with or without
// the "ed25519:" prefix the trusted-key registry and the proxy's start banner
// use.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(text), "ed25519:"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("spendproxy: the public key must be %d bytes of hex, optionally prefixed ed25519:", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ExportEvidencePacks reads the durable receipt log, groups receipts by spend
// intent, renders each group into a spend EvidencePack via core/pkg/evidencepack,
// verifies every pack OFFLINE, and writes the pack contents under
// OutDir/<spend_intent_id>/. With pinned keys (PublicKey, PublicKeys) it also
// verifies every signature of each exported intent (helm-tracker#313, audit
// M18): the detached signature of each of its records and its budget-verdict
// seal, each against the pinned key its key id names. A record that is
// unsigned, signed by a key not pinned or whose signature does not verify
// fails the export.
func ExportEvidencePacks(opts ExportOptions) ([]ExportResult, error) {
	records, err := LoadRecords(filepath.Join(opts.ReceiptsDir, ReceiptLogName))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("spendproxy: receipt log is empty; nothing to export")
	}
	pinned := make(map[string]ed25519.PublicKey)
	for _, pub := range append([]ed25519.PublicKey{opts.PublicKey}, opts.PublicKeys...) {
		if pub == nil {
			continue
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("spendproxy: a pinned public key must be %d bytes", ed25519.PublicKeySize)
		}
		pinned[IssuerKeyID(pub)] = pub
	}

	type group struct {
		set        evidencepack.SpendReceiptSet
		policyHash string
		records    []*ReceiptRecord
	}
	groups := make(map[string]*group)
	order := make([]string, 0)
	for _, rec := range records {
		if rec.SpendIntentID == "" {
			continue
		}
		if opts.IntentFilter != "" && rec.SpendIntentID != opts.IntentFilter {
			continue
		}
		g, ok := groups[rec.SpendIntentID]
		if !ok {
			g = &group{}
			groups[rec.SpendIntentID] = g
			order = append(order, rec.SpendIntentID)
		}
		g.records = append(g.records, rec)
		switch rec.Kind {
		case RecordRouteQuote:
			if rec.RouteQuote != nil {
				g.set.RouteQuote = rec.RouteQuote
				g.policyHash = rec.RouteQuote.RoutePolicyHash
			}
		case RecordBudgetVerdict:
			g.set.Budget = rec.BudgetVerdict
		case RecordUsage:
			g.set.Usage = rec.Usage
		case RecordSettlement:
			g.set.Settlement = rec.Settlement
		}
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("spendproxy: no receipts matched intent filter %q", opts.IntentFilter)
	}
	sort.Strings(order)

	results := make([]ExportResult, 0, len(order))
	for _, intentID := range order {
		g := groups[intentID]
		packID := "spendpack-" + intentID
		manifest, contents, err := evidencepack.BuildSpendEvidencePack(
			packID, "did:helm:spend-proxy", intentID, g.policyHash,
			g.set, economic.DefaultRedactionProfile(),
		)
		if err != nil {
			return nil, fmt.Errorf("spendproxy: build pack for %s: %w", intentID, err)
		}
		verification, err := evidencepack.VerifySpendEvidenceOffline(contents)
		if err != nil {
			return nil, fmt.Errorf("spendproxy: offline verify pack for %s: %w", intentID, err)
		}

		res := ExportResult{
			SpendIntentID:     intentID,
			PackID:            packID,
			ManifestHash:      manifest.ManifestHash,
			ReceiptsVerified:  verification.ReceiptsVerified,
			OfflineVerified:   verification.OK,
			SignaturesChecked: []string{},
		}
		if len(pinned) > 0 {
			checked, signers, err := verifyIntentSignatures(pinned, intentID, g.records, g.set.Budget)
			if err != nil {
				return nil, err
			}
			res.SignaturesChecked, res.SignatureKeyIDs = checked, signers
			switch {
			case len(pinned) == 1:
				for keyID := range pinned {
					res.SignatureKeyID = keyID
				}
			case len(signers) == 1:
				res.SignatureKeyID = signers[0]
			}
			res.SignatureVerified = len(checked) > 0
		}

		dir := filepath.Join(opts.OutDir, intentID)
		if err := writePackContents(dir, contents); err != nil {
			return nil, err
		}
		res.OutputDir = dir
		results = append(results, res)
	}
	return results, nil
}

// verifyIntentSignatures checks the detached signature of every record of one
// intent that carries a receipt payload, and the seal of its budget verdict,
// each against the pinned key its key id names. It returns what it checked
// and the ids of the keys that signed it, sorted.
func verifyIntentSignatures(pinned map[string]ed25519.PublicKey, intentID string, records []*ReceiptRecord, budget *economic.BudgetVerdictReceipt) ([]string, []string, error) {
	var checked []string
	signers := make(map[string]bool)
	for _, rec := range records {
		if err := rec.checkPayload(); err != nil {
			return nil, nil, fmt.Errorf("spendproxy: intent %s: %w", intentID, err)
		}
		payload := rec.Payload()
		if payload == nil {
			continue
		}
		if rec.PayloadSignature == "" || rec.PayloadSignatureKeyID == "" {
			return nil, nil, fmt.Errorf("spendproxy: %s record of intent %s carries no signature; it cannot be verified", rec.Kind, intentID)
		}
		pub, ok := pinned[rec.PayloadSignatureKeyID]
		if !ok {
			return nil, nil, fmt.Errorf("spendproxy: %s record of intent %s is signed by key %q, not a pinned key (%s)", rec.Kind, intentID, rec.PayloadSignatureKeyID, pinnedIDs(pinned))
		}
		if err := verifyDetached(pub, payload, rec.PayloadSignature); err != nil {
			return nil, nil, fmt.Errorf("spendproxy: %s record of intent %s: %w", rec.Kind, intentID, err)
		}
		checked = append(checked, string(rec.Kind))
		signers[rec.PayloadSignatureKeyID] = true
	}
	if budget != nil {
		pub, ok := pinned[budget.SignatureKeyID]
		if !ok {
			return nil, nil, fmt.Errorf("spendproxy: budget verdict of intent %s is sealed by key %q, not a pinned key (%s)", intentID, budget.SignatureKeyID, pinnedIDs(pinned))
		}
		if err := budget.VerifySignature(pub); err != nil {
			return nil, nil, fmt.Errorf("spendproxy: budget verdict seal of intent %s: %w", intentID, err)
		}
		checked = append(checked, "budget_verdict_seal")
		signers[budget.SignatureKeyID] = true
	}
	ids := make([]string, 0, len(signers))
	for id := range signers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return checked, ids, nil
}

// pinnedIDs lists the pinned keys' ids, sorted.
func pinnedIDs(pinned map[string]ed25519.PublicKey) string {
	ids := make([]string, 0, len(pinned))
	for id := range pinned {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

// verifyDetached checks an issuer's detached Ed25519 signature over the JCS
// canonicalization of payload.
func verifyDetached(pub ed25519.PublicKey, payload any, signature string) error {
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errors.New("the signature is not base64")
	}
	if !ed25519.Verify(pub, canonical, raw) {
		return errors.New("the signature does not verify against the pinned key")
	}
	return nil
}

func writePackContents(dir string, contents map[string][]byte) error {
	for path, data := range contents {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return fmt.Errorf("spendproxy: create pack dir: %w", err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			return fmt.Errorf("spendproxy: write pack entry %s: %w", path, err)
		}
	}
	return nil
}
