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
	SignatureKeyID    string   `json:"signature_key_id,omitempty"`
	OutputDir         string   `json:"output_dir"`
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
// OutDir/<spend_intent_id>/. With a pinned PublicKey it also verifies every
// signature of each exported intent (helm-tracker#313, audit M18): the detached
// signature of each of its records and its budget-verdict seal. A record that is
// unsigned, signed by another key or whose signature does not verify fails the
// export.
func ExportEvidencePacks(opts ExportOptions) ([]ExportResult, error) {
	records, err := LoadRecords(filepath.Join(opts.ReceiptsDir, ReceiptLogName))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("spendproxy: receipt log is empty; nothing to export")
	}
	keyID := ""
	if opts.PublicKey != nil {
		if len(opts.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("spendproxy: the pinned public key must be %d bytes", ed25519.PublicKeySize)
		}
		keyID = IssuerKeyID(opts.PublicKey)
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
		if opts.PublicKey != nil {
			checked, err := verifyIntentSignatures(opts.PublicKey, keyID, intentID, g.records, g.set.Budget)
			if err != nil {
				return nil, err
			}
			res.SignaturesChecked = checked
			res.SignatureKeyID = keyID
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

// verifyIntentSignatures checks, against pub, the detached signature of every
// record of one intent that carries a receipt payload, and the seal of its
// budget verdict. It returns what it checked.
func verifyIntentSignatures(pub ed25519.PublicKey, keyID, intentID string, records []*ReceiptRecord, budget *economic.BudgetVerdictReceipt) ([]string, error) {
	var checked []string
	for _, rec := range records {
		payload := rec.Payload()
		if payload == nil {
			continue
		}
		if rec.PayloadSignature == "" || rec.PayloadSignatureKeyID == "" {
			return nil, fmt.Errorf("spendproxy: %s record of intent %s carries no signature; it cannot be verified", rec.Kind, intentID)
		}
		if rec.PayloadSignatureKeyID != keyID {
			return nil, fmt.Errorf("spendproxy: %s record of intent %s is signed by key %q, not the pinned key %q", rec.Kind, intentID, rec.PayloadSignatureKeyID, keyID)
		}
		if err := verifyDetached(pub, payload, rec.PayloadSignature); err != nil {
			return nil, fmt.Errorf("spendproxy: %s record of intent %s: %w", rec.Kind, intentID, err)
		}
		checked = append(checked, string(rec.Kind))
	}
	if budget != nil {
		if budget.SignatureKeyID != keyID {
			return nil, fmt.Errorf("spendproxy: budget verdict of intent %s is sealed by key %q, not the pinned key %q", intentID, budget.SignatureKeyID, keyID)
		}
		if err := budget.VerifySignature(pub); err != nil {
			return nil, fmt.Errorf("spendproxy: budget verdict seal of intent %s: %w", intentID, err)
		}
		checked = append(checked, "budget_verdict_seal")
	}
	return checked, nil
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
