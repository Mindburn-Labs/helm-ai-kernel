package decisionreceipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// HelmExternalFormatID is HELM's own self-describing external decision-receipt
// format. It exercises the full verify+classify pipeline end-to-end and is the
// import target that vendor adapters (AAR, ACTA, …) normalize into.
const HelmExternalFormatID = "helm_external.v1"

func init() { Register(helmExternalAdapter{}) }

type helmExternalAdapter struct{}

func (helmExternalAdapter) FormatID() string { return HelmExternalFormatID }
func (helmExternalAdapter) Kind() contracts.ExternalReceiptKind {
	return contracts.KindExternalDecision
}

func (helmExternalAdapter) Detect(raw []byte) bool {
	return strings.Contains(string(raw), HelmExternalFormatID)
}

func (helmExternalAdapter) Parse(raw []byte) ([]contracts.ExternalDecisionReceipt, error) {
	var bundle contracts.ExternalDecisionReceiptBundle
	if err := json.Unmarshal(raw, &bundle); err == nil && len(bundle.Receipts) > 0 {
		out := bundle.Receipts
		for i := range out {
			normalizeHelmExternal(&out[i])
		}
		return out, nil
	}
	var single contracts.ExternalDecisionReceipt
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, err
	}
	normalizeHelmExternal(&single)
	return []contracts.ExternalDecisionReceipt{single}, nil
}

func normalizeHelmExternal(r *contracts.ExternalDecisionReceipt) {
	if r.SchemaVersion == "" {
		r.SchemaVersion = contracts.ExternalDecisionReceiptVersion
	}
	r.Kind = contracts.KindExternalDecision
	if r.FormatID == "" {
		r.FormatID = HelmExternalFormatID
	}
}

// CanonicalSignedBytes is JCS over the receipt with every HELM-assigned and
// signature field cleared, so the bytes are identical at signing and
// verification time.
func (helmExternalAdapter) CanonicalSignedBytes(r contracts.ExternalDecisionReceipt) ([]byte, error) {
	c := r
	c.Signature = ""
	c.ReceiptHash = ""
	c.Classification = ""
	c.OriginalDigest = ""
	c.Limitations = nil
	return canonicalize.JCS(c)
}

// SignHelmExternal signs r under helm_external.v1, setting ReceiptHash and
// Signature. Exposed for producers and test fixtures.
func SignHelmExternal(r contracts.ExternalDecisionReceipt, priv ed25519.PrivateKey) (contracts.ExternalDecisionReceipt, error) {
	a := helmExternalAdapter{}
	normalizeHelmExternal(&r)
	if r.SignatureAlgorithm == "" {
		r.SignatureAlgorithm = "Ed25519"
	}
	data, err := a.CanonicalSignedBytes(r)
	if err != nil {
		return r, err
	}
	r.ReceiptHash = "sha256:" + canonicalize.HashBytes(data)
	r.Signature = hex.EncodeToString(ed25519.Sign(priv, data))
	return r, nil
}
