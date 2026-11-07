// quantum_posture: recomputes the SHA-256 output_hash of gateway decision
// receipts over their binding documents; it adds no signature scheme or
// trusted root, and the receipts themselves stay classical Ed25519.
package receiptverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// CheckBinding recomputes the output_hash of gateway receipts over the binding
// documents the bundle supplies and checks that each binding describes the
// receipt that signs it. It proves the gateway signed those exact gateway
// facts (tenant, workspace, attempt, version, state and the rest of the
// binding). It does not prove the facts are true of any ledger it cannot see.
const CheckBinding CheckName = "binding"

// GatewayBindingVersion names the closed document whose SHA-256 a gateway
// decision receipt signs as output_hash. Its JSON schema is
// protocols/json-schemas/gateway/receipt-binding.v1.schema.json. A new member
// is a new version; this one stays verifiable.
const GatewayBindingVersion = "helm.gateway.receipt-binding.v1"

// GatewayBinding is helm.gateway.receipt-binding.v1, the one definition the
// gateway writes and this verifier reads. Every member is always present: an
// empty string is a signed value, never an omitted field. Amounts are decimal
// strings so the document stays inside the number range every RFC 8785
// implementation reproduces.
type GatewayBinding struct {
	BindingVersion        string                           `json:"binding_version"`
	ChainID               string                           `json:"chain_id"`
	Seq                   uint64                           `json:"seq"`
	TenantID              string                           `json:"tenant_id"`
	WorkspaceID           string                           `json:"workspace_id"`
	AttemptID             string                           `json:"attempt_id"`
	AttemptVersion        int64                            `json:"attempt_version"`
	FromState             string                           `json:"from_state"`
	State                 string                           `json:"state"`
	Verdict               string                           `json:"verdict"`
	ReasonCode            string                           `json:"reason_code"`
	EffectType            string                           `json:"effect_type"`
	RequesterPrincipalID  string                           `json:"requester_principal_id"`
	RequesterActorID      string                           `json:"requester_actor_id"`
	MandateID             string                           `json:"mandate_id"`
	RiskClass             string                           `json:"risk_class"`
	RequestDigest         string                           `json:"request_digest"`
	TargetDigest          string                           `json:"target_digest"`
	ArgumentDigest        string                           `json:"argument_digest"`
	Quote                 []GatewayBindingAmount           `json:"quote"`
	ApprovalDigest        string                           `json:"approval_digest"`
	ApprovalExpiresAt     string                           `json:"approval_expires_at"`
	ApproverPrincipalID   string                           `json:"approver_principal_id"`
	ApproverActorID       string                           `json:"approver_actor_id"`
	StepUpIssuer          string                           `json:"step_up_issuer"`
	StepUpJTI             string                           `json:"step_up_jti"`
	PermitID              string                           `json:"permit_id"`
	AuthorityVersions     []GatewayBindingAuthorityVersion `json:"authority_versions"`
	PolicyHash            string                           `json:"policy_hash"`
	EpisodeID             string                           `json:"episode_id"`
	OrganizationVersionID string                           `json:"organization_version_id"`
	DecidedAt             string                           `json:"decided_at"`
}

// GatewayBindingAmount is one quote entry of a binding.
type GatewayBindingAmount struct {
	Unit   string `json:"unit"`
	Amount string `json:"amount"`
}

// GatewayBindingAuthorityVersion is one authority row version a decision
// locked.
type GatewayBindingAuthorityVersion struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Version int64  `json:"version"`
}

// GatewayChainID names the receipt chain of a (tenant, workspace): each part
// is prefixed by its byte length, so no two pairs share an id whatever they
// contain. A gateway receipt carries it as session_id.
func GatewayChainID(tenantID, workspaceID string) string {
	return "helm-gateway:" + strconv.Itoa(len(tenantID)) + ":" + tenantID + ":" + strconv.Itoa(len(workspaceID)) + ":" + workspaceID
}

// ParseGatewayBinding parses binding bytes as the closed
// helm.gateway.receipt-binding.v1 document. It refuses a duplicate or unknown
// member, a missing one, a null array, an integer spelled any other way, a
// binding_version it does not know, and bytes that are not their own RFC 8785
// (JCS) encoding: the bytes a receipt signs are the canonical bytes, so any
// other spelling of the same values is a different document.
func ParseGatewayBinding(raw []byte) (GatewayBinding, error) {
	if err := ValidateJSONStructure(raw); err != nil {
		return GatewayBinding{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var binding GatewayBinding
	if err := decoder.Decode(&binding); err != nil {
		return GatewayBinding{}, fmt.Errorf("not a %s document: %w", GatewayBindingVersion, err)
	}
	if binding.BindingVersion != GatewayBindingVersion {
		return GatewayBinding{}, fmt.Errorf("binding_version %q is not %q", binding.BindingVersion, GatewayBindingVersion)
	}
	if binding.Quote == nil || binding.AuthorityVersions == nil {
		return GatewayBinding{}, errors.New("quote and authority_versions must be arrays")
	}
	canonical, err := canonicalize.InteroperableJCS(binding)
	if err != nil {
		return GatewayBinding{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return GatewayBinding{}, errors.New("the bytes are not the canonical (JCS) encoding of a complete binding; a member is missing, misspelled or re-encoded")
	}
	return binding, nil
}

// gatewayBindingMismatch names the first signed receipt field the binding does
// not agree with, or "" when every one agrees.
func gatewayBindingMismatch(r *contracts.Receipt, b GatewayBinding) string {
	checks := []struct {
		name      string
		got, want string
	}{
		{"chain_id framing", b.ChainID, GatewayChainID(b.TenantID, b.WorkspaceID)},
		{"session_id", r.SessionID, b.ChainID},
		{"lamport_clock", strconv.FormatUint(r.LamportClock, 10), strconv.FormatUint(b.Seq, 10)},
		{"decision_id", r.DecisionID, b.AttemptID + ":" + strconv.FormatInt(b.AttemptVersion, 10)},
		{"effect_id", r.EffectID, b.AttemptID},
		{"status", r.Status, b.State},
		{"verdict", r.Verdict, b.Verdict},
		{"reason_code", r.ReasonCode, b.ReasonCode},
		{"policy_hash", r.PolicyHash, b.PolicyHash},
		{"args_hash", r.ArgsHash, b.ArgumentDigest},
	}
	if b.TenantID == "" || b.WorkspaceID == "" || b.AttemptID == "" || b.AttemptVersion < 1 || b.Seq < 1 {
		return "the binding names no tenant, workspace, attempt, version or sequence"
	}
	for _, c := range checks {
		if c.got != c.want {
			return fmt.Sprintf("%s %q does not match the binding's %q", c.name, c.got, c.want)
		}
	}
	return ""
}

// checkBindings runs CheckBinding. No binding supplied is not_applicable,
// never success. A binding for a receipt the bundle does not hold fails: a
// verifier that ignored it would let a reader believe it had been checked.
func checkBindings(receipts []*contracts.Receipt, bindings map[string][]byte) Check {
	if len(bindings) == 0 {
		return Check{CheckBinding, StatusNotApplicable,
			"the bundle carries no gateway bindings; no output_hash was recomputed"}
	}
	byID := make(map[string]int, len(receipts))
	for i, r := range receipts {
		if _, seen := byID[r.ReceiptID]; seen {
			byID[r.ReceiptID] = -1
			continue
		}
		byID[r.ReceiptID] = i
	}
	ids := make([]string, 0, len(bindings))
	for id := range bindings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		i, ok := byID[id]
		if !ok {
			return Check{CheckBinding, StatusFail, fmt.Sprintf(
				"a binding is supplied for receipt %q, which the bundle does not hold", id)}
		}
		if i < 0 {
			return Check{CheckBinding, StatusFail, fmt.Sprintf(
				"receipt id %q names more than one receipt; its binding cannot be placed", id)}
		}
		r := receipts[i]
		sum := sha256.Sum256(bindings[id])
		if r.OutputHash != hex.EncodeToString(sum[:]) {
			return Check{CheckBinding, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: output_hash %q is not the SHA-256 of the supplied binding (%x); the binding is not the document the receipt signed",
				i, id, r.OutputHash, sum)}
		}
		binding, err := ParseGatewayBinding(bindings[id])
		if err != nil {
			return Check{CheckBinding, StatusFail, fmt.Sprintf("receipt[%d] %q: binding: %v", i, id, err)}
		}
		if mismatch := gatewayBindingMismatch(r, binding); mismatch != "" {
			return Check{CheckBinding, StatusFail, fmt.Sprintf("receipt[%d] %q: %s", i, id, mismatch)}
		}
	}
	d := fmt.Sprintf("%d/%d receipt(s) carry a %s binding whose SHA-256 is the signed output_hash, in its canonical form, "+
		"naming the receipt's chain, sequence, attempt, version, state, verdict, policy and argument digests; "+
		"the binding states what the gateway recorded, which this verifier cannot see",
		len(bindings), len(receipts), GatewayBindingVersion)
	if len(bindings) < len(receipts) {
		d += fmt.Sprintf(" (%d receipt(s) carry no binding and their output_hash was not recomputed)", len(receipts)-len(bindings))
	}
	return Check{CheckBinding, StatusPass, d}
}

// GatewayReceipt is one stored gateway receipt: the exact envelope bytes it
// was signed and stored as, and the exact binding bytes its output_hash
// covers.
type GatewayReceipt struct {
	ReceiptID string
	Envelope  []byte
	Binding   []byte
}

// gatewayBundle is the export document: the bundle shape ParseBundle reads.
type gatewayBundle struct {
	Receipts        []json.RawMessage `json:"receipts"`
	GatewayBindings map[string][]byte `json:"gateway_bindings"`
	KeyID           string            `json:"key_id,omitempty"`
}

// EncodeGatewayBundle writes receipts, in the order given, as the document
// receipt_verify --receipt reads: a receipts array holding each envelope's
// exact bytes, gateway_bindings mapping each receipt id to its binding bytes
// (base64), and key_id, the signing key the receipts name, when they all name
// one. Every envelope must parse as a receipt with that receipt id. Nothing
// about trust travels in it: the verifier supplies the key.
func EncodeGatewayBundle(receipts []GatewayReceipt) ([]byte, error) {
	if len(receipts) == 0 {
		return nil, errors.New("a gateway bundle needs at least one receipt")
	}
	out := gatewayBundle{Receipts: make([]json.RawMessage, 0, len(receipts)), GatewayBindings: make(map[string][]byte, len(receipts))}
	keys := map[string]bool{}
	for i, r := range receipts {
		if len(r.Binding) == 0 {
			return nil, fmt.Errorf("receipt[%d] %q has no binding", i, r.ReceiptID)
		}
		parsed, err := ParseBundle(r.Envelope)
		if err != nil || len(parsed.Receipts) != 1 || parsed.Receipts[0] == nil {
			return nil, fmt.Errorf("receipt[%d] %q does not parse as one receipt: %v", i, r.ReceiptID, err)
		}
		if parsed.Receipts[0].ReceiptID != r.ReceiptID {
			return nil, fmt.Errorf("receipt[%d] carries receipt_id %q, not %q", i, parsed.Receipts[0].ReceiptID, r.ReceiptID)
		}
		if _, dup := out.GatewayBindings[r.ReceiptID]; dup {
			return nil, fmt.Errorf("receipt %q appears twice", r.ReceiptID)
		}
		keys[parsed.Receipts[0].KeyID] = true
		out.Receipts = append(out.Receipts, json.RawMessage(bytes.TrimSpace(r.Envelope)))
		out.GatewayBindings[r.ReceiptID] = r.Binding
	}
	if len(keys) == 1 {
		for id := range keys {
			out.KeyID = id
		}
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
