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
	"strings"
	"time"

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

// GatewayOutcomeBindingVersion names the closed document whose SHA-256 a
// gateway outcome receipt (status OBSERVED, RECONCILED or SETTLED, empty
// verdict) signs as output_hash. Its JSON schema is
// protocols/json-schemas/gateway/outcome-binding.v1.schema.json.
const GatewayOutcomeBindingVersion = "helm.gateway.outcome-binding.v1"

// GatewayOutcomeBinding is helm.gateway.outcome-binding.v1: the outcome of an
// admitted effect tied to its attempt, the permit it was dispatched under and
// the authority versions of that permit, with the observation it rests on and
// the settlement the ledger holds after the write. Every member is always
// present; ModelCall is null for an effect that is not a model call.
type GatewayOutcomeBinding struct {
	BindingVersion    string                           `json:"binding_version"`
	ChainID           string                           `json:"chain_id"`
	Seq               uint64                           `json:"seq"`
	TenantID          string                           `json:"tenant_id"`
	WorkspaceID       string                           `json:"workspace_id"`
	AttemptID         string                           `json:"attempt_id"`
	AttemptVersion    int64                            `json:"attempt_version"`
	FromState         string                           `json:"from_state"`
	State             string                           `json:"state"`
	ReasonCode        string                           `json:"reason_code"`
	EffectType        string                           `json:"effect_type"`
	RequestDigest     string                           `json:"request_digest"`
	TargetDigest      string                           `json:"target_digest"`
	ArgumentDigest    string                           `json:"argument_digest"`
	PermitID          string                           `json:"permit_id"`
	AuthorityVersions []GatewayBindingAuthorityVersion `json:"authority_versions"`
	PolicyHash        string                           `json:"policy_hash"`
	Outcome           string                           `json:"outcome"`
	OutcomeBasis      string                           `json:"outcome_basis"`
	SettledBy         string                           `json:"settled_by"`
	Observation       GatewayOutcomeObservation        `json:"observation"`
	Reservation       string                           `json:"reservation"`
	ReadbackAbsent    bool                             `json:"readback_absent"`
	Exposures         []GatewayOutcomeExposure         `json:"exposures"`
	ModelCall         *GatewayOutcomeModelCall         `json:"model_call"`
	SettledAt         string                           `json:"settled_at"`
}

// GatewayOutcomeObservation is the stored observation an outcome rests on.
type GatewayOutcomeObservation struct {
	ID             int64  `json:"id"`
	Source         string `json:"source"`
	TrustClass     string `json:"trust_class"`
	Outcome        string `json:"outcome"`
	EvidenceDigest string `json:"evidence_digest"`
	ResultKind     string `json:"result_kind"`
	ResultRef      string `json:"result_ref"`
	ObservedAt     string `json:"observed_at"`
}

// GatewayOutcomeExposure is one exposure of the attempt after the outcome
// write.
type GatewayOutcomeExposure struct {
	LimitID     string `json:"limit_id"`
	BucketStart string `json:"bucket_start"`
	Kind        string `json:"kind"`
	Amount      string `json:"amount"`
}

// GatewayOutcomeModelCall is a model call's money row after its settlement.
type GatewayOutcomeModelCall struct {
	State           string `json:"state"`
	HeldMicros      string `json:"held_micros"`
	EstimatedMicros string `json:"estimated_micros"`
	ConfirmedMicros string `json:"confirmed_micros"`
	BillableMicros  string `json:"billable_micros"`
	UsageDigest     string `json:"usage_digest"`
}

// GatewayChainID names the receipt chain of a (tenant, workspace): each part
// is prefixed by its byte length, so no two pairs share an id whatever they
// contain. A gateway receipt carries it as session_id.
func GatewayChainID(tenantID, workspaceID string) string {
	return "helm-gateway:" + strconv.Itoa(len(tenantID)) + ":" + tenantID + ":" + strconv.Itoa(len(workspaceID)) + ":" + workspaceID
}

// gatewayChainPrefix starts every gateway chain id. A receipt whose
// session_id has it is a gateway receipt, whose gateway facts only a binding
// document carries.
const gatewayChainPrefix = "helm-gateway:"

// parseClosedBinding decodes raw into the closed document out points to. It
// refuses a duplicate or unknown member and bytes that are not their own
// RFC 8785 (JCS) encoding: the bytes a receipt signs are the canonical bytes,
// so a missing member, or any other spelling of the same values, is a
// different document.
func parseClosedBinding(raw []byte, version string, out any) error {
	if err := ValidateJSONStructure(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("not a %s document: %w", version, err)
	}
	canonical, err := canonicalize.InteroperableJCS(out)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, raw) {
		return errors.New("the bytes are not the canonical (JCS) encoding of a complete binding; a member is missing, misspelled or re-encoded")
	}
	return nil
}

// ParseGatewayBinding parses binding bytes as the closed
// helm.gateway.receipt-binding.v1 document: no duplicate, unknown or missing
// member, no null array, integers spelled as integers, its own
// binding_version, and its own JCS bytes.
func ParseGatewayBinding(raw []byte) (GatewayBinding, error) {
	var binding GatewayBinding
	if err := parseClosedBinding(raw, GatewayBindingVersion, &binding); err != nil {
		return GatewayBinding{}, err
	}
	if binding.BindingVersion != GatewayBindingVersion {
		return GatewayBinding{}, fmt.Errorf("binding_version %q is not %q", binding.BindingVersion, GatewayBindingVersion)
	}
	if binding.Quote == nil || binding.AuthorityVersions == nil {
		return GatewayBinding{}, errors.New("quote and authority_versions must be arrays")
	}
	return binding, nil
}

// ParseGatewayOutcomeBinding parses binding bytes as the closed
// helm.gateway.outcome-binding.v1 document, under the same rules as
// ParseGatewayBinding.
func ParseGatewayOutcomeBinding(raw []byte) (GatewayOutcomeBinding, error) {
	var binding GatewayOutcomeBinding
	if err := parseClosedBinding(raw, GatewayOutcomeBindingVersion, &binding); err != nil {
		return GatewayOutcomeBinding{}, err
	}
	if binding.BindingVersion != GatewayOutcomeBindingVersion {
		return GatewayOutcomeBinding{}, fmt.Errorf("binding_version %q is not %q", binding.BindingVersion, GatewayOutcomeBindingVersion)
	}
	if binding.AuthorityVersions == nil || binding.Exposures == nil {
		return GatewayOutcomeBinding{}, errors.New("authority_versions and exposures must be arrays")
	}
	return binding, nil
}

// bindingRow is one signed receipt field and what its binding says it is.
type bindingRow struct {
	name, got, want string
}

// receiptTime is a receipt's timestamp as the gateway writes a binding's
// times: UTC, RFC 3339 with nanoseconds. The timestamp is outside the
// receipt.v5 preimage; the row that compares it with the signed binding is
// what binds it.
func receiptTime(r *contracts.Receipt) string {
	return r.Timestamp.UTC().Format(time.RFC3339Nano)
}

// decisionRows are the receipt fields a helm.gateway.receipt-binding.v1
// document must agree with.
func decisionRows(r *contracts.Receipt, b GatewayBinding) ([]bindingRow, error) {
	if b.TenantID == "" || b.WorkspaceID == "" || b.AttemptID == "" || b.AttemptVersion < 1 || b.Seq < 1 {
		return nil, errors.New("the binding names no tenant, workspace, attempt, version or sequence")
	}
	return []bindingRow{
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
		{"timestamp", receiptTime(r), b.DecidedAt},
	}, nil
}

// outcomeRows are the receipt fields a helm.gateway.outcome-binding.v1
// document must agree with. An outcome receipt carries no verdict: its status
// is the outcome state the write left.
func outcomeRows(r *contracts.Receipt, b GatewayOutcomeBinding) ([]bindingRow, error) {
	if b.TenantID == "" || b.WorkspaceID == "" || b.AttemptID == "" || b.AttemptVersion < 1 || b.Seq < 1 || b.PermitID == "" {
		return nil, errors.New("the binding names no tenant, workspace, attempt, version, sequence or permit")
	}
	switch b.State {
	case "OBSERVED", "RECONCILED", "SETTLED":
	default:
		return nil, fmt.Errorf("state %q is not an outcome state", b.State)
	}
	return []bindingRow{
		{"chain_id framing", b.ChainID, GatewayChainID(b.TenantID, b.WorkspaceID)},
		{"session_id", r.SessionID, b.ChainID},
		{"lamport_clock", strconv.FormatUint(r.LamportClock, 10), strconv.FormatUint(b.Seq, 10)},
		{"decision_id", r.DecisionID, b.AttemptID + ":" + strconv.FormatInt(b.AttemptVersion, 10)},
		{"effect_id", r.EffectID, b.AttemptID},
		{"status", r.Status, b.State},
		{"verdict", r.Verdict, ""},
		{"reason_code", r.ReasonCode, b.ReasonCode},
		{"policy_hash", r.PolicyHash, b.PolicyHash},
		{"args_hash", r.ArgsHash, b.ArgumentDigest},
		{"timestamp", receiptTime(r), b.SettledAt},
	}, nil
}

// gatewayBindingMismatch parses a binding under the closed document its
// binding_version names and returns the first signed receipt field it does
// not agree with, or "" when every one agrees. A version this verifier does
// not know fails: it is never read as another version.
func gatewayBindingMismatch(r *contracts.Receipt, raw []byte) (string, error) {
	if err := ValidateJSONStructure(raw); err != nil {
		return "", err
	}
	var head struct {
		BindingVersion *string `json:"binding_version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.BindingVersion == nil {
		return "", errors.New("the binding names no binding_version")
	}
	var rows []bindingRow
	switch *head.BindingVersion {
	case GatewayBindingVersion:
		binding, err := ParseGatewayBinding(raw)
		if err != nil {
			return "", err
		}
		if rows, err = decisionRows(r, binding); err != nil {
			return "", err
		}
	case GatewayOutcomeBindingVersion:
		binding, err := ParseGatewayOutcomeBinding(raw)
		if err != nil {
			return "", err
		}
		if rows, err = outcomeRows(r, binding); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("binding_version %q is not one this verifier knows (%s, %s)",
			*head.BindingVersion, GatewayBindingVersion, GatewayOutcomeBindingVersion)
	}
	for _, row := range rows {
		if row.got != row.want {
			return fmt.Sprintf("%s %q does not match the binding's %q", row.name, row.got, row.want), nil
		}
	}
	return "", nil
}

// checkBindings runs CheckBinding and counts what it covered into res. No
// binding supplied is not_applicable, never success, unless require is set
// and the bundle holds a gateway receipt: then it fails. A binding for a
// receipt the bundle does not hold fails: a verifier that ignored it would let
// a reader believe it had been checked.
func checkBindings(receipts []*contracts.Receipt, bindings map[string][]byte, require bool, res *Result) Check {
	for _, r := range receipts {
		if strings.HasPrefix(r.SessionID, gatewayChainPrefix) {
			res.GatewayReceipts++
		}
	}
	if require {
		for i, r := range receipts {
			if _, bound := bindings[r.ReceiptID]; strings.HasPrefix(r.SessionID, gatewayChainPrefix) && !bound {
				return Check{CheckBinding, StatusFail, fmt.Sprintf(
					"receipt[%d] %q is a gateway receipt with no binding document, and bindings are required: its gateway facts would go unchecked",
					i, r.ReceiptID)}
			}
		}
	}
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
		if r.SignatureVersion != contracts.ReceiptSignatureV5 {
			return Check{CheckBinding, StatusFail, fmt.Sprintf(
				"receipt[%d] %q is signed under %q, not %s: its signature does not cover session_id, verdict, reason_code or policy_hash, so no binding can be checked against it",
				i, id, r.SignatureVersion, contracts.ReceiptSignatureV5)}
		}
		sum := sha256.Sum256(bindings[id])
		if r.OutputHash != hex.EncodeToString(sum[:]) {
			return Check{CheckBinding, StatusFail, fmt.Sprintf(
				"receipt[%d] %q: output_hash %q is not the SHA-256 of the supplied binding (%x); the binding is not the document the receipt signed",
				i, id, r.OutputHash, sum)}
		}
		mismatch, err := gatewayBindingMismatch(r, bindings[id])
		if err != nil {
			return Check{CheckBinding, StatusFail, fmt.Sprintf("receipt[%d] %q: binding: %v", i, id, err)}
		}
		if mismatch != "" {
			return Check{CheckBinding, StatusFail, fmt.Sprintf("receipt[%d] %q: %s", i, id, mismatch)}
		}
	}
	res.BindingsChecked = len(bindings)
	d := fmt.Sprintf("%d/%d receipt(s) carry a binding document whose SHA-256 is the signed output_hash, closed, canonical "+
		"and in agreement with the receipt's chain, sequence, attempt, version, state, verdict, reason, policy and argument "+
		"digests and time; the binding states what the gateway recorded, which this verifier cannot see",
		len(bindings), len(receipts))
	if len(bindings) < len(receipts) {
		d += fmt.Sprintf(" (%d receipt(s) carry no binding and their output_hash was not recomputed)", len(receipts)-len(bindings))
	}
	return Check{CheckBinding, StatusPass, d}
}
