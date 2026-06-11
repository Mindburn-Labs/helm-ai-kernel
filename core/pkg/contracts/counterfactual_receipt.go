package contracts

import (
	"fmt"
	"sort"
	"time"
)

// Enforcement labels whether a receipt records authority that was actually
// enforced at the boundary, or a counterfactual ("would-have") verdict computed
// under an observe grant without any enforcement or side effect.
//
// This distinction is proof-semantics-critical: conflating a counterfactual
// receipt with an enforced one would manufacture false execution authority. The
// two values are therefore machine-distinct, and CounterfactualReceipt below
// can ONLY ever carry EnforcementCounterfactual — its sealing refuses any other
// value (see negative vector in counterfactual_receipt_test.go).
type Enforcement string

const (
	// EnforcementEnforced marks a receipt for a verdict the boundary actually
	// enforced. This is the default proof-bearing disposition.
	EnforcementEnforced Enforcement = "enforced"

	// EnforcementCounterfactual marks a receipt for a verdict the PDP WOULD
	// have issued under an observe grant. It is signed and verifiable like any
	// receipt, but it confers NO execution authority and MUST NEVER be
	// presentable or parseable as enforced.
	EnforcementCounterfactual Enforcement = "counterfactual"
)

// IsCanonicalEnforcement reports whether e is one of the two canonical
// enforcement labels.
func IsCanonicalEnforcement(e string) bool {
	return e == string(EnforcementEnforced) || e == string(EnforcementCounterfactual)
}

// CounterfactualReceipt is a signed, content-addressed proof of the verdict the
// PDP would have issued under an observe grant, carrying the full verdict and
// reason codes without enforcing anything. It is the artifact that turns the
// "observe → enforce" on-ramp into a business case: the weekly summary becomes
// "HELM would have blocked these N actions".
//
// Invariants (enforced by Validate):
//   - Enforcement is ALWAYS EnforcementCounterfactual. A counterfactual receipt
//     that claims to be enforced is rejected — that is the P0 negative vector.
//   - It binds the explicit ObserveGrantID it was produced under. No grant, no
//     counterfactual receipt (mirrors firewall.ObserveGrant.Active).
//   - It binds the sealed ExecutionBoundaryRecord hash whose verdict it mirrors,
//     so an offline verifier can re-derive the would-have decision.
type CounterfactualReceipt struct {
	ReceiptID string `json:"receipt_id"`

	// Enforcement is always EnforcementCounterfactual for this type.
	Enforcement Enforcement `json:"enforcement"`

	// WouldHaveVerdict is the verdict the PDP would have issued (ALLOW, DENY, or
	// ESCALATE). Counterfactual receipts are emitted for every evaluated action,
	// including ALLOW, so the summary can show coverage as well as blocks.
	WouldHaveVerdict Verdict    `json:"would_have_verdict"`
	ReasonCode       ReasonCode `json:"reason_code,omitempty"`

	// Boundary linkage — what was evaluated and under which authority.
	ObserveGrantID     string `json:"observe_grant_id"`
	BoundaryRecordID   string `json:"boundary_record_id"`
	BoundaryRecordHash string `json:"boundary_record_hash"`
	PolicyEpoch        string `json:"policy_epoch"`

	// Attribution dimensions for the deterministic summary.
	ToolName    string `json:"tool_name,omitempty"`
	MCPServerID string `json:"mcp_server_id,omitempty"`
	ArgsHash    string `json:"args_hash,omitempty"`

	CreatedAt time.Time `json:"created_at"`

	// Signature over SigningPayload, populated after signing. Empty until signed.
	SignerKeyID string `json:"signer_key_id,omitempty"`
	Signature   string `json:"signature,omitempty"`

	// ReceiptHash is the JCS+SHA-256 digest of the unsigned receipt. It is the
	// content address and the basis the signature covers.
	ReceiptHash string `json:"receipt_hash,omitempty"`
}

// Validate enforces the counterfactual invariants. It deliberately REJECTS any
// receipt whose Enforcement is not EnforcementCounterfactual — coercing one into
// "enforced" must fail closed, never succeed silently.
func (r CounterfactualReceipt) Validate() error {
	if r.ReceiptID == "" {
		return fmt.Errorf("counterfactual receipt id is required")
	}
	if r.Enforcement != EnforcementCounterfactual {
		return fmt.Errorf("counterfactual receipt enforcement must be %q, got %q (false execution authority is forbidden)", EnforcementCounterfactual, r.Enforcement)
	}
	if !IsCanonicalVerdict(string(r.WouldHaveVerdict)) {
		return fmt.Errorf("invalid would-have verdict %q", r.WouldHaveVerdict)
	}
	if r.WouldHaveVerdict != VerdictAllow && r.ReasonCode == "" {
		return fmt.Errorf("counterfactual DENY/ESCALATE receipts require a reason code")
	}
	if r.ReasonCode != "" && !IsCanonicalReasonCode(string(r.ReasonCode)) {
		return fmt.Errorf("invalid reason code %q", r.ReasonCode)
	}
	if r.ObserveGrantID == "" {
		return fmt.Errorf("counterfactual receipt requires an observe grant id (no grant, no observe mode)")
	}
	if r.BoundaryRecordID == "" || r.BoundaryRecordHash == "" {
		return fmt.Errorf("counterfactual receipt must bind a sealed boundary record id and hash")
	}
	if r.PolicyEpoch == "" {
		return fmt.Errorf("policy epoch is required")
	}
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	return nil
}

// Seal validates the receipt and computes its content-addressed ReceiptHash
// over the unsigned, JCS-canonicalized body (signature fields excluded). The
// returned receipt is the signing preimage carrier; call SigningPayload for the
// exact bytes a Signer covers.
func (r CounterfactualReceipt) Seal() (CounterfactualReceipt, error) {
	if err := r.Validate(); err != nil {
		return CounterfactualReceipt{}, err
	}
	r.Signature = ""
	r.SignerKeyID = ""
	r.ReceiptHash = ""
	hash, err := hashJCS(r)
	if err != nil {
		return CounterfactualReceipt{}, err
	}
	r.ReceiptHash = hash
	return r, nil
}

// SigningPayload returns the deterministic bytes a Signer covers. It is the
// sealed ReceiptHash prefixed with the enforcement label so a signature minted
// over a counterfactual receipt can never be replayed as an enforced one.
func (r CounterfactualReceipt) SigningPayload() string {
	return string(EnforcementCounterfactual) + ":" + r.ReceiptHash
}

// AsEnforcedReceipt is intentionally NOT provided. Counterfactual receipts have
// no path to an enforced Receipt; any such coercion must be written explicitly
// at a call site and will fail Validate() because Enforcement is locked.

// CounterfactualSummary aggregates counterfactual DENY/ESCALATE counts by
// policy, tool, and MCP server. Output is deterministic: maps are emitted as
// sorted slices so the same receipt stream always produces byte-identical JSON.
type CounterfactualSummary struct {
	Version        string                     `json:"version"`
	ObserveGrantID string                     `json:"observe_grant_id,omitempty"`
	TotalEvaluated int                        `json:"total_evaluated"`
	WouldAllow     int                        `json:"would_allow"`
	WouldDeny      int                        `json:"would_deny"`
	WouldEscalate  int                        `json:"would_escalate"`
	ByPolicyEpoch  []CounterfactualCountEntry `json:"by_policy_epoch"`
	ByTool         []CounterfactualCountEntry `json:"by_tool"`
	ByMCPServer    []CounterfactualCountEntry `json:"by_mcp_server"`
	ByReasonCode   []CounterfactualCountEntry `json:"by_reason_code"`
	GeneratedAt    time.Time                  `json:"generated_at"`
}

// CounterfactualCountEntry is one (key, deny, escalate) tuple in a summary
// dimension. Allow is intentionally omitted from per-dimension entries: the
// negative-space screenshot counts blocks, not permits.
type CounterfactualCountEntry struct {
	Key      string `json:"key"`
	Deny     int    `json:"deny"`
	Escalate int    `json:"escalate"`
}

// SummarizeCounterfactuals folds a slice of sealed counterfactual receipts into
// a deterministic summary. Receipts whose Enforcement is not counterfactual are
// rejected — a summary must never silently fold an enforced receipt into the
// "would have" narrative.
func SummarizeCounterfactuals(receipts []CounterfactualReceipt, generatedAt time.Time) (CounterfactualSummary, error) {
	summary := CounterfactualSummary{
		Version:     "counterfactual-summary/v1",
		GeneratedAt: generatedAt.UTC(),
	}
	byPolicy := map[string]*[2]int{}
	byTool := map[string]*[2]int{}
	byServer := map[string]*[2]int{}
	byReason := map[string]*[2]int{}

	bump := func(m map[string]*[2]int, key string, idx int) {
		if key == "" {
			return
		}
		entry, ok := m[key]
		if !ok {
			entry = &[2]int{}
			m[key] = entry
		}
		entry[idx]++
	}

	for i, r := range receipts {
		if r.Enforcement != EnforcementCounterfactual {
			return CounterfactualSummary{}, fmt.Errorf("receipt %d is not counterfactual (enforcement=%q); refusing to fold into a would-have summary", i, r.Enforcement)
		}
		if summary.ObserveGrantID == "" {
			summary.ObserveGrantID = r.ObserveGrantID
		} else if summary.ObserveGrantID != r.ObserveGrantID {
			summary.ObserveGrantID = "mixed"
		}
		summary.TotalEvaluated++
		switch r.WouldHaveVerdict {
		case VerdictAllow:
			summary.WouldAllow++
			continue // ALLOW is coverage, not a block; not folded per-dimension.
		case VerdictDeny:
			summary.WouldDeny++
			bump(byPolicy, r.PolicyEpoch, 0)
			bump(byTool, r.ToolName, 0)
			bump(byServer, r.MCPServerID, 0)
			bump(byReason, string(r.ReasonCode), 0)
		case VerdictEscalate:
			summary.WouldEscalate++
			bump(byPolicy, r.PolicyEpoch, 1)
			bump(byTool, r.ToolName, 1)
			bump(byServer, r.MCPServerID, 1)
			bump(byReason, string(r.ReasonCode), 1)
		}
	}

	summary.ByPolicyEpoch = sortedEntries(byPolicy)
	summary.ByTool = sortedEntries(byTool)
	summary.ByMCPServer = sortedEntries(byServer)
	summary.ByReasonCode = sortedEntries(byReason)
	return summary, nil
}

func sortedEntries(m map[string]*[2]int) []CounterfactualCountEntry {
	out := make([]CounterfactualCountEntry, 0, len(m))
	for key, counts := range m {
		out = append(out, CounterfactualCountEntry{Key: key, Deny: counts[0], Escalate: counts[1]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
