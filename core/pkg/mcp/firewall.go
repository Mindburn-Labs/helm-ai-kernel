package mcp

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type ExecutionFirewall struct {
	Catalog             *ToolCatalog
	Quarantine          *QuarantineRegistry
	PolicyEpoch         string
	RequirePinnedSchema bool
	Clock               func() time.Time

	// Observe, when non-nil and unexpired, switches the firewall into the
	// shadow on-ramp: verdicts are computed and sealed exactly as in enforce
	// mode, but every record is labeled with EnforcementMode "shadow" and the
	// grant ID, and ShouldDispatch permits dispatch for onboarding visibility.
	// It is an explicit, time-boxed grant — never a default. Expiry restores
	// fail-closed enforcement automatically.
	Observe *ObserveGrant
}

// ObserveGrant is the explicit grant that enables shadow (observe-only)
// disposition at the MCP boundary.
type ObserveGrant struct {
	GrantID   string
	Reason    string
	ExpiresAt time.Time
}

// Active reports whether the grant is usable at the given time. A grant with
// no ID or no expiry is never active — shadow mode cannot be open-ended.
func (g *ObserveGrant) Active(now time.Time) bool {
	return g != nil && g.GrantID != "" && !g.ExpiresAt.IsZero() && now.Before(g.ExpiresAt)
}

type ToolCallAuthorization struct {
	ServerID         string
	ToolName         string
	ArgsHash         string
	GrantedScopes    []string
	PinnedSchemaHash string
	OAuthResource    string
	ReceiptID        string
}

func NewExecutionFirewall(catalog *ToolCatalog, quarantine *QuarantineRegistry, policyEpoch string) *ExecutionFirewall {
	if catalog == nil {
		catalog = NewToolCatalog()
	}
	if quarantine == nil {
		quarantine = NewQuarantineRegistry()
	}
	return &ExecutionFirewall{
		Catalog:     catalog,
		Quarantine:  quarantine,
		PolicyEpoch: policyEpoch,
		Clock:       time.Now,
	}
}

// FilterVisibleTools enforces list-time visibility based on quarantine and
// scopes. Call-time authorization is still mandatory.
func (f *ExecutionFirewall) FilterVisibleTools(ctx context.Context, serverID string, tools []ToolRef, grantedScopes []string) ([]ToolRef, error) {
	now := f.now()
	if err := f.Quarantine.RequireApproved(ctx, serverID, now); err != nil {
		return nil, err
	}
	visible := make([]ToolRef, 0, len(tools))
	for _, tool := range tools {
		if tool.ServerID != "" && tool.ServerID != serverID {
			continue
		}
		if hasAllScopes(grantedScopes, tool.RequiredScopes) {
			visible = append(visible, tool)
		}
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].Name < visible[j].Name })
	return visible, nil
}

func (f *ExecutionFirewall) AuthorizeToolCall(ctx context.Context, req ToolCallAuthorization) (contracts.ExecutionBoundaryRecord, error) {
	record := contracts.ExecutionBoundaryRecord{
		RecordID:      fmt.Sprintf("mcp-boundary-%d", f.now().UnixNano()),
		ToolName:      req.ToolName,
		ArgsHash:      req.ArgsHash,
		PolicyEpoch:   f.PolicyEpoch,
		MCPServerID:   req.ServerID,
		OAuthResource: req.OAuthResource,
		OAuthScopes:   sortedCopy(req.GrantedScopes),
		ReceiptID:     req.ReceiptID,
		CreatedAt:     f.now().UTC(),
	}
	if f.Observe.Active(f.now()) {
		record.EnforcementMode = contracts.EnforcementModeShadow
		record.ObserveGrantID = f.Observe.GrantID
	}

	if err := f.Quarantine.RequireApproved(ctx, req.ServerID, f.now()); err != nil {
		record.Verdict = contracts.VerdictDeny
		record.ReasonCode = contracts.ReasonApprovalRequired
		return record.Seal()
	}

	tool, ok := f.Catalog.Lookup(req.ToolName)
	if !ok || (tool.ServerID != "" && tool.ServerID != req.ServerID) {
		record.Verdict = contracts.VerdictDeny
		record.ReasonCode = contracts.ReasonSchemaViolation
		return record.Seal()
	}

	if !hasAllScopes(req.GrantedScopes, tool.RequiredScopes) {
		record.Verdict = contracts.VerdictDeny
		record.ReasonCode = contracts.ReasonInsufficientPrivilege
		return record.Seal()
	}

	hash, err := ToolSchemaHash(tool)
	if err != nil {
		record.Verdict = contracts.VerdictDeny
		record.ReasonCode = contracts.ReasonSchemaViolation
		return record.Seal()
	}
	if f.RequirePinnedSchema && req.PinnedSchemaHash == "" {
		record.Verdict = contracts.VerdictDeny
		record.ReasonCode = contracts.ReasonSchemaViolation
		return record.Seal()
	}
	if req.PinnedSchemaHash != "" && req.PinnedSchemaHash != hash {
		record.Verdict = contracts.VerdictDeny
		record.ReasonCode = contracts.ReasonSchemaViolation
		return record.Seal()
	}

	record.Verdict = contracts.VerdictAllow
	return record.Seal()
}

// CounterfactualReceiptFor mints the signed-able would-have receipt for a
// sealed boundary record produced under an active observe grant. It is the
// observe-mode bridge: every action evaluated in shadow mode yields a
// counterfactual receipt carrying the verdict the PDP WOULD have issued and its
// reason code, with no enforcement and no side effect.
//
// It fails closed: a record that is not labeled shadow (or carries no grant id,
// or is unsealed) has no counterfactual standing and is rejected — there is no
// counterfactual receipt without an explicit grant, mirroring ObserveGrant.Active.
func (f *ExecutionFirewall) CounterfactualReceiptFor(record contracts.ExecutionBoundaryRecord) (contracts.CounterfactualReceipt, error) {
	if record.RecordHash == "" {
		return contracts.CounterfactualReceipt{}, fmt.Errorf("boundary record must be sealed before a counterfactual receipt can be minted")
	}
	if record.EnforcementMode != contracts.EnforcementModeShadow || record.ObserveGrantID == "" {
		return contracts.CounterfactualReceipt{}, fmt.Errorf("counterfactual receipts require a shadow-labeled record with an observe grant id")
	}
	receipt := contracts.CounterfactualReceipt{
		ReceiptID:          fmt.Sprintf("cf-receipt-%s", record.RecordID),
		Enforcement:        contracts.EnforcementCounterfactual,
		WouldHaveVerdict:   record.Verdict,
		ReasonCode:         record.ReasonCode,
		ObserveGrantID:     record.ObserveGrantID,
		BoundaryRecordID:   record.RecordID,
		BoundaryRecordHash: record.RecordHash,
		PolicyEpoch:        record.PolicyEpoch,
		ToolName:           record.ToolName,
		MCPServerID:        record.MCPServerID,
		ArgsHash:           record.ArgsHash,
		CreatedAt:          record.CreatedAt,
	}
	return receipt.Seal()
}

// ShouldDispatch reports whether a sealed boundary record authorizes the
// gateway to dispatch the tool call. Fail-closed: ALLOW always dispatches;
// DENY and ESCALATE dispatch only when the record is explicitly labeled with
// shadow enforcement mode (observe on-ramp). An unsealed or unlabeled
// non-ALLOW record never dispatches.
func ShouldDispatch(record contracts.ExecutionBoundaryRecord) bool {
	if record.RecordHash == "" {
		return false
	}
	if record.Verdict == contracts.VerdictAllow {
		return true
	}
	return record.EnforcementMode == contracts.EnforcementModeShadow && record.ObserveGrantID != ""
}

func ToolSchemaHash(tool ToolRef) (string, error) {
	preimage := struct {
		Name         string `json:"name"`
		Schema       any    `json:"schema,omitempty"`
		OutputSchema any    `json:"output_schema,omitempty"`
	}{
		Name:         tool.Name,
		Schema:       tool.Schema,
		OutputSchema: tool.OutputSchema,
	}
	hash, err := canonicalize.CanonicalHash(preimage)
	if err != nil {
		return "", err
	}
	return "sha256:" + hash, nil
}

func hasAllScopes(granted, required []string) bool {
	if len(required) == 0 {
		return true
	}
	seen := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		seen[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := seen[scope]; !ok {
			return false
		}
	}
	return true
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func (f *ExecutionFirewall) now() time.Time {
	if f.Clock == nil {
		return time.Now()
	}
	return f.Clock()
}
