package mcp

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

type ExecutionFirewall struct {
	Catalog             *ToolCatalog
	Quarantine          *QuarantineRegistry
	PolicyEpoch         string
	RequirePinnedSchema bool
	Clock               func() time.Time
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
