package mcp

import (
	"context"
	"encoding/json"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/events"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/privacy"
)

// protectDispatchReceipt sanitizes only the telemetry projection. The
// authoritative receipt returned by the governed runtime is never mutated;
// lifecycle fields are a public export and must not become an egress channel
// for a malicious handler/provider.
func (f *GovernanceFirewall) protectDispatchReceipt(ctx context.Context, receipt contracts.Receipt) contracts.Receipt {
	receipt.ReceiptID = f.protectDispatchString(ctx, receipt.ReceiptID)
	receipt.ID = f.protectDispatchString(ctx, receipt.ID)
	receipt.Status = f.protectDispatchString(ctx, receipt.Status)
	receipt.ArgsHash = f.protectDispatchString(ctx, receipt.ArgsHash)
	receipt.EffectID = f.protectDispatchString(ctx, receipt.EffectID)
	receipt.EffectType = f.protectDispatchString(ctx, receipt.EffectType)
	return receipt
}

func (f *GovernanceFirewall) protectDispatchString(ctx context.Context, value string) string {
	if value == "" {
		return ""
	}
	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	protected, _, err := manager.Protect(ctx, value)
	if err == nil {
		if protectedString, ok := protected.(string); ok {
			if protectedString == value {
				return value
			}
			return events.StableRef(value)
		}
	}
	// A restricted or unsupported projection cannot be emitted verbatim. A
	// deterministic one-way reference retains correlation without exporting the
	// receipt/provider value or the cause of a privacy failure.
	return events.StableRef(value)
}

func (f *GovernanceFirewall) publicLifecycleToolName(ctx context.Context, name string) string {
	if name == "" {
		return ""
	}
	if f.catalog != nil {
		if _, known := f.catalog.Lookup(name); known {
			return f.protectDispatchString(ctx, name)
		}
	}
	// Unknown names are untrusted request data. Keep lifecycle correlation
	// possible without exporting a caller-controlled name.
	return events.StableRef(name)
}

func (f *GovernanceFirewall) publicDecisionProjection(ctx context.Context, decision contracts.DecisionRecord) contracts.DecisionRecord {
	decision.ID = f.protectDispatchString(ctx, decision.ID)
	decision.Verdict = f.protectDispatchString(ctx, decision.Verdict)
	decision.PolicyBackend = f.protectDispatchString(ctx, decision.PolicyBackend)
	decision.PolicyVersion = f.protectDispatchString(ctx, decision.PolicyVersion)
	decision.PolicyContentHash = f.protectDispatchString(ctx, decision.PolicyContentHash)
	decision.PolicyEpoch = f.protectDispatchString(ctx, decision.PolicyEpoch)
	decision.PolicyDecisionHash = f.protectDispatchString(ctx, decision.PolicyDecisionHash)
	decision.ReasonCode = f.protectDispatchString(ctx, decision.ReasonCode)
	decision.Action = f.protectDispatchString(ctx, decision.Action)
	decision.Resource = f.protectDispatchString(ctx, decision.Resource)
	return decision
}

// protectToolExecutionResponse copies every public response representation
// before audit, lifecycle completion, or returning it through the gateway.
// ExecutionReceipt and the other runtime-only anchors are deliberately not
// traversed or mutated.
func (f *GovernanceFirewall) protectToolExecutionResponse(ctx context.Context, resp ToolExecutionResponse) (ToolExecutionResponse, error) {
	if !responseWithinPrivacyBudget(resp, false) {
		return ToolExecutionResponse{}, privacy.ErrDataEgressInvalid
	}
	manager := f.privacy
	if manager == nil {
		manager = privacy.NewPrivacyManager()
	}
	content, _, err := manager.Protect(ctx, resp.Content)
	if err != nil {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}
	protectedContent, ok := content.(string)
	if !ok {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}

	var protectedItems []ToolContentItem
	if resp.ContentItems != nil {
		protectedItems = make([]ToolContentItem, len(resp.ContentItems))
	}
	for index, item := range resp.ContentItems {
		protectedItems[index] = item
		var protectErr error
		protectedItems[index].Type, protectErr = protectResponseString(ctx, manager, item.Type)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].Text, protectErr = protectResponseString(ctx, manager, item.Text)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].URI, protectErr = protectResponseString(ctx, manager, item.URI)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].MimeType, protectErr = protectResponseString(ctx, manager, item.MimeType)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
		protectedItems[index].Name, protectErr = protectResponseString(ctx, manager, item.Name)
		if protectErr != nil {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
	}

	structured, _, err := manager.Protect(ctx, resp.StructuredContent)
	if err != nil {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}
	var protectedStructured map[string]any
	if structured != nil {
		var mapOK bool
		protectedStructured, mapOK = structured.(map[string]any)
		if !mapOK {
			return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
		}
	}
	receiptID, protectErr := protectResponseString(ctx, manager, resp.ReceiptID)
	if protectErr != nil {
		return ToolExecutionResponse{}, privacy.ErrDataEgressBlocked
	}

	resp.Content = protectedContent
	resp.ContentItems = protectedItems
	resp.StructuredContent = protectedStructured
	resp.ReceiptID = receiptID
	if !responseWithinPrivacyBudget(resp, true) {
		return ToolExecutionResponse{}, privacy.ErrDataEgressInvalid
	}
	return resp, nil
}

func responseWithinPrivacyBudget(resp ToolExecutionResponse, includeStructured bool) bool {
	if len(resp.ContentItems) > maxMCPResponseItems {
		return false
	}
	if includeStructured {
		encodedResponse, responseErr := json.Marshal(resp)
		encodedToolResult, resultErr := json.Marshal(ToolResultPayload(resp))
		return responseErr == nil && resultErr == nil &&
			len(encodedResponse)+1 <= MaxResponseBytes && len(encodedToolResult)+1 <= MaxResponseBytes
	}
	total := 0
	add := func(size int) bool {
		if size < 0 || size > MaxResponseBytes-total {
			return false
		}
		total += size
		return true
	}
	if !add(len(resp.Content)) || !add(len(resp.ReceiptID)) {
		return false
	}
	for _, item := range resp.ContentItems {
		if !add(len(item.Type)) || !add(len(item.Text)) || !add(len(item.URI)) ||
			!add(len(item.MimeType)) || !add(len(item.Name)) {
			return false
		}
	}
	return true
}

func protectResponseString(ctx context.Context, manager *privacy.StandardPrivacyManager, value string) (string, error) {
	protected, _, err := manager.Protect(ctx, value)
	if err != nil {
		return "", err
	}
	protectedString, ok := protected.(string)
	if !ok {
		return "", privacy.ErrDataEgressBlocked
	}
	return protectedString, nil
}
