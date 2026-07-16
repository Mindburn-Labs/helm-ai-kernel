package riskscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

type receiptProjectionInput struct {
	Source       string
	ReceiptID    string
	AgentSurface string
	EffectID     string
	EffectType   string
	EffectMode   string
	Verdict      string
	ObservedOnly bool
}

type receiptSourceSummary struct {
	AgentRunReceipts int            `json:"agent_run_receipts"`
	DecisionReceipts int            `json:"decision_receipts"`
	Actions          int            `json:"actions"`
	DeniedActions    int            `json:"denied_actions"`
	ObservedOnly     int            `json:"observed_only"`
	ByEffectType     map[string]int `json:"by_effect_type"`
	ByToolClass      map[string]int `json:"by_tool_class"`
	ByRiskCode       map[string]int `json:"by_risk_code"`
}

// ScanReceipts projects workstation observe/decision receipts into the same
// anonymized RiskEnvelope shape as Scan. It never exports raw receipt fields.
func ScanReceipts(root string, opts BuildOptions) (riskenvelope.RiskEnvelope, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	events, summary, surface, err := collectReceiptProjectionInputs(root)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	for _, event := range events {
		tool, risk := receiptToolAndRisk(event.EffectType)
		summary.ByToolClass[string(tool)]++
		summary.ByRiskCode[string(risk)]++
	}
	sourceHash, err := riskenvelope.CanonicalSHA256Ref(summary)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	envelopeID, err := riskenvelope.EnvelopeID(opts.Salt, sourceHash)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	findings, err := projectReceiptFindings(events, opts.Salt)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].RiskCode != findings[j].RiskCode {
			return findings[i].RiskCode < findings[j].RiskCode
		}
		return findings[i].ResourceID < findings[j].ResourceID
	})
	envelope := riskenvelope.RiskEnvelope{
		SchemaVersion:  riskenvelope.SchemaVersion,
		EnvelopeID:     envelopeID,
		CohortBucket:   opts.Cohort,
		SourcePackHash: sourceHash,
		Findings:       findings,
		Posture: riskenvelope.PostureProbe{
			AgentSurface: surface,
			// Receipt projections can describe declared effect modes, but cannot
			// establish the active agent permission policy. Keep this unknown.
			PermissionMode:         riskenvelope.PermissionModeUnknown,
			ManagedSettingsPresent: false,
			MCPServerCount:         0,
			OAuthScopeBuckets:      []riskenvelope.OAuthScopeBucketCount{},
			IAMGrantBuckets:        []riskenvelope.IAMGrantBucketCount{},
			StaticConfigFilesRead:  0,
			MetadataAPICalls:       0,
			SuppressedFindingCount: 0,
			KAnonymityFloor:        0,
		},
		Privacy:     riskenvelope.PrivacyNonCollection{},
		GeneratedAt: opts.Now.UTC(),
	}
	sealed, err := riskenvelope.Seal(envelope)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	if err := sealed.Validate(); err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	return sealed, nil
}

func collectReceiptProjectionInputs(root string) ([]receiptProjectionInput, receiptSourceSummary, riskenvelope.AgentSurface, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, err
	}
	summary := receiptSourceSummary{
		ByEffectType: map[string]int{},
		ByToolClass:  map[string]int{},
		ByRiskCode:   map[string]int{},
	}
	var events []receiptProjectionInput
	surface := riskenvelope.AgentSurfaceUnknown
	err = filepath.WalkDir(absRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if !shouldSkipPath(path) {
				return receiptCoverageError("declared receipt input could not be traversed")
			}
			return nil
		}
		if entry == nil {
			return receiptCoverageError("declared receipt input could not be traversed")
		}
		if entry.IsDir() {
			if shouldSkipDir(entry.Name()) && path != absRoot {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".ndjson" {
			return nil
		}
		fileEvents, fileSummary, fileSurface, err := parseReceiptFile(path)
		if err != nil {
			return err
		}
		events = append(events, fileEvents...)
		summary.AgentRunReceipts += fileSummary.AgentRunReceipts
		summary.DecisionReceipts += fileSummary.DecisionReceipts
		summary.Actions += fileSummary.Actions
		summary.DeniedActions += fileSummary.DeniedActions
		summary.ObservedOnly += fileSummary.ObservedOnly
		for k, v := range fileSummary.ByEffectType {
			summary.ByEffectType[k] += v
		}
		if surface == riskenvelope.AgentSurfaceUnknown && fileSurface != riskenvelope.AgentSurfaceUnknown {
			surface = fileSurface
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, ErrScanCoverageIncomplete) {
			return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, receiptCoverageError("declared receipt input could not be traversed")
		}
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, err
	}
	if len(events) == 0 {
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, fmt.Errorf("no supported receipt events found in declared input")
	}
	return events, summary, surface, nil
}

func parseReceiptFile(path string) ([]receiptProjectionInput, receiptSourceSummary, riskenvelope.AgentSurface, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, receiptCoverageError("declared receipt input could not be read")
	}
	if strings.EqualFold(filepath.Ext(path), ".ndjson") {
		events, summary, surface, err := parseReceiptNDJSON(data)
		if err != nil {
			return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, receiptCoverageError("declared receipt input is invalid")
		}
		return events, summary, surface, nil
	}
	events, summary, surface, ok, err := parseReceiptJSON(data)
	if err != nil {
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, receiptCoverageError("declared receipt input is invalid")
	}
	if !ok {
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, nil
	}
	return events, summary, surface, nil
}

func parseReceiptNDJSON(data []byte) ([]receiptProjectionInput, receiptSourceSummary, riskenvelope.AgentSurface, error) {
	summary := receiptSourceSummary{ByEffectType: map[string]int{}, ByToolClass: map[string]int{}, ByRiskCode: map[string]int{}}
	var events []receiptProjectionInput
	surface := riskenvelope.AgentSurfaceUnknown
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lineEvents, lineSummary, lineSurface, ok, err := parseReceiptJSON(line)
		if err != nil {
			return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, err
		}
		if !ok {
			continue
		}
		events = append(events, lineEvents...)
		mergeReceiptSummary(&summary, lineSummary)
		if surface == riskenvelope.AgentSurfaceUnknown && lineSurface != riskenvelope.AgentSurfaceUnknown {
			surface = lineSurface
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, receiptSourceSummary{}, riskenvelope.AgentSurfaceUnknown, err
	}
	return events, summary, surface, nil
}

func parseReceiptJSON(data []byte) ([]receiptProjectionInput, receiptSourceSummary, riskenvelope.AgentSurface, bool, error) {
	summary := receiptSourceSummary{ByEffectType: map[string]int{}, ByToolClass: map[string]int{}, ByRiskCode: map[string]int{}}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, summary, riskenvelope.AgentSurfaceUnknown, false, err
	}
	if raw, ok := header["receipt"]; ok {
		return parseReceiptJSON(raw)
	}
	var version string
	_ = json.Unmarshal(header["receipt_version"], &version)
	if version == contracts.AgentRunReceiptVersion {
		var receipt contracts.AgentRunReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return nil, summary, riskenvelope.AgentSurfaceUnknown, false, err
		}
		events := eventsFromAgentRunReceipt(receipt)
		summary.AgentRunReceipts = 1
		accumulateReceiptEvents(&summary, events)
		return events, summary, normalizeReceiptSurface(receipt.AgentSurface), true, nil
	}
	if _, ok := header["decision_id"]; ok {
		var receipt contracts.WorkstationPolicyDecisionReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return nil, summary, riskenvelope.AgentSurfaceUnknown, false, err
		}
		if strings.TrimSpace(receipt.DecisionID) == "" {
			return nil, summary, riskenvelope.AgentSurfaceUnknown, false, nil
		}
		event := eventFromDecisionReceipt(receipt)
		events := []receiptProjectionInput{event}
		summary.DecisionReceipts = 1
		accumulateReceiptEvents(&summary, events)
		return events, summary, normalizeReceiptSurface(receipt.Request.AgentSurface), true, nil
	}
	return nil, summary, riskenvelope.AgentSurfaceUnknown, false, nil
}

func eventsFromAgentRunReceipt(receipt contracts.AgentRunReceipt) []receiptProjectionInput {
	events := make([]receiptProjectionInput, 0, len(receipt.ToolActions)+len(receipt.DeniedEffects))
	for _, action := range receipt.ToolActions {
		events = append(events, receiptProjectionInput{
			Source:       "agent_run_receipt",
			ReceiptID:    receipt.ReceiptID,
			AgentSurface: receipt.AgentSurface,
			EffectID:     action.ActionID,
			EffectType:   action.EffectType,
			EffectMode:   action.EffectMode,
			Verdict:      action.Verdict,
			ObservedOnly: strings.EqualFold(action.EffectMode, contracts.WorkstationEffectModeObserve),
		})
	}
	for _, denied := range receipt.DeniedEffects {
		events = append(events, receiptProjectionInput{
			Source:       "agent_run_receipt",
			ReceiptID:    receipt.ReceiptID,
			AgentSurface: receipt.AgentSurface,
			EffectID:     denied.EffectID,
			EffectType:   denied.EffectType,
			Verdict:      contracts.WorkstationVerdictDeny,
		})
	}
	return events
}

func eventFromDecisionReceipt(receipt contracts.WorkstationPolicyDecisionReceipt) receiptProjectionInput {
	return receiptProjectionInput{
		Source:       "policy_decision_receipt",
		ReceiptID:    receipt.DecisionID,
		AgentSurface: receipt.Request.AgentSurface,
		EffectID:     receipt.Request.RequestID,
		EffectType:   receipt.Request.EffectType,
		EffectMode:   receipt.Request.EffectMode,
		Verdict:      receipt.Verdict,
		ObservedOnly: receipt.ObservedOnly,
	}
}

func accumulateReceiptEvents(summary *receiptSourceSummary, events []receiptProjectionInput) {
	for _, event := range events {
		summary.Actions++
		if strings.EqualFold(event.Verdict, contracts.WorkstationVerdictDeny) {
			summary.DeniedActions++
		}
		if event.ObservedOnly || strings.EqualFold(event.EffectMode, contracts.WorkstationEffectModeObserve) {
			summary.ObservedOnly++
		}
		summary.ByEffectType[event.EffectType]++
	}
}

func mergeReceiptSummary(dst *receiptSourceSummary, src receiptSourceSummary) {
	dst.AgentRunReceipts += src.AgentRunReceipts
	dst.DecisionReceipts += src.DecisionReceipts
	dst.Actions += src.Actions
	dst.DeniedActions += src.DeniedActions
	dst.ObservedOnly += src.ObservedOnly
	for k, v := range src.ByEffectType {
		dst.ByEffectType[k] += v
	}
}

func projectReceiptFindings(events []receiptProjectionInput, salt []byte) ([]riskenvelope.EnvelopeFinding, error) {
	findings := make([]riskenvelope.EnvelopeFinding, 0, len(events))
	for i, event := range events {
		tool, risk := receiptToolAndRisk(event.EffectType)
		direct := true
		secretReadable := tool == riskenvelope.ToolClassSecretRead && !strings.EqualFold(event.Verdict, contracts.WorkstationVerdictDeny)
		resourceID, err := riskenvelope.Pseudonym(salt, fmt.Sprintf("receipt:%s:%s:%s:%s:%d", event.Source, event.ReceiptID, event.EffectID, event.EffectType, i))
		if err != nil {
			return nil, err
		}
		evidence := riskenvelope.EnvelopeEvidence{
			AgentTool:          tool,
			PermissionMode:     permissionModeFromReceiptEvent(event),
			DirectDispatchSeen: &direct,
		}
		if tool == riskenvelope.ToolClassSecretRead {
			evidence.SecretValueAccessible = &secretReadable
		}
		findings = append(findings, riskenvelope.EnvelopeFinding{
			ResourceID:   resourceID,
			ResourceType: resourceTypeForTool(tool),
			RiskCode:     risk,
			Severity:     receiptSeverity(event, tool),
			Evidence:     evidence,
		})
	}
	return findings, nil
}

func receiptToolAndRisk(effectType string) (riskenvelope.ToolClass, riskenvelope.RiskCode) {
	switch effectType {
	case contracts.EffectTypeWorkstationMCPToolCall:
		return riskenvelope.ToolClassMCPWrite, riskenvelope.RiskMCPWriteScopeWithoutApproval
	case contracts.EffectTypeWorkstationShellCommand:
		return riskenvelope.ToolClassShellOperate, riskenvelope.RiskBroadShellAllow
	case contracts.EffectTypeWorkstationNetworkEgress:
		return riskenvelope.ToolClassNetworkEgress, riskenvelope.RiskDirectDispatchSeen
	case contracts.EffectTypeWorkstationDeployPublish:
		return riskenvelope.ToolClassDeployPublish, riskenvelope.RiskAgentWriteWithoutEnvApproval
	case contracts.EffectTypeWorkstationSecretRead:
		return riskenvelope.ToolClassSecretRead, riskenvelope.RiskSecretClassAgentReadable
	case contracts.EffectTypeWorkstationPaymentInitiate:
		return riskenvelope.ToolClassPaymentInitiate, riskenvelope.RiskDirectDispatchSeen
	case contracts.EffectTypeWorkstationFileWrite, contracts.EffectTypeWorkstationFileDraft:
		return riskenvelope.ToolClassGitWrite, riskenvelope.RiskAgentWriteWithoutEnvApproval
	default:
		return riskenvelope.ToolClassUnknown, riskenvelope.RiskDirectDispatchSeen
	}
}

func resourceTypeForTool(tool riskenvelope.ToolClass) riskenvelope.ResourceType {
	switch tool {
	case riskenvelope.ToolClassMCPWrite, riskenvelope.ToolClassMCPRead:
		return riskenvelope.ResourceMCPServer
	case riskenvelope.ToolClassSecretRead:
		return riskenvelope.ResourceSecretClass
	case riskenvelope.ToolClassDeployPublish:
		return riskenvelope.ResourceEnvironment
	default:
		return riskenvelope.ResourcePermissionProfile
	}
}

func receiptSeverity(event receiptProjectionInput, tool riskenvelope.ToolClass) riskenvelope.Severity {
	if strings.EqualFold(event.Verdict, contracts.WorkstationVerdictDeny) {
		return riskenvelope.SeverityInfo
	}
	switch tool {
	case riskenvelope.ToolClassSecretRead, riskenvelope.ToolClassPaymentInitiate, riskenvelope.ToolClassDeployPublish, riskenvelope.ToolClassShellOperate:
		return riskenvelope.SeverityHigh
	default:
		if event.ObservedOnly || strings.EqualFold(event.EffectMode, contracts.WorkstationEffectModeObserve) {
			return riskenvelope.SeverityMedium
		}
		return riskenvelope.SeverityLow
	}
}

func permissionModeFromReceiptEvent(receiptProjectionInput) riskenvelope.PermissionMode {
	// An event's declared effect mode is not evidence of the active agent
	// permission policy. Keep projections conservative until provenance exists.
	return riskenvelope.PermissionModeUnknown
}

func receiptCoverageError(reason string) error {
	return fmt.Errorf("%w: %s", ErrScanCoverageIncomplete, reason)
}

func normalizeReceiptSurface(value string) riskenvelope.AgentSurface {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(v, "claude"):
		return riskenvelope.AgentSurfaceClaudeCode
	case strings.Contains(v, "codex"):
		return riskenvelope.AgentSurfaceCodex
	case strings.Contains(v, "github"):
		return riskenvelope.AgentSurfaceGitHubActions
	case strings.Contains(v, "mcp"):
		return riskenvelope.AgentSurfaceMCP
	default:
		return riskenvelope.AgentSurfaceUnknown
	}
}
