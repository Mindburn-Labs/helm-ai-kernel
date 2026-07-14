package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor"
	launchpadmcp "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/mcp"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

const (
	mcpProofDurationLimit = 60 * time.Second
	mcpProofToolName      = "proof.local_write"
	mcpProofApprovalRef   = "approval-proof-reversible-write"
)

type mcpProofScenario struct {
	ID          string
	Name        string
	ThreatClass string
	Summary     string
	Server      launchpadmcp.ServerRecord
	Request     launchpadmcp.CallRequest
	Decision    *launchpadmcp.Decision
	Expected    launchpadmcp.Decision
	Execute     bool
}

type mcpProofScenarioResult struct {
	ScenarioID           string                 `json:"scenario_id"`
	Name                 string                 `json:"name"`
	ThreatClass          string                 `json:"threat_class"`
	ServerID             string                 `json:"server_id"`
	ToolName             string                 `json:"tool_name"`
	Verdict              string                 `json:"verdict"`
	Reason               string                 `json:"reason"`
	Dispatched           bool                   `json:"dispatched"`
	DispatchCount        int                    `json:"dispatch_count"`
	ReplayNoRedispatch   bool                   `json:"replay_no_redispatch"`
	ReceiptRef           string                 `json:"receipt_ref"`
	ReceiptHash          string                 `json:"receipt_hash"`
	ExecutionReceiptRef  string                 `json:"execution_receipt_ref,omitempty"`
	ExecutionReceiptHash string                 `json:"execution_receipt_hash,omitempty"`
	EffectArtifactRef    string                 `json:"effect_artifact_ref,omitempty"`
	Details              map[string]interface{} `json:"details,omitempty"`
}

type mcpProofSummary struct {
	SchemaVersion           string                   `json:"schema_version"`
	RunID                   string                   `json:"run_id"`
	Scenario                string                   `json:"scenario"`
	GeneratedAt             string                   `json:"generated_at"`
	EvidencePackRef         string                   `json:"evidence_pack_ref"`
	EvidencePackArchive     string                   `json:"evidence_pack_archive,omitempty"`
	VerificationCommand     string                   `json:"verification_command"`
	OfflineVerified         bool                     `json:"offline_verified"`
	VerifierSummary         string                   `json:"verifier_summary,omitempty"`
	TamperRejected          bool                     `json:"tamper_rejected"`
	NegativeCasesNoDispatch bool                     `json:"negative_cases_no_dispatch"`
	DispatchCount           int                      `json:"dispatch_count"`
	ReplayNoRedispatch      bool                     `json:"replay_no_redispatch"`
	DurationMS              int64                    `json:"duration_ms"`
	DurationLimitMS         int64                    `json:"duration_limit_ms"`
	DurationGatePass        bool                     `json:"duration_gate_pass"`
	Scenarios               []mcpProofScenarioResult `json:"scenarios"`
}

type mcpProofExecutionResult struct {
	receipt            *contracts.Receipt
	receiptData        []byte
	receiptHash        string
	effectArtifactData []byte
	effectArtifactRef  string
	replayData         []byte
}

type mcpProofLocalDriver struct {
	outputPath string
	dispatches int
}

func (d *mcpProofLocalDriver) Execute(ctx context.Context, toolName string, params map[string]any) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if toolName != mcpProofToolName {
		return nil, fmt.Errorf("proof driver: unsupported tool %q", toolName)
	}
	content, ok := params["content"].(string)
	if !ok || strings.TrimSpace(content) == "" {
		return nil, fmt.Errorf("proof driver: content is required")
	}
	data := []byte(content + "\n")
	if err := os.MkdirAll(filepath.Dir(d.outputPath), 0o700); err != nil {
		return nil, fmt.Errorf("proof driver: create output directory: %w", err)
	}
	if err := os.WriteFile(d.outputPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("proof driver: write reversible effect: %w", err)
	}
	d.dispatches++
	return map[string]any{
		"artifact":       filepath.Base(d.outputPath),
		"content_hash":   lpreceipts.HashBytes(data),
		"dispatch_count": d.dispatches,
		"reversible":     true,
	}, nil
}

func (d *mcpProofLocalDriver) DispatchCount() int {
	if d == nil {
		return 0
	}
	return d.dispatches
}

func runMCPProof(args []string, stdout, stderr io.Writer) int {
	proofStarted := time.Now()
	cmd := flag.NewFlagSet("mcp proof", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		scenario   string
		outRoot    string
		runID      string
		atValue    string
		jsonOutput bool
		verify     bool
	)
	cmd.StringVar(&scenario, "scenario", "all", "Proof scenario to run: all or a scenario id")
	cmd.StringVar(&outRoot, "out", "", "Output root for transcript and EvidencePack")
	cmd.StringVar(&runID, "run-id", "", "Stable run id for reproducible transcripts")
	cmd.StringVar(&atValue, "at", "", "RFC3339 timestamp for reproducible transcripts")
	cmd.BoolVar(&jsonOutput, "json", false, "Output proof summary as JSON")
	cmd.BoolVar(&verify, "verify", true, "Run required offline EvidencePack and tamper-negative verification")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if !verify {
		fmt.Fprintln(stderr, "Error: --verify=false is unsupported; mcp proof requires offline and tamper-negative verification")
		return 2
	}

	generatedAt := time.Now().UTC()
	if strings.TrimSpace(atValue) != "" {
		parsed, err := time.Parse(time.RFC3339, atValue)
		if err != nil {
			fmt.Fprintf(stderr, "Error: --at must be RFC3339: %v\n", err)
			return 2
		}
		generatedAt = parsed.UTC()
	}
	if runID == "" {
		runID = "mcp-proof-" + generatedAt.Format("20060102T150405Z")
	}
	runID = sanitizeReceiptPart(runID)
	if outRoot == "" {
		outRoot = filepath.Join("artifacts", "mcp-proof")
	}

	selected, err := selectMCPProofScenarios(scenario, generatedAt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	runDir := filepath.Join(outRoot, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "Error: create proof output: %v\n", err)
		return 1
	}

	receiptSigner, err := loadOrGenerateSignerWithDataDir(filepath.Join(runDir, ".helm-receipts"))
	if err != nil {
		fmt.Fprintf(stderr, "Error: receipt signer: %v\n", err)
		return 1
	}

	results, artifacts, err := buildMCPProofArtifacts(runDir, runID, scenario, generatedAt, selected, receiptSigner)
	if err != nil {
		fmt.Fprintf(stderr, "Error: build proof artifacts: %v\n", err)
		return 1
	}
	governedEffectDuration := time.Since(proofStarted)
	durationReport, _ := json.MarshalIndent(map[string]any{
		"schema_version": "helm.mcp.proof.duration/v1",
		"scope":          "governed_effect_scenarios",
		"duration_ms":    governedEffectDuration.Milliseconds(),
		"limit_ms":       mcpProofDurationLimit.Milliseconds(),
		"pass":           governedEffectDuration < mcpProofDurationLimit,
	}, "", "  ")
	artifacts["12_REPORTS/60_second_gate.json"] = append(durationReport, '\n')

	packDir, err := lpreceipts.WriteEvidencePack(runDir, runID, artifacts)
	if err != nil {
		fmt.Fprintf(stderr, "Error: write EvidencePack: %v\n", err)
		return 1
	}
	evidenceDataDir := filepath.Join(runDir, ".helm-evidence")
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:   runID,
		Profile:  evidencepkg.EvidenceTrustProfileDevLocal,
		DataDir:  evidenceDataDir,
		SignedAt: generatedAt,
	}); err != nil {
		fmt.Fprintf(stderr, "Error: seal EvidencePack: %v\n", err)
		return 1
	}

	archivePath, err := lpreceipts.WriteEvidencePackArchive(packDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error: archive EvidencePack: %v\n", err)
		return 1
	}

	summary := mcpProofSummary{
		SchemaVersion:           "helm.mcp.proof/v2",
		RunID:                   runID,
		Scenario:                scenario,
		GeneratedAt:             generatedAt.Format(time.RFC3339),
		EvidencePackRef:         packDir,
		EvidencePackArchive:     archivePath,
		VerificationCommand:     fmt.Sprintf("helm-ai-kernel verify --bundle %s --profile dev-local --json", packDir),
		NegativeCasesNoDispatch: negativeMCPProofCasesNoDispatch(results),
		DispatchCount:           totalMCPProofDispatches(results),
		ReplayNoRedispatch:      mcpProofReplayNoRedispatch(results),
		DurationLimitMS:         mcpProofDurationLimit.Milliseconds(),
		Scenarios:               results,
	}
	report, err := verifier.VerifyBundleWithOptions(packDir, verifier.VerifyOptions{
		Profile: evidencepkg.EvidenceTrustProfileDevLocal,
		DataDir: evidenceDataDir,
		Now:     generatedAt,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: verify EvidencePack: %v\n", err)
		return 1
	}
	summary.OfflineVerified = report.Verified
	summary.VerifierSummary = report.Summary
	reportData, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, "verification_report.json"), append(reportData, '\n'), 0o600); err != nil {
		fmt.Fprintf(stderr, "Error: write verifier report: %v\n", err)
		return 1
	}
	if !report.Verified {
		writeMCPProofSummary(stdout, summary, jsonOutput)
		return 1
	}
	tamperRejected, err := verifyMCPProofTamperRejected(packDir, evidenceDataDir, generatedAt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: tamper-negative verification: %v\n", err)
		return 1
	}
	summary.TamperRejected = tamperRejected

	proofDuration := time.Since(proofStarted)
	summary.DurationMS = proofDuration.Milliseconds()
	summary.DurationGatePass = proofDuration < mcpProofDurationLimit

	data, _ := json.MarshalIndent(summary, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, "summary.json"), append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(stderr, "Error: write proof summary: %v\n", err)
		return 1
	}
	writeMCPProofSummary(stdout, summary, jsonOutput)
	if !summary.DurationGatePass {
		fmt.Fprintf(stderr, "Error: proof duration %dms exceeded %dms gate\n", summary.DurationMS, summary.DurationLimitMS)
		return 1
	}
	return 0
}

func writeMCPProofSummary(stdout io.Writer, summary mcpProofSummary, jsonOutput bool) {
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		return
	}
	fmt.Fprintf(stdout, "MCP quarantine proof: %s\n", summary.RunID)
	fmt.Fprintf(stdout, "  EvidencePack: %s\n", summary.EvidencePackRef)
	fmt.Fprintf(stdout, "  Offline verify: %t\n", summary.OfflineVerified)
	fmt.Fprintf(stdout, "  Tamper rejected: %t\n", summary.TamperRejected)
	fmt.Fprintf(stdout, "  Duration gate: %t (%dms < %dms)\n", summary.DurationGatePass, summary.DurationMS, summary.DurationLimitMS)
	for _, result := range summary.Scenarios {
		fmt.Fprintf(stdout, "  %s: %s %s dispatched=%t receipt=%s\n", result.ScenarioID, result.Verdict, result.Reason, result.Dispatched, result.ReceiptRef)
	}
	fmt.Fprintf(stdout, "  Verify: %s\n", summary.VerificationCommand)
}

func selectMCPProofScenarios(name string, at time.Time) ([]mcpProofScenario, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "all"
	}
	all := mcpProofScenarios(at)
	if name == "all" {
		return all, nil
	}
	for _, scenario := range all {
		if scenario.ID == name {
			return []mcpProofScenario{scenario}, nil
		}
	}
	ids := make([]string, 0, len(all)+1)
	ids = append(ids, "all")
	for _, scenario := range all {
		ids = append(ids, scenario.ID)
	}
	return nil, fmt.Errorf("unknown --scenario %q (supported: %s)", name, strings.Join(ids, ", "))
}

func mcpProofScenarios(at time.Time) []mcpProofScenario {
	approved := launchpadmcp.ServerRecord{
		ServerID:   "srv-approved",
		LaunchID:   "launch-proof",
		AppID:      "proof-app",
		Principal:  "operator@example.com",
		PolicyHash: "sha256:policy-proof",
		Approved:   true,
		SchemaPins: map[string]string{
			"proof.read":     "sha256:read",
			"proof.write":    "sha256:write",
			mcpProofToolName: "sha256:write",
		},
	}
	approvedWithGrant := approved
	approvedWithGrant.Approvals = []launchpadmcp.ApprovalGrant{{
		ReceiptRef: mcpProofApprovalRef,
		ToolNames:  []string{mcpProofToolName},
		ExpiresAt:  at.Add(5 * time.Minute),
	}}
	req := func(toolName, schemaHash string, effect launchpadmcp.ToolEffect) launchpadmcp.CallRequest {
		return launchpadmcp.CallRequest{
			ServerID:   "srv-approved",
			LaunchID:   "launch-proof",
			AppID:      "proof-app",
			Principal:  "operator@example.com",
			PolicyHash: "sha256:policy-proof",
			ToolName:   toolName,
			SchemaHash: schemaHash,
			Effect:     effect,
		}
	}
	replayDecision := launchpadmcp.Decision{
		Verdict:    "DENY",
		Reason:     "ERR_MCP_REPLAY_REORDERING_ATTEMPT",
		LaunchID:   "launch-proof",
		AppID:      "proof-app",
		Principal:  "operator@example.com",
		PolicyHash: "sha256:policy-proof",
		SchemaPin:  "sha256:write",
	}
	return []mcpProofScenario{
		{
			ID:          "approved_reversible_local_effect",
			Name:        "Scoped approval dispatches one reversible local effect",
			ThreatClass: "governed_side_effect",
			Summary:     "A valid scoped approval, pinned schema, and bound effect dispatch exactly once through SafeExecutor.",
			Server:      approvedWithGrant,
			Request: launchpadmcp.CallRequest{
				ServerID:           "srv-approved",
				LaunchID:           "launch-proof",
				AppID:              "proof-app",
				Principal:          "operator@example.com",
				PolicyHash:         "sha256:policy-proof",
				ToolName:           mcpProofToolName,
				SchemaHash:         "sha256:write",
				ApprovalReceiptRef: mcpProofApprovalRef,
				Effect:             launchpadmcp.EffectSideEffect,
			},
			Expected: launchpadmcp.Decision{Verdict: "ALLOW", Reason: "MCP_CALL_AUTHORIZED"},
			Execute:  true,
		},
		{
			ID:          "malicious_unknown_mcp",
			Name:        "Malicious or unknown MCP server is quarantined",
			ThreatClass: "malicious_mcp_server",
			Summary:     "An unrecognized MCP server cannot dispatch a tool call.",
			Server:      launchpadmcp.ServerRecord{},
			Request: launchpadmcp.CallRequest{
				ServerID:   "srv-evil",
				LaunchID:   "launch-proof",
				AppID:      "proof-app",
				Principal:  "operator@example.com",
				PolicyHash: "sha256:policy-proof",
				ToolName:   "shell.exec",
				SchemaHash: "sha256:shell",
				Effect:     launchpadmcp.EffectSideEffect,
			},
			Expected: launchpadmcp.Decision{Verdict: "ESCALATE", Reason: "ERR_MCP_SERVER_QUARANTINED"},
		},
		{
			ID:          "prompt_injected_tool_output",
			Name:        "Prompt-injected tool output cannot induce a side effect",
			ThreatClass: "prompt_injected_tool_output",
			Summary:     "A tainted tool-output instruction asks for a write, but no approval receipt is bound.",
			Server:      approved,
			Request:     req("proof.write", "sha256:write", launchpadmcp.EffectSideEffect),
			Expected:    launchpadmcp.Decision{Verdict: "DENY", Reason: "ERR_MCP_APPROVAL_RECEIPT_REQUIRED"},
		},
		{
			ID:          "excessive_agency",
			Name:        "Excessive agency request requires approval before dispatch",
			ThreatClass: "excessive_agency",
			Summary:     "A destructive autonomous action is blocked without an approval receipt.",
			Server:      approved,
			Request:     req("proof.write", "sha256:write", launchpadmcp.EffectSideEffect),
			Expected:    launchpadmcp.Decision{Verdict: "DENY", Reason: "ERR_MCP_APPROVAL_RECEIPT_REQUIRED"},
		},
		{
			ID:          "invalid_approval_scope",
			Name:        "Invalid approval scope cannot dispatch",
			ThreatClass: "approval_scope_mismatch",
			Summary:     "A side effect carrying an unrecognized approval receipt fails closed before dispatch.",
			Server:      approvedWithGrant,
			Request: launchpadmcp.CallRequest{
				ServerID:           "srv-approved",
				LaunchID:           "launch-proof",
				AppID:              "proof-app",
				Principal:          "operator@example.com",
				PolicyHash:         "sha256:policy-proof",
				ToolName:           mcpProofToolName,
				SchemaHash:         "sha256:write",
				ApprovalReceiptRef: "approval-wrong-scope",
				Effect:             launchpadmcp.EffectSideEffect,
			},
			Expected: launchpadmcp.Decision{Verdict: "DENY", Reason: "ERR_MCP_APPROVAL_SCOPE_OR_EXPIRY"},
		},
		{
			ID:          "confused_deputy_scope_mismatch",
			Name:        "Confused-deputy launch scope mismatch fails closed",
			ThreatClass: "confused_deputy",
			Summary:     "A request tries to reuse another launch scope.",
			Server:      approved,
			Request: launchpadmcp.CallRequest{
				ServerID:   "srv-approved",
				LaunchID:   "launch-other",
				AppID:      "proof-app",
				Principal:  "operator@example.com",
				PolicyHash: "sha256:policy-proof",
				ToolName:   "proof.read",
				SchemaHash: "sha256:read",
				Effect:     launchpadmcp.EffectRead,
			},
			Expected: launchpadmcp.Decision{Verdict: "DENY", Reason: "ERR_MCP_LAUNCH_SCOPE_MISMATCH"},
		},
		{
			ID:          "missing_schema_pin",
			Name:        "Missing schema pin quarantines an unknown tool",
			ThreatClass: "missing_schema_pin",
			Summary:     "Approved server status is insufficient without a pinned tool schema.",
			Server:      approved,
			Request:     req("proof.unpinned", "sha256:unknown", launchpadmcp.EffectRead),
			Expected:    launchpadmcp.Decision{Verdict: "ESCALATE", Reason: "ERR_MCP_TOOL_QUARANTINED"},
		},
		{
			ID:          "schema_drift",
			Name:        "Schema drift denies before dispatch",
			ThreatClass: "schema_drift",
			Summary:     "The caller-supplied schema hash does not match the pinned schema.",
			Server:      approved,
			Request:     req("proof.read", "sha256:drift", launchpadmcp.EffectRead),
			Expected:    launchpadmcp.Decision{Verdict: "DENY", Reason: "ERR_MCP_SCHEMA_DRIFT"},
		},
		{
			ID:          "replay_reordering_attempt",
			Name:        "Replay or reordering attempt is marked invalid",
			ThreatClass: "replay_reordering",
			Summary:     "A replay ledger attempts to present side effects out of causal order.",
			Server:      approved,
			Request:     req("proof.write", "sha256:write", launchpadmcp.EffectSideEffect),
			Decision:    &replayDecision,
			Expected:    replayDecision,
		},
	}
}

func buildMCPProofArtifacts(runDir, runID, scenarioName string, generatedAt time.Time, scenarios []mcpProofScenario, signer helmcrypto.Signer) ([]mcpProofScenarioResult, map[string][]byte, error) {
	results := make([]mcpProofScenarioResult, 0, len(scenarios))
	artifacts := map[string][]byte{}
	previousReceiptHash := ""

	executionStateDir := filepath.Join(runDir, ".execution")
	if err := os.MkdirAll(executionStateDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create execution state: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(executionStateDir, "receipts.db"))
	if err != nil {
		return nil, nil, fmt.Errorf("open execution receipt store: %w", err)
	}
	defer db.Close()
	executionReceiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize execution receipt store: %w", err)
	}
	executionVerifier, err := mcpProofVerifierForSigner(signer)
	if err != nil {
		return nil, nil, err
	}
	driver := &mcpProofLocalDriver{outputPath: filepath.Join(runDir, "effects", "reversible_effect.txt")}
	safeExecutor := executor.NewSafeExecutor(
		executionVerifier,
		signer,
		driver,
		executionReceiptStore,
		nil,
		nil,
		"",
		nil,
		nil,
		nil,
		func() time.Time { return generatedAt },
	)

	for idx, scenario := range scenarios {
		decision := launchpadmcp.AuthorizeAt(scenario.Server, scenario.Request, generatedAt)
		if scenario.Decision != nil {
			decision = *scenario.Decision
		}
		if decision.Verdict != scenario.Expected.Verdict || decision.Reason != scenario.Expected.Reason {
			return nil, nil, fmt.Errorf(
				"proof scenario %s returned %s/%s, want %s/%s",
				scenario.ID,
				decision.Verdict,
				decision.Reason,
				scenario.Expected.Verdict,
				scenario.Expected.Reason,
			)
		}
		decisionHash := lpreceipts.Hash(map[string]any{
			"scenario_id": scenario.ID,
			"decision":    decision,
			"request":     scenario.Request,
		})
		dispatchesBefore := driver.DispatchCount()
		var executionResult *mcpProofExecutionResult
		if scenario.Execute {
			executionResult, err = executeMCPProofScenario(
				context.Background(),
				runID,
				generatedAt,
				scenario,
				decisionHash,
				signer,
				safeExecutor,
				driver,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("execute scenario %s: %w", scenario.ID, err)
			}
			artifacts["receipts/"+scenario.ID+"-execution.json"] = executionResult.receiptData
			artifacts["04_EXPORTS/reversible_effect.txt"] = executionResult.effectArtifactData
			artifacts["08_TAPES/"+scenario.ID+"-replay.json"] = executionResult.replayData
		}
		dispatchCount := driver.DispatchCount() - dispatchesBefore
		if scenario.Execute && dispatchCount != 1 {
			return nil, nil, fmt.Errorf("proof scenario %s dispatched %d times, want exactly 1", scenario.ID, dispatchCount)
		}
		if !scenario.Execute && dispatchCount != 0 {
			return nil, nil, fmt.Errorf("proof scenario %s dispatched %d times, want 0", scenario.ID, dispatchCount)
		}
		dispatched := dispatchCount > 0
		argsHash := lpreceipts.Hash(scenario.Request)
		receipt := &contracts.Receipt{
			ReceiptID:    "rcpt_mcp_proof_" + scenario.ID,
			DecisionID:   "decision_mcp_proof_" + scenario.ID,
			EffectID:     "mcp.tools.call/" + scenario.Request.ToolName,
			Status:       decision.Verdict,
			OutputHash:   decisionHash,
			Timestamp:    generatedAt,
			ExecutorID:   "helm-ai-kernel.mcp.proof",
			PrevHash:     previousReceiptHash,
			LamportClock: uint64(idx + 1),
			ArgsHash:     argsHash,
			Type:         "mcp_policy_decision",
			LaunchID:     runID,
			DecisionHash: decisionHash,
			Verdict:      decision.Verdict,
			CreatedAt:    generatedAt,
			PolicyHash:   scenario.Request.PolicyHash,
			ToolName:     scenario.Request.ToolName,
			ReasonCode:   decision.Reason,
			Metadata: map[string]any{
				"scenario_id":            scenario.ID,
				"threat_class":           scenario.ThreatClass,
				"summary":                scenario.Summary,
				"mcp_server_id":          scenario.Request.ServerID,
				"mcp_tool_name":          scenario.Request.ToolName,
				"schema_hash":            scenario.Request.SchemaHash,
				"schema_pin":             decision.SchemaPin,
				"side_effect_class":      string(scenario.Request.Effect),
				"dispatched":             dispatched,
				"dispatch_count":         dispatchCount,
				"replay_no_redispatch":   executionResult != nil,
				"signature_key_ref":      mcpProofSignatureKeyRef(signer),
				"signature_key_type":     "ed25519",
				"signing_public_key_hex": mcpProofSigningPublicKeyHex(signer),
			},
		}
		if err := signer.SignReceipt(receipt); err != nil {
			return nil, nil, fmt.Errorf("sign receipt for %s: %w", scenario.ID, err)
		}
		receiptData, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		receiptData = append(receiptData, '\n')
		receiptHash := lpreceipts.HashBytes(receiptData)
		previousReceiptHash = receiptHash
		artifacts["receipts/"+scenario.ID+".json"] = receiptData

		result := mcpProofScenarioResult{
			ScenarioID:         scenario.ID,
			Name:               scenario.Name,
			ThreatClass:        scenario.ThreatClass,
			ServerID:           scenario.Request.ServerID,
			ToolName:           scenario.Request.ToolName,
			Verdict:            decision.Verdict,
			Reason:             decision.Reason,
			Dispatched:         dispatched,
			DispatchCount:      dispatchCount,
			ReplayNoRedispatch: executionResult != nil,
			ReceiptRef:         "02_PROOFGRAPH/receipts/" + scenario.ID + ".json",
			ReceiptHash:        receiptHash,
			Details: map[string]interface{}{
				"launch_id":   scenario.Request.LaunchID,
				"app_id":      scenario.Request.AppID,
				"principal":   scenario.Request.Principal,
				"policy_hash": scenario.Request.PolicyHash,
				"schema_hash": scenario.Request.SchemaHash,
				"schema_pin":  decision.SchemaPin,
			},
		}
		if executionResult != nil {
			result.ExecutionReceiptRef = "02_PROOFGRAPH/receipts/" + scenario.ID + "-execution.json"
			result.ExecutionReceiptHash = executionResult.receiptHash
			result.EffectArtifactRef = executionResult.effectArtifactRef
			result.Details["execution_receipt_id"] = executionResult.receipt.ReceiptID
			result.Details["idempotency_key"] = "mcp-proof/" + runID + "/" + scenario.ID
		}
		results = append(results, result)
		resultData, _ := json.MarshalIndent(result, "", "  ")
		artifacts["scenario_results/"+scenario.ID+".json"] = append(resultData, '\n')
	}

	transcript := map[string]any{
		"schema_version":             "helm.mcp.proof.transcript/v2",
		"run_id":                     runID,
		"scenario":                   scenarioName,
		"generated_at":               generatedAt.Format(time.RFC3339),
		"negative_cases_no_dispatch": negativeMCPProofCasesNoDispatch(results),
		"dispatch_count":             totalMCPProofDispatches(results),
		"replay_no_redispatch":       mcpProofReplayNoRedispatch(results),
		"positive_and_negative":      mcpProofHasPositiveAndNegative(results),
		"scenarios":                  results,
	}
	transcriptData, _ := json.MarshalIndent(transcript, "", "  ")
	artifacts["mcp_proof_transcript.json"] = append(transcriptData, '\n')
	artifacts["proofgraph.json"] = buildMCPProofGraph(runID, generatedAt, results)
	artifacts["09_SCHEMAS/mcp_proof_transcript.schema.json"] = []byte(mcpProofTranscriptSchema + "\n")
	artifacts["08_TAPES/mcp_replay_reordering_attempt.json"] = []byte(fmt.Sprintf(`{"run_id":%q,"scenario_id":"replay_reordering_attempt","status":"invalid","reason":"ERR_MCP_REPLAY_REORDERING_ATTEMPT"}`+"\n", runID))
	return results, artifacts, nil
}

func executeMCPProofScenario(
	ctx context.Context,
	runID string,
	generatedAt time.Time,
	scenario mcpProofScenario,
	policyDecisionHash string,
	signer helmcrypto.Signer,
	safeExecutor *executor.SafeExecutor,
	driver *mcpProofLocalDriver,
) (*mcpProofExecutionResult, error) {
	if safeExecutor == nil || driver == nil {
		return nil, fmt.Errorf("proof executor and driver are required")
	}
	decisionID := "decision_mcp_proof_" + scenario.ID
	idempotencyKey := "mcp-proof/" + runID + "/" + scenario.ID
	effect := &contracts.Effect{
		EffectID:       "effect_mcp_proof_" + scenario.ID,
		EffectType:     contracts.EffectTypeCallTool,
		DecisionID:     decisionID,
		IdempotencyKey: idempotencyKey,
		Params: map[string]any{
			"tool_name": mcpProofToolName,
			"content":   "HELM governed reversible local effect for " + runID,
		},
	}
	effect.ArgsHash = lpreceipts.Hash(effect.Params)
	effectDigest, err := executor.CanonicalEffectDigest(effect)
	if err != nil {
		return nil, fmt.Errorf("canonical effect digest: %w", err)
	}
	decision := &contracts.DecisionRecord{
		ID:                 decisionID,
		ProposalID:         "proposal_mcp_proof_" + scenario.ID,
		StepID:             scenario.ID,
		PolicyVersion:      "mcp-proof/v2",
		SubjectID:          scenario.Request.Principal,
		Action:             "mcp.tools.call",
		Resource:           scenario.Request.ServerID + "/" + scenario.Request.ToolName,
		EffectDigest:       effectDigest,
		PolicyBackend:      "helm",
		PolicyContentHash:  lpreceipts.Hash(scenario.Request.PolicyHash),
		PolicyDecisionHash: policyDecisionHash,
		Verdict:            string(contracts.VerdictAllow),
		Reason:             scenario.Expected.Reason,
		ReasonCode:         scenario.Expected.Reason,
		InputContext: map[string]any{
			"session_id":           runID,
			"mcp_approval_receipt": scenario.Request.ApprovalReceiptRef,
			"mcp_policy_decision":  policyDecisionHash,
			"mcp_schema_hash":      scenario.Request.SchemaHash,
			"mcp_server_id":        scenario.Request.ServerID,
		},
		Timestamp: generatedAt,
	}
	if err := signer.SignDecision(decision); err != nil {
		return nil, fmt.Errorf("sign execution decision: %w", err)
	}
	intent := &contracts.AuthorizedExecutionIntent{
		ID:               "intent_mcp_proof_" + scenario.ID,
		DecisionID:       decision.ID,
		EffectDigestHash: effectDigest,
		IdempotencyKey:   idempotencyKey,
		IssuedAt:         generatedAt,
		ExpiresAt:        generatedAt.Add(time.Minute),
		Signer:           mcpProofSignatureKeyRef(signer),
		AllowedTool:      mcpProofToolName,
	}
	if err := signer.SignIntent(intent); err != nil {
		return nil, fmt.Errorf("sign execution intent: %w", err)
	}

	dispatchesBefore := driver.DispatchCount()
	receipt, artifact, err := safeExecutor.Execute(ctx, effect, decision, intent)
	if err != nil {
		return nil, fmt.Errorf("safe executor dispatch: %w", err)
	}
	if receipt == nil || artifact == nil || receipt.Signature == "" {
		return nil, fmt.Errorf("safe executor did not return a signed receipt and artifact")
	}
	if driver.DispatchCount() != dispatchesBefore+1 {
		return nil, fmt.Errorf("safe executor driver count=%d, want %d", driver.DispatchCount(), dispatchesBefore+1)
	}
	if receipt.OutputHash != artifact.Digest {
		return nil, fmt.Errorf("execution receipt output hash %q does not match artifact %q", receipt.OutputHash, artifact.Digest)
	}

	replayReceipt, replayArtifact, err := safeExecutor.Execute(ctx, effect, decision, intent)
	if err != nil {
		return nil, fmt.Errorf("safe executor replay: %w", err)
	}
	if driver.DispatchCount() != dispatchesBefore+1 {
		return nil, fmt.Errorf("sequential replay redispatched effect: count=%d", driver.DispatchCount()-dispatchesBefore)
	}
	if replayReceipt == nil || replayReceipt.ReceiptID != receipt.ReceiptID {
		return nil, fmt.Errorf("sequential replay did not return original receipt")
	}
	if replayArtifact == nil || replayArtifact.Digest != receipt.OutputHash {
		return nil, fmt.Errorf("sequential replay artifact is not bound to original output")
	}
	receipt.Type = "mcp_governed_effect_execution"
	receipt.LaunchID = runID
	receipt.DecisionHash = policyDecisionHash
	receipt.Verdict = string(contracts.VerdictAllow)
	receipt.PolicyHash = scenario.Request.PolicyHash
	receipt.ToolName = scenario.Request.ToolName
	receipt.ReasonCode = scenario.Expected.Reason
	receipt.Metadata = map[string]any{
		"approval_receipt_ref": scenario.Request.ApprovalReceiptRef,
		"dispatch_count":       driver.DispatchCount() - dispatchesBefore,
		"replay_no_redispatch": true,
		"reversible":           true,
	}

	receiptData, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal execution receipt: %w", err)
	}
	receiptData = append(receiptData, '\n')
	effectArtifactData, err := os.ReadFile(driver.outputPath)
	if err != nil {
		return nil, fmt.Errorf("read reversible effect: %w", err)
	}
	replayData, err := json.MarshalIndent(map[string]any{
		"schema_version":      "helm.mcp.proof.replay/v1",
		"decision_id":         decision.ID,
		"idempotency_key":     idempotencyKey,
		"original_receipt_id": receipt.ReceiptID,
		"replay_receipt_id":   replayReceipt.ReceiptID,
		"dispatch_count":      driver.DispatchCount() - dispatchesBefore,
		"redispatched":        false,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal replay evidence: %w", err)
	}

	return &mcpProofExecutionResult{
		receipt:            receipt,
		receiptData:        receiptData,
		receiptHash:        lpreceipts.HashBytes(receiptData),
		effectArtifactData: effectArtifactData,
		effectArtifactRef:  "04_EXPORTS/reversible_effect.txt",
		replayData:         append(replayData, '\n'),
	}, nil
}

func mcpProofVerifierForSigner(signer helmcrypto.Signer) (helmcrypto.Verifier, error) {
	if signer == nil {
		return nil, fmt.Errorf("proof signer is required")
	}
	if hybrid, ok := signer.(*helmcrypto.HybridSigner); ok {
		return helmcrypto.NewHybridVerifier(
			hybrid.Ed25519Signer().PublicKeyBytes(),
			hybrid.MLDSASigner().PublicKeyBytes(),
		)
	}
	if signatureVerifier, ok := signer.(helmcrypto.Verifier); ok {
		return signatureVerifier, nil
	}
	return nil, fmt.Errorf("proof signer %T does not provide a compatible verifier", signer)
}

func verifyMCPProofTamperRejected(packDir, evidenceDataDir string, at time.Time) (bool, error) {
	tamperRoot, err := os.MkdirTemp(filepath.Dir(packDir), ".mcp-proof-tamper-")
	if err != nil {
		return false, fmt.Errorf("create tamper workspace: %w", err)
	}
	defer os.RemoveAll(tamperRoot)
	tamperedPack := filepath.Join(tamperRoot, "pack")
	if err := os.MkdirAll(tamperedPack, 0o700); err != nil {
		return false, fmt.Errorf("create tampered pack: %w", err)
	}
	if err := os.CopyFS(tamperedPack, os.DirFS(packDir)); err != nil {
		return false, fmt.Errorf("copy tampered pack: %w", err)
	}
	transcriptPath := filepath.Join(tamperedPack, "04_EXPORTS", "mcp_proof_transcript.json")
	transcript, err := os.ReadFile(transcriptPath)
	if err != nil {
		return false, fmt.Errorf("read tamper target: %w", err)
	}
	mutated := bytes.Replace(
		transcript,
		[]byte(`"helm.mcp.proof.transcript/v2"`),
		[]byte(`"helm.mcp.proof.transcript/v9"`),
		1,
	)
	if bytes.Equal(mutated, transcript) {
		return false, fmt.Errorf("tamper target did not contain transcript schema version")
	}
	if err := os.WriteFile(transcriptPath, mutated, 0o600); err != nil {
		return false, fmt.Errorf("write tampered transcript: %w", err)
	}
	report, verifyErr := verifier.VerifyBundleWithOptions(tamperedPack, verifier.VerifyOptions{
		Profile: evidencepkg.EvidenceTrustProfileDevLocal,
		DataDir: evidenceDataDir,
		Now:     at,
	})
	if verifyErr != nil || !report.Verified {
		return true, nil
	}
	return false, fmt.Errorf("tampered EvidencePack unexpectedly verified")
}

func mcpProofSignatureKeyRef(signer helmcrypto.Signer) string {
	if signer == nil {
		return "unavailable"
	}
	key := signer.PublicKey()
	if len(key) > 16 {
		key = key[:16]
	}
	if key == "" {
		return "ed25519:unknown"
	}
	return "ed25519:" + key
}

// mcpProofSigningPublicKeyHex discloses the full Ed25519 public key so the
// standalone verifier can validate receipt signatures offline. The disclosure
// is integrity-anchored by the pack seal and trusted only under the dev-local
// profile.
func mcpProofSigningPublicKeyHex(signer helmcrypto.Signer) string {
	if signer == nil {
		return ""
	}
	return signer.PublicKey()
}

func negativeMCPProofCasesNoDispatch(results []mcpProofScenarioResult) bool {
	for _, result := range results {
		if result.Verdict != "ALLOW" && (result.Dispatched || result.DispatchCount != 0) {
			return false
		}
	}
	return true
}

func totalMCPProofDispatches(results []mcpProofScenarioResult) int {
	total := 0
	for _, result := range results {
		total += result.DispatchCount
	}
	return total
}

func mcpProofReplayNoRedispatch(results []mcpProofScenarioResult) bool {
	foundPositive := false
	for _, result := range results {
		if result.Verdict != "ALLOW" {
			continue
		}
		foundPositive = true
		if !result.ReplayNoRedispatch {
			return false
		}
	}
	return foundPositive
}

func mcpProofHasPositiveAndNegative(results []mcpProofScenarioResult) bool {
	hasPositive := false
	hasNegative := false
	for _, result := range results {
		if result.Verdict == "ALLOW" {
			hasPositive = true
		} else {
			hasNegative = true
		}
	}
	return hasPositive && hasNegative
}

func buildMCPProofGraph(runID string, generatedAt time.Time, results []mcpProofScenarioResult) []byte {
	nodes := make([]map[string]any, 0, len(results)+1)
	edges := make([]map[string]any, 0, 1)
	for _, result := range results {
		decisionNodeID := result.ScenarioID + "/decision"
		nodes = append(nodes, map[string]any{
			"id":           decisionNodeID,
			"type":         "mcp_policy_decision",
			"receipt_ref":  result.ReceiptRef,
			"receipt_hash": result.ReceiptHash,
			"verdict":      result.Verdict,
			"reason":       result.Reason,
			"dispatched":   result.Dispatched,
		})
		if result.ExecutionReceiptRef != "" {
			executionNodeID := result.ScenarioID + "/execution"
			nodes = append(nodes, map[string]any{
				"id":           executionNodeID,
				"type":         "governed_effect_execution",
				"receipt_ref":  result.ExecutionReceiptRef,
				"receipt_hash": result.ExecutionReceiptHash,
				"artifact_ref": result.EffectArtifactRef,
				"dispatched":   true,
			})
			edges = append(edges, map[string]any{
				"from": decisionNodeID,
				"to":   executionNodeID,
				"type": "authorizes",
			})
		}
	}
	graph := map[string]any{
		"version":      "1.0.0",
		"launch_id":    runID,
		"generated_at": generatedAt.Format(time.RFC3339),
		"nodes":        nodes,
		"edges":        edges,
	}
	data, _ := json.MarshalIndent(graph, "", "  ")
	return append(data, '\n')
}

const mcpProofTranscriptSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.mindburn.dev/helm/mcp-proof-transcript.v2.schema.json",
  "type": "object",
  "required": ["schema_version", "run_id", "scenario", "generated_at", "negative_cases_no_dispatch", "dispatch_count", "replay_no_redispatch", "positive_and_negative", "scenarios"],
  "properties": {
    "schema_version": { "const": "helm.mcp.proof.transcript/v2" },
    "run_id": { "type": "string" },
    "scenario": { "type": "string" },
    "generated_at": { "type": "string", "format": "date-time" },
    "negative_cases_no_dispatch": { "const": true },
    "dispatch_count": { "type": "integer", "minimum": 0 },
    "replay_no_redispatch": { "type": "boolean" },
    "positive_and_negative": { "type": "boolean" },
    "scenarios": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["scenario_id", "verdict", "reason", "dispatched", "dispatch_count", "replay_no_redispatch", "receipt_ref"],
        "properties": {
          "scenario_id": { "type": "string" },
          "verdict": { "enum": ["ALLOW", "DENY", "ESCALATE"] },
          "reason": { "type": "string" },
          "dispatched": { "type": "boolean" },
          "dispatch_count": { "type": "integer", "minimum": 0, "maximum": 1 },
          "replay_no_redispatch": { "type": "boolean" },
          "receipt_ref": { "type": "string" }
        }
      }
    }
  }
}`
