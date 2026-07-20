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
	mcpProofDurationLimit  = 60 * time.Second
	mcpProofToolName       = "proof.local_write"
	mcpProofApprovalRef    = "approval-proof-reversible-write"
	mcpPolicyReceiptPrefix = "mcp_policy_decision/"
	mcpEffectReceiptPrefix = "mcp_governed_effect_execution/"
)

type mcpProofScenario struct {
	ID          string
	Name        string
	ThreatClass string
	Summary     string
	Server      launchpadmcp.ServerRecord
	Request     launchpadmcp.CallRequest
	Expected    launchpadmcp.Decision
	Execute     bool
}

// mcpProofAuthorizationInputs is the exact input passed to AuthorizeAt. It is
// exported and hashed before the evaluation result is recorded so an auditor
// can independently inspect the server record, approval scope, and authority
// time that produced a proof verdict.
type mcpProofAuthorizationInputs struct {
	SchemaVersion string                    `json:"schema_version"`
	ScenarioID    string                    `json:"scenario_id"`
	EvaluatedAt   string                    `json:"evaluated_at"`
	Server        launchpadmcp.ServerRecord `json:"server"`
	Request       launchpadmcp.CallRequest  `json:"request"`
}

type mcpProofAuthorizationEvaluation struct {
	SchemaVersion           string                `json:"schema_version"`
	AuthorizationInputsHash string                `json:"authorization_inputs_hash"`
	AuthorizationInputsRef  string                `json:"authorization_inputs_ref"`
	Decision                launchpadmcp.Decision `json:"decision"`
}

type mcpProofScenarioResult struct {
	ScenarioID                  string                 `json:"scenario_id"`
	Name                        string                 `json:"name"`
	ThreatClass                 string                 `json:"threat_class"`
	PreDispatchAdapter          string                 `json:"pre_dispatch_adapter"`
	ServerID                    string                 `json:"server_id"`
	ToolName                    string                 `json:"tool_name"`
	Verdict                     string                 `json:"verdict"`
	Reason                      string                 `json:"reason"`
	Dispatched                  bool                   `json:"dispatched"`
	DispatchCount               int                    `json:"dispatch_count"`
	ConnectorCalls              int                    `json:"connector_calls"`
	ReplayNoRedispatch          bool                   `json:"replay_no_redispatch"`
	ReceiptRef                  string                 `json:"receipt_ref"`
	ReceiptHash                 string                 `json:"receipt_hash"`
	AuthorizationInputsRef      string                 `json:"authorization_inputs_ref"`
	AuthorizationInputsHash     string                 `json:"authorization_inputs_hash"`
	AuthorizationEvaluationRef  string                 `json:"authorization_evaluation_ref"`
	AuthorizationEvaluationHash string                 `json:"authorization_evaluation_hash"`
	ExecutionReceiptRef         string                 `json:"execution_receipt_ref,omitempty"`
	ExecutionReceiptHash        string                 `json:"execution_receipt_hash,omitempty"`
	ReplayReceiptRef            string                 `json:"replay_receipt_ref,omitempty"`
	ReplayReceiptHash           string                 `json:"replay_receipt_hash,omitempty"`
	ReplayEnvelopeEqual         bool                   `json:"replay_envelope_equal"`
	EffectArtifactRef           string                 `json:"effect_artifact_ref,omitempty"`
	Details                     map[string]interface{} `json:"details,omitempty"`
}

type mcpProofSummary struct {
	SchemaVersion               string                   `json:"schema_version"`
	RunID                       string                   `json:"run_id"`
	Scenario                    string                   `json:"scenario"`
	ProofScope                  string                   `json:"proof_scope"`
	GeneratedAt                 string                   `json:"generated_at"`
	EvidencePackRef             string                   `json:"evidence_pack_ref"`
	EvidencePackArchive         string                   `json:"evidence_pack_archive,omitempty"`
	VerificationCommand         string                   `json:"verification_command"`
	OfflineVerified             bool                     `json:"offline_verified"`
	VerifierSummary             string                   `json:"verifier_summary,omitempty"`
	TamperRejected              bool                     `json:"tamper_rejected"`
	CompletePositiveAndNegative bool                     `json:"complete_positive_and_negative"`
	ProofComplete               bool                     `json:"proof_complete"`
	NegativeCasesNoDispatch     bool                     `json:"negative_cases_no_dispatch"`
	DispatchCount               int                      `json:"dispatch_count"`
	ReplayNoRedispatch          bool                     `json:"replay_no_redispatch"`
	DurationMS                  int64                    `json:"duration_ms"`
	DurationLimitMS             int64                    `json:"duration_limit_ms"`
	DurationGatePass            bool                     `json:"duration_gate_pass"`
	Scenarios                   []mcpProofScenarioResult `json:"scenarios"`
}

type mcpProofExecutionResult struct {
	receipt             *contracts.Receipt
	receiptData         []byte
	receiptHash         string
	replayReceiptData   []byte
	replayReceiptHash   string
	decisionData        []byte
	decisionHash        string
	intentData          []byte
	intentHash          string
	effectArtifactData  []byte
	effectArtifactRef   string
	replayData          []byte
	replayEnvelopeEqual bool
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
	// Return the exact bytes written to disk. SafeExecutor hashes this string
	// as the canonical text artifact, so the signed execution receipt's output
	// hash is the hash of the exported reversible-effect file itself.
	return string(data), nil
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
	scenario = strings.TrimSpace(scenario)
	if scenario == "" {
		scenario = "all"
	}

	selected, err := selectMCPProofScenarios(scenario, generatedAt)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	runDir := filepath.Join(outRoot, runID)
	if err := mcpProofRequireClassicalProfile(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := mcpProofCreateFreshRunDir(runDir); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
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
	proofScope := mcpProofScope(scenario)
	completePositiveAndNegative := mcpProofHasPositiveAndNegative(results)
	if proofScope == "complete" && !completePositiveAndNegative {
		fmt.Fprintln(stderr, "Error: complete MCP proof requires both positive and negative governed-effect scenarios")
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
	if err := mcpProofRequireReplayGate(packDir); err != nil {
		fmt.Fprintf(stderr, "Error: mark MCP proof replay gate: %v\n", err)
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
		SchemaVersion:               "helm.mcp.proof/v3",
		RunID:                       runID,
		Scenario:                    scenario,
		ProofScope:                  proofScope,
		GeneratedAt:                 generatedAt.Format(time.RFC3339),
		EvidencePackRef:             packDir,
		EvidencePackArchive:         archivePath,
		VerificationCommand:         fmt.Sprintf("helm-ai-kernel verify --bundle %s --profile dev-local --json", packDir),
		CompletePositiveAndNegative: completePositiveAndNegative,
		NegativeCasesNoDispatch:     negativeMCPProofCasesNoDispatch(results),
		DispatchCount:               totalMCPProofDispatches(results),
		ReplayNoRedispatch:          mcpProofReplayNoRedispatch(results),
		DurationLimitMS:             mcpProofDurationLimit.Milliseconds(),
		Scenarios:                   results,
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
	summary.ProofComplete = proofScope == "complete" &&
		summary.CompletePositiveAndNegative &&
		summary.NegativeCasesNoDispatch &&
		summary.DispatchCount == 1 &&
		summary.ReplayNoRedispatch &&
		summary.OfflineVerified &&
		summary.TamperRejected &&
		summary.DurationGatePass

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
	if proofScope == "complete" && !summary.ProofComplete {
		fmt.Fprintln(stderr, "Error: complete MCP proof did not satisfy all required positive-and-negative gates")
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
	fmt.Fprintf(stdout, "  Scope: %s (complete=%t)\n", summary.ProofScope, summary.ProofComplete)
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
	}
}

const mcpProofPreDispatchAdapterID = "mcp_proof_pre_dispatch/v1"

// mcpProofPreDispatchAdapter is the proof-only boundary wrapper. Every vector
// goes through it: only an ALLOW vector explicitly marked for execution can
// reach SafeExecutor and its local connector.
type mcpProofPreDispatchAdapter struct {
	runID       string
	generatedAt time.Time
	signer      helmcrypto.Signer
	executor    *executor.SafeExecutor
	driver      *mcpProofLocalDriver
}

type mcpProofDispatchResult struct {
	execution      *mcpProofExecutionResult
	connectorCalls int
}

func (a *mcpProofPreDispatchAdapter) Authorize(scenario mcpProofScenario) launchpadmcp.Decision {
	return launchpadmcp.AuthorizeAt(scenario.Server, scenario.Request, a.generatedAt)
}

func (a *mcpProofPreDispatchAdapter) Dispatch(
	ctx context.Context,
	scenario mcpProofScenario,
	decision launchpadmcp.Decision,
	policyEvaluationHash string,
	authorizationInputsHash string,
) (*mcpProofDispatchResult, error) {
	if a == nil || a.executor == nil || a.driver == nil || a.signer == nil {
		return nil, fmt.Errorf("pre-dispatch adapter is not initialized")
	}
	before := a.driver.DispatchCount()
	result := &mcpProofDispatchResult{}
	if decision.Verdict == string(contracts.VerdictAllow) {
		if !scenario.Execute {
			return nil, fmt.Errorf("ALLOW scenario %s has no declared SafeExecutor path", scenario.ID)
		}
		executionResult, err := executeMCPProofScenario(
			ctx,
			a.runID,
			a.generatedAt,
			scenario,
			policyEvaluationHash,
			authorizationInputsHash,
			a.signer,
			a.executor,
			a.driver,
		)
		if err != nil {
			return nil, err
		}
		result.execution = executionResult
	} else if scenario.Execute {
		return nil, fmt.Errorf("non-ALLOW scenario %s attempted execution", scenario.ID)
	}
	result.connectorCalls = a.driver.DispatchCount() - before
	if decision.Verdict != string(contracts.VerdictAllow) && result.connectorCalls != 0 {
		return nil, fmt.Errorf("non-ALLOW scenario %s reached connector %d times", scenario.ID, result.connectorCalls)
	}
	return result, nil
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
	preDispatch := &mcpProofPreDispatchAdapter{
		runID:       runID,
		generatedAt: generatedAt,
		signer:      signer,
		executor:    safeExecutor,
		driver:      driver,
	}

	for idx, scenario := range scenarios {
		decision := preDispatch.Authorize(scenario)
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
		authorizationInputs := mcpProofAuthorizationInputs{
			SchemaVersion: "helm.mcp.proof.authorization-inputs/v1",
			ScenarioID:    scenario.ID,
			EvaluatedAt:   generatedAt.Format(time.RFC3339),
			Server:        scenario.Server,
			Request:       scenario.Request,
		}
		authorizationInputsData, err := mcpProofJSON(authorizationInputs)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal authorization inputs for %s: %w", scenario.ID, err)
		}
		authorizationInputsHash := lpreceipts.HashBytes(authorizationInputsData)
		authorizationInputsRef := "02_PROOFGRAPH/authorization_inputs/" + scenario.ID + ".json"
		artifacts[authorizationInputsRef] = authorizationInputsData

		authorizationEvaluation := mcpProofAuthorizationEvaluation{
			SchemaVersion:           "helm.mcp.proof.authorization-evaluation/v1",
			AuthorizationInputsHash: authorizationInputsHash,
			AuthorizationInputsRef:  authorizationInputsRef,
			Decision:                decision,
		}
		authorizationEvaluationData, err := mcpProofJSON(authorizationEvaluation)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal authorization evaluation for %s: %w", scenario.ID, err)
		}
		authorizationEvaluationHash := lpreceipts.HashBytes(authorizationEvaluationData)
		authorizationEvaluationRef := "02_PROOFGRAPH/authorization_evaluations/" + scenario.ID + ".json"
		artifacts[authorizationEvaluationRef] = authorizationEvaluationData
		dispatchResult, err := preDispatch.Dispatch(
			context.Background(),
			scenario,
			decision,
			authorizationEvaluationHash,
			authorizationInputsHash,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("pre-dispatch scenario %s: %w", scenario.ID, err)
		}
		executionResult := dispatchResult.execution
		if executionResult != nil {
			artifacts["receipts/"+scenario.ID+"-execution.json"] = executionResult.receiptData
			artifacts["receipts/"+scenario.ID+"-execution-replay.json"] = executionResult.replayReceiptData
			artifacts["02_PROOFGRAPH/decisions/"+scenario.ID+".json"] = executionResult.decisionData
			artifacts["02_PROOFGRAPH/intents/"+scenario.ID+".json"] = executionResult.intentData
			artifacts["04_EXPORTS/reversible_effect.txt"] = executionResult.effectArtifactData
			artifacts["08_TAPES/"+scenario.ID+"-replay.json"] = executionResult.replayData
		}
		dispatchCount := dispatchResult.connectorCalls
		if scenario.Execute && dispatchCount != 1 {
			return nil, nil, fmt.Errorf("proof scenario %s dispatched %d times, want exactly 1", scenario.ID, dispatchCount)
		}
		if !scenario.Execute && dispatchCount != 0 {
			return nil, nil, fmt.Errorf("proof scenario %s dispatched %d times, want 0", scenario.ID, dispatchCount)
		}
		dispatched := dispatchCount > 0
		receipt := &contracts.Receipt{
			ReceiptID:  "rcpt_mcp_proof_" + scenario.ID,
			DecisionID: "decision_mcp_proof_" + scenario.ID,
			EffectID:   mcpPolicyReceiptPrefix + scenario.ID,
			Status:     decision.Verdict,
			// OutputHash binds the complete evaluation (input hash plus actual
			// AuthorizeAt result) while ArgsHash binds the raw authorization
			// inputs. Both fields are covered by the receipt signature.
			OutputHash:   authorizationEvaluationHash,
			Timestamp:    generatedAt,
			ExecutorID:   "helm-ai-kernel.mcp.proof",
			PrevHash:     previousReceiptHash,
			LamportClock: uint64(idx + 1),
			ArgsHash:     authorizationInputsHash,
		}
		if err := signer.SignReceipt(receipt); err != nil {
			return nil, nil, fmt.Errorf("sign receipt for %s: %w", scenario.ID, err)
		}
		receiptData, err := mcpProofJSON(receipt)
		if err != nil {
			return nil, nil, err
		}
		receiptHash := lpreceipts.HashBytes(receiptData)
		previousReceiptHash = receiptHash
		artifacts["receipts/"+scenario.ID+".json"] = receiptData

		result := mcpProofScenarioResult{
			ScenarioID:                  scenario.ID,
			Name:                        scenario.Name,
			ThreatClass:                 scenario.ThreatClass,
			PreDispatchAdapter:          mcpProofPreDispatchAdapterID,
			ServerID:                    scenario.Request.ServerID,
			ToolName:                    scenario.Request.ToolName,
			Verdict:                     decision.Verdict,
			Reason:                      decision.Reason,
			Dispatched:                  dispatched,
			DispatchCount:               dispatchCount,
			ConnectorCalls:              dispatchResult.connectorCalls,
			ReplayNoRedispatch:          executionResult != nil && executionResult.replayEnvelopeEqual,
			ReceiptRef:                  "02_PROOFGRAPH/receipts/" + scenario.ID + ".json",
			ReceiptHash:                 receiptHash,
			AuthorizationInputsRef:      authorizationInputsRef,
			AuthorizationInputsHash:     authorizationInputsHash,
			AuthorizationEvaluationRef:  authorizationEvaluationRef,
			AuthorizationEvaluationHash: authorizationEvaluationHash,
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
			result.ReplayReceiptRef = "02_PROOFGRAPH/receipts/" + scenario.ID + "-execution-replay.json"
			result.ReplayReceiptHash = executionResult.replayReceiptHash
			result.ReplayEnvelopeEqual = executionResult.replayEnvelopeEqual
			result.EffectArtifactRef = executionResult.effectArtifactRef
			result.Details["execution_receipt_id"] = executionResult.receipt.ReceiptID
			result.Details["execution_decision_hash"] = executionResult.decisionHash
			result.Details["execution_intent_hash"] = executionResult.intentHash
			result.Details["idempotency_key"] = "mcp-proof/" + runID + "/" + scenario.ID
		}
		results = append(results, result)
		resultData, err := mcpProofJSON(result)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal scenario result for %s: %w", scenario.ID, err)
		}
		artifacts["scenario_results/"+scenario.ID+".json"] = resultData
	}

	transcript := map[string]any{
		"schema_version":                 "helm.mcp.proof.transcript/v3",
		"run_id":                         runID,
		"scenario":                       scenarioName,
		"proof_scope":                    mcpProofScope(scenarioName),
		"generated_at":                   generatedAt.Format(time.RFC3339),
		"complete_positive_and_negative": mcpProofHasPositiveAndNegative(results),
		"negative_cases_no_dispatch":     negativeMCPProofCasesNoDispatch(results),
		"dispatch_count":                 totalMCPProofDispatches(results),
		"replay_no_redispatch":           mcpProofReplayNoRedispatch(results),
		"scenarios":                      results,
	}
	transcriptData, err := mcpProofJSON(transcript)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal proof transcript: %w", err)
	}
	artifacts["mcp_proof_transcript.json"] = transcriptData
	artifacts["proofgraph.json"] = buildMCPProofGraph(runID, generatedAt, results)
	artifacts["09_SCHEMAS/mcp_proof_transcript.schema.json"] = []byte(mcpProofTranscriptSchema + "\n")
	if err := addMCPProofReplayAndTamperArtifacts(runID, results, transcriptData, artifacts); err != nil {
		return nil, nil, err
	}
	return results, artifacts, nil
}

func addMCPProofReplayAndTamperArtifacts(runID string, results []mcpProofScenarioResult, transcriptData []byte, artifacts map[string][]byte) error {
	entries := make([]map[string]any, 0, 1)
	for _, result := range results {
		if result.Verdict != string(contracts.VerdictAllow) {
			continue
		}
		if result.ExecutionReceiptRef == "" || result.ReplayReceiptRef == "" || !result.ReplayEnvelopeEqual {
			return fmt.Errorf("ALLOW scenario %s is missing replay evidence", result.ScenarioID)
		}
		entries = append(entries, map[string]any{
			"scenario_id":           result.ScenarioID,
			"execution_receipt_ref": result.ExecutionReceiptRef,
			"execution_receipt_hash": result.ExecutionReceiptHash,
			"replay_receipt_ref":    result.ReplayReceiptRef,
			"replay_receipt_hash":   result.ReplayReceiptHash,
			"connector_calls":       result.ConnectorCalls,
		})
	}
	if len(entries) == 0 {
		return fmt.Errorf("MCP proof requires replay evidence for an ALLOW scenario")
	}
	tapeManifest, err := mcpProofJSON(map[string]any{
		"schema_version": "helm.mcp.proof.tape-manifest/v1",
		"run_id":         runID,
		"entries":        entries,
	})
	if err != nil {
		return fmt.Errorf("marshal replay tape manifest: %w", err)
	}
	artifacts["08_TAPES/tape_manifest.json"] = tapeManifest
	first := entries[0]
	determinismManifest, err := mcpProofJSON(map[string]any{
		"schema_version": "helm.mcp.proof.determinism/v1",
		"run_id":         runID,
		"live_hash":      first["execution_receipt_hash"],
		"replay_hash":    first["replay_receipt_hash"],
	})
	if err != nil {
		return fmt.Errorf("marshal determinism manifest: %w", err)
	}
	artifacts["02_PROOFGRAPH/determinism_manifest.json"] = determinismManifest

	tamperVectors, err := mcpProofJSON(map[string]any{
		"schema_version":           "helm.mcp.proof.tamper-vectors/v1",
		"required_verifier_check":  "mcp_proof_semantics",
		"vectors": []map[string]any{
			{
				"id":                   "transcript_schema_tamper",
				"target_ref":           "04_EXPORTS/mcp_proof_transcript.json",
				"expected_target_hash": lpreceipts.HashBytes(transcriptData),
				"expected_rejection":   "mcp_proof_semantics",
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal tamper vectors: %w", err)
	}
	artifacts["12_REPORTS/mcp_proof_tamper_vectors.json"] = tamperVectors
	return nil
}

func executeMCPProofScenario(
	ctx context.Context,
	runID string,
	generatedAt time.Time,
	scenario mcpProofScenario,
	policyEvaluationHash string,
	authorizationInputsHash string,
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
		EffectID:       mcpEffectReceiptPrefix + scenario.ID,
		EffectType:     contracts.EffectTypeCallTool,
		DecisionID:     decisionID,
		IdempotencyKey: idempotencyKey,
		Params: map[string]any{
			"tool_name":  mcpProofToolName,
			"content":    "HELM governed reversible local effect for " + runID,
			"reversible": true,
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
		PolicyDecisionHash: policyEvaluationHash,
		Verdict:            string(contracts.VerdictAllow),
		Reason:             scenario.Expected.Reason,
		ReasonCode:         scenario.Expected.Reason,
		InputContext: map[string]any{
			"session_id":                    runID,
			"mcp_approval_receipt":          scenario.Request.ApprovalReceiptRef,
			"mcp_authorization_inputs_hash": authorizationInputsHash,
			"mcp_policy_evaluation_hash":    policyEvaluationHash,
			"mcp_schema_hash":               scenario.Request.SchemaHash,
			"mcp_server_id":                 scenario.Request.ServerID,
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
	decisionData, err := mcpProofJSON(decision)
	if err != nil {
		return nil, fmt.Errorf("marshal signed execution decision: %w", err)
	}
	intentData, err := mcpProofJSON(intent)
	if err != nil {
		return nil, fmt.Errorf("marshal signed execution intent: %w", err)
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
	effectArtifactData, err := os.ReadFile(driver.outputPath)
	if err != nil {
		return nil, fmt.Errorf("read reversible effect: %w", err)
	}
	if !bytes.Equal(artifact.CanonicalBytes, effectArtifactData) {
		return nil, fmt.Errorf("execution artifact bytes do not match exported reversible effect")
	}
	if lpreceipts.HashBytes(effectArtifactData) != receipt.OutputHash {
		return nil, fmt.Errorf("execution receipt output hash does not bind exported reversible effect")
	}
	receiptData, err := mcpProofJSON(receipt)
	if err != nil {
		return nil, fmt.Errorf("marshal execution receipt: %w", err)
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
	replayReceiptData, err := mcpProofJSON(replayReceipt)
	if err != nil {
		return nil, fmt.Errorf("marshal replayed execution receipt: %w", err)
	}
	if !bytes.Equal(receiptData, replayReceiptData) {
		return nil, fmt.Errorf("replayed receipt envelope does not equal persisted original")
	}
	replayData, err := json.MarshalIndent(map[string]any{
		"schema_version":         "helm.mcp.proof.replay/v2",
		"decision_id":            decision.ID,
		"idempotency_key":        idempotencyKey,
		"original_receipt_id":    receipt.ReceiptID,
		"original_receipt_hash":  lpreceipts.HashBytes(receiptData),
		"replay_receipt_id":      replayReceipt.ReceiptID,
		"replay_receipt_hash":    lpreceipts.HashBytes(replayReceiptData),
		"receipt_envelope_equal": true,
		"effect_output_hash":     receipt.OutputHash,
		"effect_artifact_hash":   lpreceipts.HashBytes(effectArtifactData),
		"dispatch_count":         driver.DispatchCount() - dispatchesBefore,
		"redispatched":           false,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal replay evidence: %w", err)
	}

	return &mcpProofExecutionResult{
		receipt:             receipt,
		receiptData:         receiptData,
		receiptHash:         lpreceipts.HashBytes(receiptData),
		replayReceiptData:   replayReceiptData,
		replayReceiptHash:   lpreceipts.HashBytes(replayReceiptData),
		decisionData:        decisionData,
		decisionHash:        lpreceipts.HashBytes(decisionData),
		intentData:          intentData,
		intentHash:          lpreceipts.HashBytes(intentData),
		effectArtifactData:  effectArtifactData,
		effectArtifactRef:   "04_EXPORTS/reversible_effect.txt",
		replayData:          append(replayData, '\n'),
		replayEnvelopeEqual: true,
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
		[]byte(`"helm.mcp.proof.transcript/v3"`),
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

func mcpProofJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func mcpProofRequireClassicalProfile() error {
	profile := strings.TrimSpace(os.Getenv("HELM_RECEIPT_PROFILE"))
	if profile == "" || profile == helmcrypto.ReceiptProfileClassical {
		return nil
	}
	return fmt.Errorf("mcp proof is a dev-local classical-only proof; HELM_RECEIPT_PROFILE=%q is rejected before any governed effect", profile)
}

// mcpProofCreateFreshRunDir makes a run ID an immutable proof instance. A
// retry never resumes an old execution store, which prevents a stale
// idempotency receipt from being mistaken for a new governed effect.
func mcpProofCreateFreshRunDir(runDir string) error {
	if _, err := os.Lstat(runDir); err == nil {
		return fmt.Errorf("proof output %q already exists; mcp proof never resumes a run ID, choose a new --run-id or --out", runDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect proof output %q: %w", runDir, err)
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return fmt.Errorf("create proof output: %w", err)
	}
	return nil
}

// mcpProofRequireReplayGate upgrades the generated launchpad index before it
// is sealed. The generic offline verifier then requires the proof replay tape
// in addition to the MCP-specific semantic check.
func mcpProofRequireReplayGate(packDir string) error {
	path := filepath.Join(packDir, "00_INDEX.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var index map[string]json.RawMessage
	if err := json.Unmarshal(data, &index); err != nil {
		return err
	}
	var gates []string
	if raw, ok := index["gates"]; ok {
		if err := json.Unmarshal(raw, &gates); err != nil {
			return fmt.Errorf("decode 00_INDEX.json gates: %w", err)
		}
	}
	for _, gate := range gates {
		if gate == "G2" {
			return nil
		}
	}
	gates = append(gates, "G2")
	raw, err := json.Marshal(gates)
	if err != nil {
		return err
	}
	index["gates"] = raw
	updated, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(updated, '\n'), 0o600)
}

func mcpProofScope(scenario string) string {
	if strings.TrimSpace(scenario) == "all" {
		return "complete"
	}
	return "vector_only"
}

func negativeMCPProofCasesNoDispatch(results []mcpProofScenarioResult) bool {
	foundNegative := false
	for _, result := range results {
		if result.Verdict != "ALLOW" {
			foundNegative = true
			if result.Dispatched || result.DispatchCount != 0 {
				return false
			}
		}
	}
	return foundNegative
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
		if !result.ReplayNoRedispatch || !result.ReplayEnvelopeEqual {
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
  "$id": "https://schemas.mindburn.dev/helm/mcp-proof-transcript.v3.schema.json",
  "type": "object",
  "required": ["schema_version", "run_id", "scenario", "proof_scope", "generated_at", "complete_positive_and_negative", "negative_cases_no_dispatch", "dispatch_count", "replay_no_redispatch", "scenarios"],
  "properties": {
    "schema_version": { "const": "helm.mcp.proof.transcript/v3" },
    "run_id": { "type": "string" },
    "scenario": { "type": "string" },
    "proof_scope": { "enum": ["complete", "vector_only"] },
    "generated_at": { "type": "string", "format": "date-time" },
    "complete_positive_and_negative": { "type": "boolean" },
    "negative_cases_no_dispatch": { "type": "boolean" },
    "dispatch_count": { "type": "integer", "minimum": 0 },
    "replay_no_redispatch": { "type": "boolean" },
    "scenarios": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["scenario_id", "pre_dispatch_adapter", "verdict", "reason", "dispatched", "dispatch_count", "connector_calls", "replay_no_redispatch", "receipt_ref"],
	        "properties": {
	          "scenario_id": { "type": "string" },
	          "pre_dispatch_adapter": { "const": "mcp_proof_pre_dispatch/v1" },
	          "verdict": { "enum": ["ALLOW", "DENY", "ESCALATE"] },
	          "reason": { "type": "string" },
	          "dispatched": { "type": "boolean" },
	          "dispatch_count": { "type": "integer", "minimum": 0, "maximum": 1 },
	          "connector_calls": { "type": "integer", "minimum": 0, "maximum": 1 },
          "replay_no_redispatch": { "type": "boolean" },
          "receipt_ref": { "type": "string" }
        }
      }
    }
  }
}`
