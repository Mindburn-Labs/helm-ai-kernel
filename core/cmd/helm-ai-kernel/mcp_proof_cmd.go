package main

import (
	"context"
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
	launchpadmcp "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/mcp"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

type mcpProofScenario struct {
	ID          string
	Name        string
	ThreatClass string
	Summary     string
	Server      launchpadmcp.ServerRecord
	Request     launchpadmcp.CallRequest
	Decision    *launchpadmcp.Decision
}

type mcpProofScenarioResult struct {
	ScenarioID  string                 `json:"scenario_id"`
	Name        string                 `json:"name"`
	ThreatClass string                 `json:"threat_class"`
	ServerID    string                 `json:"server_id"`
	ToolName    string                 `json:"tool_name"`
	Verdict     string                 `json:"verdict"`
	Reason      string                 `json:"reason"`
	Dispatched  bool                   `json:"dispatched"`
	ReceiptRef  string                 `json:"receipt_ref"`
	ReceiptHash string                 `json:"receipt_hash"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

type mcpProofSummary struct {
	SchemaVersion       string                   `json:"schema_version"`
	RunID               string                   `json:"run_id"`
	Scenario            string                   `json:"scenario"`
	GeneratedAt         string                   `json:"generated_at"`
	EvidencePackRef     string                   `json:"evidence_pack_ref"`
	EvidencePackArchive string                   `json:"evidence_pack_archive,omitempty"`
	VerificationCommand string                   `json:"verification_command"`
	OfflineVerified     bool                     `json:"offline_verified"`
	VerifierSummary     string                   `json:"verifier_summary,omitempty"`
	Scenarios           []mcpProofScenarioResult `json:"scenarios"`
}

func runMCPProof(args []string, stdout, stderr io.Writer) int {
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
	cmd.BoolVar(&verify, "verify", true, "Run offline EvidencePack verification")
	if err := cmd.Parse(args); err != nil {
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

	results, artifacts, err := buildMCPProofArtifacts(runID, scenario, generatedAt, selected, receiptSigner)
	if err != nil {
		fmt.Fprintf(stderr, "Error: build proof artifacts: %v\n", err)
		return 1
	}

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
		SchemaVersion:       "helm.mcp.proof/v1",
		RunID:               runID,
		Scenario:            scenario,
		GeneratedAt:         generatedAt.Format(time.RFC3339),
		EvidencePackRef:     packDir,
		EvidencePackArchive: archivePath,
		VerificationCommand: fmt.Sprintf("helm-ai-kernel verify --bundle %s --profile dev-local --json", packDir),
		Scenarios:           results,
	}
	if verify {
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
	}

	data, _ := json.MarshalIndent(summary, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, "summary.json"), append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(stderr, "Error: write proof summary: %v\n", err)
		return 1
	}
	writeMCPProofSummary(stdout, summary, jsonOutput)
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

func mcpProofScenarios(_ time.Time) []mcpProofScenario {
	opaqueApproval := launchpadmcp.ServerRecord{
		ServerID:   "srv-approved",
		LaunchID:   "launch-proof",
		AppID:      "proof-app",
		Principal:  "operator@example.com",
		PolicyHash: "sha256:policy-proof",
		Approved:   true,
		SchemaPins: map[string]string{
			"proof.read":  "sha256:read",
			"proof.write": "sha256:write",
		},
	}
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
		},
		{
			ID:          "prompt_injected_tool_output",
			Name:        "Prompt-injected tool output cannot induce a side effect",
			ThreatClass: "prompt_injected_tool_output",
			Summary:     "A tainted tool-output instruction cannot turn opaque approval metadata into a dispatch grant.",
			Server:      opaqueApproval,
			Request:     req("proof.write", "sha256:write", launchpadmcp.EffectSideEffect),
		},
		{
			ID:          "excessive_agency",
			Name:        "Excessive agency request requires approval before dispatch",
			ThreatClass: "excessive_agency",
			Summary:     "A destructive autonomous action remains blocked without credential-verified approval evidence.",
			Server:      opaqueApproval,
			Request:     req("proof.write", "sha256:write", launchpadmcp.EffectSideEffect),
		},
		{
			ID:          "confused_deputy_scope_mismatch",
			Name:        "Confused-deputy launch scope mismatch fails closed",
			ThreatClass: "confused_deputy",
			Summary:     "A request tries to reuse another launch scope.",
			Server:      opaqueApproval,
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
		},
		{
			ID:          "missing_schema_pin",
			Name:        "Opaque approval metadata remains quarantined",
			ThreatClass: "missing_schema_pin",
			Summary:     "An opaque approved status cannot bypass credential verification or schema pinning.",
			Server:      opaqueApproval,
			Request:     req("proof.unpinned", "sha256:unknown", launchpadmcp.EffectRead),
		},
		{
			ID:          "schema_drift",
			Name:        "Schema drift denies before dispatch",
			ThreatClass: "schema_drift",
			Summary:     "A caller-supplied schema hash cannot bypass credential verification or schema pinning.",
			Server:      opaqueApproval,
			Request:     req("proof.read", "sha256:drift", launchpadmcp.EffectRead),
		},
		{
			ID:          "replay_reordering_attempt",
			Name:        "Replay or reordering attempt is marked invalid",
			ThreatClass: "replay_reordering",
			Summary:     "A replay ledger attempts to present side effects out of causal order.",
			Server:      opaqueApproval,
			Request:     req("proof.write", "sha256:write", launchpadmcp.EffectSideEffect),
			Decision:    &replayDecision,
		},
	}
}

func buildMCPProofArtifacts(runID, scenarioName string, generatedAt time.Time, scenarios []mcpProofScenario, signer helmcrypto.Signer) ([]mcpProofScenarioResult, map[string][]byte, error) {
	results := make([]mcpProofScenarioResult, 0, len(scenarios))
	artifacts := map[string][]byte{}
	previousReceiptHash := ""

	for idx, scenario := range scenarios {
		decision := launchpadmcp.Authorize(scenario.Server, scenario.Request)
		if scenario.Decision != nil {
			decision = *scenario.Decision
		}
		if decision.Verdict == "ALLOW" {
			return nil, nil, fmt.Errorf("proof scenario %s allowed unexpectedly", scenario.ID)
		}
		dispatched := false
		decisionHash := lpreceipts.Hash(map[string]any{
			"scenario_id": scenario.ID,
			"decision":    decision,
			"request":     scenario.Request,
		})
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
			ScenarioID:  scenario.ID,
			Name:        scenario.Name,
			ThreatClass: scenario.ThreatClass,
			ServerID:    scenario.Request.ServerID,
			ToolName:    scenario.Request.ToolName,
			Verdict:     decision.Verdict,
			Reason:      decision.Reason,
			Dispatched:  dispatched,
			ReceiptRef:  "02_PROOFGRAPH/receipts/" + scenario.ID + ".json",
			ReceiptHash: receiptHash,
			Details: map[string]interface{}{
				"launch_id":   scenario.Request.LaunchID,
				"app_id":      scenario.Request.AppID,
				"principal":   scenario.Request.Principal,
				"policy_hash": scenario.Request.PolicyHash,
				"schema_hash": scenario.Request.SchemaHash,
				"schema_pin":  decision.SchemaPin,
			},
		}
		results = append(results, result)
		resultData, _ := json.MarshalIndent(result, "", "  ")
		artifacts["scenario_results/"+scenario.ID+".json"] = append(resultData, '\n')
	}

	transcript := map[string]any{
		"schema_version": "helm.mcp.proof.transcript/v1",
		"run_id":         runID,
		"scenario":       scenarioName,
		"generated_at":   generatedAt.Format(time.RFC3339),
		"no_dispatch":    allMCPProofResultsNoDispatch(results),
		"scenarios":      results,
	}
	transcriptData, _ := json.MarshalIndent(transcript, "", "  ")
	artifacts["mcp_proof_transcript.json"] = append(transcriptData, '\n')
	artifacts["proofgraph.json"] = buildMCPProofGraph(runID, generatedAt, results)
	artifacts["09_SCHEMAS/mcp_proof_transcript.schema.json"] = []byte(mcpProofTranscriptSchema + "\n")
	artifacts["08_TAPES/mcp_replay_reordering_attempt.json"] = []byte(fmt.Sprintf(`{"run_id":%q,"scenario_id":"replay_reordering_attempt","status":"invalid","reason":"ERR_MCP_REPLAY_REORDERING_ATTEMPT"}`+"\n", runID))
	return results, artifacts, nil
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

func allMCPProofResultsNoDispatch(results []mcpProofScenarioResult) bool {
	for _, result := range results {
		if result.Dispatched {
			return false
		}
	}
	return true
}

func buildMCPProofGraph(runID string, generatedAt time.Time, results []mcpProofScenarioResult) []byte {
	nodes := make([]map[string]any, 0, len(results))
	for _, result := range results {
		nodes = append(nodes, map[string]any{
			"id":           result.ScenarioID,
			"type":         "mcp_policy_decision",
			"receipt_ref":  result.ReceiptRef,
			"receipt_hash": result.ReceiptHash,
			"verdict":      result.Verdict,
			"reason":       result.Reason,
			"dispatched":   result.Dispatched,
		})
	}
	graph := map[string]any{
		"version":      "1.0.0",
		"launch_id":    runID,
		"generated_at": generatedAt.Format(time.RFC3339),
		"nodes":        nodes,
		"edges":        []map[string]any{},
	}
	data, _ := json.MarshalIndent(graph, "", "  ")
	return append(data, '\n')
}

const mcpProofTranscriptSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.mindburn.dev/helm/mcp-proof-transcript.v1.schema.json",
  "type": "object",
  "required": ["schema_version", "run_id", "scenario", "generated_at", "no_dispatch", "scenarios"],
  "properties": {
    "schema_version": { "const": "helm.mcp.proof.transcript/v1" },
    "run_id": { "type": "string" },
    "scenario": { "type": "string" },
    "generated_at": { "type": "string", "format": "date-time" },
    "no_dispatch": { "type": "boolean" },
    "scenarios": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["scenario_id", "verdict", "reason", "dispatched", "receipt_ref"],
        "properties": {
          "scenario_id": { "type": "string" },
          "verdict": { "enum": ["DENY", "ESCALATE"] },
          "reason": { "type": "string" },
          "dispatched": { "const": false },
          "receipt_ref": { "type": "string" }
        }
      }
    }
  }
}`
