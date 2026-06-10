package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

// Simulation fixtures. The approved server and tool exist only inside the
// simulation harness so that vectors can probe gates deeper than quarantine
// (scope checks, schema pins, catalog gaps). Nothing real is approved.
const (
	simApprovedServer = "sim-approved-fixture"
	simApprovedTool   = "files.read"
	simRequiredScope  = "files:read"
)

// NegativeVector is one adversarial probe dispatched through the real
// ExecutionFirewall during blast-radius simulation.
type NegativeVector struct {
	ID               string   `json:"id"`
	Category         string   `json:"category"`
	Description      string   `json:"description"`
	ServerID         string   `json:"server_id"`
	Tool             string   `json:"tool"`
	Scopes           []string `json:"scopes,omitempty"`
	PinnedSchemaHash string   `json:"pinned_schema_hash,omitempty"`
	Repeat           int      `json:"repeat,omitempty"`
}

// VectorResult records the boundary's verdict for one vector attempt.
type VectorResult struct {
	VectorID        string `json:"vector_id"`
	Category        string `json:"category"`
	Attempt         int    `json:"attempt"`
	Verdict         string `json:"verdict"`
	ReasonCode      string `json:"reason_code,omitempty"`
	RecordHash      string `json:"record_hash"`
	DispatchAllowed bool   `json:"dispatch_allowed"`
}

// BlastRadiusReport is the deterministic output of `autoconfigure simulate`.
type BlastRadiusReport struct {
	Version       string         `json:"version"`
	GeneratedFrom string         `json:"generated_from"`
	PolicyEpoch   string         `json:"policy_epoch"`
	Results       []VectorResult `json:"results"`
	Denied        int            `json:"denied"`
	Escalated     int            `json:"escalated"`
	Allowed       int            `json:"allowed"`
	AllBlocked    bool           `json:"all_blocked"`
}

// simulationVectors returns the negative-vector suite. The quarantined target
// is taken from the inventory when available so the probe exercises the
// operator's actual discovered surface.
func simulationVectors(quarantined []string) []NegativeVector {
	target := "sim-quarantined-fixture"
	if len(quarantined) > 0 {
		target = quarantined[0]
	}
	return []NegativeVector{
		{ID: "NV-001", Category: "spend_escalation", Description: "transfer funds via unapproved server", ServerID: target, Tool: "payments.transfer"},
		{ID: "NV-002", Category: "data_exfiltration", Description: "bulk customer export via unapproved server", ServerID: target, Tool: "db.export_customers"},
		{ID: "NV-003", Category: "privilege_escalation", Description: "self-grant admin role via unapproved server", ServerID: target, Tool: "iam.grant_admin"},
		{ID: "NV-004", Category: "retry_storm", Description: "repeated side-effecting call must stay denied on every attempt", ServerID: target, Tool: "payments.transfer", Repeat: 5},
		{ID: "NV-005", Category: "schema_mismatch", Description: "approved tool called with drifted pinned schema", ServerID: simApprovedServer, Tool: simApprovedTool, Scopes: []string{simRequiredScope}, PinnedSchemaHash: "sha256:drifted"},
		{ID: "NV-006", Category: "missing_credentials", Description: "approved tool called without required scope", ServerID: simApprovedServer, Tool: simApprovedTool},
		{ID: "NV-007", Category: "policy_gap", Description: "tool absent from catalog on approved server", ServerID: simApprovedServer, Tool: "unknown.tool", Scopes: []string{simRequiredScope}},
	}
}

// runBlastRadius dispatches every negative vector through a real
// ExecutionFirewall seeded from the inventory: discovered MCP servers are
// quarantined (never approved), and one synthetic fixture server is approved
// so deeper gates are exercised. Deterministic: fixed clock, ordered vectors.
func runBlastRadius(ctx context.Context, inv AutoconfigureInventory) (BlastRadiusReport, []NegativeVector, error) {
	report := BlastRadiusReport{
		Version:       "blast-radius-report/v1",
		GeneratedFrom: inv.ScanRoot,
		PolicyEpoch:   "sim-epoch",
		Results:       []VectorResult{},
	}

	registry := mcp.NewQuarantineRegistry()
	quarantined := make([]string, 0, len(inv.MCPServers))
	for _, s := range inv.MCPServers {
		if _, err := registry.Discover(ctx, mcp.DiscoverServerRequest{ServerID: s.ConfigPath}); err != nil {
			return report, nil, fmt.Errorf("discover %s: %w", s.ConfigPath, err)
		}
		quarantined = append(quarantined, s.ConfigPath)
	}
	vectors := simulationVectors(quarantined)
	if len(quarantined) == 0 {
		if _, err := registry.Discover(ctx, mcp.DiscoverServerRequest{ServerID: vectors[0].ServerID}); err != nil {
			return report, nil, fmt.Errorf("discover fixture: %w", err)
		}
	}

	if _, err := registry.Discover(ctx, mcp.DiscoverServerRequest{ServerID: simApprovedServer}); err != nil {
		return report, nil, fmt.Errorf("discover approved fixture: %w", err)
	}
	if _, err := registry.Approve(ctx, mcp.ApprovalDecision{
		ServerID:          simApprovedServer,
		ApproverID:        "sim-harness",
		ApprovalReceiptID: "sim-approval-fixture",
	}); err != nil {
		return report, nil, fmt.Errorf("approve fixture: %w", err)
	}

	catalog := mcp.NewToolCatalog()
	if err := catalog.Register(ctx, mcp.ToolRef{
		Name:           simApprovedTool,
		Description:    "simulation fixture tool",
		ServerID:       simApprovedServer,
		Schema:         map[string]any{"type": "object"},
		RequiredScopes: []string{simRequiredScope},
	}); err != nil {
		return report, nil, fmt.Errorf("register fixture tool: %w", err)
	}

	firewall := mcp.NewExecutionFirewall(catalog, registry, report.PolicyEpoch)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := 0
	firewall.Clock = func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Millisecond)
	}

	for _, v := range vectors {
		attempts := v.Repeat
		if attempts < 1 {
			attempts = 1
		}
		for attempt := 1; attempt <= attempts; attempt++ {
			record, err := firewall.AuthorizeToolCall(ctx, mcp.ToolCallAuthorization{
				ServerID:         v.ServerID,
				ToolName:         v.Tool,
				ArgsHash:         "sha256:sim-args",
				GrantedScopes:    v.Scopes,
				PinnedSchemaHash: v.PinnedSchemaHash,
			})
			if err != nil {
				return report, nil, fmt.Errorf("vector %s attempt %d: %w", v.ID, attempt, err)
			}
			result := VectorResult{
				VectorID:        v.ID,
				Category:        v.Category,
				Attempt:         attempt,
				Verdict:         string(record.Verdict),
				ReasonCode:      string(record.ReasonCode),
				RecordHash:      record.RecordHash,
				DispatchAllowed: mcp.ShouldDispatch(record),
			}
			report.Results = append(report.Results, result)
			switch record.Verdict {
			case contracts.VerdictDeny:
				report.Denied++
			case contracts.VerdictEscalate:
				report.Escalated++
			case contracts.VerdictAllow:
				report.Allowed++
			}
		}
	}

	report.AllBlocked = report.Allowed == 0
	for _, r := range report.Results {
		if r.DispatchAllowed {
			report.AllBlocked = false
		}
	}
	return report, vectors, nil
}

func runAutoconfigureSimulate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("autoconfigure simulate", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		path   string
		outDir string
	)
	cmd.StringVar(&path, "path", ".", "Directory to scan if no inventory exists")
	cmd.StringVar(&outDir, "out", filepath.Join("data", "autoconfigure"), "Output directory for simulation artifacts")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	inv, code := loadOrBuildInventory(path, outDir, stderr)
	if code != 0 {
		return code
	}

	ctx := context.Background()
	report, vectors, err := runBlastRadius(ctx, inv)
	if err != nil {
		fmt.Fprintf(stderr, "Simulation harness failure (this is a bug, not a policy result): %v\n", err)
		return 2
	}

	blocked := []VectorResult{}
	approvals := []VectorResult{}
	for _, r := range report.Results {
		if r.Verdict == string(contracts.VerdictDeny) {
			blocked = append(blocked, r)
		}
		if r.ReasonCode == string(contracts.ReasonApprovalRequired) {
			approvals = append(approvals, r)
		}
	}

	artifacts := map[string]any{
		"negative_vectors.json":      vectors,
		"blast_radius_report.json":   report,
		"blocked_actions.json":       blocked,
		"approval_requirements.json": approvals,
	}
	for name, v := range artifacts {
		if err := writeJSONArtifact(filepath.Join(outDir, name), v); err != nil {
			fmt.Fprintf(stderr, "Error writing %s: %v\n", name, err)
			return 2
		}
	}

	fmt.Fprintf(stdout, "\n%sAutoconfigure Blast-Radius Simulation%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "  Vectors run:      %d (%d attempts)\n", len(vectors), len(report.Results))
	fmt.Fprintf(stdout, "  Denied:           %d\n", report.Denied)
	fmt.Fprintf(stdout, "  Escalated:        %d\n", report.Escalated)
	fmt.Fprintf(stdout, "  Allowed:          %d\n", report.Allowed)
	if report.AllBlocked {
		fmt.Fprintf(stdout, "  %sAll negative vectors blocked by the boundary.%s\n", ColorGreen, ColorReset)
	} else {
		fmt.Fprintf(stdout, "  %sPOLICY GAP: at least one vector was allowed or dispatchable.%s\n", ColorRed, ColorReset)
	}
	fmt.Fprintf(stdout, "  Report:           %s\n\n", filepath.Join(outDir, "blast_radius_report.json"))
	fmt.Fprintf(stdout, "Next: author P0 ceilings, then %shelm-ai-kernel autoconfigure activate --mode constrained --ceilings <file> --approver <id> --sign%s\n\n", ColorBold, ColorReset)

	if !report.AllBlocked {
		return 1
	}
	return 0
}

func loadOrBuildInventory(path, outDir string, stderr io.Writer) (AutoconfigureInventory, int) {
	var inv AutoconfigureInventory
	invPath := filepath.Join(outDir, "inventory.json")
	if raw, err := os.ReadFile(invPath); err == nil {
		if err := json.Unmarshal(raw, &inv); err != nil {
			fmt.Fprintf(stderr, "Error parsing %s: %v\n", invPath, err)
			return inv, 2
		}
		return inv, 0
	}
	report, err := shadow.NewScanner().Scan(path)
	if err != nil {
		fmt.Fprintf(stderr, "Error scanning %q: %v\n", path, err)
		return inv, 2
	}
	inv = buildInventory(report)
	if err := writeJSONArtifact(invPath, inv); err != nil {
		fmt.Fprintf(stderr, "Error writing inventory: %v\n", err)
		return inv, 2
	}
	return inv, 0
}

// ActivationSummary is the deterministic, signable object that gates live
// mode. Activation never silently flips live: the summary binds the draft
// policy, P0 ceilings, MCP approvals, and the blast-radius impact report by
// hash, and only an explicit signature over the summary hash activates.
type ActivationSummary struct {
	Version             string `json:"version"`
	ActivationMode      string `json:"activation_mode"`
	PolicyHash          string `json:"policy_hash"`
	P0CeilingsHash      string `json:"p0_ceilings_hash"`
	ConnectorGrantsHash string `json:"connector_grants_hash,omitempty"`
	SandboxGrantsHash   string `json:"sandbox_grants_hash,omitempty"`
	MCPApprovalsHash    string `json:"mcp_approvals_hash"`
	ImpactReportHash    string `json:"impact_report_hash"`
	Doctrine            string `json:"doctrine"`
	SummaryHash         string `json:"summary_hash,omitempty"`
}

// ActivationAttestation is the ORG_GENESIS_APPROVAL-style record produced by
// an explicit signing ceremony over the activation summary hash.
type ActivationAttestation struct {
	AttestationKind string `json:"attestation_kind"`
	ActivationMode  string `json:"activation_mode"`
	SummaryHash     string `json:"summary_hash"`
	ApproverID      string `json:"approver_id"`
	PublicKey       string `json:"public_key"`
	Signature       string `json:"signature"`
	SignedAt        string `json:"signed_at"`
}

func hashFileArtifact(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// buildActivationSummary assembles and seals the activation summary from the
// draft artifacts in outDir plus the user-authored ceilings file.
func buildActivationSummary(outDir, mode, ceilingsPath string) (ActivationSummary, error) {
	var s ActivationSummary
	if mode != "constrained" && mode != "full_live" {
		return s, fmt.Errorf("activation mode must be constrained or full_live (got %q)", mode)
	}

	var report BlastRadiusReport
	reportPath := filepath.Join(outDir, "blast_radius_report.json")
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return s, fmt.Errorf("blast-radius report required before activation (run autoconfigure simulate): %w", err)
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return s, fmt.Errorf("parse %s: %w", reportPath, err)
	}
	if !report.AllBlocked {
		return s, fmt.Errorf("blast-radius report shows unblocked vectors; fix the policy gap before activation")
	}

	policyHash, err := hashFileArtifact(filepath.Join(outDir, "policy.draft.json"))
	if err != nil {
		return s, fmt.Errorf("policy draft required before activation (run autoconfigure draft-policy): %w", err)
	}
	mcpHash, err := hashFileArtifact(filepath.Join(outDir, "mcp_quarantine_plan.json"))
	if err != nil {
		return s, fmt.Errorf("mcp quarantine plan required before activation: %w", err)
	}
	impactHash, err := hashFileArtifact(reportPath)
	if err != nil {
		return s, err
	}
	ceilingsHash, err := hashFileArtifact(ceilingsPath)
	if err != nil {
		return s, fmt.Errorf("P0 ceilings file is human-authored and required (--ceilings): %w", err)
	}

	s = ActivationSummary{
		Version:          "activation-summary/v1",
		ActivationMode:   mode,
		PolicyHash:       policyHash,
		P0CeilingsHash:   ceilingsHash,
		MCPApprovalsHash: mcpHash,
		ImpactReportHash: impactHash,
		Doctrine:         autoconfigureDoctrine,
	}
	if h, err := hashFileArtifact(filepath.Join(outDir, "connector_grants.json")); err == nil {
		s.ConnectorGrantsHash = h
	}
	if h, err := hashFileArtifact(filepath.Join(outDir, "sandbox_grants.json")); err == nil {
		s.SandboxGrantsHash = h
	}

	preimage := s
	preimage.SummaryHash = ""
	data, err := json.Marshal(preimage)
	if err != nil {
		return s, err
	}
	sum := sha256.Sum256(data)
	s.SummaryHash = "sha256:" + hex.EncodeToString(sum[:])
	return s, nil
}

func runAutoconfigureActivate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("autoconfigure activate", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		outDir   string
		mode     string
		ceilings string
		approver string
		sign     bool
		dataDir  string
	)
	cmd.StringVar(&outDir, "out", filepath.Join("data", "autoconfigure"), "Directory holding the draft and simulation artifacts")
	cmd.StringVar(&mode, "mode", "constrained", "Activation mode: constrained | full_live")
	cmd.StringVar(&ceilings, "ceilings", "", "Path to the human-authored P0 ceilings file (required)")
	cmd.StringVar(&approver, "approver", "", "Approver identity (required with --sign)")
	cmd.BoolVar(&sign, "sign", false, "Sign the activation summary hash with the local trust root")
	cmd.StringVar(&dataDir, "data-dir", "data", "Directory holding the local trust root key")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if ceilings == "" {
		fmt.Fprintln(stderr, "Error: --ceilings is required. P0 ceilings are human-authored; HELM cannot grant itself authority.")
		return 2
	}

	summary, err := buildActivationSummary(outDir, mode, ceilings)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if err := writeJSONArtifact(filepath.Join(outDir, "activation_summary.json"), summary); err != nil {
		fmt.Fprintf(stderr, "Error writing activation summary: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "\n%sAutoconfigure Activation%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "  Mode:             %s\n", summary.ActivationMode)
	fmt.Fprintf(stdout, "  policy_hash:      %s\n", summary.PolicyHash)
	fmt.Fprintf(stdout, "  p0_ceilings_hash: %s\n", summary.P0CeilingsHash)
	fmt.Fprintf(stdout, "  mcp_approvals:    %s\n", summary.MCPApprovalsHash)
	fmt.Fprintf(stdout, "  impact_report:    %s\n", summary.ImpactReportHash)
	fmt.Fprintf(stdout, "  summary_hash:     %s\n", summary.SummaryHash)

	if !sign {
		fmt.Fprintf(stdout, "\n%sPrepared, not activated.%s Review %s, then re-run with --sign --approver <id>.\n\n", ColorYellow, ColorReset, filepath.Join(outDir, "activation_summary.json"))
		return 0
	}
	if approver == "" {
		fmt.Fprintln(stderr, "Error: --approver is required with --sign. Activation is attributable or it does not happen.")
		return 2
	}

	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error loading trust root: %v\n", err)
		return 2
	}
	signature, err := signer.Sign([]byte(summary.SummaryHash))
	if err != nil {
		fmt.Fprintf(stderr, "Error signing activation summary: %v\n", err)
		return 2
	}
	attestation := ActivationAttestation{
		AttestationKind: "ORG_GENESIS_APPROVAL",
		ActivationMode:  summary.ActivationMode,
		SummaryHash:     summary.SummaryHash,
		ApproverID:      approver,
		PublicKey:       signer.PublicKey(),
		Signature:       signature,
		SignedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeJSONArtifact(filepath.Join(outDir, "activation_attestation.json"), attestation); err != nil {
		fmt.Fprintf(stderr, "Error writing attestation: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "\n%s✅ Activated (%s).%s Attestation: %s\n", ColorBold+ColorGreen, summary.ActivationMode, ColorReset, filepath.Join(outDir, "activation_attestation.json"))
	fmt.Fprintf(stdout, "%s%s%s\n\n", ColorBold, autoconfigureDoctrine, ColorReset)
	return 0
}
