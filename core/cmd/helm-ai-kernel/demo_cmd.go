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
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

// quantum_posture: demo EvidencePacks are sealed with the kernel's classical
// EvidencePack controls; the demo command makes no post-quantum claim.
// runDemoCmd implements `helm-ai-kernel demo` — run governed demonstrations.
//
// Exit codes:
//
//	0 = success
//	1 = verification failure
//	2 = config error
func runDemoCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel demo <organization|research-lab|finance|mcp> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  organization  Run the canonical starter organization demo")
		fmt.Fprintln(stderr, "  research-lab  Run a research-lab reference scenario")
		fmt.Fprintln(stderr, "  finance       Run the finance payment-approval escalation demo")
		fmt.Fprintln(stderr, "  mcp           Run the MCP governance proof scenarios")
		return 2
	}

	switch args[0] {
	case "organization", "org":
		return runDemoScenario("organization", args[1:], stdout, stderr)
	case "research-lab":
		return runDemoScenario("research-lab", args[1:], stdout, stderr)
	case "finance":
		return runDemoFinance(args[1:], stdout, stderr)
	case "mcp":
		return runMCPProof(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel demo <organization|research-lab|finance|mcp> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  organization  Run the canonical starter organization demo")
		fmt.Fprintln(stdout, "  research-lab  Run a research-lab reference scenario")
		fmt.Fprintln(stdout, "  finance       Run the finance payment-approval escalation demo")
		fmt.Fprintln(stdout, "  mcp           Run the MCP governance proof scenarios")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown demo subcommand: %s\n", args[0])
		return 2
	}
}

// demoReceipt represents a receipt emitted during the demo.
type demoReceipt struct {
	ReceiptID    string            `json:"receipt_id"`
	Timestamp    string            `json:"timestamp"`
	Principal    string            `json:"principal"`
	Action       string            `json:"action"`
	Tool         string            `json:"tool,omitempty"`
	Verdict      string            `json:"verdict"`
	ReasonCode   string            `json:"reason_code"`
	Hash         string            `json:"hash"`
	DecisionHash string            `json:"decision_hash"`
	Lamport      uint64            `json:"lamport_clock"`
	PrevHash     string            `json:"prev_hash"`
	Mode         string            `json:"mode,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type demoActor struct {
	Name string
	Role string
}

type demoScenarioConfig struct {
	key                string
	header             string
	scenarioLine       string
	organizationID     string
	scopeID            string
	team               []demoActor
	plannerPrimary     string
	plannerSecondary   string
	executorPrimary    string
	executorSecondary  string
	auditor            string
	validator          string
	initiativeTitle    string
	phase2Title        string
	phase4Title        string
	phase7Title        string
	requirementsNote   string
	assignNote         string
	reviewNote         string
	approvalRequest    string
	approvalGranted    string
	sandboxNote        string
	buildResultNote    string
	validationNote     string
	deployNote         string
	denyNote           string
	skillGapNote       string
	incidentTitle      string
	incidentComponent  string
	incidentRecipe     string
	maintenanceNote    string
	incidentResolution string
}

func demoScenarioFor(kind string) demoScenarioConfig {
	switch kind {
	case "research-lab":
		team := []demoActor{
			{Name: "Lab Director", Role: "planner"},
			{Name: "Research Lead", Role: "planner"},
			{Name: "ML Engineer", Role: "executor"},
			{Name: "Platform Engineer", Role: "executor"},
			{Name: "Safety Reviewer", Role: "auditor"},
			{Name: "Evaluation Lead", Role: "executor"},
		}
		return demoScenarioConfig{
			key:                "research-lab",
			header:             "HELM Demo: Northstar Research Lab",
			scenarioLine:       "Scenario: Launch retrieval benchmark pipeline | Sandbox: %s",
			organizationID:     "northstar-research",
			scopeID:            "lab.benchmarks.pipeline",
			team:               team,
			plannerPrimary:     "Lab Director",
			plannerSecondary:   "Research Lead",
			executorPrimary:    "ML Engineer",
			executorSecondary:  "Platform Engineer",
			auditor:            "Safety Reviewer",
			validator:          "Evaluation Lead",
			initiativeTitle:    "Launch Retrieval Benchmark Pipeline",
			phase2Title:        "Safety Review & Run Approval",
			phase4Title:        "Evaluation Acceptance & Deployment",
			phase7Title:        "Benchmark Incident → Auto-Maintenance",
			requirementsNote:   "→ Benchmark pack: retrieval-v3, corpus freeze, reproducible report export",
			assignNote:         "→ Assigned to ML Engineer + Platform Engineer",
			reviewNote:         "→ Safety review: approved datasets, no external write scopes, reproducibility gate passed",
			approvalRequest:    "→ Benchmark pipeline staged, requesting benchmark-run approval",
			approvalGranted:    "→ Lab Director approved: \"Run is bounded, datasets pinned, publish the report\"",
			sandboxNote:        "→ sandbox exec: uv run bench.py --profile retrieval-v3 --emit-report",
			buildResultNote:    "→ Benchmark artifact: retrieval-v3-report.tar.gz signed and stored",
			validationNote:     "→ Eval suite: 84 checks passed, recall and latency thresholds satisfied",
			deployNote:         "→ kubectl apply -f lab/benchmarks/retrieval-v3.yaml (2 replicas, bounded egress)",
			denyNote:           "→ Blocked: export raw participant dataset - data egress outside approved scope",
			skillGapNote:       "→ Gap: team lacks automated HPA tuning for lab benchmark bursts",
			incidentTitle:      "Latency spike in retrieval benchmark worker",
			incidentComponent:  "retrieval-v3",
			incidentRecipe:     "uv run bench.py --profile retrieval-v3 --concurrency 50",
			maintenanceNote:    "→ Auto-patch: concurrency ceiling tightened, cache prewarm enabled (conformance gate: PASS)",
			incidentResolution: "Applied benchmark worker tuning, latency stable at p95 < 180ms under load",
		}
	default:
		team := []demoActor{
			{Name: "CTO", Role: "planner"},
			{Name: "Product Manager", Role: "planner"},
			{Name: "Backend Engineer", Role: "executor"},
			{Name: "DevOps Lead", Role: "executor"},
			{Name: "Security Engineer", Role: "auditor"},
			{Name: "QA Lead", Role: "executor"},
		}
		return demoScenarioConfig{
			key:                "organization",
			header:             "HELM Demo: mock organization",
			scenarioLine:       "Scenario: Deploy v2.4 API to prod | Sandbox: %s",
			organizationID:     "acme-operations",
			scopeID:            "platform.prod.deploy",
			team:               team,
			plannerPrimary:     "CTO",
			plannerSecondary:   "Product Manager",
			executorPrimary:    "Backend Engineer",
			executorSecondary:  "DevOps Lead",
			auditor:            "Security Engineer",
			validator:          "QA Lead",
			initiativeTitle:    "Deploy v2.4 API to Production",
			phase2Title:        "Security Review & Deploy Approval",
			phase4Title:        "QA Acceptance & Deployment",
			phase7Title:        "Production Incident → Auto-Maintenance",
			requirementsNote:   "→ PRD: v2.4 rate limiting + embeddings endpoint",
			assignNote:         "→ Assigned to Backend Engineer + DevOps Lead",
			reviewNote:         "→ Security scan: 0 critical, 0 high, 2 low (accepted)",
			approvalRequest:    "→ PR #1482 merged, requesting prod deploy approval",
			approvalGranted:    "→ CTO approved: \"LGTM, staging verified, deploy to prod\"",
			sandboxNote:        "→ sandbox exec: npm run test:ci && npm run build",
			buildResultNote:    "→ Docker image acme/api:2.4.0 pushed to registry",
			validationNote:     "→ E2E suite: 84 scenarios passed, p99 latency < 200ms",
			deployNote:         "→ kubectl apply -f k8s/api-v2.4.yaml (3 replicas, rolling update)",
			denyNote:           "→ Blocked: DROP TABLE users - destructive action not in allowlist",
			skillGapNote:       "→ Gap: team lacks HPA auto-scaling configuration expertise",
			incidentTitle:      "Memory leak in /v1/embeddings after 10k requests",
			incidentComponent:  "api-v2.4",
			incidentRecipe:     "ab -n 10000 -c 50 https://api.acme.ai/v1/embeddings",
			maintenanceNote:    "→ Auto-patch: GOGC=50, GOMEMLIMIT=512Mi (conformance gate: PASS)",
			incidentResolution: "Applied GC tuning patch, memory stable at 380Mi under load",
		}
	}
}

func runDemoScenario(kind string, args []string, stdout, stderr io.Writer) int {
	cfg := demoScenarioFor(kind)
	cmd := flag.NewFlagSet("demo "+cfg.key, flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		template string
		provider string
		outDir   string
		dryRun   bool
	)

	cmd.StringVar(&template, "template", "starter", "Scenario template: starter")
	cmd.StringVar(&provider, "provider", "mock", "Sandbox provider: mock, opensandbox, e2b, daytona")
	cmd.StringVar(&outDir, "out", "data/evidence", "Output directory for EvidencePack")
	cmd.BoolVar(&dryRun, "dry-run", false, "Simulate organization-scoped execution and bind dry-run metadata into receipts")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if template != "starter" {
		fmt.Fprintf(stderr, "Error: unknown template %q (valid: starter)\n", template)
		return 2
	}

	p := ui.NewPrinter(stdout)
	p.Blank()
	p.Title(cfg.header)
	p.Muted("   " + fmt.Sprintf(cfg.scenarioLine, provider))
	if dryRun {
		p.Muted("   Mode: policy simulation / dry-run (organization-scoped metadata bound into receipts)")
	}
	p.Blank()
	p.Title("Team")
	for _, a := range cfg.team {
		p.Line("  %s  %s", p.R.Bold(a.Name), a.Role)
	}
	p.Blank()

	var receipts []demoReceipt
	var prevHash string
	var lamport uint64
	mode := "demo"
	if dryRun {
		mode = "dry-run"
	}

	emitReceipt := func(principal, action, tool, verdict, reason string) demoReceipt {
		lamport++
		ts := time.Now().UTC().Format(time.RFC3339)
		preimage := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s", principal, action, tool, verdict, reason, lamport, prevHash)
		h := sha256.Sum256([]byte(preimage))
		hash := hex.EncodeToString(h[:])
		principalID := strings.ReplaceAll(strings.ToLower(principal), " ", "_")

		r := demoReceipt{
			ReceiptID:    fmt.Sprintf("rcpt-%s-%d", hash[:8], lamport),
			Timestamp:    ts,
			Principal:    principal,
			Action:       action,
			Tool:         tool,
			Verdict:      verdict,
			ReasonCode:   reason,
			Hash:         hash,
			DecisionHash: hash,
			Lamport:      lamport,
			PrevHash:     prevHash,
			Mode:         mode,
			Metadata: map[string]string{
				"organization_id": cfg.organizationID,
				"scope_id":        cfg.scopeID,
				"principal_id":    principalID,
				"scenario":        cfg.key,
				"execution_mode":  mode,
			},
		}
		prevHash = hash
		receipts = append(receipts, r)

		status := ui.StatusFromVerdict(verdict)
		if verdict == "PENDING" {
			status = ui.StatusWait
		}
		p.Event(ui.EventLine{
			Status: status,
			Actor:  principal,
			Action: action,
			Meta:   fmt.Sprintf("L=%d", lamport),
		})
		return r
	}

	p.Title(cfg.initiativeTitle)

	p.Title("Step 1: Sprint Planning")
	emitReceipt(cfg.plannerSecondary, "DEFINE_REQUIREMENTS", "jira", "ALLOW", "POLICY_PASS")
	p.Muted("    " + cfg.requirementsNote)
	emitReceipt(cfg.plannerPrimary, "PLAN_INITIATIVE", "jira", "ALLOW", "POLICY_PASS")
	p.Muted(fmt.Sprintf("    → Created INIT-2847: %s", cfg.initiativeTitle))
	emitReceipt(cfg.plannerPrimary, "ASSIGN_TASK", "jira", "ALLOW", "POLICY_PASS")
	p.Muted("    " + cfg.assignNote)

	p.Blank()
	p.Title("Step 2: " + cfg.phase2Title)
	emitReceipt(cfg.auditor, "AUDIT_REVIEW", "snyk_scan", "ALLOW", "AUDIT_PASS")
	p.Muted("    " + cfg.reviewNote)
	emitReceipt(cfg.executorPrimary, "REQUEST_APPROVAL", "deploy_staging", "PENDING", "APPROVAL_REQUIRED")
	p.Muted("    " + cfg.approvalRequest)
	emitReceipt(cfg.plannerPrimary, "APPROVE_EXECUTION", "deploy_production", "ALLOW", "APPROVAL_GRANTED")
	p.Muted("    " + cfg.approvalGranted)

	p.Blank()
	p.Title("Step 3: Sandboxed Build & Test (" + provider + ")")
	emitReceipt(cfg.executorPrimary, "SANDBOX_EXEC", "sandbox_run", "ALLOW", "PREFLIGHT_PASS")
	if provider == "mock" {
		p.Muted("    " + cfg.sandboxNote)
		p.Muted("    → 247 checks passed, 0 failed. Scoped artifacts prepared for export")
	}
	emitReceipt(cfg.executorPrimary, "SANDBOX_RESULT", "artifact_build", "ALLOW", "EXECUTION_COMPLETE")
	p.Muted("    " + cfg.buildResultNote)

	p.Blank()
	p.Title("Step 4: " + cfg.phase4Title)
	emitReceipt(cfg.validator, "RUN_ACCEPTANCE", "validator", "ALLOW", "TESTS_PASS")
	p.Muted("    " + cfg.validationNote)
	emitReceipt(cfg.executorSecondary, "SANDBOX_EXEC", "apply_change", "ALLOW", "POLICY_PASS")
	p.Muted("    " + cfg.deployNote)

	p.Blank()
	p.Title("Step 5: Governance Deny (fail-closed)")
	emitReceipt(cfg.executorPrimary, "EXECUTE_TOOL", "psql_drop_table", "DENY", "ERR_TOOL_NOT_ALLOWED")
	p.Muted("    " + cfg.denyNote)
	p.Card(ui.CompletionCard{
		Title: "Deny Details",
		Fields: []ui.KeyValue{
			{Key: "Reason", Value: "ERR_TOOL_NOT_ALLOWED"},
			{Key: "Explanation", Value: "tool is not in the allowed-tools list for this organizational scope"},
			{Key: "Policy", Value: "policy.allowed_tools"},
			{Key: "Fix", Value: "Add psql_drop_table to allowed_tools only if the authority scope explicitly permits it"},
		},
	})

	p.Blank()
	p.Title("Deployment Complete")

	p.Title("Step 6: Skill Gap Detection")
	emitReceipt(cfg.executorSecondary, "DETECT_SKILL_GAP", "k8s_hpa_config", "ALLOW", "SKILL_GAP_DETECTED")
	p.Muted("    " + cfg.skillGapNote)

	candidatesDir := filepath.Join("data", "candidates")
	_ = os.MkdirAll(candidatesDir, 0750)
	demoCandidate := map[string]any{
		"name":               "k8s_hpa_config",
		"version":            "1.0.0",
		"purpose":            "Scoped auto-scaling configuration",
		"allowed_tools":      []string{"kubectl", "helm_chart"},
		"effect_classes":     []string{"compute", "network"},
		"risk":               "medium",
		"required_approvals": 1,
		"idempotent":         true,
		"organization_id":    cfg.organizationID,
		"scope_id":           cfg.scopeID,
		"hash":               hex.EncodeToString(sha256.New().Sum([]byte(cfg.key + "_k8s_hpa_config_demo"))),
		"created_at":         time.Now().UTC().Format(time.RFC3339),
	}
	candidateData, _ := json.MarshalIndent(demoCandidate, "", "  ")
	_ = os.WriteFile(filepath.Join(candidatesDir, "k8s_hpa_config-demo.json"), candidateData, 0644)

	emitReceipt(cfg.plannerPrimary, "AUTO_APPROVE_SKILL", "k8s_hpa_config", "ALLOW", "DEMO_AUTO_APPROVE")
	p.Muted(fmt.Sprintf("    → SkillCandidate ‹k8s_hpa_config› proposed and auto-approved (%s)", mode))

	p.Blank()
	p.Title("Step 7: " + cfg.phase7Title)
	incDir := filepath.Join("data", "incidents")
	_ = os.MkdirAll(incDir, 0750)
	demoIncident := Incident{
		ID:                 "INC-demo-001",
		Severity:           "high",
		Category:           "performance",
		Component:          cfg.incidentComponent,
		Title:              cfg.incidentTitle,
		ReproductionRecipe: cfg.incidentRecipe,
		Status:             "open",
		Recurrence:         1,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	_ = saveIncident(&demoIncident)

	emitReceipt("System", "INCIDENT_CREATED", "pagerduty", "ALLOW", "INCIDENT_OPEN")
	p.Muted(fmt.Sprintf("    → INC-demo-001: %s (severity: high)", cfg.incidentTitle))
	emitReceipt("System", "MAINTENANCE_RUN", "gc_tuning_patch", "ALLOW", "CONFORMANCE_PASS")
	p.Muted("    " + cfg.maintenanceNote)

	demoIncident.Status = "resolved"
	demoIncident.Resolution = cfg.incidentResolution
	demoIncident.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = saveIncident(&demoIncident)

	p.Muted(fmt.Sprintf("    → Resolved: %s", cfg.incidentResolution))
	p.Title("All Phases Complete")

	p.Title("Exporting EvidencePack...")
	if err := writeVerifiableEvidencePack(outDir, cfg, receipts, template, provider, mode, prevHash, lamport); err != nil {
		fmt.Fprintf(stderr, "Error sealing EvidencePack: %v\n", err)
		return 2
	}

	p.Line("  %d receipts → %s/", len(receipts), outDir)
	p.Line("  Sealed (dev-local) → %s/%s", outDir, evidencepkg.EvidencePackSealPath)
	p.Line("  Run Report → %s/%s", outDir, demoRunReportRelPath)

	p.Title("Verifying EvidencePack...")
	if code := runVerifyCmd([]string{"--bundle", outDir, "--profile", "dev-local", "--allow-self-attested"}, stdout, stderr); code != 0 {
		fmt.Fprintf(stderr, "Error verifying generated EvidencePack (exit %d)\n", code)
		return 1
	}

	reportPath := filepath.Join(outDir, demoRunReportRelPath)
	verifyCmd := evidencepkg.BuildEvidencePackVerifyCommand(outDir, evidencepkg.EvidenceTrustProfileDevLocal, "")
	p.Card(ui.CompletionCard{
		Title: "HELM Demo Complete",
		Fields: []ui.KeyValue{
			{Key: "Report", Value: reportPath},
			{Key: "Evidence", Value: outDir + "/"},
			{Key: "Verify", Value: verifyCmd},
			{Key: "Switch", Value: "helm-ai-kernel demo organization --provider opensandbox"},
			{Key: "Scope", Value: fmt.Sprintf("org=%s scope=%s mode=%s", cfg.organizationID, cfg.scopeID, mode)},
		},
	})
	p.Line("%s", verifyCmd)

	return 0
}

// runDemoCompany preserves the legacy test/programmatic surface while routing
// through the canonical organization scenario.
func runDemoCompany(args []string, stdout, stderr io.Writer) int {
	return runDemoScenario("organization", args, stdout, stderr)
}

// writeVerifiableEvidencePack emits a canonical, dev-local-sealed EvidencePack
// under outDir so that
// `helm-ai-kernel verify --profile dev-local --allow-self-attested <outDir>`
// verifies its local seal (MIN-738). The pack follows the §3.1 directory layout,
// carries receipts under 02_PROOFGRAPH/receipts/, derives a canonical manifest
// via the evidence pack Builder, and is sealed in place under the dev-local
// trust profile. The dev-local signer key is auto-provisioned in the HELM data
// dir on first use, so no env var or HELM_SIGNING_KEY_HEX is required.
// Fail-closed: any error here aborts the demo before a success/verify instruction
// is printed.
func writeVerifiableEvidencePack(outDir string, cfg demoScenarioConfig, receipts []demoReceipt, template, provider, mode, finalHash string, lamport uint64) error {
	if len(receipts) == 0 {
		return fmt.Errorf("no receipts to seal")
	}
	if err := conform.CreateEvidencePackDirs(outDir); err != nil {
		return err
	}

	// Canonical manifest via the evidence pack Builder (JCS + Merkle root).
	packID := "demo-" + cfg.key
	builder := evidencepack.NewBuilder(packID, cfg.organizationID, cfg.scopeID, demoPolicyID)
	for i, r := range receipts {
		if err := builder.AddReceipt(fmt.Sprintf("%03d_%s", i+1, r.ReceiptID), r); err != nil {
			return err
		}
	}
	manifest, _, err := builder.Build()
	if err != nil {
		return err
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "04_EXPORTS", "evidence_manifest.json"), append(manifestJSON, '\n'), 0o600); err != nil {
		return err
	}

	// Receipts in canonical proofgraph layout (Lamport-ordered).
	receiptsDir := filepath.Join(outDir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o750); err != nil {
		return err
	}
	for i, r := range receipts {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		fname := fmt.Sprintf("%03d_%s.json", i+1, r.ReceiptID)
		if err := os.WriteFile(filepath.Join(receiptsDir, fname), append(data, '\n'), 0o600); err != nil {
			return err
		}
	}

	// Proof graph summary (deterministic — no wall clock in the chain).
	proofGraph := map[string]any{
		"version":         "1.0.0",
		"pack_id":         packID,
		"scenario":        cfg.key,
		"organization_id": cfg.organizationID,
		"scope_id":        cfg.scopeID,
		"execution_mode":  mode,
		"receipt_count":   len(receipts),
		"lamport_final":   lamport,
		"root_hash":       finalHash,
		"topo_order_rule": "lamport_monotonic",
		"manifest_hash":   manifest.ManifestHash,
		"entries_root":    manifest.EntriesMerkleRoot,
	}
	proofGraphJSON, err := json.MarshalIndent(proofGraph, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "02_PROOFGRAPH", "proofgraph.json"), append(proofGraphJSON, '\n'), 0o600); err != nil {
		return err
	}

	// 01_SCORE.json (+ sha256 sidecar) — required by the canonical layout.
	score := map[string]any{
		"pass":            true,
		"run_id":          packID,
		"scope":           "demo",
		"template":        template,
		"provider":        provider,
		"execution_mode":  mode,
		"receipt_count":   len(receipts),
		"deny_path":       "fail-closed",
		"organization_id": cfg.organizationID,
		"scope_id":        cfg.scopeID,
	}
	scoreJSON, err := json.MarshalIndent(score, "", "  ")
	if err != nil {
		return err
	}
	scoreJSON = append(scoreJSON, '\n')
	if err := os.WriteFile(filepath.Join(outDir, "01_SCORE.json"), scoreJSON, 0o600); err != nil {
		return err
	}
	scoreSum := sha256.Sum256(scoreJSON)
	if err := os.WriteFile(filepath.Join(outDir, "01_SCORE.json.sha256"), []byte(hex.EncodeToString(scoreSum[:])+"\n"), 0o600); err != nil {
		return err
	}

	if err := generateProofReportJSON(receipts, outDir, template, provider); err != nil {
		return fmt.Errorf("generate run report: %w", err)
	}

	// 00_INDEX.json over every pack file (excluding the index itself and the
	// seal, which is written after the index is hashed).
	if err := writeDemoEvidenceIndex(outDir, packID); err != nil {
		return err
	}

	// Seal in place with the dev-local profile. The file-dev signer
	// auto-generates its Ed25519 key under the data dir if absent.
	if _, err := evidencepkg.SealEvidencePack(context.Background(), outDir, evidencepkg.SealEvidencePackOptions{
		PackID:  packID,
		Profile: evidencepkg.EvidenceTrustProfileDevLocal,
	}); err != nil {
		return err
	}
	return nil
}

// writeDemoEvidenceIndex walks the pack directory and writes 00_INDEX.json,
// mirroring the conform engine's index format. Entries are sorted by path for
// deterministic output.
func writeDemoEvidenceIndex(outDir, runID string) error {
	type indexEntry struct {
		Path        string `json:"path"`
		SHA256      string `json:"sha256"`
		SizeBytes   int64  `json:"size_bytes"`
		ContentType string `json:"content_type"`
	}
	var entries []indexEntry
	err := filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "00_INDEX.json" || rel == evidencepkg.EvidencePackSealPath {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		ct := "application/json"
		if !strings.HasSuffix(rel, ".json") {
			ct = "text/plain"
		}
		entries = append(entries, indexEntry{
			Path:        rel,
			SHA256:      hex.EncodeToString(sum[:]),
			SizeBytes:   info.Size(),
			ContentType: ct,
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	index := map[string]any{
		"run_id":          runID,
		"profile":         string(conform.ProfileCore),
		"created_at":      time.Now().UTC(),
		"topo_order_rule": "lamport_monotonic",
		"entries":         entries,
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "00_INDEX.json"), append(data, '\n'), 0o600)
}

func init() {
	Register(Subcommand{Name: "demo", Aliases: []string{}, Usage: "Run governed demonstrations (demo organization / research-lab)", RunFn: runDemoCmd})
}
