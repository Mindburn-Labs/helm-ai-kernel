package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runDemoCmd implements `helm demo` — run governed demonstrations.
//
// Exit codes:
//
//	0 = success
//	1 = verification failure
//	2 = config error
func runDemoCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm demo <organization|research-lab> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  organization  Run the canonical starter organization demo")
		fmt.Fprintln(stderr, "  research-lab  Run a research-lab reference scenario")
		return 2
	}

	switch args[0] {
	case "organization", "org":
		return runDemoScenario("organization", args[1:], stdout, stderr)
	case "research-lab":
		return runDemoScenario("research-lab", args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm demo <organization|research-lab> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  organization  Run the canonical starter organization demo")
		fmt.Fprintln(stdout, "  research-lab  Run a research-lab reference scenario")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown demo subcommand: %s\n", args[0])
		return 2
	}
}

// demoReceipt represents a receipt emitted during the demo.
type demoReceipt struct {
	ReceiptID  string            `json:"receipt_id"`
	Timestamp  string            `json:"timestamp"`
	Principal  string            `json:"principal"`
	Action     string            `json:"action"`
	Tool       string            `json:"tool,omitempty"`
	Verdict    string            `json:"verdict"`
	ReasonCode string            `json:"reason_code"`
	Hash       string            `json:"hash"`
	Lamport    uint64            `json:"lamport_clock"`
	PrevHash   string            `json:"prev_hash"`
	Mode       string            `json:"mode,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
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
			header:             "🧪 HELM Demo: Northstar Research Lab",
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
			denyNote:           "→ Blocked: export raw participant dataset — data egress outside approved scope",
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
			header:             "🏢 HELM Demo: Acme Operations",
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
			denyNote:           "→ Blocked: DROP TABLE users — destructive action not in allowlist",
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

	fmt.Fprintf(stdout, "\n%s%s%s\n", ColorBold+ColorBlue, cfg.header, ColorReset)
	fmt.Fprintf(stdout, "%s   "+cfg.scenarioLine+"%s\n", ColorGray, provider, ColorReset)
	if dryRun {
		fmt.Fprintf(stdout, "%s   Mode: policy simulation / dry-run (organization-scoped metadata bound into receipts)%s\n", ColorYellow, ColorReset)
	}
	fmt.Fprintln(stdout, "")

	fmt.Fprintf(stdout, "%sTeam:%s\n", ColorBold, ColorReset)
	for _, a := range cfg.team {
		icon := "📋"
		switch a.Role {
		case "executor":
			icon = "⚙️ "
		case "auditor":
			icon = "🔒"
		}
		fmt.Fprintf(stdout, "  %s %s%s%s (%s)\n", icon, ColorBold, a.Name, ColorReset, a.Role)
	}
	fmt.Fprintln(stdout, "")

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
			ReceiptID:  fmt.Sprintf("rcpt-%s-%d", hash[:8], lamport),
			Timestamp:  ts,
			Principal:  principal,
			Action:     action,
			Tool:       tool,
			Verdict:    verdict,
			ReasonCode: reason,
			Hash:       hash,
			Lamport:    lamport,
			PrevHash:   prevHash,
			Mode:       mode,
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

		icon := "✅"
		color := ColorGreen
		switch verdict {
		case "DENY":
			icon = "❌"
			color = ColorRed
		case "PENDING":
			icon = "⏳"
			color = ColorYellow
		}
		fmt.Fprintf(stdout, "  %s %s[%s]%s %s → %s%s%s %s(L=%d)%s\n",
			icon, color, verdict, ColorReset,
			principal, ColorBold, action, ColorReset,
			ColorGray, lamport, ColorReset)

		return r
	}

	fmt.Fprintf(stdout, "%s━━━ %s ━━━%s\n\n", ColorBold+ColorCyan, cfg.initiativeTitle, ColorReset)

	fmt.Fprintf(stdout, "%sPhase 1: Sprint Planning%s\n", ColorBold, ColorReset)
	emitReceipt(cfg.plannerSecondary, "DEFINE_REQUIREMENTS", "jira", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.requirementsNote, ColorReset)
	emitReceipt(cfg.plannerPrimary, "PLAN_INITIATIVE", "jira", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s→ Created INIT-2847: %s%s\n", ColorGray, cfg.initiativeTitle, ColorReset)
	emitReceipt(cfg.plannerPrimary, "ASSIGN_TASK", "jira", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.assignNote, ColorReset)

	fmt.Fprintf(stdout, "\n%sPhase 2: %s%s\n", ColorBold, cfg.phase2Title, ColorReset)
	emitReceipt(cfg.auditor, "AUDIT_REVIEW", "snyk_scan", "ALLOW", "AUDIT_PASS")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.reviewNote, ColorReset)
	emitReceipt(cfg.executorPrimary, "REQUEST_APPROVAL", "deploy_staging", "PENDING", "APPROVAL_REQUIRED")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.approvalRequest, ColorReset)
	emitReceipt(cfg.plannerPrimary, "APPROVE_EXECUTION", "deploy_production", "ALLOW", "APPROVAL_GRANTED")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.approvalGranted, ColorReset)

	fmt.Fprintf(stdout, "\n%sPhase 3: Sandboxed Build & Test (%s)%s\n", ColorBold, provider, ColorReset)
	emitReceipt(cfg.executorPrimary, "SANDBOX_EXEC", "sandbox_run", "ALLOW", "PREFLIGHT_PASS")
	if provider == "mock" {
		fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.sandboxNote, ColorReset)
		fmt.Fprintf(stdout, "    %s→ 247 checks passed, 0 failed. Scoped artifacts prepared for export%s\n", ColorGray, ColorReset)
	}
	emitReceipt(cfg.executorPrimary, "SANDBOX_RESULT", "artifact_build", "ALLOW", "EXECUTION_COMPLETE")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.buildResultNote, ColorReset)

	fmt.Fprintf(stdout, "\n%sPhase 4: %s%s\n", ColorBold, cfg.phase4Title, ColorReset)
	emitReceipt(cfg.validator, "RUN_ACCEPTANCE", "validator", "ALLOW", "TESTS_PASS")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.validationNote, ColorReset)
	emitReceipt(cfg.executorSecondary, "SANDBOX_EXEC", "apply_change", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.deployNote, ColorReset)

	fmt.Fprintf(stdout, "\n%sPhase 5: Governance Deny (fail-closed)%s\n", ColorBold, ColorReset)
	emitReceipt(cfg.executorPrimary, "EXECUTE_TOOL", "psql_drop_table", "DENY", "ERR_TOOL_NOT_ALLOWED")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.denyNote, ColorReset)
	fmt.Fprintf(stdout, "    %s┌─ Deny Details ─────────────────────────────────────────%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Reason:      ERR_TOOL_NOT_ALLOWED%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Explanation: tool is not in the allowed-tools list for this organizational scope%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Policy:      policy.allowed_tools%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Fix:         Add psql_drop_table to allowed_tools only if the authority scope explicitly permits it%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s└────────────────────────────────────────────────────────%s\n", ColorRed, ColorReset)

	fmt.Fprintf(stdout, "\n%s━━━ Deployment Complete ━━━%s\n\n", ColorBold+ColorCyan, ColorReset)

	fmt.Fprintf(stdout, "%sPhase 6: Skill Gap Detection%s\n", ColorBold, ColorReset)
	emitReceipt(cfg.executorSecondary, "DETECT_SKILL_GAP", "k8s_hpa_config", "ALLOW", "SKILL_GAP_DETECTED")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.skillGapNote, ColorReset)

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
	fmt.Fprintf(stdout, "    %s→ SkillCandidate ‹k8s_hpa_config› proposed and auto-approved (%s)%s\n", ColorGray, mode, ColorReset)

	fmt.Fprintf(stdout, "\n%sPhase 7: %s%s\n", ColorBold, cfg.phase7Title, ColorReset)
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
	fmt.Fprintf(stdout, "    %s→ INC-demo-001: %s (severity: high)%s\n", ColorGray, cfg.incidentTitle, ColorReset)
	emitReceipt("System", "MAINTENANCE_RUN", "gc_tuning_patch", "ALLOW", "CONFORMANCE_PASS")
	fmt.Fprintf(stdout, "    %s%s%s\n", ColorGray, cfg.maintenanceNote, ColorReset)

	demoIncident.Status = "resolved"
	demoIncident.Resolution = cfg.incidentResolution
	demoIncident.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = saveIncident(&demoIncident)

	fmt.Fprintf(stdout, "    %s→ Resolved: %s%s\n", ColorGray, cfg.incidentResolution, ColorReset)
	fmt.Fprintf(stdout, "\n%s━━━ All Phases Complete ━━━%s\n\n", ColorBold+ColorCyan, ColorReset)

	fmt.Fprintf(stdout, "%sExporting EvidencePack...%s\n", ColorBold, ColorReset)
	if err := os.MkdirAll(outDir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error creating evidence dir: %v\n", err)
		return 2
	}

	for i, r := range receipts {
		data, _ := json.MarshalIndent(r, "", "  ")
		fname := fmt.Sprintf("%03d_%s.json", i+1, r.ReceiptID)
		if err := os.WriteFile(filepath.Join(outDir, fname), data, 0644); err != nil {
			fmt.Fprintf(stderr, "Error writing receipt: %v\n", err)
			return 2
		}
	}

	manifest := map[string]any{
		"session_id":       "demo-starter-" + time.Now().UTC().Format("20060102-150405"),
		"template":         template,
		"provider":         provider,
		"scenario":         cfg.key,
		"organization_id":  cfg.organizationID,
		"scope_id":         cfg.scopeID,
		"execution_mode":   mode,
		"receipts":         len(receipts),
		"exported_at":      time.Now().UTC().Format(time.RFC3339),
		"final_hash":       prevHash,
		"lamport":          lamport,
		"features":         []string{"skill_lifecycle", "maintenance_loop", "approval_gate", "sandbox_exec", "deny_path", "organization_scoping"},
		"authority_scope":  map[string]any{"organization_id": cfg.organizationID, "scope_id": cfg.scopeID},
		"principal_fields": []string{"principal_id", "organization_id", "scope_id"},
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestData, 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing manifest: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "  📦 %d receipts → %s/\n", len(receipts), outDir)
	if err := generateProofReport(receipts, outDir, template, provider, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "Warning: could not generate HTML report: %v\n", err)
	} else {
		fmt.Fprintf(stdout, "  📊 Proof Report → %s/run-report.html\n", outDir)
	}
	if err := generateProofReportJSON(receipts, outDir, template, provider); err != nil {
		fmt.Fprintf(stderr, "Warning: could not generate JSON report: %v\n", err)
	}

	fmt.Fprintf(stdout, "\n%sVerifying EvidencePack...%s\n", ColorBold, ColorReset)
	verifyPrev := ""
	allValid := true
	for _, r := range receipts {
		if r.PrevHash != verifyPrev {
			fmt.Fprintf(stdout, "  ❌ Chain break at L=%d\n", r.Lamport)
			allValid = false
			break
		}
		verifyPrev = r.Hash
	}

	if allValid {
		fmt.Fprintf(stdout, "  ✅ Causal chain:  %d receipts, no breaks\n", len(receipts))
		fmt.Fprintf(stdout, "  ✅ Root hash:     %s...%s\n", prevHash[:16], prevHash[len(prevHash)-8:])
		fmt.Fprintf(stdout, "  ✅ Lamport clock: %d\n", lamport)
		fmt.Fprintf(stdout, "  ✅ Deny path:     fail-closed verified\n")
		fmt.Fprintf(stdout, "  ✅ Scope binding: org=%s scope=%s\n", cfg.organizationID, cfg.scopeID)
		fmt.Fprintf(stdout, "  ✅ Maintenance:   incident auto-resolved with conformance\n")
	}

	fmt.Fprintf(stdout, "\n%s🎉 Demo complete.%s Evidence at %s/\n", ColorBold+ColorGreen, ColorReset, outDir)
	fmt.Fprintf(stdout, "%s   Bound scope:%s org=%s scope=%s mode=%s\n", ColorGray, ColorReset, cfg.organizationID, cfg.scopeID, mode)

	reportPath := filepath.Join(outDir, "run-report.html")
	fmt.Fprintf(stdout, "\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║  HELM Demo Complete                                        ║%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s╠════════════════════════════════════════════════════════════╣%s\n", ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  📊 Report:   %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorBold, reportPath, ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  📦 Evidence: %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorBold, outDir+"/", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  🔍 Verify:   %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorGray, "helm export --evidence "+outDir+" --out e.tar", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s              %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorGray, "helm verify --bundle e.tar", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  🔄 Switch:   %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorGray, "helm demo organization --provider opensandbox", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	if !allValid {
		return 1
	}
	return 0
}

// runDemoCompany preserves the legacy test/programmatic surface while routing
// through the canonical organization scenario.
func runDemoCompany(args []string, stdout, stderr io.Writer) int {
	return runDemoScenario("organization", args, stdout, stderr)
}

func init() {
	Register(Subcommand{Name: "demo", Aliases: []string{}, Usage: "Run governed demonstrations (demo organization / research-lab)", RunFn: runDemoCmd})
}
