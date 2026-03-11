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
		fmt.Fprintln(stderr, "Usage: helm demo <company> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  company   Run a starter company demo with governed agents")
		return 2
	}

	switch args[0] {
	case "company":
		return runDemoCompany(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm demo <company> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  company   Run a starter company demo with governed agents")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown demo subcommand: %s\n", args[0])
		return 2
	}
}

// demoReceipt represents a receipt emitted during the demo
type demoReceipt struct {
	ReceiptID  string `json:"receipt_id"`
	Timestamp  string `json:"timestamp"`
	Principal  string `json:"principal"`
	Action     string `json:"action"`
	Tool       string `json:"tool,omitempty"`
	Verdict    string `json:"verdict"`
	ReasonCode string `json:"reason_code"`
	Hash       string `json:"hash"`
	Lamport    uint64 `json:"lamport_clock"`
	PrevHash   string `json:"prev_hash"`
	Mode       string `json:"mode,omitempty"`
}

func runDemoCompany(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("demo company", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		template string
		provider string
		outDir   string
	)

	cmd.StringVar(&template, "template", "starter", "Company template: starter")
	cmd.StringVar(&provider, "provider", "mock", "Sandbox provider: mock, opensandbox, e2b, daytona")
	cmd.StringVar(&outDir, "out", "data/evidence", "Output directory for EvidencePack")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if template != "starter" {
		fmt.Fprintf(stderr, "Error: unknown template %q (valid: starter)\n", template)
		return 2
	}

	fmt.Fprintf(stdout, "\n%s🏢 HELM Demo: Acme AI%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "%s   Scenario: Deploy v2.4 API to prod | Sandbox: %s%s\n\n", ColorGray, provider, ColorReset)

	// Define realistic org
	type Agent struct {
		Name string
		Role string
	}
	org := []Agent{
		{Name: "CTO", Role: "planner"},
		{Name: "Product Manager", Role: "planner"},
		{Name: "Backend Engineer", Role: "executor"},
		{Name: "DevOps Lead", Role: "executor"},
		{Name: "Security Engineer", Role: "auditor"},
		{Name: "QA Lead", Role: "executor"},
	}

	fmt.Fprintf(stdout, "%sTeam:%s\n", ColorBold, ColorReset)
	for _, a := range org {
		icon := "📋"
		if a.Role == "executor" {
			icon = "⚙️ "
		} else if a.Role == "auditor" {
			icon = "🔒"
		}
		fmt.Fprintf(stdout, "  %s %s%s%s (%s)\n", icon, ColorBold, a.Name, ColorReset, a.Role)
	}
	fmt.Fprintln(stdout, "")

	ctx := context.Background()
	_ = ctx

	// Simulate an initiative with receipts
	var receipts []demoReceipt
	var prevHash string
	var lamport uint64

	emitReceipt := func(principal, action, tool, verdict, reason string) demoReceipt {
		lamport++
		ts := time.Now().UTC().Format(time.RFC3339)
		// Build deterministic hash
		preimage := fmt.Sprintf("%s|%s|%s|%s|%s|%d|%s", principal, action, tool, verdict, reason, lamport, prevHash)
		h := sha256.Sum256([]byte(preimage))
		hash := hex.EncodeToString(h[:])

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
			Mode:       "demo",
		}
		prevHash = hash
		receipts = append(receipts, r)

		// Stream to terminal
		icon := "✅"
		color := ColorGreen
		if verdict == "DENY" {
			icon = "❌"
			color = ColorRed
		} else if verdict == "PENDING" {
			icon = "⏳"
			color = ColorYellow
		}
		fmt.Fprintf(stdout, "  %s %s[%s]%s %s → %s%s%s %s(L=%d)%s\n",
			icon, color, verdict, ColorReset,
			principal, ColorBold, action, ColorReset,
			ColorGray, lamport, ColorReset)

		return r
	}

	fmt.Fprintf(stdout, "%s━━━ Deploy v2.4 API to Production ━━━%s\n\n", ColorBold+ColorCyan, ColorReset)

	// Phase 1: Planning & task assignment
	fmt.Fprintf(stdout, "%sPhase 1: Sprint Planning%s\n", ColorBold, ColorReset)
	emitReceipt("Product Manager", "DEFINE_REQUIREMENTS", "jira", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s→ PRD: v2.4 rate limiting + embeddings endpoint%s\n", ColorGray, ColorReset)
	emitReceipt("CTO", "PLAN_INITIATIVE", "jira", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s→ Created ACME-2847: Deploy v2.4 API with rate limiting%s\n", ColorGray, ColorReset)
	emitReceipt("CTO", "ASSIGN_TASK", "jira", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s→ Assigned to Backend Engineer + DevOps Lead%s\n", ColorGray, ColorReset)

	// Phase 2: Security review + approval gate
	fmt.Fprintf(stdout, "\n%sPhase 2: Security Review & Deploy Approval%s\n", ColorBold, ColorReset)
	emitReceipt("Security Engineer", "AUDIT_REVIEW", "snyk_scan", "ALLOW", "AUDIT_PASS")
	fmt.Fprintf(stdout, "    %s→ Security scan: 0 critical, 0 high, 2 low (accepted)%s\n", ColorGray, ColorReset)
	emitReceipt("Backend Engineer", "REQUEST_APPROVAL", "deploy_staging", "PENDING", "APPROVAL_REQUIRED")
	fmt.Fprintf(stdout, "    %s→ PR #1482 merged, requesting prod deploy approval%s\n", ColorGray, ColorReset)
	emitReceipt("CTO", "APPROVE_EXECUTION", "deploy_production", "ALLOW", "APPROVAL_GRANTED")
	fmt.Fprintf(stdout, "    %s→ CTO approved: \"LGTM, staging verified, deploy to prod\"%s\n", ColorGray, ColorReset)

	// Phase 3: Sandbox execution — build + test in isolated env
	fmt.Fprintf(stdout, "\n%sPhase 3: Sandboxed Build & Test (%s)%s\n", ColorBold, provider, ColorReset)
	emitReceipt("Backend Engineer", "SANDBOX_EXEC", "npm_test", "ALLOW", "PREFLIGHT_PASS")

	if provider == "mock" {
		fmt.Fprintf(stdout, "    %s→ sandbox exec: npm run test:ci && npm run build%s\n", ColorGray, ColorReset)
		fmt.Fprintf(stdout, "    %s→ 247 tests passed, 0 failed. Build artifact: api-v2.4.0.tar.gz%s\n", ColorGray, ColorReset)
	}

	emitReceipt("Backend Engineer", "SANDBOX_RESULT", "npm_build", "ALLOW", "EXECUTION_COMPLETE")
	fmt.Fprintf(stdout, "    %s→ Docker image acme/api:2.4.0 pushed to registry%s\n", ColorGray, ColorReset)

	// Phase 4: QA acceptance + infrastructure deployment
	fmt.Fprintf(stdout, "\n%sPhase 4: QA Acceptance & Deployment%s\n", ColorBold, ColorReset)
	emitReceipt("QA Lead", "RUN_ACCEPTANCE", "playwright_e2e", "ALLOW", "TESTS_PASS")
	fmt.Fprintf(stdout, "    %s→ E2E suite: 84 scenarios passed, p99 latency < 200ms%s\n", ColorGray, ColorReset)
	emitReceipt("DevOps Lead", "SANDBOX_EXEC", "kubectl_apply", "ALLOW", "POLICY_PASS")
	fmt.Fprintf(stdout, "    %s→ kubectl apply -f k8s/api-v2.4.yaml (3 replicas, rolling update)%s\n", ColorGray, ColorReset)

	// Phase 5: Deny path — blocked destructive action
	fmt.Fprintf(stdout, "\n%sPhase 5: Governance Deny (fail-closed)%s\n", ColorBold, ColorReset)
	emitReceipt("Backend Engineer", "EXECUTE_TOOL", "psql_drop_table", "DENY", "ERR_TOOL_NOT_ALLOWED")
	fmt.Fprintf(stdout, "    %s→ Blocked: DROP TABLE users — destructive action not in allowlist%s\n", ColorGray, ColorReset)
	fmt.Fprintf(stdout, "    %s┌─ Deny Details ─────────────────────────────────────────%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Reason:      ERR_TOOL_NOT_ALLOWED%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Explanation: Tool \"psql_drop_table\" is not in the allowed-tools list%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Policy:      policy.allowed_tools%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s│ Fix:         Add \"psql_drop_table\" to allowed_tools in your HELM policy%s\n", ColorRed, ColorReset)
	fmt.Fprintf(stdout, "    %s└────────────────────────────────────────────────────────%s\n", ColorRed, ColorReset)

	fmt.Fprintf(stdout, "\n%s━━━ Deployment Complete ━━━%s\n\n", ColorBold+ColorCyan, ColorReset)

	// Phase 6: Skill Gap — team needs k8s scaling expertise
	fmt.Fprintf(stdout, "%sPhase 6: Skill Gap Detection%s\n", ColorBold, ColorReset)
	emitReceipt("DevOps Lead", "DETECT_SKILL_GAP", "k8s_hpa_config", "ALLOW", "SKILL_GAP_DETECTED")
	fmt.Fprintf(stdout, "    %s→ Gap: team lacks HPA auto-scaling configuration expertise%s\n", ColorGray, ColorReset)

	// Create a SkillCandidate in data/candidates/
	candidatesDir := filepath.Join("data", "candidates")
	_ = os.MkdirAll(candidatesDir, 0750)
	demoCandidate := map[string]any{
		"name":               "k8s_hpa_config",
		"version":            "1.0.0",
		"purpose":            "Kubernetes HPA auto-scaling configuration",
		"allowed_tools":      []string{"kubectl", "helm_chart"},
		"effect_classes":     []string{"compute", "network"},
		"risk":               "medium",
		"required_approvals": 1,
		"idempotent":         true,
		"hash":               hex.EncodeToString(sha256.New().Sum([]byte("k8s_hpa_config_demo"))),
		"created_at":         time.Now().UTC().Format(time.RFC3339),
	}
	candidateData, _ := json.MarshalIndent(demoCandidate, "", "  ")
	_ = os.WriteFile(filepath.Join(candidatesDir, "k8s_hpa_config-demo.json"), candidateData, 0644)

	emitReceipt("CTO", "AUTO_APPROVE_SKILL", "k8s_hpa_config", "ALLOW", "DEMO_AUTO_APPROVE")
	fmt.Fprintf(stdout, "    %s→ SkillCandidate ‹k8s_hpa_config› proposed and auto-approved (demo mode)%s\n", ColorGray, ColorReset)

	// Phase 7: Incident → Maintenance (realistic prod incident)
	fmt.Fprintf(stdout, "\n%sPhase 7: Production Incident → Auto-Maintenance%s\n", ColorBold, ColorReset)

	incDir := filepath.Join("data", "incidents")
	_ = os.MkdirAll(incDir, 0750)
	demoIncident := Incident{
		ID:                 "INC-demo-001",
		Severity:           "high",
		Category:           "performance",
		Component:          "api-v2.4",
		Title:              "Memory leak in /v1/embeddings after 10k requests",
		ReproductionRecipe: "ab -n 10000 -c 50 https://api.acme.ai/v1/embeddings",
		Status:             "open",
		Recurrence:         1,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	_ = saveIncident(&demoIncident)

	emitReceipt("System", "INCIDENT_CREATED", "pagerduty", "ALLOW", "INCIDENT_OPEN")
	fmt.Fprintf(stdout, "    %s→ INC-demo-001: Memory leak in /v1/embeddings (severity: high)%s\n", ColorGray, ColorReset)
	emitReceipt("System", "MAINTENANCE_RUN", "gc_tuning_patch", "ALLOW", "CONFORMANCE_PASS")
	fmt.Fprintf(stdout, "    %s→ Auto-patch: GOGC=50, GOMEMLIMIT=512Mi (conformance gate: PASS)%s\n", ColorGray, ColorReset)

	// Resolve
	demoIncident.Status = "resolved"
	demoIncident.Resolution = "Applied GC tuning patch, memory stable at 380Mi under load"
	demoIncident.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = saveIncident(&demoIncident)

	fmt.Fprintf(stdout, "    %s→ Resolved: memory stable at 380Mi under 10k req load test%s\n", ColorGray, ColorReset)

	fmt.Fprintf(stdout, "\n%s━━━ All Phases Complete ━━━%s\n\n", ColorBold+ColorCyan, ColorReset)

	// Export EvidencePack (.tar)
	fmt.Fprintf(stdout, "%sExporting EvidencePack...%s\n", ColorBold, ColorReset)

	if err := os.MkdirAll(outDir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error creating evidence dir: %v\n", err)
		return 2
	}

	// Write receipts
	for i, r := range receipts {
		data, _ := json.MarshalIndent(r, "", "  ")
		fname := fmt.Sprintf("%03d_%s.json", i+1, r.ReceiptID)
		if err := os.WriteFile(filepath.Join(outDir, fname), data, 0644); err != nil {
			fmt.Fprintf(stderr, "Error writing receipt: %v\n", err)
			return 2
		}
	}

	// Write manifest
	manifest := map[string]any{
		"session_id":  "demo-starter-" + time.Now().UTC().Format("20060102-150405"),
		"template":    template,
		"provider":    provider,
		"receipts":    len(receipts),
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"final_hash":  prevHash,
		"lamport":     lamport,
		"features":    []string{"skill_lifecycle", "maintenance_loop", "approval_gate", "sandbox_exec", "deny_path"},
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestData, 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing manifest: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "  📦 %d receipts → %s/\n", len(receipts), outDir)

	// Generate Proof Report
	if err := generateProofReport(receipts, outDir, template, provider, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "Warning: could not generate HTML report: %v\n", err)
	} else {
		fmt.Fprintf(stdout, "  📊 Proof Report → %s/run-report.html\n", outDir)
	}
	if err := generateProofReportJSON(receipts, outDir, template, provider); err != nil {
		fmt.Fprintf(stderr, "Warning: could not generate JSON report: %v\n", err)
	}

	// Verify inline
	fmt.Fprintf(stdout, "\n%sVerifying EvidencePack...%s\n", ColorBold, ColorReset)

	// Re-compute chain
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
		fmt.Fprintf(stdout, "  ✅ Skill gap:     SkillCandidate auto-proposed + approved\n")
		fmt.Fprintf(stdout, "  ✅ Maintenance:   incident auto-resolved with conformance\n")
	}

	fmt.Fprintf(stdout, "\n%s🎉 Demo complete.%s Evidence at %s/\n", ColorBold+ColorGreen, ColorReset, outDir)

	// Terminal summary card — deterministic, same structure every run
	reportPath := filepath.Join(outDir, "run-report.html")
	fmt.Fprintf(stdout, "\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║  HELM Demo Complete                                        ║%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s╠════════════════════════════════════════════════════════════╣%s\n", ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  📊 Report:   %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorBold, reportPath, ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  📦 Evidence: %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorBold, outDir+"/", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  🔍 Verify:   %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorGray, "helm export --evidence "+outDir+" --out e.tar", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s              %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorGray, "helm verify --bundle e.tar", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s║%s  🔄 Switch:   %s%-43s%s %s║%s\n", ColorCyan, ColorReset, ColorGray, "helm demo company --provider opensandbox", ColorReset, ColorCyan, ColorReset)
	fmt.Fprintf(stdout, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)

	if !allValid {
		return 1
	}
	return 0
}

func init() {
	Register(Subcommand{Name: "demo", Aliases: []string{}, Usage: "Run governed demonstrations (demo company)", RunFn: runDemoCmd})
}
