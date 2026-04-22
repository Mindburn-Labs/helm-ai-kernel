package main

import (
	"crypto/rand"
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

// AgentTemplate defines defaults for a workforce agent role.
type AgentTemplate struct {
	Description string   `json:"description"`
	Tools       []string `json:"tools"`
	MaxRiskClass string  `json:"max_risk_class"`
	DefaultMode string   `json:"default_mode"`
}

var agentTemplates = map[string]AgentTemplate{
	"research-agent": {
		Description: "Autonomous research agent with web search, document analysis, and publication",
		Tools:       []string{"web_search", "document_read", "arxiv_search", "pdf_extract", "github_search", "publish_draft"},
		MaxRiskClass: "R2",
		DefaultMode: "supervised",
	},
	"support-agent": {
		Description: "Customer support agent with ticket management and knowledge base access",
		Tools:       []string{"ticket_read", "ticket_update", "kb_search", "email_send", "slack_post"},
		MaxRiskClass: "R1",
		DefaultMode: "supervised",
	},
	"devops-agent": {
		Description: "DevOps agent with CI/CD, monitoring, and infrastructure management",
		Tools:       []string{"github_api", "ci_trigger", "monitoring_read", "log_search", "alert_ack"},
		MaxRiskClass: "R2",
		DefaultMode: "supervised",
	},
	"compliance-agent": {
		Description: "Compliance monitoring agent with audit, scanning, and reporting",
		Tools:       []string{"audit_log_read", "policy_check", "compliance_scan", "report_generate", "evidence_export"},
		MaxRiskClass: "R1",
		DefaultMode: "autonomous",
	},
}

// StoredAgent is the on-disk representation of a workforce agent.
type StoredAgent struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Manager       string    `json:"manager"`
	Template      string    `json:"template"`
	Mode          string    `json:"mode"`
	Tools         []string  `json:"tools"`
	MaxRisk       string    `json:"max_risk_class"`
	DailyBudget   int64     `json:"daily_budget_cents"`
	MonthlyBudget int64     `json:"monthly_budget_cents"`
	Status        string    `json:"status"` // ACTIVE, SUSPENDED, TERMINATED
	CreatedAt     time.Time `json:"created_at"`
	Description   string    `json:"description"`
}

type agentStore struct {
	Agents []StoredAgent `json:"agents"`
}

func workforceStorePath() string {
	dir := os.Getenv("HELM_DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	return filepath.Join(dir, "workforce", "agents.json")
}

func loadAgentStore() (*agentStore, error) {
	data, err := os.ReadFile(workforceStorePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &agentStore{}, nil
		}
		return nil, err
	}
	var s agentStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveAgentStore(s *agentStore) error {
	dir := filepath.Dir(workforceStorePath())
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(workforceStorePath(), data, 0600)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fallback: should never happen with crypto/rand
		return "000000"
	}
	return hex.EncodeToString(b)
}

func formatCents(cents int64) string {
	dollars := cents / 100
	remainder := cents % 100
	return fmt.Sprintf("$%d.%02d", dollars, remainder)
}

func init() {
	Register(Subcommand{
		Name:    "workforce",
		Aliases: []string{"wf"},
		Usage:   "Manage virtual employee agents (hire, list, suspend, terminate, inspect)",
		RunFn:   runWorkforceCmd,
	})
}

func runWorkforceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm workforce <hire|list|inspect|suspend|resume|terminate> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  hire        Hire a new virtual employee agent")
		fmt.Fprintln(stderr, "  list        List workforce agents")
		fmt.Fprintln(stderr, "  inspect     Show full agent configuration and history")
		fmt.Fprintln(stderr, "  suspend     Suspend an active agent (kill switch)")
		fmt.Fprintln(stderr, "  resume      Resume a suspended agent")
		fmt.Fprintln(stderr, "  terminate   Permanently deactivate an agent")
		return 2
	}

	switch args[0] {
	case "hire":
		return runWorkforceHire(args[1:], stdout, stderr)
	case "list":
		return runWorkforceList(args[1:], stdout, stderr)
	case "inspect":
		return runWorkforceInspect(args[1:], stdout, stderr)
	case "suspend":
		return runWorkforceTransition(args[1:], stdout, stderr, "SUSPENDED")
	case "resume":
		return runWorkforceTransition(args[1:], stdout, stderr, "ACTIVE")
	case "terminate":
		return runWorkforceTransition(args[1:], stdout, stderr, "TERMINATED")
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm workforce <hire|list|inspect|suspend|resume|terminate> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  hire        Hire a new virtual employee agent")
		fmt.Fprintln(stdout, "  list        List workforce agents")
		fmt.Fprintln(stdout, "  inspect     Show full agent configuration and history")
		fmt.Fprintln(stdout, "  suspend     Suspend an active agent (kill switch)")
		fmt.Fprintln(stdout, "  resume      Resume a suspended agent")
		fmt.Fprintln(stdout, "  terminate   Permanently deactivate an agent")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown workforce subcommand: %s\n", args[0])
		return 2
	}
}

func runWorkforceHire(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workforce hire", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		name          string
		manager       string
		template      string
		budget        int64
		monthlyBudget int64
		mode          string
		tools         string
		jsonOutput    bool
	)

	cmd.StringVar(&name, "name", "", "Agent display name (REQUIRED)")
	cmd.StringVar(&manager, "manager", "", "Manager ID/email (REQUIRED)")
	cmd.StringVar(&template, "template", "custom", "Role template: research-agent, support-agent, devops-agent, compliance-agent, custom")
	cmd.Int64Var(&budget, "budget", 0, "Daily budget in cents (REQUIRED, must be > 0)")
	cmd.Int64Var(&monthlyBudget, "monthly-budget", 0, "Monthly budget in cents (optional)")
	cmd.StringVar(&mode, "mode", "", "Execution mode: autonomous, supervised, manual (default depends on template)")
	cmd.StringVar(&tools, "tools", "", "Comma-separated allowed tools (optional, template provides defaults)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// Validate required fields
	if name == "" {
		fmt.Fprintln(stderr, "Error: --name is required")
		return 2
	}
	if manager == "" {
		fmt.Fprintln(stderr, "Error: --manager is required")
		return 2
	}
	if budget <= 0 {
		fmt.Fprintln(stderr, "Error: --budget is required and must be > 0")
		return 2
	}

	// Validate template
	if template != "custom" {
		if _, ok := agentTemplates[template]; !ok {
			fmt.Fprintf(stderr, "Error: unknown template %q\n", template)
			fmt.Fprintln(stderr, "Available: research-agent, support-agent, devops-agent, compliance-agent, custom")
			return 2
		}
	}

	// Validate mode
	validModes := map[string]bool{"autonomous": true, "supervised": true, "manual": true}
	if mode == "" {
		if template != "custom" {
			mode = agentTemplates[template].DefaultMode
		} else {
			mode = "supervised"
		}
	}
	if !validModes[mode] {
		fmt.Fprintf(stderr, "Error: invalid mode %q (valid: autonomous, supervised, manual)\n", mode)
		return 2
	}

	// Resolve tools
	var toolList []string
	if tools != "" {
		for _, t := range strings.Split(tools, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				toolList = append(toolList, trimmed)
			}
		}
	} else if template != "custom" {
		toolList = agentTemplates[template].Tools
	}

	// Resolve risk class
	maxRisk := "R2"
	if template != "custom" {
		maxRisk = agentTemplates[template].MaxRiskClass
	}

	// Resolve description
	description := ""
	if template != "custom" {
		description = agentTemplates[template].Description
	}

	agent := StoredAgent{
		ID:            fmt.Sprintf("emp-%s", randomHex(6)),
		Name:          name,
		Manager:       manager,
		Template:      template,
		Mode:          mode,
		Tools:         toolList,
		MaxRisk:       maxRisk,
		DailyBudget:   budget,
		MonthlyBudget: monthlyBudget,
		Status:        "ACTIVE",
		CreatedAt:     time.Now().UTC(),
		Description:   description,
	}

	store, err := loadAgentStore()
	if err != nil {
		fmt.Fprintf(stderr, "Error loading agent store: %v\n", err)
		return 2
	}

	store.Agents = append(store.Agents, agent)

	if err := saveAgentStore(store); err != nil {
		fmt.Fprintf(stderr, "Error saving agent store: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(agent, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stdout, "\n%sAgent Hired%s\n\n", ColorBold+ColorGreen, ColorReset)
		fmt.Fprintf(stdout, "  ID:        %s%s%s\n", ColorBold, agent.ID, ColorReset)
		fmt.Fprintf(stdout, "  Name:      %s\n", agent.Name)
		fmt.Fprintf(stdout, "  Manager:   %s\n", agent.Manager)
		fmt.Fprintf(stdout, "  Template:  %s\n", agent.Template)
		fmt.Fprintf(stdout, "  Mode:      %s\n", agent.Mode)
		fmt.Fprintf(stdout, "  Budget:    %s/day\n", formatCents(agent.DailyBudget))
		if agent.MonthlyBudget > 0 {
			fmt.Fprintf(stdout, "  Monthly:   %s/month\n", formatCents(agent.MonthlyBudget))
		}
		fmt.Fprintf(stdout, "  Risk:      %s\n", agent.MaxRisk)
		fmt.Fprintf(stdout, "  Status:    %s\n", agent.Status)
		if len(agent.Tools) > 0 {
			fmt.Fprintf(stdout, "  Tools:     %s\n", strings.Join(agent.Tools, ", "))
		}
		fmt.Fprintln(stdout)
	}

	return 0
}

func runWorkforceList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workforce list", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		status     string
		jsonOutput bool
	)

	cmd.StringVar(&status, "status", "active", "Filter by status (active, suspended, terminated, all)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	store, err := loadAgentStore()
	if err != nil {
		fmt.Fprintf(stderr, "Error loading agent store: %v\n", err)
		return 2
	}

	// Filter agents
	var filtered []StoredAgent
	filterStatus := strings.ToUpper(status)
	for _, a := range store.Agents {
		if filterStatus == "ALL" || a.Status == filterStatus {
			filtered = append(filtered, a)
		}
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(filtered, "", "  ")
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	if len(filtered) == 0 {
		fmt.Fprintf(stdout, "\nHELM Workforce — No %s agents\n\n", strings.ToLower(status))
		fmt.Fprintln(stdout, "  Hire an agent: helm workforce hire --name <name> --manager <email> --budget <cents>")
		fmt.Fprintln(stdout)
		return 0
	}

	// Header
	statusLabel := capitalizeFirst(strings.ToLower(status))
	if filterStatus == "ALL" {
		statusLabel = "All"
	}
	fmt.Fprintf(stdout, "\n%sHELM Workforce%s — %s Agents\n\n", ColorBold, ColorReset, statusLabel)

	// Table header
	fmt.Fprintf(stdout, "  %-14s %-18s %-18s %-18s %-12s %-12s %s\n",
		"ID", "Name", "Manager", "Template", "Mode", "Budget", "Status")
	fmt.Fprintf(stdout, "  %s\n", strings.Repeat("-", 106))

	// Rows
	var totalDailyBudget int64
	activeCount := 0
	for _, a := range filtered {
		budgetStr := fmt.Sprintf("%s/day", formatCents(a.DailyBudget))

		statusColor := ColorGreen
		switch a.Status {
		case "SUSPENDED":
			statusColor = ColorYellow
		case "TERMINATED":
			statusColor = ColorRed
		}

		fmt.Fprintf(stdout, "  %-14s %-18s %-18s %-18s %-12s %-12s %s%s%s\n",
			a.ID, truncate(a.Name, 16), truncate(a.Manager, 16), a.Template, a.Mode, budgetStr,
			statusColor, a.Status, ColorReset)

		if a.Status == "ACTIVE" {
			totalDailyBudget += a.DailyBudget
			activeCount++
		}
	}

	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "%d agent(s) shown", len(filtered))
	if activeCount > 0 {
		fmt.Fprintf(stdout, " | %d active | Total daily budget: %s", activeCount, formatCents(totalDailyBudget))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout)

	return 0
}

func runWorkforceInspect(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workforce inspect", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		id         string
		jsonOutput bool
	)

	cmd.StringVar(&id, "id", "", "Agent ID (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if id == "" {
		fmt.Fprintln(stderr, "Error: --id is required")
		return 2
	}

	store, err := loadAgentStore()
	if err != nil {
		fmt.Fprintf(stderr, "Error loading agent store: %v\n", err)
		return 2
	}

	agent := findAgent(store, id)
	if agent == nil {
		fmt.Fprintf(stderr, "Error: agent %q not found\n", id)
		return 1
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(agent, "", "  ")
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	statusColor := ColorGreen
	switch agent.Status {
	case "SUSPENDED":
		statusColor = ColorYellow
	case "TERMINATED":
		statusColor = ColorRed
	}

	fmt.Fprintf(stdout, "\n%sAgent: %s%s\n\n", ColorBold, agent.Name, ColorReset)
	fmt.Fprintf(stdout, "  ID:            %s\n", agent.ID)
	fmt.Fprintf(stdout, "  Status:        %s%s%s\n", statusColor, agent.Status, ColorReset)
	fmt.Fprintf(stdout, "  Manager:       %s\n", agent.Manager)
	fmt.Fprintf(stdout, "  Template:      %s\n", agent.Template)
	fmt.Fprintf(stdout, "  Mode:          %s\n", agent.Mode)
	fmt.Fprintf(stdout, "  Max Risk:      %s\n", agent.MaxRisk)
	fmt.Fprintf(stdout, "  Daily Budget:  %s\n", formatCents(agent.DailyBudget))
	if agent.MonthlyBudget > 0 {
		fmt.Fprintf(stdout, "  Monthly Budget: %s\n", formatCents(agent.MonthlyBudget))
	}
	fmt.Fprintf(stdout, "  Created:       %s\n", agent.CreatedAt.Format(time.RFC3339))

	if agent.Description != "" {
		fmt.Fprintf(stdout, "\n  Description:\n    %s\n", agent.Description)
	}

	if len(agent.Tools) > 0 {
		fmt.Fprintf(stdout, "\n  Tool Scope (%d tools):\n", len(agent.Tools))
		for _, t := range agent.Tools {
			fmt.Fprintf(stdout, "    - %s\n", t)
		}
	}

	fmt.Fprintln(stdout)

	return 0
}

func runWorkforceTransition(args []string, stdout, stderr io.Writer, targetStatus string) int {
	actionLabel := strings.ToLower(targetStatus)
	switch targetStatus {
	case "ACTIVE":
		actionLabel = "resume"
	case "SUSPENDED":
		actionLabel = "suspend"
	case "TERMINATED":
		actionLabel = "terminate"
	}

	cmd := flag.NewFlagSet("workforce "+actionLabel, flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		id         string
		jsonOutput bool
	)

	cmd.StringVar(&id, "id", "", "Agent ID (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if id == "" {
		fmt.Fprintln(stderr, "Error: --id is required")
		return 2
	}

	store, err := loadAgentStore()
	if err != nil {
		fmt.Fprintf(stderr, "Error loading agent store: %v\n", err)
		return 2
	}

	agent := findAgent(store, id)
	if agent == nil {
		fmt.Fprintf(stderr, "Error: agent %q not found\n", id)
		return 1
	}

	// Validate transition
	switch targetStatus {
	case "SUSPENDED":
		if agent.Status != "ACTIVE" {
			fmt.Fprintf(stderr, "Error: can only suspend ACTIVE agents (current: %s)\n", agent.Status)
			return 1
		}
	case "ACTIVE":
		if agent.Status != "SUSPENDED" {
			fmt.Fprintf(stderr, "Error: can only resume SUSPENDED agents (current: %s)\n", agent.Status)
			return 1
		}
	case "TERMINATED":
		if agent.Status == "TERMINATED" {
			fmt.Fprintln(stderr, "Error: agent is already TERMINATED")
			return 1
		}
	}

	agent.Status = targetStatus

	if err := saveAgentStore(store); err != nil {
		fmt.Fprintf(stderr, "Error saving agent store: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(agent, "", "  ")
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	statusColor := ColorGreen
	statusIcon := "RESUMED"
	switch targetStatus {
	case "SUSPENDED":
		statusColor = ColorYellow
		statusIcon = "SUSPENDED"
	case "TERMINATED":
		statusColor = ColorRed
		statusIcon = "TERMINATED"
	}

	fmt.Fprintf(stdout, "\n%s%s%s: %s (%s)\n\n", statusColor+ColorBold, statusIcon, ColorReset, agent.Name, agent.ID)

	return 0
}

// findAgent returns a pointer to the agent in the store (mutating it will mutate the store).
func findAgent(s *agentStore, id string) *StoredAgent {
	for i := range s.Agents {
		if s.Agents[i].ID == id {
			return &s.Agents[i]
		}
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
