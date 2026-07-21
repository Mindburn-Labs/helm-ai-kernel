package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

// runAutoconfigureCmd implements `helm-ai-kernel autoconfigure` — autonomous
// setup with explicit authority. HELM automates the recon and configuration
// layer (discovery, quarantine planning, policy drafting) but cannot grant
// itself authority: every artifact it produces is a draft that requires human
// review, and activation runs through the VGL genesis ceremony
// (INGEST → MIRROR → WARGAME → CEILINGS → REVIEW → ACTIVATION), which binds
// P0 ceilings and requires an ORG_GENESIS_APPROVAL attestation.
//
// Exit codes:
//
//	0 = success
//	1 = ungoverned surface found (scan)
//	2 = config error
func runAutoconfigureCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		autoconfigureUsage(stderr)
		return 2
	}
	switch args[0] {
	case "scan":
		return runAutoconfigureScan(args[1:], stdout, stderr)
	case "draft-policy":
		return runAutoconfigureDraftPolicy(args[1:], stdout, stderr)
	case "simulate":
		return runAutoconfigureSimulate(args[1:], stdout, stderr)
	case "activate":
		return runAutoconfigureActivate(args[1:], stdout, stderr)
	case "--help", "-h", "help":
		autoconfigureUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown autoconfigure subcommand: %s\n\n", args[0])
		autoconfigureUsage(stderr)
		return 2
	}
}

func autoconfigureUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel autoconfigure <scan|draft-policy|simulate|activate> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Autonomous setup. Explicit authority. HELM discovers the environment and")
	fmt.Fprintln(w, "drafts least-authority configuration; it prepares approval records but")
	fmt.Fprintln(w, "never approves them itself.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  scan          Discover agent surface; write deterministic inventory JSON")
	fmt.Fprintln(w, "  draft-policy  Draft default-deny policy + MCP quarantine plan from inventory")
	fmt.Fprintln(w, "  simulate      Blast-radius wargame: negative vectors through the real firewall")
	fmt.Fprintln(w, "  activate      Deterministic activation summary; live only with an explicit")
	fmt.Fprintln(w, "                signature over policy/ceilings/approvals/impact hashes")
	fmt.Fprintln(w, "                (ORG_GENESIS_APPROVAL attestation; never a silent flip)")
}

// AgentSurfaceEntry is one detected agent-SDK signal.
type AgentSurfaceEntry struct {
	Vendor   string `json:"vendor"`
	Language string `json:"language"`
	Path     string `json:"path"`
	Line     int    `json:"line,omitempty"`
	Kind     string `json:"kind"`
}

// MCPServerEntry is one detected MCP server configuration.
type MCPServerEntry struct {
	ConfigPath string `json:"config_path"`
	Severity   string `json:"severity"`
}

// SecretExposureEntry is one detected hardcoded credential pattern.
type SecretExposureEntry struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Vendor string `json:"vendor"`
}

// AutoconfigureInventory is the deterministic discovery output of
// `autoconfigure scan`. It is a structured projection of the shadow scan
// report: same tree in, same inventory out.
type AutoconfigureInventory struct {
	Version         string                `json:"version"`
	ScanRoot        string                `json:"scan_root"`
	Grade           shadow.Grade          `json:"grade"`
	AgentSurface    []AgentSurfaceEntry   `json:"agent_surface"`
	MCPServers      []MCPServerEntry      `json:"mcp_servers"`
	SecretExposures []SecretExposureEntry `json:"secret_exposures"`
	GeneratedAt     string                `json:"generated_at"`
}

// buildInventory projects a shadow report into the autoconfigure inventory.
// Entries are sorted by path for deterministic output.
func buildInventory(report *shadow.Report) AutoconfigureInventory {
	inv := AutoconfigureInventory{
		Version:         "autoconfigure-inventory/v1",
		ScanRoot:        report.ScanRoot,
		Grade:           report.Grade,
		AgentSurface:    []AgentSurfaceEntry{},
		MCPServers:      []MCPServerEntry{},
		SecretExposures: []SecretExposureEntry{},
		GeneratedAt:     report.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	for _, f := range report.Findings {
		switch f.Kind {
		case "sdk_import", "helm_absent", "agt_detected", "local_llm_runtime", "llm_gateway":
			if f.Vendor == "helm" {
				continue
			}
			inv.AgentSurface = append(inv.AgentSurface, AgentSurfaceEntry{
				Vendor:   f.Vendor,
				Language: f.Language,
				Path:     f.Path,
				Line:     f.Line,
				Kind:     f.Kind,
			})
		case "mcp_config":
			inv.MCPServers = append(inv.MCPServers, MCPServerEntry{
				ConfigPath: f.Path,
				Severity:   f.Severity,
			})
		case "api_key":
			inv.SecretExposures = append(inv.SecretExposures, SecretExposureEntry{
				Path:   f.Path,
				Line:   f.Line,
				Vendor: f.Vendor,
			})
		}
	}
	sort.Slice(inv.AgentSurface, func(i, j int) bool {
		a, b := inv.AgentSurface[i], inv.AgentSurface[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	sort.Slice(inv.MCPServers, func(i, j int) bool {
		return inv.MCPServers[i].ConfigPath < inv.MCPServers[j].ConfigPath
	})
	sort.Slice(inv.SecretExposures, func(i, j int) bool {
		a, b := inv.SecretExposures[i], inv.SecretExposures[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return inv
}

func runAutoconfigureScan(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("autoconfigure scan", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		path   string
		outDir string
	)
	cmd.StringVar(&path, "path", ".", "Directory to scan")
	cmd.StringVar(&outDir, "out", filepath.Join("data", "autoconfigure"), "Output directory for inventory artifacts")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	report, err := shadow.NewScanner().Scan(path)
	if err != nil {
		fmt.Fprintf(stderr, "Error scanning %q: %v\n", path, err)
		return 2
	}
	inv := buildInventory(report)

	if err := writeJSONArtifact(filepath.Join(outDir, "inventory.json"), inv); err != nil {
		fmt.Fprintf(stderr, "Error writing inventory: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "\n%sAutoconfigure Scan%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "  Root:             %s\n", inv.ScanRoot)
	fmt.Fprintf(stdout, "  Boundary grade:   %s — %s\n", inv.Grade.Letter, inv.Grade.Reason)
	fmt.Fprintf(stdout, "  Agent surface:    %d signal(s)\n", len(inv.AgentSurface))
	fmt.Fprintf(stdout, "  MCP servers:      %d config(s)\n", len(inv.MCPServers))
	fmt.Fprintf(stdout, "  Secret exposures: %d\n", len(inv.SecretExposures))
	fmt.Fprintf(stdout, "  Inventory:        %s\n\n", filepath.Join(outDir, "inventory.json"))
	fmt.Fprintf(stdout, "Next: %shelm-ai-kernel autoconfigure draft-policy%s\n\n", ColorBold, ColorReset)

	if !inv.Grade.BoundaryPresent && (len(inv.AgentSurface) > 0 || len(inv.MCPServers) > 0) {
		return 1
	}
	return 0
}

// PolicyDraftRule is one recommended rule in the draft policy.
type PolicyDraftRule struct {
	Surface            string `json:"surface"`
	Path               string `json:"path"`
	RecommendedVerdict string `json:"recommended_verdict"`
	RiskClass          string `json:"risk_class"`
	Reason             string `json:"reason"`
}

// PolicyDraft is the least-authority draft policy generated from an
// inventory. It is a draft: default-deny, never self-approving.
type PolicyDraft struct {
	Version             string            `json:"version"`
	Draft               bool              `json:"draft"`
	RequiresHumanReview bool              `json:"requires_human_review"`
	GeneratedFrom       string            `json:"generated_from"`
	DefaultVerdict      string            `json:"default_verdict"`
	Doctrine            string            `json:"doctrine"`
	Rules               []PolicyDraftRule `json:"rules"`
}

// QuarantinePlanEntry is one prepared (not approved) quarantine decision.
type QuarantinePlanEntry struct {
	ConfigPath       string            `json:"config_path"`
	State            string            `json:"state"`
	PreparedApproval map[string]string `json:"prepared_approval"`
}

// QuarantinePlan lists detected MCP servers with prepared approval records.
// Approver fields are intentionally empty: HELM prepares approval records,
// it never approves them itself.
type QuarantinePlan struct {
	Version string                `json:"version"`
	Draft   bool                  `json:"draft"`
	Servers []QuarantinePlanEntry `json:"servers"`
}

const autoconfigureDoctrine = "Autonomous setup. Explicit authority. HELM prepares approval records; it never approves them."

// buildPolicyDraft derives the default-deny draft policy and quarantine plan
// from an inventory. Deterministic: same inventory in, same drafts out.
func buildPolicyDraft(inv AutoconfigureInventory) (PolicyDraft, QuarantinePlan) {
	draft := PolicyDraft{
		Version:             "policy-draft/v1",
		Draft:               true,
		RequiresHumanReview: true,
		GeneratedFrom:       inv.ScanRoot,
		DefaultVerdict:      "DENY",
		Doctrine:            autoconfigureDoctrine,
		Rules:               []PolicyDraftRule{},
	}
	plan := QuarantinePlan{
		Version: "mcp-quarantine-plan/v1",
		Draft:   true,
		Servers: []QuarantinePlanEntry{},
	}

	for _, e := range inv.AgentSurface {
		draft.Rules = append(draft.Rules, PolicyDraftRule{
			Surface:            "sdk:" + e.Vendor,
			Path:               e.Path,
			RecommendedVerdict: "DENY",
			RiskClass:          "unclassified_default_deny",
			Reason:             "agent SDK detected without boundary routing; wrap via proxy before allowing",
		})
	}
	for _, e := range inv.MCPServers {
		draft.Rules = append(draft.Rules, PolicyDraftRule{
			Surface:            "mcp",
			Path:               e.ConfigPath,
			RecommendedVerdict: "ESCALATE",
			RiskClass:          "irreversible_until_classified",
			Reason:             "MCP server configuration; quarantine until schema, identity, and policy approved",
		})
		plan.Servers = append(plan.Servers, QuarantinePlanEntry{
			ConfigPath: e.ConfigPath,
			State:      "quarantine_recommended",
			PreparedApproval: map[string]string{
				"server_id":           "",
				"approver_id":         "",
				"approval_receipt_id": "",
			},
		})
	}
	for _, e := range inv.SecretExposures {
		draft.Rules = append(draft.Rules, PolicyDraftRule{
			Surface:            "secret:" + e.Vendor,
			Path:               e.Path,
			RecommendedVerdict: "DENY",
			RiskClass:          "irreversible",
			Reason:             "hardcoded credential pattern; move to a secret store before any allow rule",
		})
	}

	sort.Slice(draft.Rules, func(i, j int) bool {
		a, b := draft.Rules[i], draft.Rules[j]
		if a.Surface != b.Surface {
			return a.Surface < b.Surface
		}
		return a.Path < b.Path
	})
	return draft, plan
}

func runAutoconfigureDraftPolicy(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("autoconfigure draft-policy", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		path   string
		outDir string
	)
	cmd.StringVar(&path, "path", ".", "Directory to scan if no inventory exists")
	cmd.StringVar(&outDir, "out", filepath.Join("data", "autoconfigure"), "Output directory for draft artifacts")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	var inv AutoconfigureInventory
	invPath := filepath.Join(outDir, "inventory.json")
	if raw, err := os.ReadFile(invPath); err == nil {
		if err := json.Unmarshal(raw, &inv); err != nil {
			fmt.Fprintf(stderr, "Error parsing %s: %v\n", invPath, err)
			return 2
		}
	} else {
		report, scanErr := shadow.NewScanner().Scan(path)
		if scanErr != nil {
			fmt.Fprintf(stderr, "Error scanning %q: %v\n", path, scanErr)
			return 2
		}
		inv = buildInventory(report)
		if err := writeJSONArtifact(invPath, inv); err != nil {
			fmt.Fprintf(stderr, "Error writing inventory: %v\n", err)
			return 2
		}
	}

	draft, plan := buildPolicyDraft(inv)
	if err := writeJSONArtifact(filepath.Join(outDir, "policy.draft.json"), draft); err != nil {
		fmt.Fprintf(stderr, "Error writing policy draft: %v\n", err)
		return 2
	}
	if err := writeJSONArtifact(filepath.Join(outDir, "mcp_quarantine_plan.json"), plan); err != nil {
		fmt.Fprintf(stderr, "Error writing quarantine plan: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "\n%sAutoconfigure Policy Draft%s\n", ColorBold+ColorBlue, ColorReset)
	fmt.Fprintf(stdout, "  Default verdict:  DENY\n")
	fmt.Fprintf(stdout, "  Rules drafted:    %d\n", len(draft.Rules))
	fmt.Fprintf(stdout, "  MCP quarantines:  %d\n", len(plan.Servers))
	fmt.Fprintf(stdout, "  Policy draft:     %s\n", filepath.Join(outDir, "policy.draft.json"))
	fmt.Fprintf(stdout, "  Quarantine plan:  %s\n\n", filepath.Join(outDir, "mcp_quarantine_plan.json"))
	fmt.Fprintf(stdout, "%s%s%s\n", ColorBold, autoconfigureDoctrine, ColorReset)
	fmt.Fprintf(stdout, "Review the drafts, then bind ceilings and activate through the genesis\nceremony (WARGAME -> CEILINGS -> REVIEW -> ACTIVATION).\n\n")
	return 0
}

func writeJSONArtifact(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func init() {
	Register(Subcommand{
		Name:    "autoconfigure",
		Aliases: []string{"autoconf"},
		Usage:   "Autonomous setup, explicit authority: discover agent surface, draft least-authority policy",
		RunFn:   runAutoconfigureCmd,
	})
}
