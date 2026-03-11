package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// runRiskCmd implements `helm risk-summary`.
//
// Usage:
//
//	helm risk-summary --effect <EFFECT_TYPE_ID> [--frozen] [--context-mismatch] [--json]
//	helm risk-summary --list                     [--json]
func runRiskCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("risk-summary", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		effect          string
		frozen          bool
		contextMismatch bool
		budgetImpact    bool
		egressRisk      bool
		identityRisk    bool
		listAll         bool
		jsonOutput      bool
	)

	cmd.StringVar(&effect, "effect", "", "Effect type ID (e.g., INFRA_DESTROY)")
	cmd.BoolVar(&frozen, "frozen", false, "Include SYSTEM_FROZEN flag")
	cmd.BoolVar(&contextMismatch, "context-mismatch", false, "Include CONTEXT_MISMATCH flag")
	cmd.BoolVar(&budgetImpact, "budget-impact", false, "Include budget impact flag")
	cmd.BoolVar(&egressRisk, "egress", false, "Include egress risk flag")
	cmd.BoolVar(&identityRisk, "identity", false, "Include identity risk flag")
	cmd.BoolVar(&listAll, "list", false, "List all effect types in catalog")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// List mode
	if listAll {
		catalog := contracts.DefaultEffectCatalog()
		if jsonOutput {
			data, _ := json.MarshalIndent(catalog, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			_, _ = fmt.Fprintf(stdout, "HELM Effect Type Catalog v%s\n", catalog.CatalogVersion)
			_, _ = fmt.Fprintln(stdout, "─────────────────────────────")
			for _, et := range catalog.EffectTypes {
				rc := contracts.EffectRiskClass(et.TypeID)
				_, _ = fmt.Fprintf(stdout, "  %s%-30s%s %s  approval=%s\n",
					ColorCyan, et.TypeID, ColorReset, rc, et.DefaultApprovalLevel)
			}
			_, _ = fmt.Fprintf(stdout, "\n%d effect type(s)\n", len(catalog.EffectTypes))
		}
		return 0
	}

	if effect == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --effect or --list is required")
		_, _ = fmt.Fprintln(stderr, "Usage: helm risk-summary --effect INFRA_DESTROY [--frozen] [--json]")
		_, _ = fmt.Fprintln(stderr, "       helm risk-summary --list [--json]")
		return 2
	}

	// Build risk options
	var opts []contracts.RiskOption
	if frozen {
		opts = append(opts, contracts.WithFrozen())
	}
	if contextMismatch {
		opts = append(opts, contracts.WithContextMismatch())
	}
	if budgetImpact {
		opts = append(opts, contracts.WithBudgetImpact())
	}
	if egressRisk {
		opts = append(opts, contracts.WithEgressRisk())
	}
	if identityRisk {
		opts = append(opts, contracts.WithIdentityRisk())
	}

	rs := contracts.ComputeRiskSummary(effect, opts...)

	if jsonOutput {
		data, _ := json.MarshalIndent(rs, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		riskColor := ColorGreen
		switch rs.OverallRisk {
		case "CRITICAL":
			riskColor = ColorRed
		case "HIGH":
			riskColor = ColorYellow
		case "MEDIUM":
			riskColor = ColorPurple
		}

		_, _ = fmt.Fprintf(stdout, "Risk Summary for %s%s%s\n", ColorBold, rs.EffectTypeID, ColorReset)
		_, _ = fmt.Fprintln(stdout, "───────────────────────────")
		_, _ = fmt.Fprintf(stdout, "  Effect Class:      %s\n", rs.EffectClass)
		_, _ = fmt.Fprintf(stdout, "  Overall Risk:      %s%s%s\n", riskColor, rs.OverallRisk, ColorReset)
		_, _ = fmt.Fprintf(stdout, "  Approval Required: %v\n", rs.ApprovalRequired)

		if rs.BudgetImpact || rs.EgressRisk || rs.IdentityRisk || !rs.ContextMatch || rs.Frozen {
			_, _ = fmt.Fprintln(stdout, "  Flags:")
			if rs.BudgetImpact {
				_, _ = fmt.Fprintln(stdout, "    ⚠️  Budget Impact")
			}
			if rs.EgressRisk {
				_, _ = fmt.Fprintln(stdout, "    ⚠️  Egress Risk")
			}
			if rs.IdentityRisk {
				_, _ = fmt.Fprintln(stdout, "    ⚠️  Identity Risk")
			}
			if !rs.ContextMatch {
				_, _ = fmt.Fprintln(stdout, "    🔴 Context Mismatch")
			}
			if rs.Frozen {
				_, _ = fmt.Fprintln(stdout, "    🔴 System Frozen")
			}
		}
	}

	return 0
}

func init() {
	Register(Subcommand{Name: "risk-summary", Aliases: []string{}, Usage: "Risk assessment (--effect, --list)", RunFn: runRiskCmd})
}
