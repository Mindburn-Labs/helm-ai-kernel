package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func runAuditCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel audit <scope> [flags]")
		return 2
	}
	switch args[0] {
	case "scope":
		return runAuditScopeCmd(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown audit command: %s\n", args[0])
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel audit <scope> [flags]")
		return 2
	}
}

func runAuditScopeCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("audit scope", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var input, out string
	var jsonOut, evidencePack bool
	cmd.StringVar(&input, "input", "", "Comma-separated workstation receipt files or directories")
	cmd.StringVar(&out, "out", "", "Write scope-audit.json, scope-audit.md, and evidence-refs.json to this directory")
	cmd.BoolVar(&jsonOut, "json", false, "Print canonical scope audit JSON")
	cmd.BoolVar(&evidencePack, "evidence-pack", false, "Write scope-audit-evidencepack under --out")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	paths := splitInputs(input)
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --input is required")
		return 2
	}
	if evidencePack && strings.TrimSpace(out) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --evidence-pack requires --out")
		return 2
	}
	report, err := workstation.BuildScopeAudit(paths...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: scope audit failed: %v\n", err)
		return 1
	}
	var export workstation.ScopeAuditExport
	if out != "" {
		export, err = workstation.WriteScopeAuditArtifacts(report, out, evidencePack)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: write scope audit artifacts: %v\n", err)
			return 1
		}
	}
	if jsonOut {
		data, err := canonicalize.JCS(report)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: canonicalize scope audit: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	printScopeAuditSummary(stdout, report, export)
	return 0
}

func printScopeAuditSummary(stdout io.Writer, report workstation.ScopeAuditReport, export workstation.ScopeAuditExport) {
	_, _ = fmt.Fprintf(stdout, "%sAgent Scope Audit%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(stdout, "  inputs:        %d\n", report.Summary.InputFiles)
	_, _ = fmt.Fprintf(stdout, "  actions:       %d\n", report.Summary.TotalActions)
	_, _ = fmt.Fprintf(stdout, "  allowed:       %d\n", report.Summary.AllowedActions)
	_, _ = fmt.Fprintf(stdout, "  denied:        %d\n", report.Summary.DeniedActions)
	_, _ = fmt.Fprintf(stdout, "  tainted:       %d\n", report.Summary.TaintedActions)
	_, _ = fmt.Fprintf(stdout, "  unknown mcp:   %d\n", report.Summary.UnknownMCPActions)
	_, _ = fmt.Fprintf(stdout, "  out of scope:  %d\n", report.Summary.OutOfScopeAttempts)
	_, _ = fmt.Fprintf(stdout, "  missing ctrl:  %d\n", report.Summary.MissingControls)
	for _, boundary := range report.Boundaries {
		if boundary.Total == 0 {
			continue
		}
		_, _ = fmt.Fprintf(stdout, "  %-11s total=%d allow=%d deny=%d tainted=%d unknown=%d\n", boundary.Boundary+":", boundary.Total, boundary.Allowed, boundary.Denied, boundary.Tainted, boundary.Unknown)
	}
	if export.ReportPath != "" {
		_, _ = fmt.Fprintf(stdout, "  report:        %s\n", export.ReportPath)
		_, _ = fmt.Fprintf(stdout, "  markdown:      %s\n", export.MarkdownPath)
		_, _ = fmt.Fprintf(stdout, "  evidence refs: %s\n", export.EvidenceRefsPath)
	}
	if export.EvidencePackDir != "" {
		_, _ = fmt.Fprintf(stdout, "  evidencepack:  %s\n", export.EvidencePackDir)
		_, _ = fmt.Fprintf(stdout, "  pack root:     %s\n", export.EvidencePackRootHash)
	}
}

func init() {
	Register(Subcommand{
		Name:  "audit",
		Usage: "Generate audit reports from HELM evidence and receipts",
		RunFn: runAuditCmd,
	})
}
