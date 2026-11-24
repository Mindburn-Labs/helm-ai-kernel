package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
)

const runMaintenanceUsage = "Usage: helm-ai-kernel run maintenance [--once] [--max N]"

func printRunMaintenanceHelp(stdout io.Writer) {
	fmt.Fprintln(stdout, runMaintenanceUsage)
}

func runMaintenanceCommandGroup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, runMaintenanceUsage)
		return 2
	}
	if args[0] != "maintenance" {
		fmt.Fprintf(stderr, "Unknown run subcommand: %s\n", args[0])
		return 2
	}
	if helpArgs, ok := normalizeHelpRequest(args[1:]); ok {
		_ = runMaintenanceCmd(helpArgs, stdout, stdout)
		return 0
	}
	return runMaintenanceCmd(args[1:], stdout, stderr)
}

func runMaintenanceCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("run maintenance", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	once := cmd.Bool("once", true, "Read the incident registry once (default)")
	maxItems := cmd.Int("max", 5, "Maximum pending incidents to display")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() != 0 || !*once || *maxItems < 1 {
		fmt.Fprintln(stderr, runMaintenanceUsage)
		return 2
	}

	incidents, err := loadAllIncidents()
	if err != nil {
		fmt.Fprintf(stderr, "Read incident registry: %v\n", err)
		return 1
	}

	var pending []Incident
	for _, incident := range incidents {
		if incident.Status == "open" || incident.Status == "acked" {
			pending = append(pending, incident)
		}
	}
	if len(pending) == 0 {
		fmt.Fprintln(stdout, "No open or acknowledged incidents in the local registry.")
		return 0
	}

	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.SliceStable(pending, func(i, j int) bool {
		left, leftKnown := severityOrder[pending[i].Severity]
		right, rightKnown := severityOrder[pending[j].Severity]
		if leftKnown != rightKnown {
			return leftKnown
		}
		if left != right {
			return left < right
		}
		return pending[i].Recurrence > pending[j].Recurrence
	})

	fmt.Fprintf(stdout, "Pending incidents: %d\n", len(pending))
	for _, incident := range pending[:min(len(pending), *maxItems)] {
		fmt.Fprintf(stdout, "  %s  %s  %s\n", incident.ID, incident.Severity, incident.Title)
	}
	fmt.Fprintln(stderr, "Pending incidents require review. Inspect one with helm-ai-kernel incident show <id>.")
	return 1
}

func init() {
	Register(Subcommand{
		Name:   "run",
		Usage:  "List pending maintenance incidents",
		RunFn:  runMaintenanceCommandGroup,
		HelpFn: printRunMaintenanceHelp,
	})
}
