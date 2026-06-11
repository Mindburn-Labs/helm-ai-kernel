package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func runWorkstationCaptureCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel workstation capture <start|finish|wrap> [flags]")
		return 2
	}
	switch args[0] {
	case "start":
		return runWorkstationCaptureStartCmd(args[1:], stdout, stderr)
	case "finish":
		return runWorkstationCaptureFinishCmd(args[1:], stdout, stderr)
	case "wrap":
		return runWorkstationEnforceCmd(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown workstation capture command: %s\n", args[0])
		return 2
	}
}

func runWorkstationCaptureStartCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation capture start", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var surface, workspacePath, goal, actorID, workspaceID, repository, policyProfile, startedAtRaw, out string
	var jsonOut bool
	cmd.StringVar(&surface, "surface", "codex", "Agent surface: codex or claude-code")
	cmd.StringVar(&workspacePath, "workspace", ".", "Workspace path")
	cmd.StringVar(&goal, "goal", "", "Run goal")
	cmd.StringVar(&actorID, "actor", "agent.local", "Actor id")
	cmd.StringVar(&workspaceID, "workspace-id", "local-workstation", "Workspace id")
	cmd.StringVar(&repository, "repository", "", "Repository name")
	cmd.StringVar(&policyProfile, "policy-profile", "", "Policy profile id")
	cmd.StringVar(&startedAtRaw, "started-at", "", "Optional RFC3339 start timestamp")
	cmd.StringVar(&out, "out", "", "Artifact output directory")
	cmd.BoolVar(&jsonOut, "json", false, "Print manifest JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if out == "" || goal == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --out and --goal are required")
		return 2
	}
	startedAt, err := parseOptionalTime(startedAtRaw)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	manifest, err := workstation.StartCapture(out, workstation.CaptureStartOptions{
		Surface:       surface,
		WorkspacePath: workspacePath,
		Goal:          goal,
		ActorID:       actorID,
		WorkspaceID:   workspaceID,
		Repository:    repository,
		PolicyProfile: policyProfile,
		StartedAt:     startedAt,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: capture start failed: %v\n", err)
		return 1
	}
	if jsonOut {
		data, _ := json.MarshalIndent(manifest, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "%sWorkstation Capture Started%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(stdout, "  run:      %s\n", manifest.RunID)
	_, _ = fmt.Fprintf(stdout, "  surface:  %s\n", manifest.AgentSurface)
	_, _ = fmt.Fprintf(stdout, "  artifacts:%s\n", out)
	return 0
}

func runWorkstationCaptureFinishCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation capture finish", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var artifacts, validationCommand, toolEvents, out, seedHex, seedFile, completedAtRaw string
	var jsonOut bool
	cmd.StringVar(&artifacts, "artifacts", "", "Artifact directory from capture start")
	cmd.StringVar(&validationCommand, "validation-command", "", "Validation command to run in workspace")
	cmd.StringVar(&toolEvents, "tool-events", "", "Optional tool-events.ndjson source path")
	cmd.StringVar(&out, "out", "", "Write canonical import result JSON to this path")
	cmd.StringVar(&seedHex, "signing-seed-hex", "", "Deprecated unsafe argv seed input; use --signing-seed-file")
	cmd.StringVar(&seedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	cmd.StringVar(&completedAtRaw, "completed-at", "", "Optional RFC3339 completed timestamp")
	cmd.BoolVar(&jsonOut, "json", false, "Print canonical import result JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if artifacts == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --artifacts is required")
		return 2
	}
	seed, err := loadSigningSeed(seedHex, seedFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	completedAt, err := parseOptionalTime(completedAtRaw)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	result, err := workstation.FinishCapture(artifacts, workstation.CaptureFinishOptions{
		ValidationCommand: validationCommand,
		ToolEventsPath:    toolEvents,
		SigningSeed:       seed,
		CompletedAt:       completedAt,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: capture finish failed: %v\n", err)
		return 1
	}
	if out != "" {
		data, err := canonicalize.JCS(result)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: canonicalize result: %v\n", err)
			return 1
		}
		if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: write %s: %v\n", out, err)
			return 1
		}
	}
	if jsonOut {
		data, _ := canonicalize.JCS(result)
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	printWorkstationSummary(stdout, workstation.Summary(result.Receipt))
	if out != "" {
		_, _ = fmt.Fprintf(stdout, "Output: %s\n", out)
	}
	return 0
}

func parseOptionalTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	return parsed.UTC(), nil
}
