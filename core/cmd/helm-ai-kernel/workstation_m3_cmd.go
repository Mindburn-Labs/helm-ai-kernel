package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func runWorkstationDecisionCmd(args []string, stdout, stderr io.Writer) int {
	receipt, out, receiptDir, jsonOut, err := buildDecisionFromFlags("workstation decide", args, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if _, err := writeDecisionReceipt(out, receiptDir, receipt); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if jsonOut {
		data, _ := canonicalize.JCS(receipt)
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	printDecisionSummary(stdout, receipt)
	return 0
}

func runWorkstationEnforceCmd(args []string, stdout, stderr io.Writer) int {
	receipt, out, jsonOut, remaining, err := buildEnforceFromFlags(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if _, err := writeDecisionReceipt(out, "", receipt); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if jsonOut {
		data, _ := canonicalize.JCS(receipt)
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		printDecisionSummary(stdout, receipt)
	}
	if receipt.Verdict == contracts.WorkstationVerdictDeny {
		return 126
	}
	if len(remaining) == 0 {
		return 0
	}
	if receipt.Verdict != contracts.WorkstationVerdictAllow || receipt.Request.EffectMode != contracts.WorkstationEffectModeOperate {
		_, _ = fmt.Fprintf(stderr, "Error: refusing to execute command without operate-mode ALLOW receipt (verdict=%s mode=%s)\n", receipt.Verdict, receipt.Request.EffectMode)
		return 126
	}
	cmd := exec.CommandContext(context.Background(), remaining[0], remaining[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: command failed: %v\n", err)
		return 1
	}
	return 0
}

func runWorkstationVerifyDecisionCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation verify-decision", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var receiptPath string
	var jsonOut bool
	cmd.StringVar(&receiptPath, "receipt", "", "Workstation policy decision receipt JSON")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if receiptPath == "" && cmd.NArg() == 1 {
		receiptPath = cmd.Arg(0)
	}
	if receiptPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --receipt is required")
		return 2
	}
	receipt, err := workstation.LoadDecisionReceipt(receiptPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot load decision receipt: %v\n", err)
		return 1
	}
	ok, err := workstation.VerifyDecisionReceiptSignature(receipt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: decision receipt signature check failed: %v\n", err)
		return 1
	}
	result := map[string]any{
		"receipt":         receiptPath,
		"decision_id":     receipt.DecisionID,
		"verdict":         receipt.Verdict,
		"reason_code":     receipt.ReasonCode,
		"effect_type":     receipt.Request.EffectType,
		"target":          receipt.Request.Target,
		"receipt_hash":    receipt.ReceiptHash,
		"signature_valid": ok,
	}
	if jsonOut {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		_, _ = fmt.Fprintf(stdout, "%sWorkstation Policy Decision Verification%s\n", ColorBold, ColorReset)
		_, _ = fmt.Fprintf(stdout, "  receipt:   %s\n", receiptPath)
		_, _ = fmt.Fprintf(stdout, "  decision:  %s\n", receipt.DecisionID)
		_, _ = fmt.Fprintf(stdout, "  verdict:   %s\n", receipt.Verdict)
		_, _ = fmt.Fprintf(stdout, "  reason:    %s\n", receipt.ReasonCode)
		_, _ = fmt.Fprintf(stdout, "  effect:    %s\n", receipt.Request.EffectType)
		_, _ = fmt.Fprintf(stdout, "  target:    %s\n", receipt.Request.Target)
		_, _ = fmt.Fprintf(stdout, "  hash:      %s\n", receipt.ReceiptHash)
		_, _ = fmt.Fprintf(stdout, "  signature: %v\n", ok)
	}
	if !ok {
		return 1
	}
	return 0
}

func runWorkstationOperatorCmd(section string, args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation "+section, flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var input string
	var jsonOut bool
	cmd.StringVar(&input, "input", "", "Comma-separated receipt files or directories")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	paths := splitInputs(input)
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --input is required")
		return 2
	}
	view, err := workstation.BuildOperatorView(paths...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if jsonOut {
		data, _ := json.MarshalIndent(sectionValue(section, view), "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	printOperatorView(stdout, section, view)
	return 0
}

func runWorkstationEvidenceCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation evidence", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var receiptPath, out string
	var jsonOut bool
	cmd.StringVar(&receiptPath, "receipt", "", "Workstation import result JSON")
	cmd.StringVar(&out, "out", "", "EvidencePack output directory")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if receiptPath == "" || out == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --receipt and --out are required")
		return 2
	}
	result, err := workstation.LoadResult(receiptPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot load receipt: %v\n", err)
		return 1
	}
	export, err := workstation.ExportEvidencePack(result, out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: evidence export failed: %v\n", err)
		return 1
	}
	if jsonOut {
		data, _ := json.MarshalIndent(export, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "%sWorkstation EvidencePack%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(stdout, "  pack:    %s\n", export.PackID)
	_, _ = fmt.Fprintf(stdout, "  root:    %s\n", export.RootHash)
	_, _ = fmt.Fprintf(stdout, "  receipt: %s\n", export.ReceiptID)
	_, _ = fmt.Fprintf(stdout, "  out:     %s\n", export.OutDir)
	return 0
}

func runWorkstationCertifyCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation certify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var fixtures, adapterID, mode string
	var jsonOut bool
	cmd.StringVar(&fixtures, "fixtures", defaultWorkstationFixtureRoot(), "Workstation fixture root")
	cmd.StringVar(&adapterID, "adapter", "workstation-manifest-adapter", "Adapter identifier")
	cmd.StringVar(&mode, "mode", workstation.CertificationHighRiskEffectCapable, "observe-only, enforceable, or high-risk-effect-capable")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	result := workstation.CertifyAdapterFixtures(adapterID, fixtures, mode)
	if jsonOut {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		_, _ = fmt.Fprintf(stdout, "%sWorkstation Adapter Certification%s\n", ColorBold, ColorReset)
		_, _ = fmt.Fprintf(stdout, "  adapter:   %s\n", result.AdapterID)
		_, _ = fmt.Fprintf(stdout, "  requested: %s\n", result.Requested)
		_, _ = fmt.Fprintf(stdout, "  certified: %s\n", result.CertifiedAs)
		_, _ = fmt.Fprintf(stdout, "  passed:    %v\n", result.Passed)
		for _, check := range result.Checks {
			_, _ = fmt.Fprintf(stdout, "  %s: %s\n", check.ID, check.Status)
		}
	}
	if !result.Passed {
		return 1
	}
	return 0
}

func buildDecisionFromFlags(name string, args []string, stderr io.Writer) (*contracts.WorkstationPolicyDecisionReceipt, string, string, bool, error) {
	cmd := flag.NewFlagSet(name, flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var class, effectType, effectMode, action, toolID, target, policyPath, runID, workspaceID, actorID, out, receiptDir, seedHex, seedFile string
	var jsonOut bool
	cmd.StringVar(&class, "class", "shell", "Effect class: shell, network, mcp, memory, loop, file")
	cmd.StringVar(&effectType, "effect-type", "", "Explicit workstation effect type")
	cmd.StringVar(&effectMode, "mode", "", "Explicit effect mode: observe, draft, operate")
	cmd.StringVar(&action, "action", "", "Action name")
	cmd.StringVar(&toolID, "tool-id", "", "Tool identifier")
	cmd.StringVar(&target, "target", "", "Effect target")
	cmd.StringVar(&policyPath, "policy-profile", "", "Policy profile JSON path")
	cmd.StringVar(&runID, "run-id", "workstation-decision", "Run id")
	cmd.StringVar(&workspaceID, "workspace-id", "local-workstation", "Workspace id")
	cmd.StringVar(&actorID, "actor", "agent.local", "Actor id")
	cmd.StringVar(&out, "out", "", "Write decision receipt JSON")
	cmd.StringVar(&receiptDir, "receipt-dir", "", "Write decision receipt JSON as <decision_id>.json in this directory")
	cmd.StringVar(&seedHex, "signing-seed-hex", "", "Deprecated unsafe argv seed input; use --signing-seed-file")
	cmd.StringVar(&seedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		return nil, "", "", false, err
	}
	defaultType, defaultMode, defaultAction, defaultTool := workstation.EffectDefaults(class)
	if effectType == "" {
		effectType = defaultType
	}
	if effectMode == "" {
		effectMode = defaultMode
	}
	if action == "" {
		action = defaultAction
	}
	if toolID == "" {
		toolID = defaultTool
	}
	profile, err := workstation.LoadPolicyProfileFile(policyPath)
	if err != nil {
		return nil, "", "", false, err
	}
	seed, err := loadSigningSeed(seedHex, seedFile)
	if err != nil {
		return nil, "", "", false, err
	}
	req := contracts.WorkstationDecisionRequest{
		RunID:        runID,
		ActorID:      actorID,
		WorkspaceID:  workspaceID,
		AgentSurface: "workstation-cli",
		ToolID:       toolID,
		Action:       action,
		EffectType:   effectType,
		EffectMode:   effectMode,
		Target:       target,
		OccurredAt:   time.Unix(0, 0).UTC(),
	}
	receipt, err := workstation.Decide(profile, req, workstation.DecisionOptions{SigningSeed: seed})
	if err != nil {
		return nil, "", "", false, err
	}
	return receipt, out, receiptDir, jsonOut, nil
}

func buildEnforceFromFlags(args []string, stderr io.Writer) (*contracts.WorkstationPolicyDecisionReceipt, string, bool, []string, error) {
	cmd := flag.NewFlagSet("workstation enforce", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var class, target, out, receiptDir, policyPath string
	var jsonOut bool
	cmd.StringVar(&class, "class", "shell", "Effect class: shell, network, mcp, memory, loop, file")
	cmd.StringVar(&target, "target", "", "Effect target")
	cmd.StringVar(&policyPath, "policy-profile", "", "Policy profile JSON path")
	cmd.StringVar(&out, "out", "", "Write decision receipt JSON")
	cmd.StringVar(&receiptDir, "receipt-dir", "", "Write decision receipt JSON as <decision_id>.json in this directory")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		return nil, "", false, nil, err
	}
	remaining := cmd.Args()
	decisionArgs := []string{"--class", class, "--target", firstNonEmptyString(target, strings.Join(remaining, " ")), "--policy-profile", policyPath, "--out", out, "--receipt-dir", receiptDir}
	if jsonOut {
		decisionArgs = append(decisionArgs, "--json")
	}
	receipt, receiptOut, decisionReceiptDir, receiptJSON, err := buildDecisionFromFlags("workstation enforce", decisionArgs, io.Discard)
	if receiptOut == "" && decisionReceiptDir != "" && receipt != nil {
		receiptOut = filepath.Join(decisionReceiptDir, receipt.DecisionID+".json")
	}
	return receipt, receiptOut, receiptJSON, remaining, err
}

func writeDecisionReceipt(path, receiptDir string, receipt *contracts.WorkstationPolicyDecisionReceipt) (string, error) {
	if path == "" && receiptDir != "" {
		if err := os.MkdirAll(receiptDir, 0o755); err != nil {
			return "", err
		}
		path = filepath.Join(receiptDir, receipt.DecisionID+".json")
	}
	if path == "" {
		return "", nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	data, err := canonicalize.JCS(receipt)
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, append(data, '\n'), 0o600)
}

func printDecisionSummary(stdout io.Writer, receipt *contracts.WorkstationPolicyDecisionReceipt) {
	_, _ = fmt.Fprintf(stdout, "%sWorkstation Policy Decision%s\n", ColorBold, ColorReset)
	_, _ = fmt.Fprintf(stdout, "  decision: %s\n", receipt.DecisionID)
	_, _ = fmt.Fprintf(stdout, "  verdict:  %s\n", receipt.Verdict)
	_, _ = fmt.Fprintf(stdout, "  reason:   %s\n", receipt.ReasonCode)
	_, _ = fmt.Fprintf(stdout, "  effect:   %s\n", receipt.Request.EffectType)
	_, _ = fmt.Fprintf(stdout, "  target:   %s\n", receipt.Request.Target)
	_, _ = fmt.Fprintf(stdout, "  hash:     %s\n", receipt.ReceiptHash)
}

func printOperatorView(stdout io.Writer, section string, view workstation.OperatorView) {
	_, _ = fmt.Fprintf(stdout, "%sWorkstation Operator View%s\n", ColorBold, ColorReset)
	if section == "all" || section == "runs" {
		_, _ = fmt.Fprintf(stdout, "Runs: %d\n", len(view.Runs))
		for _, run := range view.Runs {
			_, _ = fmt.Fprintf(stdout, "  %s %s denied=%d memory=%d loops=%d\n", firstNonEmptyString(run.RunID, run.DecisionID), run.PolicyProfile, run.DeniedEffects, run.MemoryEffects, run.RecurringLoops)
		}
	}
	if section == "all" || section == "denied" {
		_, _ = fmt.Fprintf(stdout, "Denied timeline: %d\n", len(view.DeniedTimeline))
		for _, item := range view.DeniedTimeline {
			_, _ = fmt.Fprintf(stdout, "  %s %s %s %s\n", item.RunID, item.Effect, item.Reason, item.Target)
		}
	}
	if section == "all" || section == "memory" {
		_, _ = fmt.Fprintf(stdout, "Memory review queue: %d\n", len(view.MemoryReviewQueue))
		for _, item := range view.MemoryReviewQueue {
			_, _ = fmt.Fprintf(stdout, "  %s %s ttl=%d sensitivity=%s verdict=%s\n", item.RunID, item.MemoryClass, item.TTLDays, item.Sensitivity, item.Verdict)
		}
	}
	if section == "all" || section == "loops" {
		_, _ = fmt.Fprintf(stdout, "Recurring loops: %d\n", len(view.RecurringLoops))
		for _, item := range view.RecurringLoops {
			_, _ = fmt.Fprintf(stdout, "  %s %s max=%s verdict=%s\n", item.RunID, item.Schedule, item.MaxRuntime, item.Verdict)
		}
	}
}

func sectionValue(section string, view workstation.OperatorView) any {
	switch section {
	case "runs":
		return view.Runs
	case "denied":
		return view.DeniedTimeline
	case "memory":
		return view.MemoryReviewQueue
	case "loops":
		return view.RecurringLoops
	default:
		return view
	}
}

func splitInputs(input string) []string {
	var out []string
	for _, item := range strings.Split(input, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func defaultWorkstationFixtureRoot() string {
	return filepath.Clean(filepath.Join("..", "fixtures", "workstation"))
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
