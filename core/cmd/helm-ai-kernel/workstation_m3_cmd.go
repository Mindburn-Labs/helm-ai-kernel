// quantum_posture: this workstation command surface references classical
// Ed25519 receipt signing only; it adds no post-quantum control.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
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
	flags, err := parseEnforceFlags(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	effects, refusal := enforceEffects(flags)
	receipts, err := decideEnforceEffects(flags, effects)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	// The receipt that settles the outcome: the first denial, else the first
	// decision. With several effects the rest go to --receipt-dir.
	var decisive *contracts.WorkstationPolicyDecisionReceipt
	denied := false
	for _, receipt := range receipts {
		if receipt.Verdict == contracts.WorkstationVerdictDeny && !denied {
			decisive, denied = receipt, true
		}
	}
	if decisive == nil && len(receipts) > 0 {
		decisive = receipts[0]
	}
	if denied || refusal == "" {
		for _, receipt := range receipts {
			out := ""
			if receipt == decisive {
				out = flags.out
			}
			if _, err := writeDecisionReceipt(out, flags.receiptDir, receipt); err != nil {
				// Without its receipt the decision cannot be shown, so the
				// command does not run, and the exit code says so as a
				// denial does.
				_, _ = fmt.Fprintf(stderr, "Error: refusing to execute command: write decision receipt: %v\n", err)
				return cliui.ExitDenied
			}
		}
		if decisive != nil {
			if flags.jsonOut {
				data, _ := canonicalize.JCS(decisive)
				_, _ = fmt.Fprintln(stdout, string(data))
			} else {
				printDecisionSummary(stdout, decisive)
			}
		}
	}
	if denied {
		return cliui.ExitDenied
	}
	if refusal != "" {
		// Nothing was denied, but nothing decided covers the command either:
		// an ALLOW for some other effect must not be left on disk for it.
		_, _ = fmt.Fprintf(stderr, "Error: refusing to execute command: %s\n", refusal)
		return cliui.ExitDenied
	}
	remaining := flags.argv
	if len(remaining) == 0 {
		return 0
	}
	for _, receipt := range receipts {
		if receipt.Verdict != contracts.WorkstationVerdictAllow || receipt.Request.EffectMode != contracts.WorkstationEffectModeOperate {
			_, _ = fmt.Fprintf(stderr, "Error: refusing to execute command without operate-mode ALLOW receipt (verdict=%s mode=%s)\n", receipt.Verdict, receipt.Request.EffectMode)
			return cliui.ExitDenied
		}
	}
	cmd := exec.CommandContext(context.Background(), remaining[0], remaining[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	return childExitCode(cmd.Run(), stderr)
}

// childExitCode is the wrapper's exit code for a command it ran: the
// command's own code, 128 plus the signal number when a signal ended it, and
// 127, as a shell gives, when it could not be started.
func childExitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		_, _ = fmt.Fprintf(stderr, "Error: command could not be started: %v\n", err)
		return 127
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exitErr.ExitCode()
}

func runWorkstationVerifyDecisionCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation verify-decision", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var receiptPath, dataDir, trustedPublicKeyFile string
	var jsonOut bool
	cmd.StringVar(&receiptPath, "receipt", "", "Workstation policy decision receipt JSON")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")
	cmd.StringVar(&trustedPublicKeyFile, "trusted-public-key-file", "", "Path to caller-owned Ed25519 public key file")
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
	integrityValid, err := workstation.VerifyDecisionReceiptSignature(receipt)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: decision receipt integrity check failed: %v\n", err)
		return 1
	}
	trustedKey, trustAnchor, trustAnchorAvailable, err := resolveTrustedWorkstationPublicKey(dataDir, trustedPublicKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: load trusted public key: %v\n", err)
		return 1
	}
	signerTrusted := false
	if trustAnchorAvailable {
		signerTrusted, err = workstation.VerifyDecisionReceiptWithTrustedKey(receipt, trustedKey)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: trusted decision receipt verification failed: %v\n", err)
			return 1
		}
	}
	result := map[string]any{
		"receipt":         receiptPath,
		"decision_id":     receipt.DecisionID,
		"verdict":         receipt.Verdict,
		"reason_code":     receipt.ReasonCode,
		"effect_type":     receipt.Request.EffectType,
		"target":          receipt.Request.Target,
		"receipt_hash":    receipt.ReceiptHash,
		"integrity_valid": integrityValid,
		"signer_trusted":  signerTrusted,
		"trust_anchor":    trustAnchor,
	}
	if jsonOut {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		// Lead with the admissibility verdict, not the receipt's own claim. A
		// tampered receipt still carries a verdict field, and printing it at the
		// same weight as everything else made the forgery the loudest thing on
		// screen while the one line that mattered — integrity:false — sat two
		// rows below in plain text. The receipt's verdict is only meaningful
		// once the receipt verifies against a trusted signer; until then it is
		// an unverified claim and is labelled as one.
		admissible := integrityValid && signerTrusted
		switch {
		case !integrityValid:
			_, _ = fmt.Fprintf(stdout, "%sTAMPERED — this receipt does not match its own signature%s\n", ColorRed, ColorReset)
			_, _ = fmt.Fprintf(stdout, "  Its contents were altered after signing. Do not act on anything below.\n")
		case !signerTrusted:
			_, _ = fmt.Fprintf(stdout, "%sUNVERIFIED — signature is intact but the signer is not a trusted anchor%s\n", ColorRed, ColorReset)
			if !trustAnchorAvailable {
				_, _ = fmt.Fprintf(stdout, "  No trust anchor was available. Pass --trusted-public-key-file to name the key you trust.\n")
			} else {
				_, _ = fmt.Fprintf(stdout, "  The receipt was signed by a key you have not anchored. A key that arrives with the receipt is not a trust root.\n")
			}
		default:
			_, _ = fmt.Fprintf(stdout, "%sADMISSIBLE — signature verifies under a trusted anchor%s\n", ColorGreen, ColorReset)
		}
		_, _ = fmt.Fprintf(stdout, "%sWorkstation Policy Decision Verification%s\n", ColorBold, ColorReset)
		_, _ = fmt.Fprintf(stdout, "  receipt:   %s\n", receiptPath)
		_, _ = fmt.Fprintf(stdout, "  decision:  %s\n", receipt.DecisionID)
		if admissible {
			_, _ = fmt.Fprintf(stdout, "  verdict:   %s\n", receipt.Verdict)
		} else {
			// Never present the verdict of an inadmissible receipt as a bare
			// fact; the reader must not be able to quote it as the finding.
			_, _ = fmt.Fprintf(stdout, "  verdict:   %s (unverified — claimed by the receipt, not established)\n", receipt.Verdict)
		}
		_, _ = fmt.Fprintf(stdout, "  reason:    %s\n", receipt.ReasonCode)
		_, _ = fmt.Fprintf(stdout, "  effect:    %s\n", receipt.Request.EffectType)
		_, _ = fmt.Fprintf(stdout, "  target:    %s\n", receipt.Request.Target)
		_, _ = fmt.Fprintf(stdout, "  hash:      %s\n", receipt.ReceiptHash)
		_, _ = fmt.Fprintf(stdout, "  integrity: %v\n", integrityValid)
		_, _ = fmt.Fprintf(stdout, "  trusted:   %v\n", signerTrusted)
		_, _ = fmt.Fprintf(stdout, "  anchor:    %s\n", trustAnchor)
	}
	if !integrityValid || !signerTrusted {
		return 1
	}
	return 0
}

func runWorkstationOperatorCmd(section string, args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("workstation "+section, flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var input, dataDir, trustedPublicKeyFile string
	var jsonOut bool
	cmd.StringVar(&input, "input", "", "Comma-separated receipt files or directories")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON")
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")
	cmd.StringVar(&trustedPublicKeyFile, "trusted-public-key-file", "", "Path to caller-owned Ed25519 public key file")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	paths := splitInputs(input)
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --input is required")
		return 2
	}
	trust, err := receiptTrustAnchor(dataDir, trustedPublicKeyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: load trusted public key: %v\n", err)
		return 1
	}
	view, err := workstation.BuildOperatorView(trust, paths...)
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

func buildDecisionFromFlags(name string, args []string, stderr io.Writer) (*contracts.WorkstationPolicyDecisionReceipt, string, string, bool, error) {
	cmd := flag.NewFlagSet(name, flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var class, effectType, effectMode, action, toolID, target, policyPath, runID, workspaceID, actorID, out, receiptDir, seedHex, seedFile, dataDir string
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
	cmd.StringVar(&dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")
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
	seed, err := resolveWorkstationSigningSeed(dataDir, seedHex, seedFile)
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

type enforceFlags struct {
	class, target, out, receiptDir         string
	policyPath, seedHex, seedFile, dataDir string
	jsonOut                                bool
	// argv is the command to run after the decision; empty for a decision
	// about an effect the caller performs itself.
	argv []string
}

func parseEnforceFlags(args []string, stderr io.Writer) (enforceFlags, error) {
	cmd := flag.NewFlagSet("workstation enforce", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var flags enforceFlags
	cmd.StringVar(&flags.class, "class", "shell", "Effect class: shell, network, mcp, memory, loop, file")
	cmd.StringVar(&flags.target, "target", "", "Effect target")
	cmd.StringVar(&flags.policyPath, "policy-profile", "", "Policy profile JSON path")
	cmd.StringVar(&flags.out, "out", "", "Write decision receipt JSON")
	cmd.StringVar(&flags.receiptDir, "receipt-dir", "", "Write decision receipt JSON as <decision_id>.json in this directory")
	cmd.StringVar(&flags.seedHex, "signing-seed-hex", "", "Deprecated unsafe argv seed input; use --signing-seed-file")
	cmd.StringVar(&flags.seedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	cmd.StringVar(&flags.dataDir, "data-dir", defaultSetupDataDir(), "Directory for HELM local signing state")
	cmd.BoolVar(&flags.jsonOut, "json", false, "Print JSON")
	if err := cmd.Parse(args); err != nil {
		return enforceFlags{}, err
	}
	flags.argv = cmd.Args()
	return flags, nil
}

// enforceEffects lists every effect that must be allowed before the wrapped
// command runs. With no command it is the declared effect alone. With a
// command, the effects are read from the argv that will be executed: the
// declared class and target can add a requirement or name what the command
// is expected to do, but they never stand in for what the argv shows. refusal
// is set when the declaration cannot be matched to the command at all.
func enforceEffects(flags enforceFlags) (effects []hookClassification, refusal string) {
	declared := hookClassification{ShouldDecide: true, Class: flags.class, Target: flags.target}
	if len(flags.argv) == 0 {
		return []hookClassification{declared}, ""
	}
	dataDir := flags.dataDir
	if abs, err := filepath.Abs(dataDir); err == nil && strings.TrimSpace(dataDir) != "" {
		dataDir = abs
	}
	cwd, _ := os.Getwd()
	command := strings.Join(flags.argv, " ")
	// The command runs with this process's environment, so the decision is
	// made on it too: a proxy set there is a destination, and a variable
	// that changes how a client connects or what a shell runs first leaves
	// the destinations undetermined.
	scan := shellscan.ClassifyArgvAt(flags.argv, cwd,
		shellscan.WithPathGuard(workstationPathGuard(dataDir, flags.seedFile, flags.policyPath)),
		shellscan.WithEnvironment(enforceEnvironment(os.Environ())))
	derived := shellClassifications("workstation.enforce", command, scan)
	if scan.ProtectedPath != "" {
		return derived, ""
	}
	effectType, _, _, _ := workstation.EffectDefaults(flags.class)
	switch effectType {
	case contracts.EffectTypeWorkstationNetworkEgress:
		// The destinations come from the argv; --target only says which one
		// the caller expects to find there.
		reached := map[string]bool{}
		for _, effect := range derived {
			if effect.Class == "network" {
				reached[effect.Target] = true
			}
		}
		switch {
		case len(reached) == 0:
			refusal = "cannot confirm where it connects: its arguments name no network destination"
		case strings.TrimSpace(flags.target) != "":
			expected, err := netdest.Parse(strings.TrimSpace(flags.target))
			if err != nil {
				refusal = "the declared --target is not a network destination"
			} else if !reached[expected.String()] {
				refusal = "cannot confirm that it connects to the declared target " + expected.String()
			}
		}
		return derived, refusal
	case contracts.EffectTypeWorkstationShellCommand:
		if strings.TrimSpace(flags.target) != "" && flags.target != command {
			refusal = "the declared --target does not match the command"
		}
		declared.Target = command
	default:
		declared.Target = firstNonEmptyString(flags.target, command)
	}
	effects = []hookClassification{declared}
	for _, effect := range derived {
		if effect.Class == "shell-operate" && effect.Target == declared.Target && effectType == contracts.EffectTypeWorkstationShellCommand && strings.Contains(flags.class, "operate") {
			continue // the declared decision already is this one
		}
		effects = append(effects, effect)
	}
	return effects, refusal
}

// enforceEnvironment is the part of the wrapper's environment the decision
// covers: every entry with a value, except HOME and XDG_CONFIG_HOME. Those
// locate the user's own configuration, which every command run here reads
// alike; what that configuration says is a limit of the decision (CTL-036),
// not a reason to refuse every command.
func enforceEnvironment(environ []string) []string {
	kept := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" || name == "HOME" || name == "XDG_CONFIG_HOME" {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// decideEnforceEffects signs one decision per effect. Every receipt for a
// wrapped command binds the argv, so a receipt cannot be shown for a command
// other than the one it was decided for.
func decideEnforceEffects(flags enforceFlags, effects []hookClassification) ([]*contracts.WorkstationPolicyDecisionReceipt, error) {
	if len(effects) == 0 {
		return nil, nil
	}
	profile, err := workstation.LoadPolicyProfileFile(flags.policyPath)
	if err != nil {
		return nil, err
	}
	seed, err := resolveWorkstationSigningSeed(flags.dataDir, flags.seedHex, flags.seedFile)
	if err != nil {
		return nil, err
	}
	var argvBinding map[string]string
	if len(flags.argv) > 0 {
		canonicalArgv, err := canonicalize.JCS(flags.argv)
		if err != nil {
			return nil, fmt.Errorf("canonicalize argv: %w", err)
		}
		argvBinding = map[string]string{
			"argv_binding": "jcs-sha256",
			"argv_sha256":  canonicalize.ComputeArtifactHash(canonicalArgv),
		}
	}
	receipts := make([]*contracts.WorkstationPolicyDecisionReceipt, 0, len(effects))
	for _, effect := range effects {
		effectType, effectMode, defaultAction, defaultTool := workstation.EffectDefaults(effect.Class)
		req := contracts.WorkstationDecisionRequest{
			RunID:        "workstation-decision",
			ActorID:      "agent.local",
			WorkspaceID:  "local-workstation",
			AgentSurface: "workstation-cli",
			ToolID:       firstNonEmptyString(effect.ToolID, defaultTool),
			Action:       firstNonEmptyString(effect.Action, defaultAction),
			EffectType:   effectType,
			EffectMode:   effectMode,
			Target:       effect.Target,
			OccurredAt:   time.Unix(0, 0).UTC(),
		}
		if len(effect.Metadata)+len(argvBinding) > 0 {
			req.Metadata = map[string]string{}
			for key, value := range effect.Metadata {
				req.Metadata[key] = value
			}
			for key, value := range argvBinding {
				req.Metadata[key] = value
			}
		}
		receipt, err := workstation.Decide(profile, req, workstation.DecisionOptions{SigningSeed: seed, TrustMaterial: effect.TrustMaterial})
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
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

// printReceiptVerification says, ahead of any figure taken from receipts,
// which signature checks those receipts went through.
func printReceiptVerification(stdout io.Writer, verification *workstation.ReceiptVerification) {
	if verification == nil {
		return
	}
	_, _ = fmt.Fprintf(stdout, "Signatures: %d input files match the key they name, %d do not and are not counted\n", verification.Counted(), len(verification.NotCounted))
	for _, input := range verification.NotCounted {
		_, _ = fmt.Fprintf(stdout, "  not counted: %s (%s)\n", input.SourcePath, input.SignatureStatus)
	}
	for _, input := range verification.DuplicateInputs {
		_, _ = fmt.Fprintf(stdout, "  duplicate, counted once: %s (copy of %s)\n", input.SourcePath, input.DuplicateOf)
	}
	if verification.TrustAnchor == "" {
		_, _ = fmt.Fprintln(stdout, "Signer trust: not checked (no trusted workstation public key; pass --trusted-public-key-file)")
		return
	}
	_, _ = fmt.Fprintf(stdout, "Signer trust: checked against %s: %d by that key, %d by another key, %d by the retired built-in key\n",
		verification.TrustAnchor,
		verification.Statuses[workstation.SignatureTrustedKey],
		verification.Statuses[workstation.SignatureUntrustedKey],
		verification.Statuses[workstation.SignatureRetiredKey])
}

func printOperatorView(stdout io.Writer, section string, view workstation.OperatorView) {
	_, _ = fmt.Fprintf(stdout, "%sWorkstation Operator View%s\n", ColorBold, ColorReset)
	printReceiptVerification(stdout, view.Verification)
	if section == "all" || section == "runs" {
		_, _ = fmt.Fprintf(stdout, "Runs: %d\n", len(view.Runs))
		for _, run := range view.Runs {
			_, _ = fmt.Fprintf(stdout, "  %s %s denied=%d memory=%d loops=%d %s\n", firstNonEmptyString(run.RunID, run.DecisionID), run.PolicyProfile, run.DeniedEffects, run.MemoryEffects, run.RecurringLoops, run.SignatureStatus)
		}
	}
	if section == "all" || section == "denied" {
		_, _ = fmt.Fprintf(stdout, "Denied timeline: %d\n", len(view.DeniedTimeline))
		for _, item := range view.DeniedTimeline {
			_, _ = fmt.Fprintf(stdout, "  %s %s %s %s %s\n", item.RunID, item.Effect, item.Reason, item.Target, item.SignatureStatus)
		}
	}
	if section == "all" || section == "memory" {
		_, _ = fmt.Fprintf(stdout, "Memory review queue: %d\n", len(view.MemoryReviewQueue))
		for _, item := range view.MemoryReviewQueue {
			_, _ = fmt.Fprintf(stdout, "  %s %s ttl=%d sensitivity=%s verdict=%s %s\n", item.RunID, item.MemoryClass, item.TTLDays, item.Sensitivity, item.Verdict, item.SignatureStatus)
		}
	}
	if section == "all" || section == "loops" {
		_, _ = fmt.Fprintf(stdout, "Recurring loops: %d\n", len(view.RecurringLoops))
		for _, item := range view.RecurringLoops {
			_, _ = fmt.Fprintf(stdout, "  %s %s max=%s verdict=%s %s\n", item.RunID, item.Schedule, item.MaxRuntime, item.Verdict, item.SignatureStatus)
		}
	}
}

// sectionValue is the JSON of one operator section: the same envelope as
// the whole view, the section's items under the key the whole view uses and
// the signature checks beside them, so one section never reads as more
// trusted than the view it is part of.
func sectionValue(section string, view workstation.OperatorView) any {
	var key string
	var items any
	switch section {
	case "runs":
		key, items = "runs", view.Runs
	case "denied":
		key, items = "denied_timeline", view.DeniedTimeline
	case "memory":
		key, items = "memory_review_queue", view.MemoryReviewQueue
	case "loops":
		key, items = "recurring_loops", view.RecurringLoops
	default:
		return view
	}
	return map[string]any{key: items, "verification": view.Verification}
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

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
