// quantum_posture: hook decision receipts are signed with the classical
// Ed25519 workstation seed resolved via workstation_signing.go; no
// post-quantum or hybrid primitives are used in this file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

var (
	hookStdin = io.Reader(os.Stdin)
	hookNow   = func() time.Time { return time.Now().UTC() }
)

type hookOptions struct {
	Client          string
	DataDir         string
	SigningSeedFile string
	JSON            bool
}

type preToolPayload struct {
	ToolName       string         `json:"tool_name"`
	ToolNameCamel  string         `json:"toolName"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolInputCamel map[string]any `json:"toolInput"`
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
}

type hookDecisionOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type hookClassification struct {
	ShouldDecide bool
	Class        string
	Target       string
	Action       string
	ToolID       string
	Reason       string
}

func init() {
	Register(Subcommand{
		Name:  "hook",
		Usage: "Handle local agent client hooks",
		RunFn: runHookCmd,
	})
}

func runHookCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHookUsage(stderr)
		return 2
	}
	switch args[0] {
	case "pre-tool":
		return runHookPreToolCmd(args[1:], hookStdin, stdout, stderr)
	case "help", "--help", "-h":
		printHookUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "hook: unknown subcommand %q\n", args[0])
		printHookUsage(stderr)
		return 2
	}
}

func runHookPreToolCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts := hookOptions{DataDir: defaultSetupDataDir()}
	fs := flag.NewFlagSet("hook pre-tool", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Client, "client", "", "Client name: claude-code or codex")
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for HELM local state")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.BoolVar(&opts.JSON, "json", false, "Reserved for structured diagnostics")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client, err := normalizeSetupTarget(opts.Client)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	opts.Client = client
	if strings.TrimSpace(opts.DataDir) != "" {
		if abs, err := filepath.Abs(opts.DataDir); err == nil {
			opts.DataDir = abs
		}
	}
	payload, err := decodePreToolPayload(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	classification := classifyPreToolPayload(payload)
	if !classification.ShouldDecide {
		return 0
	}
	receipt, err := buildHookDecisionReceipt(opts, payload, classification)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, "HELM denied operation: local receipt signer is unavailable")
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny {
		return 0
	}
	receiptPath, err := writeDecisionReceipt("", filepath.Join(opts.DataDir, "receipts", "hooks"), receipt)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
		return emitHookDenyOrFail(stdout, stderr, "HELM denied operation: receipt persistence is unavailable")
	}
	return emitHookDenyOrFail(stdout, stderr, fmt.Sprintf("HELM denied %s: %s (receipt: %s)", classification.Reason, receipt.ReasonCode, receiptPath))
}

func emitHookDenyOrFail(stdout, stderr io.Writer, reason string) int {
	if err := writeHookDeny(stdout, reason); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
		return 2
	}
	return 0
}

func writeHookDeny(stdout io.Writer, reason string) error {
	out := hookDecisionOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
	return json.NewEncoder(stdout).Encode(out)
}

func printHookUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel hook pre-tool --client <claude-code|codex> [--data-dir DIR] [--signing-seed-file PATH]")
}

func decodePreToolPayload(stdin io.Reader) (preToolPayload, error) {
	var payload preToolPayload
	dec := json.NewDecoder(stdin)
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode hook payload: %w", err)
	}
	if payload.ToolName == "" {
		payload.ToolName = payload.ToolNameCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.ToolInputCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = map[string]any{}
	}
	return payload, nil
}

func classifyPreToolPayload(payload preToolPayload) hookClassification {
	tool := strings.TrimSpace(payload.ToolName)
	switch {
	case strings.EqualFold(tool, "Bash"):
		command := inputString(payload.ToolInput, "command", "cmd")
		// Secret material is checked first, and deliberately so. A command that
		// both reads a secret and sends bytes off the machine is exfiltration,
		// and classifying it as egress would let an operator who allowlisted the
		// destination ship credentials to it without the secret policy ever being
		// consulted. Reading the secret is the precondition, so that is the effect
		// the decision is bound to. This is still one effect per call. Evaluating
		// egress and secret policy together needs a decision-request change and is
		// noted in the PR discussion.
		secretTarget, isSecret := shellSecretReadTarget(command)
		egressTarget, isEgress := shellEgressTarget(command)
		switch {
		case isSecret:
			reason := "shell secret read"
			if isEgress {
				reason = "shell secret read with network egress to " + egressTarget
			}
			return hookClassification{
				ShouldDecide: true,
				Class:        "secret",
				Target:       secretTarget,
				Action:       "secret_read",
				ToolID:       "shell",
				Reason:       reason,
			}
		case isEgress:
			return hookClassification{
				ShouldDecide: true,
				Class:        "network",
				Target:       egressTarget,
				Action:       "network_egress",
				ToolID:       "shell",
				Reason:       "shell network egress",
			}
		}
		if isDestructiveShellCommand(command) {
			return hookClassification{
				ShouldDecide: true,
				Class:        "shell-operate",
				Target:       command,
				Action:       "shell_operate",
				ToolID:       "shell",
				Reason:       "shell operation",
			}
		}
	case strings.HasPrefix(tool, "mcp__"):
		if isHelmSelfMCPTool(tool) {
			return hookClassification{}
		}
		return hookClassification{
			ShouldDecide: true,
			Class:        "mcp",
			Target:       tool,
			Action:       "mcp_tool_call",
			ToolID:       tool,
			Reason:       "MCP tool call",
		}
	case strings.EqualFold(tool, "Edit"), strings.EqualFold(tool, "Write"), strings.EqualFold(tool, "MultiEdit"), strings.EqualFold(tool, "apply_patch"):
		target := inputString(payload.ToolInput, "file_path", "path", "target_file")
		if target == "" && strings.EqualFold(tool, "apply_patch") {
			target = sensitiveApplyPatchTarget(inputString(payload.ToolInput, "command", "cmd", "patch"))
		}
		if target == "" && strings.EqualFold(tool, "apply_patch") {
			target = "apply_patch"
		}
		if isSensitiveWriteTarget(target) {
			return hookClassification{
				ShouldDecide: true,
				Class:        "secret",
				Target:       target,
				Action:       "file_write",
				ToolID:       tool,
				Reason:       "sensitive file write",
			}
		}
	}
	return hookClassification{}
}

func buildHookDecisionReceipt(opts hookOptions, payload preToolPayload, classification hookClassification) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	effectType, effectMode, defaultAction, defaultTool := workstation.EffectDefaults(classification.Class)
	action := firstNonEmptyString(classification.Action, defaultAction)
	toolID := firstNonEmptyString(classification.ToolID, payload.ToolName, defaultTool)
	profile, err := workstation.LoadPolicyProfileFile("")
	if err != nil {
		return nil, err
	}
	req := contracts.WorkstationDecisionRequest{
		RunID:        firstNonEmptyString(payload.SessionID, "hook-pre-tool"),
		ActorID:      "agent.local",
		WorkspaceID:  firstNonEmptyString(payload.CWD, "local-workstation"),
		AgentSurface: opts.Client,
		ToolID:       toolID,
		Action:       action,
		EffectType:   effectType,
		EffectMode:   effectMode,
		Target:       classification.Target,
		OccurredAt:   hookNow(),
		Metadata: map[string]string{
			"client": opts.Client,
			"tool":   payload.ToolName,
		},
	}
	seed, err := resolveWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile)
	if err != nil {
		return nil, fmt.Errorf("load workstation signing key: %w", err)
	}
	return workstation.Decide(profile, req, workstation.DecisionOptions{SigningSeed: seed})
}

func inputString(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := input[key]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// normalizeShellCommand lowercases a command and collapses runs of whitespace,
// so that substring matching is not defeated by extra spaces, tabs, or newlines.
// Without this, "rm  -rf /" reaches the agent because it never matches "rm -rf ".
func normalizeShellCommand(command string) string {
	return strings.ToLower(strings.Join(strings.Fields(command), " "))
}

// shellNetworkTools are commands whose primary effect is moving bytes off the
// machine. A shell command that runs one of these is a network egress effect and
// belongs under the egress allowlist, not under the destructive-command list.
var shellNetworkTools = map[string]bool{
	"curl":   true,
	"wget":   true,
	"nc":     true,
	"ncat":   true,
	"netcat": true,
	"telnet": true,
	"socat":  true,
	"scp":    true,
	"sftp":   true,
	"rsync":  true,
	"ftp":    true,
	"aria2c": true,
	"httpie": true,
	"http":   true,
}

// shellEgressTarget reports whether a shell command sends data off the machine and
// returns the destination it targets. The destination is handed to the egress
// allowlist that already exists in the workstation policy, which already fails
// closed when the allowlist is empty.
func shellEgressTarget(command string) (string, bool) {
	if strings.TrimSpace(command) == "" {
		return "", false
	}
	if target, ok := devSocketTarget(command); ok {
		return target, true
	}
	// A concrete destination anywhere in the command wins. A recognized tool with
	// no parsable destination is only a fallback, so that "curl --help; curl
	// https://host" reports the host rather than stopping on the first segment.
	fallback := ""
	for _, segment := range splitShellSegments(command) {
		fields := stripCommandWrappers(trimEnvAssignments(strings.Fields(segment)))
		if len(fields) == 0 {
			continue
		}
		tool := shellToolName(fields[0])
		if !shellNetworkTools[tool] {
			continue
		}
		args := fields[1:]
		if dest, ok := firstDestinationArg(args); ok {
			return dest, true
		}
		// An invocation that only asks for help or a version moves no bytes. Any
		// other unparsable destination still fails closed under the tool name,
		// since a destination we cannot read is not a destination that is absent.
		if fallback == "" && !isInformationalInvocation(args) {
			fallback = tool
		}
	}
	if fallback != "" {
		return fallback, true
	}
	return "", false
}

// isInformationalInvocation reports whether a network tool was invoked only to
// print usage or a version, which performs no egress.
func isInformationalInvocation(args []string) bool {
	if len(args) == 0 {
		return true
	}
	for _, arg := range args {
		switch strings.ToLower(strings.Trim(arg, `"'`)) {
		case "-h", "--help", "--version", "--usage", "--manual":
			return true
		}
	}
	return false
}

// shellCommandWrappers run another command as an argument. Without stripping
// them, "bash -c 'curl https://host'" hides the egress tool behind the wrapper
// and no decision is emitted.
var shellCommandWrappers = map[string]bool{
	"bash":    true,
	"sh":      true,
	"zsh":     true,
	"dash":    true,
	"ksh":     true,
	"fish":    true,
	"env":     true,
	"sudo":    true,
	"doas":    true,
	"nohup":   true,
	"nice":    true,
	"timeout": true,
	"stdbuf":  true,
	"xargs":   true,
	"command": true,
	"exec":    true,
}

// wrapperValueFlags lists the flags of each wrapper that consume the token after
// them. Without this, "sudo -u root curl host" resolves to root rather than curl
// and the egress is never classified.
var wrapperValueFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-p": true, "-r": true, "-t": true, "-c": true, "-h": true},
	"doas":    {"-u": true, "-c": true},
	"env":     {"-u": true, "-c": true, "-s": true},
	"nice":    {"-n": true},
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"xargs":   {"-i": true, "-l": true, "-n": true, "-p": true, "-s": true, "-a": true, "-d": true, "-e": true},
	"exec":    {"-a": true},
}

// wrapperLeadingPositional marks wrappers that take a positional argument of
// their own before the command, such as the duration in "timeout 5 curl host".
var wrapperLeadingPositional = map[string]bool{"timeout": true}

// stripCommandWrappers removes leading wrapper commands, their flags, and any
// values those flags consume, so the tool actually being run ends up first.
func stripCommandWrappers(fields []string) []string {
	for len(fields) > 0 {
		name := shellToolName(fields[0])
		if !shellCommandWrappers[name] {
			break
		}
		valueFlags := wrapperValueFlags[name]
		fields = fields[1:]
		for len(fields) > 0 {
			arg := strings.Trim(fields[0], `"'`)
			if !strings.HasPrefix(arg, "-") || arg == "-" {
				break
			}
			fields = fields[1:]
			// A flag written as --signal=TERM carries its own value.
			if strings.Contains(arg, "=") {
				continue
			}
			if valueFlags[strings.ToLower(arg)] && len(fields) > 0 {
				fields = fields[1:]
			}
		}
		if wrapperLeadingPositional[name] && len(fields) > 1 && isDurationLike(strings.Trim(fields[0], `"'`)) {
			fields = fields[1:]
		}
		fields = trimEnvAssignments(fields)
	}
	return fields
}

// isDurationLike reports whether a token looks like a timeout duration such as
// 5, 1.5, or 30s.
func isDurationLike(arg string) bool {
	trimmed := strings.TrimRight(strings.ToLower(arg), "smhd")
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// shellTokens splits a command on whitespace and on the shell operators that can
// sit flush against a path, so that "id_rsa|nc" yields "id_rsa" rather than a
// target with punctuation glued to it.
func shellTokens(command string) []string {
	return strings.FieldsFunc(command, func(r rune) bool {
		return strings.ContainsRune(" \t\n\r\v\f|;&<>()", r)
	})
}

// shellToolName reduces an argv[0] to a bare command name, dropping any path and
// surrounding quotes.
func shellToolName(field string) string {
	return strings.ToLower(filepath.Base(strings.Trim(field, `"'`)))
}

// splitShellSegments breaks a command line on the operators that begin a new
// command, so a network tool inside a pipeline or substitution is still seen.
func splitShellSegments(command string) []string {
	replacer := strings.NewReplacer(
		"&&", "\n",
		"||", "\n",
		";", "\n",
		"|", "\n",
		"$(", "\n",
		")", "\n",
		"`", "\n",
		"\r", "\n",
	)
	return strings.Split(replacer.Replace(command), "\n")
}

// trimEnvAssignments drops leading VAR=value prefixes so that
// "HTTPS_PROXY=http://p curl host" still resolves to curl.
func trimEnvAssignments(fields []string) []string {
	for len(fields) > 0 {
		name, _, ok := strings.Cut(fields[0], "=")
		if !ok || name == "" || strings.ContainsAny(name, `/\.`) {
			break
		}
		fields = fields[1:]
	}
	return fields
}

// firstDestinationArg returns the first argument that looks like a host or URL.
// An explicit URL anywhere in the argument list wins, because it is unambiguous.
// Otherwise a bare hostname is accepted only when it is not the value of a
// preceding flag, so that "curl -o output.txt host" does not report output.txt
// as the destination and write a receipt naming the wrong target.
func firstDestinationArg(args []string) (string, bool) {
	cleaned := make([]string, 0, len(args))
	for _, arg := range args {
		cleaned = append(cleaned, strings.Trim(arg, `"'`))
	}
	for _, arg := range cleaned {
		if strings.Contains(arg, "://") {
			return arg, true
		}
	}
	precededByFlag := false
	for _, arg := range cleaned {
		isFlag := strings.HasPrefix(arg, "-") && arg != "-"
		switch {
		case arg == "":
			continue
		case isFlag:
			// A flag written as --data=value carries its own value.
			precededByFlag = !strings.Contains(arg, "=")
			continue
		case precededByFlag:
			precededByFlag = false
			continue
		case strings.HasPrefix(arg, "@"), strings.HasPrefix(arg, "/"), strings.HasPrefix(arg, "."):
			continue
		case strings.Contains(arg, "."), strings.Contains(arg, ":"):
			return arg, true
		}
	}
	return "", false
}

// devSocketTarget extracts the destination from a bash /dev/tcp or /dev/udp
// redirect, the shape used by most reverse shells.
func devSocketTarget(command string) (string, bool) {
	lower := strings.ToLower(command)
	for _, prefix := range []string{"/dev/tcp/", "/dev/udp/"} {
		idx := strings.Index(lower, prefix)
		if idx < 0 {
			continue
		}
		rest := lower[idx+len(prefix):]
		parts := strings.FieldsFunc(rest, func(r rune) bool {
			return strings.ContainsRune(" \t\"';&|<>", r)
		})
		if len(parts) == 0 {
			continue
		}
		proto := "tcp"
		if strings.HasPrefix(prefix, "/dev/udp") {
			proto = "udp"
		}
		host, port, _ := strings.Cut(parts[0], "/")
		if host == "" {
			continue
		}
		if port != "" {
			return proto + "://" + host + ":" + port, true
		}
		return proto + "://" + host, true
	}
	return "", false
}

// shellSecretReadTarget reports whether a shell command touches well-known secret
// material and returns the path it references.
func shellSecretReadTarget(command string) (string, bool) {
	for _, field := range shellTokens(command) {
		cleaned := strings.Trim(field, `"'@<>`)
		// A URL that merely mentions secret-looking material, such as
		// https://example.com/cert.pem, is a download rather than a local secret
		// read. Treating it as one would route pure egress to the secret policy,
		// where a granted secret.read permission would carry it past the egress
		// allowlist entirely.
		if strings.Contains(cleaned, "://") {
			continue
		}
		if isSensitiveSecretPath(cleaned) {
			return cleaned, true
		}
	}
	return "", false
}

func isSensitiveSecretPath(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	sensitive := []string{
		"id_rsa",
		"id_ed25519",
		"id_ecdsa",
		".ssh/",
		".pem",
		".p12",
		".aws/credentials",
		".config/gcloud",
		".kube/config",
		".netrc",
		".npmrc",
		".pypirc",
		".docker/config.json",
	}
	for _, needle := range sensitive {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

func isDestructiveShellCommand(command string) bool {
	c := normalizeShellCommand(command)
	if c == "" {
		return false
	}
	needles := []string{
		"rm -rf ",
		"rm -fr ",
		"rm -r ",
		"git reset --hard",
		"git clean -fd",
		"git clean -xdf",
		"mkfs",
		"dd if=",
		"kubectl delete",
		"docker rm -f",
		"drop table",
		"drop database",
		"drop schema",
		"truncate table",
	}
	for _, needle := range needles {
		if strings.Contains(c, needle) || strings.HasPrefix(c, strings.TrimSpace(needle)) {
			return true
		}
	}
	return false
}

func sensitiveApplyPatchTarget(command string) string {
	for _, line := range strings.Split(command, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:"} {
			if strings.HasPrefix(line, prefix) {
				target := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if isSensitiveWriteTarget(target) {
					return target
				}
			}
		}
	}
	return ""
}

func isHelmSelfMCPTool(tool string) bool {
	t := strings.ToLower(tool)
	return strings.Contains(t, "helm-ai-kernel") || strings.Contains(t, "helm_ai_kernel") || strings.Contains(t, "helm-ai-kernel-governance")
}

func isSensitiveWriteTarget(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	sensitive := []string{
		".env",
		".pem",
		".key",
		"id_rsa",
		"id_ed25519",
		".git/",
		".git\\",
	}
	for _, needle := range sensitive {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
