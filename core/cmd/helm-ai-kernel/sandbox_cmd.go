package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	runtimesandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtime/sandbox"
)

// runSandboxCmd implements `helm-ai-kernel sandbox` — governed sandbox execution.
//
// Exit codes:
//
//	0 = success
//	1 = preflight/governance failure
//	2 = config error
func runSandboxCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel sandbox <exec|conform|inspect|profiles|grant|list|get|verify|preflight> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  exec      Request sandbox execution through preflight guardrails")
		fmt.Fprintln(stderr, "  conform   Report sandbox conformance status")
		fmt.Fprintln(stderr, "  inspect   Inspect sandbox backend profiles or sealed grant posture")
		fmt.Fprintln(stderr, "  profiles  List sandbox backend profiles")
		fmt.Fprintln(stderr, "  grant     Create a sealed sandbox grant")
		fmt.Fprintln(stderr, "  list      List local sandbox grants")
		fmt.Fprintln(stderr, "  get       Get a local sandbox grant")
		fmt.Fprintln(stderr, "  verify    Verify a sandbox grant hash")
		fmt.Fprintln(stderr, "  preflight Preflight sandbox authority before execution")
		return 2
	}

	switch args[0] {
	case "exec":
		return runSandboxExec(args[1:], stdout, stderr)
	case "conform":
		return runSandboxConform(args[1:], stdout, stderr)
	case "inspect":
		return runSandboxInspect(args[1:], stdout, stderr)
	case "profiles":
		return runSandboxProfiles(args[1:], stdout, stderr)
	case "grant":
		return runSandboxGrant(args[1:], stdout, stderr)
	case "list":
		return runSandboxList(args[1:], stdout, stderr)
	case "get":
		return runSandboxGet(args[1:], stdout, stderr)
	case "verify":
		return runSandboxVerify(args[1:], stdout, stderr)
	case "preflight":
		return runSandboxPreflightSurface(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel sandbox <exec|conform|inspect|profiles|grant|list|get|verify|preflight> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  exec      Request sandbox execution through preflight guardrails")
		fmt.Fprintln(stdout, "  conform   Report sandbox conformance status")
		fmt.Fprintln(stdout, "  inspect   Inspect sandbox backend profiles or sealed grant posture")
		fmt.Fprintln(stdout, "  profiles  List sandbox backend profiles")
		fmt.Fprintln(stdout, "  grant     Create a sealed sandbox grant")
		fmt.Fprintln(stdout, "  list      List local sandbox grants")
		fmt.Fprintln(stdout, "  get       Get a local sandbox grant")
		fmt.Fprintln(stdout, "  verify    Verify a sandbox grant hash")
		fmt.Fprintln(stdout, "  preflight Preflight sandbox authority before execution")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown sandbox subcommand: %s\n", args[0])
		return 2
	}
}

const (
	sandboxPreflightStatusUnavailable = "unavailable"
	sandboxPreflightReasonUnavailable = "sandbox policy evaluation is unavailable; refusing to approve execution or issue a receipt"
)

// sandboxPreflightResult captures the strict posture check.
type sandboxPreflightResult struct {
	Provider     string `json:"provider"`
	Version      string `json:"provider_version,omitempty"`
	ImageDigest  string `json:"image_digest,omitempty"`
	EgressPolicy string `json:"egress_policy_hash,omitempty"`
	Mounts       string `json:"mounts_hash,omitempty"`
	ResourceLim  string `json:"resource_limits_hash,omitempty"`
	SpecHash     string `json:"sandbox_spec_hash,omitempty"`
	Pass         bool   `json:"pass"`
	Status       string `json:"status,omitempty"`
	ReasonCode   string `json:"reason_code,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func runSandboxExec(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox exec", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		provider   string
		image      string
		jsonOutput bool
		timeout    string
	)

	cmd.StringVar(&provider, "provider", "", "Sandbox provider: mock, opensandbox, e2b, daytona (REQUIRED)")
	cmd.StringVar(&image, "image", "default", "Container image or sandbox spec")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	cmd.StringVar(&timeout, "timeout", "30s", "Execution timeout")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if provider == "" {
		fmt.Fprintln(stderr, "Error: --provider is required (mock, opensandbox, e2b, daytona)")
		return 2
	}

	// Everything after -- is the command
	remaining := cmd.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(stderr, "Error: command is required after flags")
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel sandbox exec --provider <p> -- <cmd> [args...]")
		return 2
	}

	preflight := runPreflight(provider, image)
	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]any{
			"preflight":   preflight,
			"verdict":     "DENY",
			"status":      preflight.Status,
			"reason_code": preflight.ReasonCode,
			"reason":      preflight.Reason,
		}, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stderr, "Preflight DENIED: %s\n", preflight.Reason)
		fmt.Fprintf(stderr, "   Provider: %s  Version: %s\n", preflight.Provider, preflight.Version)
	}
	return 1
}

func runPreflight(provider, image string) sandboxPreflightResult {
	result := sandboxPreflightResult{
		Provider:   provider,
		Pass:       false,
		Status:     sandboxPreflightStatusUnavailable,
		ReasonCode: "SANDBOX_POLICY_EVALUATION_UNAVAILABLE",
		Reason:     sandboxPreflightReasonUnavailable,
	}
	_ = image

	switch provider {
	case "mock":
		result.Version = "mock-1.0.0"
	case "opensandbox":
		result.Version = "opensandbox-latest"
	case "e2b":
		result.Version = "e2b-latest"
	case "daytona":
		result.Version = "daytona-latest"
	default:
		result.Status = "invalid_provider"
		result.ReasonCode = "INVALID_SANDBOX_PROVIDER"
		result.Reason = fmt.Sprintf("unknown provider: %s", provider)
	}

	return result
}

func runSandboxConform(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox conform", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		provider   string
		tier       string
		jsonOutput bool
	)

	cmd.StringVar(&provider, "provider", "", "Provider to test (REQUIRED)")
	cmd.StringVar(&tier, "tier", "compatible", "Conformance tier: compatible, verified")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if provider == "" {
		fmt.Fprintln(stderr, "Error: --provider is required")
		return 2
	}

	type conformCheck struct {
		Name   string `json:"name"`
		Pass   bool   `json:"pass"`
		Status string `json:"status,omitempty"`
		Reason string `json:"reason,omitempty"`
	}

	preflight := runPreflight(provider, "conformance")
	checks := []conformCheck{
		{Name: "preflight_posture", Pass: preflight.Pass, Status: preflight.Status, Reason: preflight.Reason},
		{Name: "receipt_binding", Pass: false, Status: preflight.Status, Reason: preflight.Reason},
		{Name: "deny_degraded", Pass: false, Status: preflight.Status, Reason: preflight.Reason},
	}

	if tier == "verified" {
		checks = append(checks,
			conformCheck{Name: "strict_preflight", Pass: false, Status: preflight.Status, Reason: preflight.Reason},
			conformCheck{Name: "receipt_preimage_binding", Pass: false, Status: preflight.Status, Reason: preflight.Reason},
		)
	}

	allPass := true
	for _, c := range checks {
		if !c.Pass {
			allPass = false
		}
	}

	result := map[string]any{
		"provider":    provider,
		"tier":        tier,
		"checks":      checks,
		"pass":        allPass,
		"status":      preflight.Status,
		"reason_code": preflight.ReasonCode,
		"reason":      preflight.Reason,
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stdout, "\n%sSandbox Conformance: %s (%s)%s\n\n", ColorBold, provider, tier, ColorReset)
		for _, c := range checks {
			icon := ""
			if !c.Pass {
				icon = ""
			}
			fmt.Fprintf(stdout, "  %s %s\n", icon, c.Name)
		}
		if allPass {
			fmt.Fprintf(stdout, "\n%sResult: %s tier PASS%s\n\n", ColorGreen+ColorBold, strings.ToUpper(tier), ColorReset)
		} else {
			fmt.Fprintf(stdout, "\n%sResult: %s tier FAIL%s\n\n", ColorRed+ColorBold, strings.ToUpper(tier), ColorReset)
		}
	}

	if !allPass {
		return 1
	}
	return 0
}

func runSandboxProfiles(args []string, stdout, stderr io.Writer) int {
	return runSandboxInspect(append(args, "--json"), stdout, stderr)
}

func runSandboxGrant(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox grant", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	runtimeName := cmd.String("runtime", "", "Runtime name")
	profileName := cmd.String("profile", "default", "Sandbox profile")
	imageDigest := cmd.String("image-digest", "", "Image/template digest")
	policyEpoch := cmd.String("policy-epoch", "local", "Policy epoch")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *runtimeName == "" {
		fmt.Fprintln(stderr, "Error: --runtime is required")
		return 2
	}
	if *imageDigest == "" {
		fmt.Fprintln(stderr, "Error: --image-digest is required before sandbox execution")
		return 2
	}
	policy := runtimesandbox.DefaultPolicy()
	policy.PolicyID = *profileName
	grant, err := runtimesandbox.GrantFromPolicy(policy, *runtimeName, *profileName, *imageDigest, *policyEpoch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, grant)
	}
	fmt.Fprintf(stdout, "Sandbox grant %s hash=%s\n", grant.GrantID, grant.GrantHash)
	return 0
}

func runSandboxList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	grants := newLocalSurfaceRegistry().ListSandboxGrants()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, grants)
	}
	fmt.Fprintln(stdout, "No sandbox grants recorded in this local CLI registry.")
	return 0
}

func runSandboxGet(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	grantID := cmd.String("grant-id", "", "Sandbox grant id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *grantID == "" && cmd.NArg() > 0 {
		*grantID = cmd.Arg(0)
	}
	if *grantID == "" {
		fmt.Fprintln(stderr, "Error: --grant-id is required")
		return 2
	}
	result := map[string]any{"grant_id": *grantID, "state": "not_found", "verified": false}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, result, false)
	}
	fmt.Fprintf(stdout, "Sandbox grant %s is not recorded in this local CLI registry\n", *grantID)
	return 1
}

func runSandboxVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	grantID := cmd.String("grant-id", "", "Sandbox grant id")
	grantHash := cmd.String("grant-hash", "", "Expected grant hash")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	result := contracts.SandboxPreflightResult{
		Verdict:       contracts.VerdictAllow,
		GrantID:       *grantID,
		GrantHash:     *grantHash,
		DispatchReady: *grantHash != "",
		CheckedAt:     time.Now().UTC(),
	}
	if *grantHash == "" {
		result.Verdict = contracts.VerdictDeny
		result.ReasonCode = contracts.ReasonSandboxViolation
		result.Findings = []string{"grant hash is required for offline verification"}
	}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, result, result.Verdict == contracts.VerdictAllow)
	}
	fmt.Fprintf(stdout, "Sandbox verify verdict=%s grant=%s\n", result.Verdict, result.GrantID)
	if result.Verdict != contracts.VerdictAllow {
		return 1
	}
	return 0
}

func runSandboxPreflightSurface(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox preflight", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	runtimeName := cmd.String("runtime", "", "Runtime name")
	profileName := cmd.String("profile", "default", "Sandbox profile")
	imageDigest := cmd.String("image-digest", "", "Image/template digest")
	policyEpoch := cmd.String("policy-epoch", "local", "Policy epoch")
	expectedHash := cmd.String("expected-grant-hash", "", "Expected grant hash")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *runtimeName == "" {
		fmt.Fprintln(stderr, "Error: --runtime is required")
		return 2
	}
	policy := runtimesandbox.DefaultPolicy()
	policy.PolicyID = *profileName
	grant, err := runtimesandbox.GrantFromPolicy(policy, *runtimeName, *profileName, *imageDigest, *policyEpoch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	result := verifySandboxGrantForDispatch(grant, *expectedHash)
	if *jsonOutput {
		_ = writeSurfaceJSON(stdout, result)
		if result.Verdict != contracts.VerdictAllow {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Sandbox preflight verdict=%s grant_hash=%s\n", result.Verdict, result.GrantHash)
	if result.Verdict != contracts.VerdictAllow {
		return 1
	}
	return 0
}

func init() {
	Register(Subcommand{Name: "sandbox", Aliases: []string{}, Usage: "Sandbox guardrails and conformance status", RunFn: runSandboxCmd})
}
