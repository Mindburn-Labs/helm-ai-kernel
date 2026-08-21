package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
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

func init() {
	Register(Subcommand{Name: "sandbox", Aliases: []string{}, Usage: "Sandbox guardrails and conformance status", RunFn: runSandboxCmd})
}
