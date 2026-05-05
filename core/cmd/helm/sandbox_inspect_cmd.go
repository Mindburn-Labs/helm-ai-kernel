package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	runtimesandbox "github.com/Mindburn-Labs/helm-oss/core/pkg/runtime/sandbox"
)

func runSandboxInspect(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("sandbox inspect", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		runtimeName string
		profileName string
		policyEpoch string
		jsonOutput  bool
	)
	cmd.StringVar(&runtimeName, "runtime", "", "Runtime name to seal a default grant for")
	cmd.StringVar(&profileName, "profile", "default", "Sandbox profile/policy name")
	cmd.StringVar(&policyEpoch, "policy-epoch", "local", "Policy epoch to bind into a grant")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if runtimeName == "" {
		profiles := runtimesandbox.DefaultBackendProfiles()
		if jsonOutput {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(profiles)
			return 0
		}
		fmt.Fprintln(stdout, "Sandbox Backend Profiles")
		for _, profile := range profiles {
			fmt.Fprintf(stdout, "  %s  kind=%s deny_network=%t hosted=%t\n", profile.Name, profile.Kind, profile.DenyNetworkByDefault, profile.Hosted)
		}
		return 0
	}

	policy := runtimesandbox.DefaultPolicy()
	policy.PolicyID = profileName
	grant, err := runtimesandbox.GrantFromPolicy(policy, runtimeName, profileName, "", policyEpoch, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(grant)
		return 0
	}
	fmt.Fprintf(stdout, "Sandbox Grant\n")
	fmt.Fprintf(stdout, "  Runtime: %s\n", grant.Runtime)
	fmt.Fprintf(stdout, "  Profile: %s\n", grant.Profile)
	fmt.Fprintf(stdout, "  Network: %s\n", grant.Network.Mode)
	fmt.Fprintf(stdout, "  Hash:    %s\n", grant.GrantHash)
	return 0
}
