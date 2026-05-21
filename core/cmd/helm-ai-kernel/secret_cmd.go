package main

import (
	"fmt"
	"io"
)

func init() {
	Register(Subcommand{Name: "secret", Usage: "Bind env-backed Launchpad secret grants", RunFn: runSecretCmd})
}

func runSecretCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel secret <set|status> [args]")
		return 2
	}
	switch args[0] {
	case "set":
		translated := append([]string{"set"}, normalizeSecretSetArgs(args[1:])...)
		return runLaunchSecrets(translated, stdout, stderr)
	case "status", "list":
		return runLaunchSecrets([]string{"status"}, stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel secret <set|status> [args]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown secret subcommand: %s\n", args[0])
		return 2
	}
}

func normalizeSecretSetArgs(args []string) []string {
	out := append([]string{}, args...)
	hasProvider := false
	hasValueEnv := false
	for i := 0; i < len(out); i++ {
		if out[i] == "--provider" {
			hasProvider = true
		}
		if out[i] == "--value-env" {
			hasValueEnv = true
		}
	}
	if !hasProvider {
		out = append(out, "--provider", "env")
	}
	if !hasValueEnv && len(args) > 0 {
		out = append(out, "--value-env", args[0])
	}
	return out
}
