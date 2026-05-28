package main

import (
	"flag"
	"fmt"
	"io"

	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
)

func init() {
	Register(Subcommand{
		Name:  "login",
		Usage: "Authenticate with the HELM Console and store a local session",
		RunFn: runLoginCmd,
	})
}

func runLoginCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var email, password, apiURL string
	fs.StringVar(&email, "email", "", "Account email address")
	fs.StringVar(&password, "password", "", "Account password")
	fs.StringVar(&apiURL, "api-url", "", "Console API base URL (default: https://console.helm.mindburn.org)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := lpcmd.LoginOptions{
		Email:    email,
		Password: password,
		APIURL:   apiURL,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	if err := lpcmd.RunLogin(opts); err != nil {
		fmt.Fprintf(stderr, "login: %v\n", err)
		return 1
	}
	return 0
}
