package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
	var passwordStdin bool
	fs.StringVar(&email, "email", "", "Account email address")
	fs.StringVar(&password, "password", "", "Deprecated unsafe argv password input; use --password-stdin")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read account password from stdin")
	fs.StringVar(&apiURL, "api-url", "", "Console API base URL (default: https://console.helm.mindburn.org)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(password) != "" {
		fmt.Fprintln(stderr, "login: --password is disabled because argv exposes secrets; use --password-stdin")
		return 2
	}
	if passwordStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(stderr, "login: read password from stdin: %v\n", err)
			return 2
		}
		password = strings.TrimRight(string(data), "\r\n")
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
