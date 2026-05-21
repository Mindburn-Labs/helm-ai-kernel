package main

import (
	"fmt"
	"io"
)

func init() {
	Register(Subcommand{Name: "teardown", Usage: "Cascade teardown a Launchpad runtime run", RunFn: runTeardownCmd})
}

func runTeardownCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel teardown <run_id> --cascade")
		return 2
	}
	return runLaunchDelete(args, stdout, stderr)
}
