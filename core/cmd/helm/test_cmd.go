package main

import (
	"fmt"
	"io"
)

func runTestCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm test conformance --level <L1|L2>")
		return 2
	}
	switch args[0] {
	case "conformance":
		return runConform(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm test conformance --level <L1|L2>")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown test subcommand: %s\n", args[0])
		fmt.Fprintln(stderr, "Usage: helm test conformance --level <L1|L2>")
		return 2
	}
}

func init() {
	Register(Subcommand{Name: "test", Aliases: []string{}, Usage: "Compatibility test commands (conformance)", RunFn: runTestCmd})
}
