package main

import (
	"fmt"
	"io"
)

// testConformanceUsage names what `test conformance` really runs. It forwards
// to `conform`; the --level L1|L2 shortcuts were retired in HELM-756 and exit 2.
const testConformanceUsage = "Usage: helm-ai-kernel test conformance --profile SMB | --vector <file>   (same as `conform`; --level is retired, see `conform vectors`)"

func runTestCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, testConformanceUsage)
		return 2
	}
	switch args[0] {
	case "conformance":
		return runConform(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, testConformanceUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown test subcommand: %s\n", args[0])
		fmt.Fprintln(stderr, testConformanceUsage)
		return 2
	}
}

func init() {
	Register(Subcommand{Name: "test", Aliases: []string{}, Usage: "Compatibility test commands (conformance)", RunFn: runTestCmd})
}
