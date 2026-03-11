package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/bundles"
)

// runBundleCmd implements `helm bundle <list|verify|inspect>`.
func runBundleCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm bundle <list|verify|inspect> [flags]")
		_, _ = fmt.Fprintln(stderr, "")
		_, _ = fmt.Fprintln(stderr, "Subcommands:")
		_, _ = fmt.Fprintln(stderr, "  list      List policy bundles in directory")
		_, _ = fmt.Fprintln(stderr, "  verify    Verify bundle integrity against hash")
		_, _ = fmt.Fprintln(stderr, "  inspect   Inspect bundle meta without activating")
		return 2
	}

	switch args[0] {
	case "list":
		return runBundleList(args[1:], stdout, stderr)
	case "verify":
		return runBundleVerify(args[1:], stdout, stderr)
	case "inspect":
		return runBundleInspect(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown bundle command: %s\n", args[0])
		return 2
	}
}

func runBundleList(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("bundle list", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		dir        string
		jsonOutput bool
	)
	cmd.StringVar(&dir, "dir", ".", "Directory containing .yaml bundle files")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	ymlFiles, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	files = append(files, ymlFiles...)

	var infos []*bundles.BundleInfo
	for _, f := range files {
		bundle, err := bundles.LoadFromFile(f)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "  ⚠ %s: %v\n", filepath.Base(f), err)
			continue
		}
		infos = append(infos, bundles.Inspect(bundle))
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(infos, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		if len(infos) == 0 {
			_, _ = fmt.Fprintln(stdout, "No policy bundles found.")
		} else {
			for _, info := range infos {
				_, _ = fmt.Fprintf(stdout, "  %s v%s  (%d rules, hash=%s)\n",
					info.Name, info.Version, info.RuleCount, info.Hash[:12])
			}
		}
	}
	return 0
}

func runBundleVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("bundle verify", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		file       string
		hash       string
		jsonOutput bool
	)
	cmd.StringVar(&file, "file", "", "Path to bundle YAML (REQUIRED)")
	cmd.StringVar(&hash, "hash", "", "Expected content hash (REQUIRED)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if file == "" || hash == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --file and --hash are required")
		return 2
	}

	bundle, err := bundles.LoadFromFile(file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error loading bundle: %v\n", err)
		return 1
	}

	if err := bundles.Verify(bundle, hash); err != nil {
		if jsonOutput {
			data, _ := json.MarshalIndent(map[string]any{
				"file":          file,
				"valid":         false,
				"expected_hash": hash,
				"actual_hash":   bundle.Metadata.Hash,
			}, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			_, _ = fmt.Fprintf(stderr, "❌ Verification failed: %v\n", err)
		}
		return 1
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(map[string]any{
			"file":  file,
			"valid": true,
			"hash":  hash,
		}, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		_, _ = fmt.Fprintf(stdout, "✅ Bundle verified: %s\n", filepath.Base(file))
	}
	return 0
}

func runBundleInspect(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("bundle inspect", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var file string
	cmd.StringVar(&file, "file", "", "Path to bundle YAML (REQUIRED)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if file == "" {
		if cmd.NArg() > 0 {
			file = cmd.Arg(0)
		} else {
			_, _ = fmt.Fprintln(stderr, "Error: --file or positional path required")
			return 2
		}
	}

	data, err := os.ReadFile(file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error reading bundle: %v\n", err)
		return 1
	}

	bundle, err := bundles.LoadFromBytes(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error parsing bundle: %v\n", err)
		return 1
	}

	info := bundles.Inspect(bundle)
	out, _ := json.MarshalIndent(info, "", "  ")
	_, _ = fmt.Fprintln(stdout, string(out))
	return 0
}

func init() {
	Register(Subcommand{Name: "bundle", Aliases: []string{}, Usage: "List and verify loaded policy bundles", RunFn: runBundleCmd})
}
