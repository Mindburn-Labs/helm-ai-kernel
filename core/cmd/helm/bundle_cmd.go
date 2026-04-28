package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/bundles"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/policybundles"
)

// runBundleCmd implements `helm bundle <list|verify|inspect|build>`.
func runBundleCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm bundle <list|verify|inspect|build> [flags]")
		_, _ = fmt.Fprintln(stderr, "")
		_, _ = fmt.Fprintln(stderr, "Subcommands:")
		_, _ = fmt.Fprintln(stderr, "  list      List policy bundles in directory")
		_, _ = fmt.Fprintln(stderr, "  verify    Verify bundle integrity against hash")
		_, _ = fmt.Fprintln(stderr, "  inspect   Inspect bundle meta without activating")
		_, _ = fmt.Fprintln(stderr, "  build     Compile a policy source (CEL, Rego, Cedar) into a signed bundle")
		return 2
	}

	switch args[0] {
	case "list":
		return runBundleList(args[1:], stdout, stderr)
	case "verify":
		return runBundleVerify(args[1:], stdout, stderr)
	case "inspect":
		return runBundleInspect(args[1:], stdout, stderr)
	case "build":
		return runBundleBuild(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown bundle command: %s\n", args[0])
		return 2
	}
}

// runBundleBuild compiles a policy source file into a signed CompiledBundle
// via the multi-language policybundles registry and prints the result.
//
//	helm bundle build --language=rego ./policy.rego
//	helm bundle build --language=cedar --entities=./entities.json ./policy.cedar
//	helm bundle build ./policy.rego                 # language detected from extension
func runBundleBuild(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("bundle build", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		language    string
		bundleID    string
		name        string
		version     int
		entitiesDoc string
	)
	cmd.StringVar(&language, "language", "", "Policy language: cel, rego, or cedar (default: detect from file extension)")
	cmd.StringVar(&bundleID, "bundle-id", "", "Bundle identifier (default: file basename)")
	cmd.StringVar(&name, "name", "", "Bundle display name")
	cmd.IntVar(&version, "version", 1, "Bundle version")
	cmd.StringVar(&entitiesDoc, "entities", "", "Cedar entities JSON document (optional, cedar only)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() < 1 {
		_, _ = fmt.Fprintln(stderr, "Error: policy source file is required")
		_, _ = fmt.Fprintln(stderr, "Usage: helm bundle build [--language=cel|rego|cedar] [--entities=path] <source>")
		return 2
	}
	srcPath := cmd.Arg(0)

	lang, err := policybundles.DetectLanguage(language, srcPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	src, err := os.ReadFile(srcPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error reading source: %v\n", err)
		return 1
	}

	if bundleID == "" {
		bundleID = filepath.Base(srcPath)
	}
	if name == "" {
		name = bundleID
	}

	var entities string
	if entitiesDoc != "" {
		raw, err := os.ReadFile(entitiesDoc)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error reading entities: %v\n", err)
			return 1
		}
		entities = string(raw)
	}

	res, err := policybundles.Compile(context.Background(), lang, string(src), policybundles.CompileOptions{
		BundleID:    bundleID,
		Name:        name,
		Version:     version,
		EntitiesDoc: entities,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Compile failed: %v\n", err)
		return 1
	}

	out := map[string]any{
		"language":  res.Language,
		"hash":      res.Hash,
		"bundle_id": bundleID,
		"name":      name,
		"version":   version,
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	_, _ = fmt.Fprintln(stdout, string(data))
	return 0
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
