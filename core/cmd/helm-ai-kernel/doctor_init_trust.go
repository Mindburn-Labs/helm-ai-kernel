package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type initProfile struct {
	Name         string
	ProviderHint string
	EnvTemplate  string
	NextSteps    []string
}

var initProfiles = map[string]initProfile{
	"default": {
		Name:         "default",
		ProviderHint: "local-kernel",
		EnvTemplate:  "# Local HELM environment\n# Add provider credentials here when needed.\n",
		NextSteps: []string{
			"helm-ai-kernel demo organization --template starter",
			"helm-ai-kernel server",
		},
	},
	"openai": {
		Name:         "openai",
		ProviderHint: "openai",
		EnvTemplate:  "OPENAI_API_KEY=\nHELM_UPSTREAM_URL=http://127.0.0.1:19090/v1\n",
		NextSteps: []string{
			"python3 scripts/launch/mock-openai-upstream.py --port 19090",
			"helm-ai-kernel proxy --upstream http://127.0.0.1:19090/v1",
		},
	},
	"claude": {
		Name:         "claude",
		ProviderHint: "claude",
		EnvTemplate:  "# Claude integrations are MCP-first.\n# Use `helm-ai-kernel mcp print-config --client claude-code` or `helm-ai-kernel mcp pack --client claude-desktop`.\n",
		NextSteps: []string{
			"helm-ai-kernel mcp print-config --client claude-code",
			"helm-ai-kernel mcp pack --client claude-desktop --out helm-ai-kernel.mcpb",
		},
	},
	"google": {
		Name:         "google",
		ProviderHint: "google",
		EnvTemplate:  "GEMINI_API_KEY=\n# Google ADK integrations can route governed tool execution through HELM.\n",
		NextSteps: []string{
			"export GEMINI_API_KEY=...",
			"helm-ai-kernel demo research-lab --template starter --provider mock --dry-run",
		},
	},
	"codex": {
		Name:         "codex",
		ProviderHint: "codex",
		EnvTemplate:  "# Codex integrates with HELM over MCP.\n",
		NextSteps: []string{
			"helm-ai-kernel mcp print-config --client codex",
			"codex mcp add helm-governance -- helm-ai-kernel mcp serve --transport stdio",
		},
	},
}

// runInitCmd implements `helm-ai-kernel init` — project initialization.
func runInitCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("init", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		dir         string
		profileName string
	)
	cmd.StringVar(&dir, "dir", ".", "Project directory to initialize")
	cmd.StringVar(&profileName, "profile", "", "Initialization profile: default|openai|claude|google|codex")

	flagArgs := make([]string, 0, len(args))
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dir" || arg == "-dir" || arg == "--profile" || arg == "-profile":
			if i+1 >= len(args) {
				_, _ = fmt.Fprintf(stderr, "Error: flag %s requires a value\n", arg)
				return 2
			}
			flagArgs = append(flagArgs, arg, args[i+1])
			i++
		case strings.HasPrefix(arg, "--dir=") || strings.HasPrefix(arg, "-dir=") ||
			strings.HasPrefix(arg, "--profile=") || strings.HasPrefix(arg, "-profile="):
			flagArgs = append(flagArgs, arg)
		default:
			remaining = append(remaining, arg)
		}
	}

	if err := cmd.Parse(flagArgs); err != nil {
		return 2
	}

	if len(remaining) > 0 {
		if detected, ok := initProfiles[remaining[0]]; ok {
			profileName = detected.Name
			remaining = remaining[1:]
		}
	}
	if len(remaining) > 0 {
		dir = remaining[0]
		remaining = remaining[1:]
	}
	if len(remaining) > 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel init [profile] [dir] [--dir DIR] [--profile PROFILE]")
		return 2
	}

	profile := initProfiles["default"]
	if profileName != "" {
		detected, ok := initProfiles[profileName]
		if !ok {
			_, _ = fmt.Fprintf(stderr, "Error: unknown init profile %q\n", profileName)
			return 2
		}
		profile = detected
	}

	if _, err := initializeProjectLayout(dir, profile); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	_, _ = fmt.Fprintf(stdout, "Initialized HELM project in %s (%s profile)\n", dir, profile.Name)
	if len(profile.NextSteps) > 0 {
		_, _ = fmt.Fprintln(stdout, "Next:")
		for _, step := range profile.NextSteps {
			_, _ = fmt.Fprintf(stdout, "  - %s\n", step)
		}
	}
	return 0
}

func initializeProjectLayout(dir string, profile initProfile) ([]string, error) {
	created := make([]string, 0, 6)
	dirs := []string{
		"data/artifacts",
		"packs",
		"schemas",
	}

	for _, d := range dirs {
		path := filepath.Join(dir, d)
		if err := os.MkdirAll(path, 0750); err != nil {
			return nil, fmt.Errorf("cannot create %s: %w", path, err)
		}
		created = append(created, path)
	}

	configPath := filepath.Join(dir, "helm.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config := `# HELM Configuration
# See: https://github.com/Mindburn-Labs/helm-ai-kernel
version: "0.2"
kernel:
  profile: CORE
  jurisdiction: ""
init:
  provider: "` + profile.ProviderHint + `"
trust:
  roots: []
`
		if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
			return nil, fmt.Errorf("cannot write %s: %w", configPath, err)
		}
		created = append(created, configPath)
	}

	envPath := filepath.Join(dir, ".env.helm.example")
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		env := "# Generated by `helm-ai-kernel init`\n" + profile.EnvTemplate
		if err := os.WriteFile(envPath, []byte(env), 0600); err != nil {
			return nil, fmt.Errorf("cannot write %s: %w", envPath, err)
		}
		created = append(created, envPath)
	}

	return created, nil
}

func applyDoctorFixes(dir string) ([]string, error) {
	created, err := initializeProjectLayout(dir, initProfiles["default"])
	if err != nil {
		return nil, err
	}
	relative := make([]string, 0, len(created))
	for _, path := range created {
		if rel, relErr := filepath.Rel(dir, path); relErr == nil {
			relative = append(relative, rel)
			continue
		}
		relative = append(relative, path)
	}
	return relative, nil
}

func init() {
	Register(Subcommand{Name: "init", Aliases: []string{}, Usage: "Initialize a new HELM project", RunFn: runInitCmd})
}
