package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// PolicyFixture is a test case for a policy.
type PolicyFixture struct {
	Name     string `json:"name" yaml:"name"`
	Action   string `json:"action" yaml:"action"`
	Tool     string `json:"tool" yaml:"tool"`
	Effect   string `json:"effect" yaml:"effect"`
	Expected string `json:"expected" yaml:"expected"` // allow | deny
	Reason   string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// PolicyTemplate defines a reusable policy with fixtures.
type PolicyTemplate struct {
	Name           string          `json:"name" yaml:"name"`
	Description    string          `json:"description" yaml:"description"`
	DefaultVerdict string          `json:"default_verdict" yaml:"default_verdict"`
	AllowedTools   []string        `json:"allowed_tools" yaml:"allowed_tools"`
	AllowedEffects []string        `json:"allowed_effects" yaml:"allowed_effects"`
	Fixtures       []PolicyFixture `json:"fixtures" yaml:"fixtures"`
}

// runPolicyCmd implements `helm policy test` — policy fixture testing.
func runPolicyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm policy <test|templates> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  test       Run policy fixtures from directory")
		fmt.Fprintln(stderr, "  templates  List available policy starter templates")
		fmt.Fprintln(stderr, "  init       Generate starter policy in current directory")
		return 2
	}

	switch args[0] {
	case "test":
		return runPolicyTest(args[1:], stdout, stderr)
	case "templates":
		return runPolicyTemplates(stdout)
	case "init":
		return runPolicyInit(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm policy <test|templates|init> [flags]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown policy subcommand: %s\n", args[0])
		return 2
	}
}

func runPolicyTest(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("policy test", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		dir     string
		jsonOut bool
		verbose bool
	)
	cmd.StringVar(&dir, "dir", "policies", "Directory containing policy fixtures")
	cmd.BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.BoolVar(&verbose, "v", false, "Verbose output")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// Find fixture files
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	yamlFiles, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	files = append(files, yamlFiles...)

	if len(files) == 0 {
		fmt.Fprintf(stderr, "No policy fixtures found in %s\n", dir)
		fmt.Fprintln(stderr, "Run: helm policy init --template deny-first")
		return 2
	}

	fmt.Fprintf(stdout, "\n%s🧪 Policy Test Runner%s\n\n", ColorBold+ColorBlue, ColorReset)

	var total, passed, failed int
	type Result struct {
		File    string `json:"file"`
		Name    string `json:"name"`
		Pass    bool   `json:"pass"`
		Details string `json:"details,omitempty"`
	}
	var results []Result

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(stderr, "Error reading %s: %v\n", f, err)
			continue
		}

		var tmpl PolicyTemplate
		if err := json.Unmarshal(data, &tmpl); err != nil {
			fmt.Fprintf(stderr, "Error parsing %s: %v\n", f, err)
			continue
		}

		fmt.Fprintf(stdout, "  %s📋 %s%s — %s\n", ColorBold, tmpl.Name, ColorReset, tmpl.Description)

		for _, fix := range tmpl.Fixtures {
			total++
			verdict := evaluateFixture(tmpl, fix)
			pass := verdict == fix.Expected

			if pass {
				passed++
				fmt.Fprintf(stdout, "    %s✅ %s%s\n", ColorGreen, fix.Name, ColorReset)
			} else {
				failed++
				fmt.Fprintf(stdout, "    %s❌ %s%s — expected %s, got %s\n",
					ColorRed, fix.Name, ColorReset, fix.Expected, verdict)
			}

			results = append(results, Result{
				File: filepath.Base(f), Name: fix.Name,
				Pass: pass, Details: fmt.Sprintf("expected=%s got=%s", fix.Expected, verdict),
			})
		}
	}

	fmt.Fprintf(stdout, "\n  %s%d/%d passed%s", ColorBold, passed, total, ColorReset)
	if failed > 0 {
		fmt.Fprintf(stdout, " (%s%d failed%s)", ColorRed, failed, ColorReset)
	}
	fmt.Fprintln(stdout, "")

	if jsonOut {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Fprintln(stdout, string(data))
	}

	if failed > 0 {
		return 1
	}
	return 0
}

func evaluateFixture(tmpl PolicyTemplate, fix PolicyFixture) string {
	// Check tool allowlist
	toolAllowed := false
	for _, t := range tmpl.AllowedTools {
		if t == fix.Tool || t == "*" {
			toolAllowed = true
			break
		}
	}

	// Check effect allowlist
	effectAllowed := false
	for _, e := range tmpl.AllowedEffects {
		if e == fix.Effect || e == "*" {
			effectAllowed = true
			break
		}
	}

	// If both tool and effect are explicitly allowed, permit
	if toolAllowed && effectAllowed {
		return "allow"
	}

	// Otherwise deny (fail-closed)
	return "deny"
}

func runPolicyTemplates(stdout io.Writer) int {
	templates := []struct {
		Name string
		Desc string
	}{
		{"deny-first", "Deny by default, explicitly allow safe operations"},
		{"safe-shell", "Allow shell tools with read-only filesystem"},
		{"safe-file", "Allow file operations within project directory"},
		{"safe-web", "Allow HTTP read, deny writes and exec"},
		{"safe-deploy", "Allow deployment tools with approval gate"},
	}

	fmt.Fprintf(stdout, "\n%s📋 Policy Templates%s\n\n", ColorBold+ColorBlue, ColorReset)
	for _, t := range templates {
		fmt.Fprintf(stdout, "  %s%-15s%s %s\n", ColorBold, t.Name, ColorReset, t.Desc)
	}
	fmt.Fprintf(stdout, "\n  Usage: helm policy init --template <name>\n\n")
	return 0
}

func runPolicyInit(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("policy init", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var template string
	cmd.StringVar(&template, "template", "deny-first", "Template name")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	tmpl := getTemplate(template)
	if tmpl == nil {
		fmt.Fprintf(stderr, "Unknown template: %s\n", template)
		return 2
	}

	dir := "policies"
	if err := os.MkdirAll(dir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	data, _ := json.MarshalIndent(tmpl, "", "  ")
	outPath := filepath.Join(dir, template+".json")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "\n%s✅ Policy initialized%s\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "   Template: %s\n", template)
	fmt.Fprintf(stdout, "   File:     %s\n", outPath)
	fmt.Fprintf(stdout, "\n   Next: helm policy test --dir policies\n\n")
	return 0
}

func getTemplate(name string) *PolicyTemplate {
	switch name {
	case "deny-first":
		return &PolicyTemplate{
			Name:           "deny-first",
			Description:    "Deny by default, then explicitly allow safe operations",
			DefaultVerdict: "deny",
			AllowedTools:   []string{"echo", "cat", "ls", "helm"},
			AllowedEffects: []string{"read", "compute"},
			Fixtures: []PolicyFixture{
				{Name: "allow read-only tool", Action: "EXECUTE_TOOL", Tool: "cat", Effect: "read", Expected: "allow"},
				{Name: "allow compute", Action: "EXECUTE_TOOL", Tool: "helm", Effect: "compute", Expected: "allow"},
				{Name: "deny write tool", Action: "EXECUTE_TOOL", Tool: "rm", Effect: "write", Expected: "deny"},
				{Name: "deny network exec", Action: "EXECUTE_TOOL", Tool: "curl", Effect: "network", Expected: "deny"},
				{Name: "deny unknown tool", Action: "EXECUTE_TOOL", Tool: "unknown", Effect: "read", Expected: "deny"},
			},
		}
	case "safe-shell":
		return &PolicyTemplate{
			Name:           "safe-shell",
			Description:    "Allow shell tools with read-only filesystem",
			DefaultVerdict: "deny",
			AllowedTools:   []string{"echo", "cat", "ls", "grep", "find", "wc", "head", "tail", "sort"},
			AllowedEffects: []string{"read", "compute"},
			Fixtures: []PolicyFixture{
				{Name: "allow cat", Action: "EXECUTE_TOOL", Tool: "cat", Effect: "read", Expected: "allow"},
				{Name: "deny rm", Action: "EXECUTE_TOOL", Tool: "rm", Effect: "write", Expected: "deny"},
				{Name: "deny chmod", Action: "EXECUTE_TOOL", Tool: "chmod", Effect: "write", Expected: "deny"},
			},
		}
	case "safe-file":
		return &PolicyTemplate{
			Name:           "safe-file",
			Description:    "Allow file operations within project directory",
			DefaultVerdict: "deny",
			AllowedTools:   []string{"cat", "ls", "find", "touch", "mkdir", "cp"},
			AllowedEffects: []string{"read", "write", "compute"},
			Fixtures: []PolicyFixture{
				{Name: "allow file read", Action: "EXECUTE_TOOL", Tool: "cat", Effect: "read", Expected: "allow"},
				{Name: "allow file create", Action: "EXECUTE_TOOL", Tool: "touch", Effect: "write", Expected: "allow"},
				{Name: "deny exec", Action: "EXECUTE_TOOL", Tool: "bash", Effect: "exec", Expected: "deny"},
				{Name: "deny network", Action: "EXECUTE_TOOL", Tool: "curl", Effect: "network", Expected: "deny"},
			},
		}
	case "safe-web":
		return &PolicyTemplate{
			Name:           "safe-web",
			Description:    "Allow HTTP read, deny writes and exec",
			DefaultVerdict: "deny",
			AllowedTools:   []string{"http_get", "fetch"},
			AllowedEffects: []string{"read", "network"},
			Fixtures: []PolicyFixture{
				{Name: "allow HTTP GET", Action: "EXECUTE_TOOL", Tool: "http_get", Effect: "network", Expected: "allow"},
				{Name: "deny HTTP POST", Action: "EXECUTE_TOOL", Tool: "http_post", Effect: "network", Expected: "deny"},
				{Name: "deny exec", Action: "EXECUTE_TOOL", Tool: "eval", Effect: "exec", Expected: "deny"},
			},
		}
	case "safe-deploy":
		return &PolicyTemplate{
			Name:           "safe-deploy",
			Description:    "Allow deployment tools with approval gate",
			DefaultVerdict: "deny",
			AllowedTools:   []string{"deploy", "rollback", "status", "logs"},
			AllowedEffects: []string{"read", "network", "compute"},
			Fixtures: []PolicyFixture{
				{Name: "allow deploy", Action: "EXECUTE_TOOL", Tool: "deploy", Effect: "network", Expected: "allow"},
				{Name: "allow status", Action: "EXECUTE_TOOL", Tool: "status", Effect: "read", Expected: "allow"},
				{Name: "deny rm_rf", Action: "EXECUTE_TOOL", Tool: "rm", Effect: "write", Expected: "deny"},
			},
		}
	}
	return nil
}

func init() {
	Register(Subcommand{Name: "policy", Aliases: []string{}, Usage: "Policy compilation and testing", RunFn: runPolicyCmd})
}
