package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// ── Init Command ───────────────────────────────────────────────────────────

// runInitCmd implements `helm init` — project scaffolding for HELM governance.
//
// Generates:
//   - helm/helm.yaml             — Main configuration
//   - helm/policies/default.cel  — Default allow-list policy
//   - helm/.keys/signing.key     — Ed25519 signing keypair
//   - helm/receipts.db           — SQLite receipt store (dev mode)
//
// Exit codes:
//
//	0 = success
//	2 = runtime error
func runScaffoldCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("init", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		framework    string
		policyBackend string
		receiptStore string
		force        bool
	)

	cmd.StringVar(&framework, "framework", "generic", "Agent framework: generic, langchain, crewai, autogen, mcp")
	cmd.StringVar(&policyBackend, "policy-backend", "cel", "Policy backend: cel, opa, cedar")
	cmd.StringVar(&receiptStore, "receipt-store", "sqlite", "Receipt store: sqlite, postgres, file")
	cmd.BoolVar(&force, "force", false, "Overwrite existing helm/ directory")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	helmDir := "helm"

	// Check for existing directory.
	if _, err := os.Stat(helmDir); err == nil && !force {
		fmt.Fprintf(stderr, "Error: %s/ already exists (use --force to overwrite)\n", helmDir)
		return 2
	}

	// Create directory structure.
	dirs := []string{
		helmDir,
		filepath.Join(helmDir, "policies"),
		filepath.Join(helmDir, ".keys"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			fmt.Fprintf(stderr, "Error creating %s: %v\n", dir, err)
			return 2
		}
	}

	// Generate Ed25519 signing keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(stderr, "Error generating signing key: %v\n", err)
		return 2
	}

	keyPath := filepath.Join(helmDir, ".keys", "signing.key")
	pubPath := filepath.Join(helmDir, ".keys", "signing.pub")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv.Seed())), 0600); err != nil {
		fmt.Fprintf(stderr, "Error writing signing key: %v\n", err)
		return 2
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing public key: %v\n", err)
		return 2
	}

	// Generate helm.yaml.
	configData := helmYAMLConfig{
		Framework:     framework,
		PolicyBackend: policyBackend,
		ReceiptStore:  receiptStore,
		Version:       displayVersion(),
		PublicKeyHex:  hex.EncodeToString(pub),
	}
	configPath := filepath.Join(helmDir, "helm.yaml")
	if err := writeTemplate(configPath, helmYAMLTemplate, configData); err != nil {
		fmt.Fprintf(stderr, "Error writing helm.yaml: %v\n", err)
		return 2
	}

	// Generate default policy.
	policyPath := filepath.Join(helmDir, "policies", "default.cel")
	if err := os.WriteFile(policyPath, []byte(defaultCELPolicy), 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing default.cel: %v\n", err)
		return 2
	}

	// Generate .helmignore.
	ignorePath := filepath.Join(helmDir, ".helmignore")
	if err := os.WriteFile(ignorePath, []byte(helmIgnoreContent), 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing .helmignore: %v\n", err)
		return 2
	}

	// Write framework-specific integration hints.
	hintsPath := filepath.Join(helmDir, "INTEGRATION.md")
	hint := frameworkHints[framework]
	if hint == "" {
		hint = frameworkHints["generic"]
	}
	_ = os.WriteFile(hintsPath, []byte(hint), 0644)

	// Print success.
	fmt.Fprintf(stdout, "\n%s✅ HELM initialized%s\n\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "  Directory:     %s/\n", helmDir)
	fmt.Fprintf(stdout, "  Framework:     %s\n", framework)
	fmt.Fprintf(stdout, "  Policy:        %s (policies/default.cel)\n", policyBackend)
	fmt.Fprintf(stdout, "  Receipt Store: %s\n", receiptStore)
	fmt.Fprintf(stdout, "  Signing Key:   %s/.keys/signing.key\n", helmDir)
	fmt.Fprintf(stdout, "  Public Key:    %s\n\n", hex.EncodeToString(pub)[:32]+"…")
	fmt.Fprintln(stdout, "  Next steps:")
	fmt.Fprintln(stdout, "    1. Edit helm/policies/default.cel to define your allow-list")
	fmt.Fprintln(stdout, "    2. Run `helm dev` to start governance in dev mode")
	fmt.Fprintln(stdout, "    3. Connect your agent via MCP: `helm mcp print-config --client <your-client>`")
	fmt.Fprintln(stdout)

	return 0
}

// ── Dev Command ────────────────────────────────────────────────────────────

// runDevCmd implements `helm dev` — start HELM in development mode.
//
// Starts the MCP gateway server with hot-reload for policy changes.
//
// Exit codes:
//
//	0 = success (clean shutdown)
//	2 = runtime error
func runDevCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("dev", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		port    int
		verbose bool
		config  string
	)

	cmd.IntVar(&port, "port", 8443, "Port for MCP gateway")
	cmd.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	cmd.StringVar(&config, "config", "helm/helm.yaml", "Path to helm.yaml config")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// Check config exists.
	if _, err := os.Stat(config); os.IsNotExist(err) {
		fmt.Fprintf(stderr, "Error: config not found at %s\n", config)
		fmt.Fprintln(stderr, "Run `helm init` first to scaffold your project.")
		return 2
	}

	// Delegate to MCP serve with HTTP transport.
	mcpArgs := []string{"--transport", "http", "--port", fmt.Sprintf("%d", port)}
	if verbose {
		fmt.Fprintf(stdout, "\n%s🔧 HELM Dev Server%s\n", ColorBold+ColorBlue, ColorReset)
		fmt.Fprintf(stdout, "   Port:     %d\n", port)
		fmt.Fprintf(stdout, "   Config:   %s\n", config)
		fmt.Fprintf(stdout, "   Verbose:  %v\n\n", verbose)
		fmt.Fprintln(stdout, "   MCP endpoint: http://localhost:"+fmt.Sprintf("%d", port)+"/mcp")
		fmt.Fprintln(stdout, "   Dashboard:    http://localhost:"+fmt.Sprintf("%d", port+1)+"/")
		fmt.Fprintln(stdout)
	}

	return runMCPServe(mcpArgs, stdout, stderr)
}

// ── Templates ──────────────────────────────────────────────────────────────

type helmYAMLConfig struct {
	Framework     string
	PolicyBackend string
	ReceiptStore  string
	Version       string
	PublicKeyHex  string
}

const helmYAMLTemplate = `# HELM Governance Configuration
# Generated by helm init v{{.Version}}
# Docs: see the repository README and docs/QUICKSTART.md

version: "1.0"

# Agent framework integration
framework: "{{.Framework}}"

# MCP Gateway configuration
gateway:
  mode: "mcp-proxy"
  listen: ":8443"

# Guardian pipeline (fail-closed by default)
guardian:
  gates:
    freeze:     { enabled: true }
    context:    { enabled: true }
    identity:   { enabled: true, require_cert: false }
    egress:     { enabled: true, allowed_domains: ["*"] }
    threat_scan: { enabled: true }
    delegation: { enabled: true }

# Policy evaluation
policy:
  backend: "{{.PolicyBackend}}"
  rules_dir: "./helm/policies/"
  default_verdict: "deny"

# Receipt chain (cryptographic proof)
receipts:
  store: "{{.ReceiptStore}}"
  path: "./helm/receipts.db"
  signing:
    algorithm: "ed25519"
    key_path: "./helm/.keys/signing.key"
    public_key: "{{.PublicKeyHex}}"

# Telemetry (optional — connect to Langfuse, Jaeger, Datadog, etc.)
# telemetry:
#   otel:
#     endpoint: "localhost:4317"
#     insecure: true
`

const defaultCELPolicy = `// HELM Default Policy — Generated by helm init
//
// This policy defines the initial governance rules for your agent.
// Edit this file to customize which tools and effects are allowed.
//
// Policy evaluation: CEL (Common Expression Language)
// Reference: https://github.com/google/cel-spec
//
// Available variables:
//   tool       — name of the tool being invoked
//   effect     — effect level (E0=read, E1=observe, E2=mutate, E3=external, E4=irreversible)
//   agent_id   — the agent requesting the action
//   args       — map of tool arguments
//   session_id — current governance session

// Default: allow read-only operations (E0, E1)
effect in ["E0", "E1"]

// To allow write operations, uncomment:
// || effect in ["E2"]

// To allow specific tools regardless of effect level:
// || tool in ["read_file", "list_dir", "search"]

// To deny specific tools:
// && !(tool in ["delete_file", "drop_database"])
`

const helmIgnoreContent = `# Files to exclude from HELM tool surface scanning
.git/
.env
*.key
*.pem
node_modules/
__pycache__/
.DS_Store
`

var frameworkHints = map[string]string{
	"generic": `# HELM Integration Guide

## Quick Start

1. Start HELM dev server:
` + "```bash" + `
helm dev
` + "```" + `

2. Connect via MCP:
` + "```bash" + `
helm mcp print-config --client <your-client>
` + "```" + `

3. All tool calls through HELM will be governed and receipted.

## Verify Receipts
` + "```bash" + `
helm verify <evidence-pack.tar.gz>
` + "```" + `
`,
	"langchain": `# HELM + LangChain Integration

## Setup
` + "```python" + `
# pip install helm-sdk
# For now, use MCP integration:
from langchain_core.tools import tool

# Point your LangChain MCP client at HELM:
# MCP endpoint: http://localhost:8443/mcp
` + "```" + `
`,
}

func writeTemplate(path, tmpl string, data interface{}) error {
	t, err := template.New("").Parse(tmpl)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.Execute(f, data)
}

// printConfigJSON is a helper to dump JSON configs for debugging.
func printConfigJSON(w io.Writer, v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(w, string(data))
}

// Ensure we don't have naming conflicts with other cmd files.
var _ = strings.TrimSpace

func init() {
	Register(Subcommand{
		Name:    "scaffold",
		Aliases: []string{},
		Usage:   "Scaffold HELM governance in current project (--framework, --policy-backend)",
		RunFn:   runScaffoldCmd,
	})
	Register(Subcommand{
		Name:    "dev",
		Aliases: []string{},
		Usage:   "Start HELM in development mode (MCP gateway + hot-reload)",
		RunFn:   runDevCmd,
	})
}
