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
		Name:  "connect",
		Usage: "One-click connect this machine to cloud HELM and route your agent through it",
		RunFn: runConnectCmd,
	})
}

func runConnectCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var target, scope, workspace, mcpURL, clientName string
	var noOpen, noConfig bool
	fs.StringVar(&target, "client", "claude-code", "Agent client to configure: claude-code or codex")
	fs.StringVar(&scope, "scope", "user", "Config scope: user or project")
	fs.StringVar(&workspace, "workspace", "", "Project directory for project scope")
	fs.StringVar(&mcpURL, "mcp-url", "", "Override the cloud MCP edge URL (default: <cloud-base>/mcp)")
	fs.StringVar(&clientName, "name", "HELM AI Kernel CLI", "Self-reported client name shown in the Console")
	fs.BoolVar(&noOpen, "no-open", false, "Do not attempt to open a browser; print the URL only")
	fs.BoolVar(&noConfig, "no-config", false, "Authenticate and store the credential without writing an agent client config")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cloudBase := ""
	if rest := fs.Args(); len(rest) > 0 {
		cloudBase = rest[0]
	}

	if target != "claude-code" && target != "codex" {
		fmt.Fprintf(stderr, "connect: unsupported --client %q (valid: claude-code, codex)\n", target)
		return 2
	}
	if scope != "user" && scope != "project" {
		fmt.Fprintf(stderr, "connect: unsupported --scope %q (valid: user, project)\n", scope)
		return 2
	}
	if scope == "project" && strings.TrimSpace(workspace) == "" {
		fmt.Fprintln(stderr, "connect: --workspace is required for project scope")
		return 2
	}

	opts := lpcmd.ConnectOptions{
		CloudBaseURL: cloudBase,
		ClientName:   clientName,
		ClientType:   "cli",
		Stdout:       stdout,
		Stderr:       stderr,
	}
	if noOpen {
		opts.OpenBrowser = func(string) error { return os.ErrInvalid }
	}

	result, err := lpcmd.RunConnect(opts)
	if err != nil {
		fmt.Fprintf(stderr, "connect: %v\n", err)
		return 1
	}

	edge := strings.TrimSpace(mcpURL)
	if edge == "" {
		edge = deriveCloudMCPURL(result.APIURL)
	}

	if noConfig {
		printConnectSummary(stdout, result, edge, target, scope, "", true)
		return 0
	}

	setupOpts := setupOptions{Target: target, Scope: scope, Workspace: workspace}
	configPath := setupClientConfigPath(setupOpts)
	if err := writeRemoteMCPConfig(setupOpts, edge, lpcmd.MachineTokenEnvVar); err != nil {
		// Fail-closed: the atomic writer never leaves a half-written config, and
		// the credential is already stored, so re-running connect is safe.
		fmt.Fprintf(stderr, "connect: authenticated, but writing the %s MCP config failed: %v\n", target, err)
		fmt.Fprintln(stderr, "connect: no client config was changed; re-run once the cause is resolved")
		return 1
	}

	printConnectSummary(stdout, result, edge, target, scope, configPath, false)
	return 0
}

// writeRemoteMCPConfig writes the remote HTTP MCP server entry for the selected
// agent client, pointing at the tenant-scoped cloud edge with an env-referenced
// bearer (never the literal token).
func writeRemoteMCPConfig(opts setupOptions, mcpURL, tokenEnvVar string) error {
	path := setupClientConfigPath(opts)
	root := setupPrivateFileRoot(opts)
	switch opts.Target {
	case "claude-code":
		return writeRemoteClaudeMCP(path, mcpURL, tokenEnvVar, root)
	case "codex":
		return writeRemoteCodexMCP(path, mcpURL, tokenEnvVar, root)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

// deriveCloudMCPURL derives the default cloud MCP edge from the control-plane
// base. Tenant scoping is carried by the workspace-scoped bearer credential, not
// the URL path; override with --mcp-url for a dedicated edge host.
func deriveCloudMCPURL(base string) string {
	return strings.TrimRight(base, "/") + "/mcp"
}

func printConnectSummary(stdout io.Writer, result lpcmd.ConnectResult, edge, target, scope, configPath string, noConfig bool) {
	fmt.Fprintf(stdout, "\n✅ Connected to cloud HELM\n")
	fmt.Fprintf(stdout, "   Workspace:  %s\n", result.WorkspaceID)
	if result.Principal != "" {
		fmt.Fprintf(stdout, "   Approved by: %s\n", result.Principal)
	}
	fmt.Fprintf(stdout, "   MCP edge:   %s\n", edge)
	if noConfig {
		fmt.Fprintf(stdout, "\nCredential stored. Skipped writing an agent client config (--no-config).\n")
		fmt.Fprintf(stdout, "Point your agent's MCP server at the edge above with header: Authorization: Bearer ${%s}\n", lpcmd.MachineTokenEnvVar)
		return
	}
	fmt.Fprintf(stdout, "   Client:     %s (%s scope)\n", target, scope)
	fmt.Fprintf(stdout, "   Config:     %s\n", configPath)
	fmt.Fprintf(stdout, "\nThe %s bearer is referenced via $%s; no token is written to the config.\n", target, lpcmd.MachineTokenEnvVar)
	fmt.Fprintf(stdout, "Your agent now routes tool calls through cloud HELM. Restart the agent to load the MCP server.\n")
}
