package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	var noOpen, noConfig, nativeHTTP bool
	fs.StringVar(&target, "client", "claude-code", "Agent client to configure: claude-code or codex")
	fs.StringVar(&scope, "scope", "user", "Config scope: user or project")
	fs.StringVar(&workspace, "workspace", "", "Project directory for project scope")
	fs.StringVar(&mcpURL, "mcp-url", "", "Override the cloud MCP edge URL (default: <cloud-base>/mcp)")
	fs.StringVar(&clientName, "name", "HELM AI Kernel CLI", "Self-reported client name shown in the Console")
	fs.BoolVar(&noOpen, "no-open", false, "Do not attempt to open a browser; print the URL only")
	fs.BoolVar(&noConfig, "no-config", false, "Authenticate and store the credential without writing an agent client config")
	fs.BoolVar(&nativeHTTP, "native-http", false, "Write a remote HTTP config referencing $"+lpcmd.MachineTokenEnvVar+" instead of the stdio bridge (you must export that env var yourself)")

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
		printConnectSummary(stdout, result, edge, target, scope, "", true, nativeHTTP)
		return 0
	}

	setupOpts := setupOptions{Target: target, Scope: scope, Workspace: workspace}
	configPath := setupClientConfigPath(setupOpts)
	var writeErr error
	if nativeHTTP {
		writeErr = writeRemoteMCPConfig(setupOpts, edge, lpcmd.MachineTokenEnvVar)
	} else {
		bin, binErr := connectBridgeBinaryPath()
		if binErr != nil {
			fmt.Fprintf(stderr, "connect: authenticated, but locating the helm-ai-kernel binary failed: %v\n", binErr)
			fmt.Fprintln(stderr, "connect: no client config was changed; re-run once the cause is resolved")
			return 1
		}
		writeErr = writeBridgeMCPConfig(setupOpts, bin, edge)
	}
	if writeErr != nil {
		// Fail-closed: the atomic writer never leaves a half-written config, and
		// the credential is already stored, so re-running connect is safe.
		fmt.Fprintf(stderr, "connect: authenticated, but writing the %s MCP config failed: %v\n", target, writeErr)
		fmt.Fprintln(stderr, "connect: no client config was changed; re-run once the cause is resolved")
		return 1
	}

	printConnectSummary(stdout, result, edge, target, scope, configPath, false, nativeHTTP)
	return 0
}

// connectBridgeBinaryPath resolves the absolute path of the running
// helm-ai-kernel binary; the generated client config spawns it as the stdio
// MCP bridge.
func connectBridgeBinaryPath() (string, error) {
	bin, err := os.Executable()
	if err != nil {
		return "", err
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	return bin, nil
}

// bridgeMCPArgs are the client-config args that spawn the stdio bridge against
// the tenant-scoped cloud edge. The bridge loads the bearer from the local
// machine credential store at call time, so no token or env var appears here.
func bridgeMCPArgs(mcpURL string) []string {
	return []string{"mcp", "bridge", "--url", mcpURL}
}

// writeBridgeMCPConfig writes the default stdio-bridge MCP server entry for the
// selected agent client: the client spawns `helm-ai-kernel mcp bridge` over
// stdio and the bridge authenticates to the cloud edge from the persisted
// machine credential. This works in a fresh shell with zero manual env setup.
func writeBridgeMCPConfig(opts setupOptions, bin, mcpURL string) error {
	path := setupClientConfigPath(opts)
	root := setupPrivateFileRoot(opts)
	switch opts.Target {
	case "claude-code":
		return writeBridgeClaudeMCP(path, bin, mcpURL, root)
	case "codex":
		return writeBridgeCodexMCP(path, bin, mcpURL, root)
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

// writeBridgeClaudeMCP merges a stdio bridge HELM MCP server into a Claude
// client config, preserving any other servers, and writes it atomically.
func writeBridgeClaudeMCP(path, bin, mcpURL, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	entry, err := structToObject(claudeMCPServer{Command: bin, Args: bridgeMCPArgs(mcpURL)})
	if err != nil {
		return err
	}
	servers := objectValue(root, "mcpServers")
	servers[setupMCPServerName] = entry
	root["mcpServers"] = servers
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return connectAtomicWrite(path, append(data, '\n'), allowedRoot)
}

// writeBridgeCodexMCP upserts a stdio bridge HELM MCP server into a Codex
// config, preserving any other tables, and writes it atomically.
func writeBridgeCodexMCP(path, bin, mcpURL, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	current := ""
	if raw, err := os.ReadFile(path); err == nil {
		current = string(raw)
		if err := validateCodexProjectTOML(current); err != nil {
			return fmt.Errorf("parse existing Codex config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	current = removeTOMLTable(current, "[mcp_servers."+setupMCPServerName+"]")
	quoted := make([]string, 0, 4)
	for _, arg := range bridgeMCPArgs(mcpURL) {
		quoted = append(quoted, fmt.Sprintf("%q", arg))
	}
	block := fmt.Sprintf("[mcp_servers.%s]\ncommand = %q\nargs = [%s]\n", setupMCPServerName, bin, strings.Join(quoted, ", "))
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	if err := validateCodexProjectTOML(next); err != nil {
		return fmt.Errorf("validate updated Codex config: %w", err)
	}
	return connectAtomicWrite(path, []byte(next), allowedRoot)
}

// writeRemoteMCPConfig writes the remote HTTP MCP server entry for the selected
// agent client, pointing at the tenant-scoped cloud edge with an env-referenced
// bearer (never the literal token). Only used with --native-http: nothing
// populates that env var, so the caller must export it before starting the
// agent.
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

func printConnectSummary(stdout io.Writer, result lpcmd.ConnectResult, edge, target, scope, configPath string, noConfig, nativeHTTP bool) {
	fmt.Fprintf(stdout, "\n✅ Connected to cloud HELM\n")
	fmt.Fprintf(stdout, "   Workspace:  %s\n", result.WorkspaceID)
	if result.Principal != "" {
		fmt.Fprintf(stdout, "   Approved by: %s\n", result.Principal)
	}
	fmt.Fprintf(stdout, "   MCP edge:   %s\n", edge)
	if noConfig {
		fmt.Fprintf(stdout, "\nCredential stored. Skipped writing an agent client config (--no-config).\n")
		fmt.Fprintf(stdout, "Point your agent at a stdio MCP server running: helm-ai-kernel mcp bridge --url %s\n", edge)
		return
	}
	fmt.Fprintf(stdout, "   Client:     %s (%s scope)\n", target, scope)
	fmt.Fprintf(stdout, "   Config:     %s\n", configPath)
	if nativeHTTP {
		fmt.Fprintf(stdout, "\nThe config references the bearer via $%s; connect does NOT populate it.\n", lpcmd.MachineTokenEnvVar)
		fmt.Fprintf(stdout, "You are responsible for exporting %s in the agent's environment before starting it.\n", lpcmd.MachineTokenEnvVar)
		return
	}
	fmt.Fprintf(stdout, "\nThe config launches 'helm-ai-kernel mcp bridge' over stdio; the bridge authenticates\n")
	fmt.Fprintf(stdout, "each call from the local machine credential store and refreshes the token automatically.\n")
	fmt.Fprintf(stdout, "No env var setup is needed. Restart the agent to route tool calls through cloud HELM.\n")
}
