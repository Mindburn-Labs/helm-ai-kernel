package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

func setupIncludesMCP(target string) bool {
	return target != "hermes" && target != "deepseek"
}

func setupClientCommand(target string) string {
	switch target {
	case "claude-code":
		return "claude"
	case "hermes":
		return "hermes"
	case "deepseek":
		return "dsh"
	default:
		return "codex"
	}
}

func installSetupMCP(opts setupOptions, bin string) error {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			if _, err := privateFileWritePath(setupClientConfigPath(opts), setupPrivateFileRoot(opts)); err != nil {
				return err
			}
		}
		return setupExecCommand(setupCommandDir(opts), "claude", "mcp", "add", "--transport", "stdio", "--scope", opts.Scope, setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio", "--data-dir", opts.DataDir)
	case "codex":
		if opts.Scope == "project" {
			return upsertCodexProjectMCP(setupClientConfigPath(opts), bin, opts.DataDir, setupPrivateFileRoot(opts))
		}
		return setupExecCommand(setupCommandDir(opts), "codex", "mcp", "add", setupMCPServerName, "--", bin, "mcp", "serve", "--transport", "stdio", "--data-dir", opts.DataDir)
	case "hermes":
		// Hermes MCP is unverified. The hop is the fail-closed shell hook.
		return nil
	case "deepseek":
		// DeepSeek MCP is out of scope. The hop is the Kernel hook + stock DSH bridge.
		return nil
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func removeSetupMCP(opts setupOptions) error {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			if _, err := privateFileWritePath(setupClientConfigPath(opts), setupPrivateFileRoot(opts)); err != nil {
				return err
			}
		}
		return setupExecCommand(setupCommandDir(opts), "claude", "mcp", "remove", "--scope", opts.Scope, setupMCPServerName)
	case "codex":
		if opts.Scope == "project" {
			return removeCodexProjectMCP(setupClientConfigPath(opts), setupPrivateFileRoot(opts))
		}
		return setupExecCommand(setupCommandDir(opts), "codex", "mcp", "remove", setupMCPServerName)
	case "hermes":
		return removeHermesMCP(setupClientConfigPath(opts), setupPrivateFileRoot(opts))
	case "deepseek":
		return nil
	default:
		return fmt.Errorf("unsupported target %q", opts.Target)
	}
}

func setupCommandDir(opts setupOptions) string {
	if opts.Scope == "project" {
		return opts.Workspace
	}
	return ""
}

func setupMCPInstalled(opts setupOptions, path, bin string) bool {
	if filepath.Clean(path) != filepath.Clean(setupClientConfigPath(opts)) {
		return false
	}
	readPath := path
	if root := setupPrivateFileRoot(opts); root != "" {
		resolved, err := privateFileWritePath(path, root)
		if err != nil {
			return false
		}
		readPath = resolved
	}
	switch opts.Target {
	case "claude-code":
		return claudeMCPInstalled(readPath, bin, opts.DataDir)
	case "codex":
		return codexMCPInstalled(readPath, bin, opts.DataDir)
	case "hermes":
		return hermesMCPInstalled(readPath, bin, opts.DataDir)
	case "deepseek":
		return false
	default:
		return false
	}
}

func setupClientConfigPath(opts setupOptions) string {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".mcp.json")
		}
		return setupUserPath(".claude.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".codex", "config.toml")
		}
		return setupUserPath(".codex", "config.toml")
	case "hermes":
		return hermesConfigPath(opts)
	case "deepseek":
		return deepseekProfilePath(opts)
	default:
		return ""
	}
}

func upsertCodexProjectMCP(path, bin, dataDir, allowedRoot string) error {
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
	block := fmt.Sprintf("[mcp_servers.%s]\ncommand = %q\nargs = [\"mcp\", \"serve\", \"--transport\", \"stdio\", \"--data-dir\", %q]\n", setupMCPServerName, bin, dataDir)
	next := strings.TrimRight(current, "\n")
	if next != "" {
		next += "\n\n"
	}
	next += block
	if err := validateCodexProjectTOML(next); err != nil {
		return fmt.Errorf("validate updated Codex config: %w", err)
	}
	return writePrivateFileAtomic(path, []byte(next), allowedRoot)
}

func removeCodexProjectMCP(path, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateCodexProjectTOML(string(raw)); err != nil {
		return fmt.Errorf("parse existing Codex config: %w", err)
	}
	next := strings.TrimRight(removeTOMLTable(string(raw), "[mcp_servers."+setupMCPServerName+"]"), "\n") + "\n"
	if err := validateCodexProjectTOML(next); err != nil {
		return fmt.Errorf("validate updated Codex config: %w", err)
	}
	return writePrivateFileAtomic(path, []byte(next), allowedRoot)
}

type codexProjectConfig struct {
	MCPServers map[string]codexMCPServer `toml:"mcp_servers"`
}

type codexMCPServer struct {
	Command string   `toml:"command,omitempty"`
	Args    []string `toml:"args,omitempty"`
	// Remote HTTP transport fields (used by `connect`). BearerTokenEnvVar names
	// the environment variable holding the bearer; the literal token is never
	// written into a client config.
	URL               string `toml:"url,omitempty"`
	BearerTokenEnvVar string `toml:"bearer_token_env_var,omitempty"`
}

type claudeMCPConfig struct {
	MCPServers map[string]claudeMCPServer `json:"mcpServers"`
}

type claudeMCPServer struct {
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// Remote HTTP transport fields (used by `connect`). Headers reference a
	// bearer via env-var expansion (e.g. Bearer ${HELM_MACHINE_TOKEN}); the
	// literal token is never written into a client config.
	Type    string            `json:"type,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func validateCodexProjectTOML(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var config map[string]any
	_, err := toml.Decode(raw, &config)
	return err
}

// codexProjectTrustPending reports whether a project-scoped Codex workspace
// has NOT been recorded as trusted in ~/.codex/config.toml. Codex only loads a
// project-scoped .codex/config.toml (and its MCP server + hook) once the
// project's trust_level is "trusted"; until then a written config is inert, so
// setup/status must not report it as an effective install.
func codexProjectTrustPending(workspace string) bool {
	abs, err := filepath.Abs(workspace)
	if err != nil {
		abs = workspace
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	home := homeDirOrEmpty()
	if home == "" {
		// Without an absolute home we cannot read recorded trust; fail closed.
		return true
	}
	userConfig := filepath.Join(home, ".codex", "config.toml")
	raw, err := os.ReadFile(userConfig)
	if err != nil {
		// No user-level Codex config means no recorded trust for this project.
		return true
	}
	var config struct {
		Projects map[string]struct {
			TrustLevel string `toml:"trust_level"`
		} `toml:"projects"`
	}
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return true
	}
	if entry, ok := config.Projects[abs]; ok && strings.EqualFold(entry.TrustLevel, "trusted") {
		return false
	}
	return true
}

func claudeMCPInstalled(path, bin, dataDir string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var config claudeMCPConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return false
	}
	server, ok := config.MCPServers[setupMCPServerName]
	return ok && server.Command == bin && equalSetupStrings(server.Args, setupMCPArgs(dataDir))
}

func codexMCPInstalled(path, bin, dataDir string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var config codexProjectConfig
	if _, err := toml.Decode(string(raw), &config); err != nil {
		return false
	}
	server, ok := config.MCPServers[setupMCPServerName]
	if !ok || server.Command != bin {
		return false
	}
	return equalSetupStrings(server.Args, setupMCPArgs(dataDir))
}

func setupMCPArgs(dataDir string) []string {
	return []string{"mcp", "serve", "--transport", "stdio", "--data-dir", dataDir}
}

// connectAtomicWrite is the atomic file writer used by the remote MCP config
// writers. It is a package var so tests can exercise fail-closed rollback by
// injecting a write error.
var connectAtomicWrite = writePrivateFileAtomic

// remoteClaudeServer builds a Claude remote HTTP MCP server entry whose bearer
// is supplied at runtime via env-var expansion; the literal token is never
// embedded in the config.
func remoteClaudeServer(mcpURL, tokenEnvVar string) claudeMCPServer {
	return claudeMCPServer{
		Type: "http",
		URL:  mcpURL,
		Headers: map[string]string{
			"Authorization": "Bearer ${" + tokenEnvVar + "}",
		},
	}
}

// writeRemoteClaudeMCP merges a remote HTTP HELM MCP server into a Claude client
// config, preserving any other servers, and writes it atomically. The bearer is
// referenced by env var only.
func writeRemoteClaudeMCP(path, mcpURL, tokenEnvVar, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	entry, err := structToObject(remoteClaudeServer(mcpURL, tokenEnvVar))
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

// writeRemoteCodexMCP upserts a remote HTTP HELM MCP server into a Codex config,
// preserving any other tables, and writes it atomically. The bearer is
// referenced by env var only.
func writeRemoteCodexMCP(path, mcpURL, tokenEnvVar, allowedRoot string) error {
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
	block := fmt.Sprintf("[mcp_servers.%s]\nurl = %q\nbearer_token_env_var = %q\n", setupMCPServerName, mcpURL, tokenEnvVar)
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

func structToObject(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func equalSetupStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func removeTOMLTable(input, table string) string {
	lines := strings.Split(input, "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == table {
			skipping = true
			continue
		}
		if skipping && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = false
		}
		if !skipping {
			out = append(out, line)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}
