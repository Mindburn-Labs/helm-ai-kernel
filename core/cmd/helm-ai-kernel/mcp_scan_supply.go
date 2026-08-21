package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const mcpScanSchema = "helm-ai-kernel.mcp-scan.v1"

// mcpScanFinding is one inspect-only supply-chain or catalog finding.
// Scan never authorizes, ALLOWs, or writes registry state.
type mcpScanFinding struct {
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	ServerID    string `json:"server_id,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Source      string `json:"source,omitempty"`
	Description string `json:"description"`
}

type mcpScanSource struct {
	Kind string `json:"kind"`
	Path string `json:"path,omitempty"`
}

type mcpScanServer struct {
	ServerID  string   `json:"server_id"`
	Source    string   `json:"source,omitempty"`
	Command   string   `json:"command,omitempty"`
	URL       string   `json:"url,omitempty"`
	Pinned    bool     `json:"pinned"`
	PinKind   string   `json:"pin_kind,omitempty"`
	ToolNames []string `json:"tool_names,omitempty"`
}

type mcpScanV1Report struct {
	Schema         string           `json:"schema"`
	Sources        []mcpScanSource  `json:"sources"`
	Servers        []mcpScanServer  `json:"servers"`
	ServersScanned int              `json:"servers_scanned"`
	ToolsScanned   int              `json:"tools_scanned"`
	Findings       []mcpScanFinding `json:"findings"`
	MaxSeverity    string           `json:"max_severity"`
	Authorizes     bool             `json:"authorizes"`
	ExitCode       int              `json:"exit_code"`
}

type mcpConfigServer struct {
	ID        string
	Source    string
	Command   string
	Args      []string
	URL       string
	Pin       string
	PinKind   string
	ToolNames []string
}

type mcpClientConfigFile struct {
	MCPServers map[string]mcpClientServer `json:"mcpServers"`
	MCP        struct {
		Servers map[string]mcpClientServer `json:"servers"`
	} `json:"mcp"`
	Servers map[string]mcpClientServer `json:"servers"`
}

type mcpClientServer struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	URL       string            `json:"url"`
	Type      string            `json:"type"`
	SHA256    string            `json:"sha256"`
	Hash      string            `json:"hash"`
	Integrity string            `json:"integrity"`
	Digest    string            `json:"digest"`
	Pin       string            `json:"pin"`
	Headers   map[string]string `json:"headers"`
}

var knownMCPServerNames = []string{
	"github", "slack", "linear", "gmail", "filesystem", "postgres",
	"sqlite", "brave-search", "puppeteer", "memory", "everything",
}

func defaultMCPConfigPaths() []string {
	var paths []string
	cwd, err := os.Getwd()
	if err == nil {
		paths = append(paths,
			filepath.Join(cwd, ".mcp.json"),
			filepath.Join(cwd, ".cursor", "mcp.json"),
			filepath.Join(cwd, ".vscode", "mcp.json"),
			filepath.Join(cwd, "mcp.json"),
		)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".codex", "config.toml"),
		)
	}
	return paths
}

func collectMCPScanTargets(manifestPath, inspectPath string) (sources []mcpScanSource, servers []mcpConfigServer, tools []mcpScanManifest, err error) {
	if manifestPath != "" {
		m, loadErr := loadMCPScanManifest(manifestPath)
		if loadErr != nil {
			return nil, nil, nil, loadErr
		}
		sources = append(sources, mcpScanSource{Kind: "manifest", Path: manifestPath})
		tools = append(tools, *m)
		servers = append(servers, mcpConfigServer{
			ID:        m.ServerID,
			Source:    manifestPath,
			ToolNames: toolNamesFromManifest(m),
		})
	}
	if inspectPath != "" {
		found, loadErr := loadMCPScanPath(inspectPath)
		if loadErr != nil {
			return nil, nil, nil, loadErr
		}
		sources = append(sources, found.sources...)
		servers = append(servers, found.servers...)
		tools = append(tools, found.tools...)
	}
	if manifestPath == "" && inspectPath == "" {
		for _, p := range defaultMCPConfigPaths() {
			if _, statErr := os.Stat(p); statErr != nil {
				continue
			}
			found, loadErr := loadMCPScanPath(p)
			if loadErr != nil {
				// Unreadable configured files are findings, not a bind.
				sources = append(sources, mcpScanSource{Kind: "config", Path: p})
				continue
			}
			sources = append(sources, found.sources...)
			servers = append(servers, found.servers...)
			tools = append(tools, found.tools...)
		}
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Kind != sources[j].Kind {
			return sources[i].Kind < sources[j].Kind
		}
		return sources[i].Path < sources[j].Path
	})
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].ID != servers[j].ID {
			return servers[i].ID < servers[j].ID
		}
		return servers[i].Source < servers[j].Source
	})
	return sources, servers, tools, nil
}

type mcpScanLoaded struct {
	sources []mcpScanSource
	servers []mcpConfigServer
	tools   []mcpScanManifest
}

func loadMCPScanPath(path string) (mcpScanLoaded, error) {
	info, err := os.Stat(path)
	if err != nil {
		return mcpScanLoaded{}, err
	}
	if info.IsDir() {
		var loaded mcpScanLoaded
		entries, err := os.ReadDir(path)
		if err != nil {
			return mcpScanLoaded{}, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			if !isMCPScanConfigName(name) {
				continue
			}
			child, childErr := loadMCPScanFile(filepath.Join(path, name))
			if childErr != nil {
				continue
			}
			loaded.sources = append(loaded.sources, child.sources...)
			loaded.servers = append(loaded.servers, child.servers...)
			loaded.tools = append(loaded.tools, child.tools...)
		}
		return loaded, nil
	}
	return loadMCPScanFile(path)
}

func isMCPScanConfigName(name string) bool {
	switch strings.ToLower(name) {
	case "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp-scan.json":
		return true
	}
	return strings.HasSuffix(strings.ToLower(name), ".json")
}

func loadMCPScanFile(path string) (mcpScanLoaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mcpScanLoaded{}, err
	}
	var manifest mcpScanManifest
	if json.Unmarshal(data, &manifest) == nil && len(manifest.Tools) > 0 {
		if manifest.ServerID == "" {
			manifest.ServerID = "unknown"
		}
		return mcpScanLoaded{
			sources: []mcpScanSource{{Kind: "manifest", Path: path}},
			servers: []mcpConfigServer{{
				ID:        manifest.ServerID,
				Source:    path,
				ToolNames: toolNamesFromManifest(&manifest),
			}},
			tools: []mcpScanManifest{manifest},
		}, nil
	}
	servers, err := parseMCPClientServers(path, data)
	if err != nil {
		return mcpScanLoaded{}, err
	}
	return mcpScanLoaded{
		sources: []mcpScanSource{{Kind: "config", Path: path}},
		servers: servers,
	}, nil
}

func parseMCPClientServers(path string, data []byte) ([]mcpConfigServer, error) {
	var cfg mcpClientConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	merged := map[string]mcpClientServer{}
	for name, srv := range cfg.MCPServers {
		merged[name] = srv
	}
	for name, srv := range cfg.MCP.Servers {
		merged[name] = srv
	}
	for name, srv := range cfg.Servers {
		merged[name] = srv
	}
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]mcpConfigServer, 0, len(names))
	for _, name := range names {
		srv := merged[name]
		pin, kind := clientServerPin(srv)
		out = append(out, mcpConfigServer{
			ID:      name,
			Source:  path,
			Command: strings.TrimSpace(srv.Command),
			Args:    append([]string(nil), srv.Args...),
			URL:     strings.TrimSpace(srv.URL),
			Pin:     pin,
			PinKind: kind,
		})
	}
	return out, nil
}

func clientServerPin(srv mcpClientServer) (string, string) {
	switch {
	case strings.TrimSpace(srv.SHA256) != "":
		return strings.TrimSpace(srv.SHA256), "sha256"
	case strings.TrimSpace(srv.Integrity) != "":
		return strings.TrimSpace(srv.Integrity), "integrity"
	case strings.TrimSpace(srv.Digest) != "":
		return strings.TrimSpace(srv.Digest), "digest"
	case strings.TrimSpace(srv.Hash) != "":
		return strings.TrimSpace(srv.Hash), "hash"
	case strings.TrimSpace(srv.Pin) != "":
		return strings.TrimSpace(srv.Pin), "pin"
	default:
		return "", ""
	}
}

func toolNamesFromManifest(m *mcpScanManifest) []string {
	names := make([]string, 0, len(m.Tools))
	for _, tool := range m.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func supplyChainFindings(servers []mcpConfigServer) []mcpScanFinding {
	var findings []mcpScanFinding
	byName := map[string][]mcpConfigServer{}
	for _, srv := range servers {
		if srv.Command != "" || srv.URL != "" {
			if srv.Pin == "" {
				findings = append(findings, mcpScanFinding{
					Kind:        "missing_hash",
					Severity:    "medium",
					ServerID:    srv.ID,
					Subject:     firstNonEmptyScan(srv.Command, srv.URL),
					Source:      srv.Source,
					Description: "MCP server entry has no sha256/integrity/digest pin",
				})
			}
		}
		if shadowed, known := shadowedMCPName(srv.ID); shadowed {
			findings = append(findings, mcpScanFinding{
				Kind:        "shadowed_name",
				Severity:    "high",
				ServerID:    srv.ID,
				Subject:     known,
				Source:      srv.Source,
				Description: "Server name is an obvious shadow of a well-known MCP server",
			})
		}
		byName[strings.ToLower(srv.ID)] = append(byName[strings.ToLower(srv.ID)], srv)
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		group := byName[name]
		if len(group) < 2 {
			continue
		}
		cmds := map[string]struct{}{}
		for _, srv := range group {
			cmds[srv.Command+"|"+srv.URL] = struct{}{}
		}
		if len(cmds) < 2 {
			continue
		}
		findings = append(findings, mcpScanFinding{
			Kind:        "shadowed_name",
			Severity:    "high",
			ServerID:    group[0].ID,
			Subject:     name,
			Source:      group[0].Source,
			Description: "Same MCP server name is configured with different command or URL",
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Kind != findings[j].Kind {
			return findings[i].Kind < findings[j].Kind
		}
		if findings[i].ServerID != findings[j].ServerID {
			return findings[i].ServerID < findings[j].ServerID
		}
		return findings[i].Description < findings[j].Description
	})
	return findings
}

func shadowedMCPName(name string) (bool, string) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false, ""
	}
	for _, known := range knownMCPServerNames {
		if n == known {
			return false, ""
		}
		if editDistanceLE2(n, known) {
			return true, known
		}
	}
	return false, ""
}

func reportServers(servers []mcpConfigServer) []mcpScanServer {
	out := make([]mcpScanServer, 0, len(servers))
	for _, srv := range servers {
		out = append(out, mcpScanServer{
			ServerID:  srv.ID,
			Source:    srv.Source,
			Command:   srv.Command,
			URL:       srv.URL,
			Pinned:    srv.Pin != "",
			PinKind:   srv.PinKind,
			ToolNames: append([]string(nil), srv.ToolNames...),
		})
	}
	return out
}

func findingSeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func maxFindingSeverity(findings []mcpScanFinding) string {
	top := ""
	topRank := 0
	for _, f := range findings {
		if r := findingSeverityRank(f.Severity); r > topRank {
			topRank = r
			top = strings.ToLower(f.Severity)
		}
	}
	return top
}

func firstNonEmptyScan(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
