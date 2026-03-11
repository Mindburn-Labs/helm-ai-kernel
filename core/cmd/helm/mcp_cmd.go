package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// runMCPCmd implements `helm mcp` — MCP server distribution and management.
//
// Exit codes:
//
//	0 = success
//	2 = config error
func runMCPCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm mcp <serve|install|pack|print-config> [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Subcommands:")
		fmt.Fprintln(stderr, "  serve         Start the HELM MCP server (stdio or remote HTTP)")
		fmt.Fprintln(stderr, "  install       Install HELM MCP server for a client")
		fmt.Fprintln(stderr, "  pack          Generate a .mcpb bundle for desktop clients")
		fmt.Fprintln(stderr, "  print-config  Print MCP config for a specific client")
		return 2
	}

	switch args[0] {
	case "serve":
		return runMCPServe(args[1:], stdout, stderr)
	case "install":
		return runMCPInstall(args[1:], stdout, stderr)
	case "pack":
		return runMCPPack(args[1:], stdout, stderr)
	case "print-config":
		return runMCPPrintConfig(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm mcp <serve|install|pack|print-config> [flags]")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Subcommands:")
		fmt.Fprintln(stdout, "  serve         Start the HELM MCP server (stdio or remote HTTP)")
		fmt.Fprintln(stdout, "  install       Install HELM MCP server for a client")
		fmt.Fprintln(stdout, "  pack          Generate a .mcpb bundle for desktop clients")
		fmt.Fprintln(stdout, "  print-config  Print MCP config for a specific client")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown mcp subcommand: %s\n", args[0])
		return 2
	}
}

func runMCPServe(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		transport string
		port      int
		authMode  string
	)

	cmd.StringVar(&transport, "transport", "stdio", "Transport: stdio, http")
	cmd.IntVar(&port, "port", 9100, "Port for HTTP transport")
	cmd.StringVar(&authMode, "auth", "none", "Auth mode: none, static-header, oauth")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	switch transport {
	case "stdio":
		if authMode != "none" {
			fmt.Fprintln(stderr, "Error: stdio transport only supports --auth none")
			return 2
		}
		if err := serveLocalMCPStdio(os.Stdin, stdout); err != nil {
			fmt.Fprintf(stderr, "Error: MCP stdio server failed: %v\n", err)
			return 2
		}
		return 0
	case "http":
		server, err := newLocalMCPHTTPServer(port, authMode)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "\n%s🔌 HELM MCP Server%s\n", ColorBold+ColorBlue, ColorReset)
		fmt.Fprintf(stdout, "   Transport: %s\n", transport)
		fmt.Fprintf(stdout, "   Port: %d\n", port)
		fmt.Fprintf(stdout, "   Auth: %s\n\n", authMode)
		fmt.Fprintf(stdout, "Serving remote HTTP MCP at http://localhost:%d/mcp\n", port)
		if err := server.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 2
		}
		return 0
	default:
		fmt.Fprintf(stderr, "Error: unknown transport %q (valid: stdio, http)\n", transport)
		return 2
	}
}

func runMCPInstall(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp install", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var client string
	cmd.StringVar(&client, "client", "", "Target client: claude-code (REQUIRED)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if client == "" {
		fmt.Fprintln(stderr, "Error: --client is required (claude-code)")
		return 2
	}

	switch client {
	case "claude-code":
		return generateClaudeCodePlugin(stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Error: unknown client %q for install (supported: claude-code)\n", client)
		fmt.Fprintln(stderr, "For other clients, use 'helm mcp print-config --client <name>'")
		return 2
	}
}

func generateClaudeCodePlugin(stdout, stderr io.Writer) int {
	// Determine the helm binary path
	helmBin, err := os.Executable()
	if err != nil {
		helmBin = "helm"
	}

	pluginDir := "helm-mcp-plugin"
	if err := os.MkdirAll(pluginDir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error creating plugin dir: %v\n", err)
		return 2
	}

	// plugin.json — Claude Code plugin manifest
	pluginJSON := map[string]any{
		"name":        "helm-governance",
		"version":     strings.TrimPrefix(displayVersion(), "v"),
		"description": "HELM Execution Authority — governed tool execution with receipts and EvidencePack",
		"author":      "Mindburn Labs",
		"homepage":    "https://github.com/Mindburn-Labs/helm-oss",
	}
	data, _ := json.MarshalIndent(pluginJSON, "", "  ")
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), data, 0644); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	// .mcp.json — MCP server definition (auto-starts when plugin is enabled)
	mcpJSON := map[string]any{
		"mcpServers": map[string]any{
			"helm-governance": map[string]any{
				"command": helmBin,
				"args":    []string{"mcp", "serve", "--transport", "stdio"},
				"env":     map[string]string{},
			},
		},
	}
	mcpData, _ := json.MarshalIndent(mcpJSON, "", "  ")
	if err := os.WriteFile(filepath.Join(pluginDir, ".mcp.json"), mcpData, 0644); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "%s✅ Claude Code plugin generated%s\n\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "  Directory: %s/\n", pluginDir)
	fmt.Fprintf(stdout, "  Files:     plugin.json, .mcp.json\n\n")
	fmt.Fprintf(stdout, "  The MCP server auto-starts when the plugin is enabled.\n")
	fmt.Fprintf(stdout, "  Binary:    %s mcp serve --transport stdio\n\n", helmBin)
	fmt.Fprintln(stdout, "  Install:")
	fmt.Fprintln(stdout, "    claude plugin install ./helm-mcp-plugin")
	fmt.Fprintln(stdout, "")

	return 0
}

func runMCPPack(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp pack", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		client string
		out    string
	)

	cmd.StringVar(&client, "client", "", "Target client: claude-desktop (REQUIRED)")
	cmd.StringVar(&out, "out", "", "Output .mcpb file path (REQUIRED)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if client == "" || out == "" {
		fmt.Fprintln(stderr, "Error: --client and --out are required")
		fmt.Fprintln(stderr, "Usage: helm mcp pack --client claude-desktop --out helm.mcpb")
		return 2
	}

	if client != "claude-desktop" {
		fmt.Fprintf(stderr, "Error: --client must be 'claude-desktop' for .mcpb packaging\n")
		return 2
	}

	return generateMCPBundle(out, stdout, stderr)
}

func generateMCPBundle(outPath string, stdout, stderr io.Writer) int {
	// Create bundle directory structure
	bundleDir := outPath + ".tmp"
	defer os.RemoveAll(bundleDir)

	serverDir := filepath.Join(bundleDir, "server")
	if err := os.MkdirAll(serverDir, 0750); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	// Determine current platform binary name
	binaryName := "helm"
	if runtime.GOOS == "windows" {
		binaryName = "helm.exe"
	}

	// manifest.json — MCPB bundle manifest
	// See: https://github.com/modelcontextprotocol/mcpb/blob/main/MANIFEST.md
	manifest := map[string]any{
		"manifest_version": "1.0",
		"name":             "helm-governance",
		"version":          strings.TrimPrefix(displayVersion(), "v"),
		"description":      "HELM Execution Authority — governed tool execution with receipts and EvidencePack",
		"author": map[string]string{
			"name":    "Mindburn Labs",
			"url":     "https://github.com/Mindburn-Labs/helm-oss",
			"support": "https://github.com/Mindburn-Labs/helm-oss/issues",
		},
		"server": map[string]any{
			"type":    "binary",
			"command": "./" + binaryName,
			"args":    []string{"mcp", "serve", "--transport", "stdio"},
		},
		"platform_overrides": map[string]any{
			"win32": map[string]any{
				"server": map[string]any{
					"command": "./helm.exe",
				},
			},
		},
	}

	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), manifestData, 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing manifest: %v\n", err)
		return 2
	}

	// Copy current binary to server/
	helmBin, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "Error finding helm binary: %v\n", err)
		return 2
	}

	binData, err := os.ReadFile(helmBin)
	if err != nil {
		fmt.Fprintf(stderr, "Error reading helm binary: %v\n", err)
		return 2
	}

	if err := os.WriteFile(filepath.Join(serverDir, binaryName), binData, 0755); err != nil {
		fmt.Fprintf(stderr, "Error writing binary to bundle: %v\n", err)
		return 2
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0750); err != nil && filepath.Dir(outPath) != "." {
		fmt.Fprintf(stderr, "Error preparing bundle output: %v\n", err)
		return 2
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error creating bundle: %v\n", err)
		return 2
	}
	defer outFile.Close()

	zipWriter := zip.NewWriter(outFile)
	if err := writeBundleZipEntry(zipWriter, "manifest.json", manifestData, 0644); err != nil {
		fmt.Fprintf(stderr, "Error writing manifest to bundle: %v\n", err)
		return 2
	}
	if err := writeBundleZipEntry(zipWriter, filepath.ToSlash(filepath.Join("server", binaryName)), binData, 0755); err != nil {
		fmt.Fprintf(stderr, "Error writing binary to bundle: %v\n", err)
		return 2
	}
	if err := zipWriter.Close(); err != nil {
		fmt.Fprintf(stderr, "Error finalizing bundle: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "%s✅ MCPB bundle generated%s\n\n", ColorBold+ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "  Bundle:    %s\n", outPath)
	fmt.Fprintf(stdout, "  Manifest:  manifest.json\n")
	fmt.Fprintf(stdout, "  Server:    server/%s (type=binary)\n", binaryName)
	fmt.Fprintf(stdout, "  Platform:  %s/%s (+ win32 override)\n\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintln(stdout, "  To install in Claude Desktop:")
	fmt.Fprintf(stdout, "    Double-click %s or drag into Claude Desktop\n\n", outPath)
	fmt.Fprintln(stdout, "  For cross-platform bundles, build for each target OS/arch")
	fmt.Fprintln(stdout, "  and include all binaries in server/ with platform_overrides.")
	fmt.Fprintln(stdout, "")

	return 0
}

func writeBundleZipEntry(zw *zip.Writer, name string, data []byte, mode os.FileMode) error {
	header := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	header.SetMode(mode)
	header.Modified = time.Unix(0, 0)

	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func runMCPPrintConfig(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("mcp print-config", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var client string
	cmd.StringVar(&client, "client", "", "Client: windsurf, codex, vscode, cursor (REQUIRED)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if client == "" {
		fmt.Fprintln(stderr, "Error: --client is required (windsurf, codex, vscode, cursor)")
		return 2
	}

	helmBin, err := os.Executable()
	if err != nil {
		helmBin = "helm"
	}

	switch client {
	case "windsurf":
		config := map[string]any{
			"mcpServers": map[string]any{
				"helm-governance": map[string]any{
					"command":   helmBin,
					"args":      []string{"mcp", "serve", "--transport", "stdio"},
					"transport": "stdio",
				},
			},
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		fmt.Fprintf(stdout, "# Windsurf MCP Configuration\n")
		fmt.Fprintf(stdout, "# Add to your Windsurf settings or use MCP install:\n\n")
		fmt.Fprintln(stdout, string(data))
		fmt.Fprintf(stdout, "\n# Alternative: remote HTTP\n")
		fmt.Fprintf(stdout, "# Start: helm mcp serve --transport http --port 9100\n")
		fmt.Fprintf(stdout, "# URL:   http://localhost:9100/mcp\n")

	case "codex":
		fmt.Fprintf(stdout, "# Codex MCP Installation\n")
		fmt.Fprintf(stdout, "# Run this command to add the HELM MCP server:\n\n")
		fmt.Fprintf(stdout, "codex mcp add helm-governance -- %s mcp serve --transport stdio\n\n", helmBin)
		fmt.Fprintf(stdout, "# Or for remote HTTP:\n")
		fmt.Fprintf(stdout, "# Start: helm mcp serve --transport http --port 9100\n")
		fmt.Fprintf(stdout, "# codex mcp add helm-governance --url http://localhost:9100/mcp\n")

	case "vscode":
		config := map[string]any{
			"mcp": map[string]any{
				"servers": map[string]any{
					"helm-governance": map[string]any{
						"command": helmBin,
						"args":    []string{"mcp", "serve", "--transport", "stdio"},
					},
				},
			},
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		fmt.Fprintf(stdout, "# VS Code MCP Configuration\n")
		fmt.Fprintf(stdout, "# Add to .vscode/settings.json:\n\n")
		fmt.Fprintln(stdout, string(data))

	case "cursor":
		config := map[string]any{
			"mcpServers": map[string]any{
				"helm-governance": map[string]any{
					"command": helmBin,
					"args":    []string{"mcp", "serve", "--transport", "stdio"},
				},
			},
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		fmt.Fprintf(stdout, "# Cursor MCP Configuration\n")
		fmt.Fprintf(stdout, "# Add to .cursor/mcp.json:\n\n")
		fmt.Fprintln(stdout, string(data))

	default:
		fmt.Fprintf(stderr, "Error: unknown client %q\n", client)
		fmt.Fprintln(stderr, "Supported: windsurf, codex, vscode, cursor")
		fmt.Fprintln(stderr, "For Claude Code: helm mcp install --client claude-code")
		fmt.Fprintln(stderr, "For Claude Desktop: helm mcp pack --client claude-desktop --out helm.mcpb")
		return 2
	}

	return 0
}

func init() {
	Register(Subcommand{Name: "mcp", Aliases: []string{}, Usage: "MCP server and distribution commands", RunFn: runMCPCmd})
}
