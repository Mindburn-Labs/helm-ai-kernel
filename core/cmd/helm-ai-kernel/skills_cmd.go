package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/skillpacks"
)

func init() {
	Register(Subcommand{Name: "skills", Usage: "Scan, install, export, and revoke HELM Skill Packs", RunFn: runSkillsCmd})
}

func runSkillsCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills <search|inspect|verify|scan|install|export|list|disable|revoke|receipt|marketplace|plugin> [args]")
		return 2
	}
	switch args[0] {
	case "search":
		return runSkillsSearch(args[1:], stdout, stderr)
	case "inspect":
		return runSkillsInspect(args[1:], stdout, stderr)
	case "verify", "scan":
		return runSkillsScan(args[1:], stdout, stderr)
	case "install":
		return runSkillsInstall(args[1:], stdout, stderr)
	case "export":
		return runSkillsExport(args[1:], stdout, stderr)
	case "list":
		return runSkillsList(args[1:], stdout, stderr)
	case "disable":
		return runSkillsDisable(args[1:], stdout, stderr)
	case "revoke":
		return runSkillsRevoke(args[1:], stdout, stderr)
	case "receipt":
		return runSkillsReceipt(args[1:], stdout, stderr)
	case "marketplace":
		return runSkillsMarketplace(args[1:], stdout, stderr)
	case "plugin":
		return runSkillsPlugin(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown skills command: %s\n", args[0])
		return 2
	}
}

func runSkillsSearch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	query := ""
	if fs.NArg() > 0 {
		query = fs.Arg(0)
	}
	skills, err := skillpacks.ListCatalog(query)
	if err != nil {
		fmt.Fprintf(stderr, "skills search error: %v\n", err)
		return 1
	}
	if *jsonOut {
		return writeSkillsJSON(stdout, map[string]any{"skills": skills, "count": len(skills)})
	}
	for _, skill := range skills {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", skill.ID, skill.Status, skill.ScopeDefault, skill.Risk)
	}
	return 0
}

func runSkillsInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	ref, parseArgs := leadingRef(args)
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	if ref == "" && fs.NArg() > 0 {
		ref = fs.Arg(0)
	}
	if ref == "" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills inspect <skill_ref> --json")
		return 2
	}
	pack, err := skillpacks.Load(ref)
	if err != nil {
		fmt.Fprintf(stderr, "skills inspect error: %v\n", err)
		return 1
	}
	payload := map[string]any{
		"manifest":           pack.Manifest,
		"authority_boundary": "This skill does not grant tool permissions.",
		"projection_targets": pack.Manifest.AgentTargets,
	}
	if *jsonOut {
		return writeSkillsJSON(stdout, payload)
	}
	fmt.Fprintf(stdout, "%s %s\n%s\nThis skill does not grant tool permissions.\n", pack.Manifest.ID, pack.Manifest.Version, pack.Manifest.Description)
	return 0
}

func runSkillsScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	ref, parseArgs := leadingRef(args)
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	if ref == "" && fs.NArg() > 0 {
		ref = fs.Arg(0)
	}
	if ref == "" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills scan <path_or_ref> --json")
		return 2
	}
	result, err := skillpacks.ScanPath(ref)
	if err != nil {
		fmt.Fprintf(stderr, "skills scan error: %v\n", err)
		return 1
	}
	if *jsonOut {
		code := writeSkillsJSON(stdout, result)
		if code != 0 {
			return code
		}
		if result.Verdict != skillpacks.VerdictAllow {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "%s %s %s\n", result.SkillID, result.Verdict, result.ReasonCode)
	if result.Verdict == skillpacks.VerdictDeny {
		return 1
	}
	return 0
}

func runSkillsInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "codex", "agent projection target")
	scope := fs.String("scope", "repo", "install scope")
	repoRoot := fs.String("repo-root", "", "repo root")
	jsonOut := fs.Bool("json", false, "emit JSON")
	ref, parseArgs := leadingRef(args)
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	if ref == "" && fs.NArg() > 0 {
		ref = fs.Arg(0)
	}
	if ref == "" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills install <skill_ref> --agent codex --scope repo")
		return 2
	}
	pack, err := skillpacks.Load(ref)
	if err != nil {
		fmt.Fprintf(stderr, "skills install error: %v\n", err)
		return 1
	}
	result, err := skillpacks.Install(pack, skillpacks.InstallRequest{Agent: *agent, Scope: *scope, RepoRoot: *repoRoot})
	if err != nil {
		fmt.Fprintf(stderr, "skills install error: %v\n", err)
		return 1
	}
	if *jsonOut {
		code := writeSkillsJSON(stdout, result)
		if code != 0 {
			return code
		}
		if result.Verdict != skillpacks.VerdictAllow {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "Skill %s %s (%s)\n", result.SkillID, result.Status, result.Verdict)
	if result.Verdict != skillpacks.VerdictAllow {
		return 1
	}
	return 0
}

func runSkillsExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "codex-skill", "codex-skill or codex-plugin")
	output := fs.String("output", "", "output directory")
	jsonOut := fs.Bool("json", false, "emit JSON")
	ref, parseArgs := leadingRef(args)
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	if ref == "" && fs.NArg() > 0 {
		ref = fs.Arg(0)
	}
	if ref == "" || *output == "" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills export <skill_ref> --format codex-plugin --output <dir>")
		return 2
	}
	pack, err := skillpacks.Load(ref)
	if err != nil {
		fmt.Fprintf(stderr, "skills export error: %v\n", err)
		return 1
	}
	result, err := skillpacks.Export(pack, *format, *output)
	if err != nil {
		fmt.Fprintf(stderr, "skills export error: %v\n", err)
		return 1
	}
	if *jsonOut {
		return writeSkillsJSON(stdout, result)
	}
	fmt.Fprintf(stdout, "Exported %s to %s\n", ref, *output)
	return 0
}

func runSkillsList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoRoot := fs.String("repo-root", "", "repo root")
	jsonOut := fs.Bool("json", false, "emit JSON")
	_ = fs.String("scope", "repo", "scope")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	result, err := skillpacks.ListInstalled(*repoRoot)
	if err != nil {
		fmt.Fprintf(stderr, "skills list error: %v\n", err)
		return 1
	}
	if *jsonOut {
		return writeSkillsJSON(stdout, result)
	}
	return writeSkillsJSON(stdout, result)
}

func runSkillsDisable(args []string, stdout, stderr io.Writer) int {
	return runSkillStatusMutation("disable", args, stdout, stderr)
}

func runSkillsRevoke(args []string, stdout, stderr io.Writer) int {
	return runSkillStatusMutation("revoke", args, stdout, stderr)
}

func runSkillStatusMutation(action string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("skills "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoRoot := fs.String("repo-root", "", "repo root")
	jsonOut := fs.Bool("json", false, "emit JSON")
	ref, parseArgs := leadingRef(args)
	if err := fs.Parse(parseArgs); err != nil {
		return 2
	}
	if ref == "" && fs.NArg() > 0 {
		ref = fs.Arg(0)
	}
	if ref == "" {
		fmt.Fprintf(stderr, "Usage: helm-ai-kernel skills %s <skill_ref>\n", action)
		return 2
	}
	var (
		receipt skillpacks.Receipt
		err     error
	)
	if action == "disable" {
		receipt, err = skillpacks.Disable(*repoRoot, ref)
	} else {
		receipt, err = skillpacks.Revoke(*repoRoot, ref)
	}
	if err != nil {
		fmt.Fprintf(stderr, "skills %s error: %v\n", action, err)
		return 1
	}
	if *jsonOut {
		return writeSkillsJSON(stdout, receipt)
	}
	fmt.Fprintf(stdout, "%s %s %s\n", action, ref, receipt.ID)
	return 0
}

func runSkillsReceipt(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills receipt <receipt_path> --json")
		return 2
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "skills receipt error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}

func runSkillsMarketplace(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills marketplace <init|add>")
		return 2
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("skills marketplace init", flag.ContinueOnError)
		fs.SetOutput(stderr)
		repoRoot := fs.String("repo-root", "", "repo root")
		jsonOut := fs.Bool("json", false, "emit JSON")
		_ = fs.String("scope", "repo", "scope")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		path, err := skillpacks.MarketplaceInit(*repoRoot)
		if err != nil {
			fmt.Fprintf(stderr, "skills marketplace init error: %v\n", err)
			return 1
		}
		if *jsonOut {
			return writeSkillsJSON(stdout, map[string]string{"path": path})
		}
		fmt.Fprintln(stdout, path)
		return 0
	case "add":
		fs := flag.NewFlagSet("skills marketplace add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		repoRoot := fs.String("repo-root", "", "repo root")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills marketplace add <plugin_path>")
			return 2
		}
		entry, err := skillpacks.MarketplaceAdd(*repoRoot, fs.Arg(0))
		if err != nil {
			fmt.Fprintf(stderr, "skills marketplace add error: %v\n", err)
			return 1
		}
		if *jsonOut {
			return writeSkillsJSON(stdout, entry)
		}
		fmt.Fprintf(stdout, "%s\t%s\n", entry.ID, entry.Path)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown skills marketplace command: %s\n", args[0])
		return 2
	}
}

func runSkillsPlugin(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel skills plugin <inspect|scan|export>")
		return 2
	}
	switch args[0] {
	case "inspect", "scan":
		if len(args) < 2 {
			fmt.Fprintf(stderr, "Usage: helm-ai-kernel skills plugin %s <plugin_path>\n", args[0])
			return 2
		}
		data, err := os.ReadFile(filepath.Join(args[1], ".codex-plugin", "plugin.json"))
		if err != nil {
			fmt.Fprintf(stderr, "skills plugin %s error: %v\n", args[0], err)
			return 1
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			fmt.Fprintf(stderr, "skills plugin %s error: %v\n", args[0], err)
			return 1
		}
		payload["helm_mcp_status"] = "pending_quarantined"
		return writeSkillsJSON(stdout, payload)
	case "export":
		return runSkillsExport(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown skills plugin command: %s\n", args[0])
		return 2
	}
}

func writeSkillsJSON(stdout io.Writer, payload any) int {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(stdout, `{"error":%q}`+"\n", err.Error())
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}

func leadingRef(args []string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args
	}
	out := make([]string, 0, len(args)-1)
	out = append(out, args[1:]...)
	return args[0], out
}
