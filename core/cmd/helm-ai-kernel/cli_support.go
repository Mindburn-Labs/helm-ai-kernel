package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type cliSupportMatrix struct {
	DirectSetup       []string `json:"direct_setup"`
	ConfigPrint       []string `json:"config_print"`
	Bundle            []string `json:"bundle"`
	WrapperExamples   []string `json:"wrapper_examples"`
	FrameworkAdapters []string `json:"framework_adapters"`
}

func supportMatrix() cliSupportMatrix {
	return cliSupportMatrix{
		DirectSetup:       []string{"claude-code", "codex"},
		ConfigPrint:       []string{"cursor", "windsurf", "vscode"},
		Bundle:            []string{"claude-desktop"},
		WrapperExamples:   []string{"openclaw", "hermes", "mastra", "browser-use", "tinyfish", "e2b", "composio"},
		FrameworkAdapters: []string{"LangGraph", "LangChain", "CrewAI", "OpenAI Agents SDK", "AutoGen/AG2", "Semantic Kernel", "PydanticAI", "LlamaIndex", "LiteLLM", "n8n", "Zapier", "raw MCP"},
	}
}

func printFrontDoor(out io.Writer) {
	fmt.Fprintf(out, "%sHELM AI Kernel%s %s (%s)\n\n", ColorBold, ColorReset, displayVersion(), displayCommit())
	fmt.Fprintln(out, "Start:")
	fmt.Fprintln(out, "  helm-ai-kernel quickstart")
	fmt.Fprintln(out, "  helm-ai-kernel setup claude-code --yes")
	fmt.Fprintln(out, "  helm-ai-kernel setup codex --yes")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Inspect:")
	fmt.Fprintln(out, "  helm-ai-kernel scan --path . --preview out.md")
	fmt.Fprintln(out, "  helm-ai-kernel receipts tail --agent <id>")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Operate:")
	fmt.Fprintln(out, "  helm-ai-kernel mcp authorize-call --server-id <id> --tool-name <tool>")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "More:")
	fmt.Fprintln(out, "  helm-ai-kernel help --all")
	fmt.Fprintln(out, "  helm-ai-kernel help --json")
}

func printSupportMatrix(out io.Writer) {
	matrix := supportMatrix()
	fmt.Fprintln(out, "Supported clients and adapters:")
	fmt.Fprintf(out, "  Direct setup:       %s\n", strings.Join(matrix.DirectSetup, ", "))
	fmt.Fprintf(out, "  Config print:       %s\n", strings.Join(matrix.ConfigPrint, ", "))
	fmt.Fprintf(out, "  Bundle:             %s\n", strings.Join(matrix.Bundle, ", "))
	fmt.Fprintf(out, "  Wrapper examples:   %s\n", strings.Join(matrix.WrapperExamples, ", "))
	fmt.Fprintf(out, "  Framework adapters: %s\n", strings.Join(matrix.FrameworkAdapters, ", "))
}

func writeSupportMatrixJSON(out io.Writer) int {
	if err := json.NewEncoder(out).Encode(supportMatrix()); err != nil {
		return 1
	}
	return 0
}

type cliVersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

func runVersionCommand(args []string, stdout, _ io.Writer) int {
	if len(args) == 1 && args[0] == "--json" {
		return writeVersionJSON(stdout)
	}
	fmt.Fprintf(stdout, "%sHELM AI Kernel%s %s (%s)\n", ColorBold, ColorReset, displayVersion(), displayCommit())
	fmt.Fprintf(stdout, "  Report Schema:          %s\n", reportSchemaVersion)
	fmt.Fprintf(stdout, "  EvidencePack Schema:    1\n")
	fmt.Fprintf(stdout, "  Compatibility Schema:   1\n")
	fmt.Fprintf(stdout, "  MCP Bundle Schema:      1\n")
	fmt.Fprintf(stdout, "  Build Time:             %s\n", displayBuildTime())
	return 0
}

func writeVersionJSON(out io.Writer) int {
	if err := json.NewEncoder(out).Encode(cliVersionInfo{
		Version:   displayVersion(),
		Commit:    displayCommit(),
		BuildTime: displayBuildTime(),
	}); err != nil {
		return 1
	}
	return 0
}

func runCompletionCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		printCompletionUsage(stderr)
		return 2
	}
	script, ok := completionScript(args[0])
	if !ok {
		fmt.Fprintf(stderr, "completion: unsupported shell %q\n", args[0])
		printCompletionUsage(stderr)
		return 2
	}
	if _, err := io.WriteString(stdout, script); err != nil {
		return 1
	}
	return 0
}

func printCompletionUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: helm-ai-kernel completion <bash|zsh|fish|powershell>")
}

func completionScript(shell string) (string, bool) {
	words := completionWords()
	switch shell {
	case "bash":
		return bashCompletionScript(strings.Join(words, " ")), true
	case "zsh":
		return zshCompletionScript(words), true
	case "fish":
		return fishCompletionScript(words), true
	case "powershell":
		return powerShellCompletionScript(words), true
	default:
		return "", false
	}
}

func bashCompletionScript(words string) string {
	return fmt.Sprintf(`# bash completion for helm-ai-kernel
_helm_ai_kernel_completion() {
  local cur
  cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W %q -- "$cur") )
}
complete -F _helm_ai_kernel_completion helm-ai-kernel
`, words)
}

func zshCompletionScript(words []string) string {
	var script strings.Builder
	script.WriteString("#compdef helm-ai-kernel\n\n")
	script.WriteString("_helm_ai_kernel_completion() {\n")
	script.WriteString("  local -a commands\n")
	script.WriteString("  commands=(\n")
	for _, word := range words {
		fmt.Fprintf(&script, "    %q\n", word)
	}
	script.WriteString("  )\n")
	script.WriteString("  _describe -t commands 'helm-ai-kernel command' commands\n")
	script.WriteString("}\n\n")
	script.WriteString("compdef _helm_ai_kernel_completion helm-ai-kernel\n")
	return script.String()
}

func fishCompletionScript(words []string) string {
	var script strings.Builder
	script.WriteString("# fish completion for helm-ai-kernel\n")
	script.WriteString("complete -c helm-ai-kernel -f\n")
	for _, word := range words {
		fmt.Fprintf(&script, "complete -c helm-ai-kernel -n '__fish_use_subcommand' -a %q\n", word)
	}
	return script.String()
}

func powerShellCompletionScript(words []string) string {
	var script strings.Builder
	script.WriteString("Register-ArgumentCompleter -Native -CommandName helm-ai-kernel -ScriptBlock {\n")
	script.WriteString("  param($wordToComplete, $commandAst, $cursorPosition)\n")
	script.WriteString("  @(\n")
	for _, word := range words {
		fmt.Fprintf(&script, "    %s\n", powerShellQuote(word))
	}
	script.WriteString("  ) | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {\n")
	script.WriteString("    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)\n")
	script.WriteString("  }\n")
	script.WriteString("}\n")
	return script.String()
}

func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
