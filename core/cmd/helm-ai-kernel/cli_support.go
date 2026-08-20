package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
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
		DirectSetup:       []string{"claude-code", "codex", "hermes", "deepseek"},
		ConfigPrint:       []string{"cursor", "windsurf", "vscode"},
		Bundle:            []string{"claude-desktop"},
		WrapperExamples:   []string{"openclaw", "hermes", "mastra", "browser-use", "tinyfish", "e2b", "composio"},
		FrameworkAdapters: []string{"LangGraph", "LangChain", "CrewAI", "OpenAI Agents SDK", "AutoGen/AG2", "Semantic Kernel", "PydanticAI", "LlamaIndex", "LiteLLM", "n8n", "Zapier", "raw MCP"},
	}
}

func printFrontDoor(out io.Writer) {
	fmt.Fprintf(out, "%s %s (%s)\n\n", terminalTitle(out, "HELM AI Kernel"), displayVersion(), displayCommit())
	renderer := ui.NewRenderer(out, frontDoorCapabilities(out))
	renderer.WriteTimeline("Your first governed-agent run", []ui.Step{
		{
			Status: ui.StatusWait,
			Title:  "Launch local Kernel and browser Console",
			Detail: "helm-ai-kernel quickstart --console (requires a Console-including package; it stays loopback-only).",
		},
		{
			Status: ui.StatusWait,
			Title:  "Connect the coding agent you use",
			Detail: "helm-ai-kernel setup codex, helm-ai-kernel setup claude-code, or helm-ai-kernel setup hermes --scope user. Also setup deepseek --scope user. Interactive terminals show the scoped change before confirmation.",
		},
		{
			Status: ui.StatusWait,
			Title:  "Review live decisions when they need you",
			Detail: "helm-ai-kernel watch. Approve or deny only after the complete server-derived ceremony is shown.",
		},
	})
	renderer.WriteCompletion(ui.CompletionCard{
		Title: "Useful next commands",
		Fields: []ui.KeyValue{
			{Key: "Inspect", Value: "helm-ai-kernel scan --path . --preview out.md"},
			{Key: "Receipts", Value: "helm-ai-kernel receipts tail --agent <id>"},
			{Key: "Automation", Value: "helm-ai-kernel help --json"},
		},
		NextAction: "Run helm-ai-kernel help --all for every command.",
	})
}

func frontDoorCapabilities(out io.Writer) ui.Capabilities {
	file, ok := out.(*os.File)
	if !ok {
		return ui.Capabilities{Width: ui.DefaultTerminalWidth}
	}
	return ui.DetectCapabilities(os.Stdin, file, ui.TerminalOptions{
		Format: ui.FormatText,
		Color:  ui.ColorAuto,
	})
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

// runVersionFlag serves the `--version`/`-v` flag: a single scriptable line
// (or a JSON object with --json), so `helm-ai-kernel --version` can be read by
// a script or pasted into a bug report and matched against a release. The rich
// multi-line block stays behind the `version` subcommand.
func runVersionFlag(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0:
		fmt.Fprintln(stdout, displayVersion())
		return 0
	case len(args) == 1 && args[0] == "--json":
		return writeVersionJSON(stdout)
	default:
		fmt.Fprintf(stderr, "Usage: helm-ai-kernel --version [--json]\n")
		return 2
	}
}

func runVersionCommand(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0:
		// full block below
	case len(args) == 1 && args[0] == "--json":
		return writeVersionJSON(stdout)
	default:
		// An unknown arg used to be ignored and still exit 0, so `version
		// --bogus` looked like it succeeded. Reject it.
		fmt.Fprintf(stderr, "Usage: helm-ai-kernel version [--json]\n")
		return 2
	}
	fmt.Fprintf(stdout, "%s %s (%s)\n", terminalTitle(stdout, "HELM AI Kernel"), displayVersion(), displayCommit())
	fmt.Fprintf(stdout, "  Report Schema:          %s\n", reportSchemaVersion)
	fmt.Fprintf(stdout, "  EvidencePack Schema:    1\n")
	fmt.Fprintf(stdout, "  Compatibility Schema:   1\n")
	fmt.Fprintf(stdout, "  MCP Bundle Schema:      1\n")
	fmt.Fprintf(stdout, "  Build Time:             %s\n", displayBuildTime())
	return 0
}

// terminalTitle applies visual hierarchy only when the destination can render it.
// Data and piped output stay plain even when the process itself has a terminal.
func terminalTitle(out io.Writer, title string) string {
	file, ok := out.(*os.File)
	if !ok {
		return title
	}
	caps := ui.DetectCapabilities(os.Stdin, file, ui.TerminalOptions{
		Format: ui.FormatText,
		Color:  ui.ColorAuto,
	})
	if !caps.Color {
		return title
	}
	return ColorBold + title + ColorReset
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
	rootWords := completionWords()
	contexts := completionContexts()
	switch shell {
	case "bash":
		return bashCompletionScript(rootWords, contexts), true
	case "zsh":
		return zshCompletionScript(rootWords, contexts), true
	case "fish":
		return fishCompletionScript(rootWords, contexts), true
	case "powershell":
		return powerShellCompletionScript(rootWords, contexts), true
	default:
		return "", false
	}
}

func bashCompletionScript(rootWords []string, contexts []completionContext) string {
	var script strings.Builder
	fmt.Fprintf(&script, "# bash completion for helm-ai-kernel\n")
	script.WriteString("_helm_ai_kernel_completion() {\n")
	script.WriteString("  local cur context words\n")
	script.WriteString("  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	fmt.Fprintf(&script, "  words=%q\n", strings.Join(rootWords, " "))
	script.WriteString("  if (( COMP_CWORD > 1 )); then\n")
	script.WriteString("    context=\"${COMP_WORDS[1]}\"\n")
	script.WriteString("    if (( COMP_CWORD >= 3 )) && [[ -n \"${COMP_WORDS[2]}\" ]]; then\n")
	script.WriteString("      context=\"$context ${COMP_WORDS[2]}\"\n")
	script.WriteString("    fi\n")
	script.WriteString("    case \"$context\" in\n")
	for _, context := range contexts {
		if len(context.Path) < 2 {
			continue
		}
		fmt.Fprintf(&script, "      %q) words=%q ;;\n", strings.Join(context.Path, " "), strings.Join(uniqueStrings(context.Candidates), " "))
	}
	script.WriteString("    esac\n")
	script.WriteString("    if [[ \"$words\" == ")
	fmt.Fprintf(&script, "%q", strings.Join(rootWords, " "))
	script.WriteString(" ]]; then\n")
	script.WriteString("      context=\"${COMP_WORDS[1]}\"\n")
	script.WriteString("      case \"$context\" in\n")
	for _, context := range contexts {
		if len(context.Path) != 1 {
			continue
		}
		fmt.Fprintf(&script, "        %q) words=%q ;;\n", strings.Join(context.Path, " "), strings.Join(uniqueStrings(context.Candidates), " "))
	}
	script.WriteString("      esac\n")
	script.WriteString("    fi\n")
	script.WriteString("  fi\n")
	script.WriteString("  COMPREPLY=( $(compgen -W \"$words\" -- \"$cur\") )\n")
	script.WriteString("}\n")
	script.WriteString("complete -F _helm_ai_kernel_completion helm-ai-kernel\n")
	return script.String()
}

func zshCompletionScript(rootWords []string, contexts []completionContext) string {
	var script strings.Builder
	script.WriteString("#compdef helm-ai-kernel\n\n")
	script.WriteString("_helm_ai_kernel_completion() {\n")
	script.WriteString("  local -a choices\n")
	script.WriteString("  local context\n")
	script.WriteString("  if (( CURRENT > 2 )); then\n")
	script.WriteString("    context=\"$words[2]\"\n")
	script.WriteString("    if (( CURRENT > 3 )) && [[ -n \"$words[3]\" ]]; then\n")
	script.WriteString("      context=\"$context $words[3]\"\n")
	script.WriteString("    fi\n")
	script.WriteString("    case \"$context\" in\n")
	for _, context := range contexts {
		if len(context.Path) < 2 {
			continue
		}
		fmt.Fprintf(&script, "      %q)\n", strings.Join(context.Path, " "))
		script.WriteString("        choices=(\n")
		for _, word := range uniqueStrings(context.Candidates) {
			fmt.Fprintf(&script, "          %q\n", word)
		}
		script.WriteString("        ) ;;\n")
	}
	script.WriteString("    esac\n")
	script.WriteString("    if (( $#choices == 0 )); then\n")
	script.WriteString("      context=\"$words[2]\"\n")
	script.WriteString("      case \"$context\" in\n")
	for _, context := range contexts {
		if len(context.Path) != 1 {
			continue
		}
		fmt.Fprintf(&script, "        %q)\n", strings.Join(context.Path, " "))
		script.WriteString("          choices=(\n")
		for _, word := range uniqueStrings(context.Candidates) {
			fmt.Fprintf(&script, "            %q\n", word)
		}
		script.WriteString("          ) ;;\n")
	}
	script.WriteString("      esac\n")
	script.WriteString("    fi\n")
	script.WriteString("  fi\n")
	script.WriteString("  if (( $#choices == 0 )); then\n")
	script.WriteString("    choices=(\n")
	for _, word := range rootWords {
		fmt.Fprintf(&script, "      %q\n", word)
	}
	script.WriteString("    )\n")
	script.WriteString("  fi\n")
	script.WriteString("  _describe -t commands 'helm-ai-kernel command' choices\n")
	script.WriteString("}\n\n")
	script.WriteString("compdef _helm_ai_kernel_completion helm-ai-kernel\n")
	return script.String()
}

func fishCompletionScript(rootWords []string, contexts []completionContext) string {
	var script strings.Builder
	script.WriteString("# fish completion for helm-ai-kernel\n")
	script.WriteString("function __fish_helm_ai_kernel_completion\n")
	script.WriteString("  set -l tokens (commandline -opc)\n")
	script.WriteString("  set -e tokens[1]\n")
	script.WriteString("  set -l choices")
	script.WriteByte('\n')
	script.WriteString("  set -l context\n")
	script.WriteString("  if test (count $tokens) -ge 1\n")
	script.WriteString("    set context $tokens[1]\n")
	script.WriteString("  end\n")
	script.WriteString("  if test (count $tokens) -ge 2\n")
	script.WriteString("    set context \"$tokens[1] $tokens[2]\"\n")
	script.WriteString("  end\n")
	script.WriteString("  switch $context\n")
	for _, context := range contexts {
		if len(context.Path) < 2 {
			continue
		}
		fmt.Fprintf(&script, "    case %q\n", strings.Join(context.Path, " "))
		for _, word := range uniqueStrings(context.Candidates) {
			fmt.Fprintf(&script, "      set -a choices %q\n", word)
		}
	}
	script.WriteString("  end\n")
	script.WriteString("  if test (count $choices) -eq 0 -a (count $tokens) -ge 1\n")
	script.WriteString("    switch $tokens[1]\n")
	for _, context := range contexts {
		if len(context.Path) != 1 {
			continue
		}
		fmt.Fprintf(&script, "      case %q\n", strings.Join(context.Path, " "))
		for _, word := range uniqueStrings(context.Candidates) {
			fmt.Fprintf(&script, "        set -a choices %q\n", word)
		}
	}
	script.WriteString("    end\n")
	script.WriteString("  end\n")
	script.WriteString("  if test (count $choices) -eq 0\n")
	for _, word := range rootWords {
		fmt.Fprintf(&script, "    set -a choices %q\n", word)
	}
	script.WriteString("  end\n")
	script.WriteString("  for word in $choices\n")
	script.WriteString("    echo $word\n")
	script.WriteString("  end\n")
	script.WriteString("end\n")
	script.WriteString("complete -c helm-ai-kernel -f -a '(__fish_helm_ai_kernel_completion)'\n")
	return script.String()
}

func powerShellCompletionScript(rootWords []string, contexts []completionContext) string {
	var script strings.Builder
	script.WriteString("Register-ArgumentCompleter -Native -CommandName helm-ai-kernel -ScriptBlock {\n")
	script.WriteString("  param($wordToComplete, $commandAst, $cursorPosition)\n")
	script.WriteString("  $elements = @($commandAst.CommandElements | ForEach-Object { $_.Extent.Text })\n")
	script.WriteString("  if ($elements.Length -gt 0) { $elements = $elements[1..($elements.Length - 1)] }\n")
	script.WriteString("  $choices = @()\n")
	script.WriteString("  $context = ''\n")
	script.WriteString("  if ($elements.Length -ge 2) { $context = \"$($elements[0]) $($elements[1])\" }\n")
	script.WriteString("  switch ($context) {\n")
	for _, context := range contexts {
		if len(context.Path) < 2 {
			continue
		}
		fmt.Fprintf(&script, "    %s { $choices = @(", powerShellQuote(strings.Join(context.Path, " ")))
		for index, word := range uniqueStrings(context.Candidates) {
			if index > 0 {
				script.WriteString(", ")
			}
			script.WriteString(powerShellQuote(word))
		}
		script.WriteString(") }\n")
	}
	script.WriteString("  }\n")
	script.WriteString("  if ($choices.Length -eq 0 -and $elements.Length -ge 1) {\n")
	script.WriteString("    switch ($elements[0]) {\n")
	for _, context := range contexts {
		if len(context.Path) != 1 {
			continue
		}
		fmt.Fprintf(&script, "      %s { $choices = @(", powerShellQuote(strings.Join(context.Path, " ")))
		for index, word := range uniqueStrings(context.Candidates) {
			if index > 0 {
				script.WriteString(", ")
			}
			script.WriteString(powerShellQuote(word))
		}
		script.WriteString(") }\n")
	}
	script.WriteString("    }\n")
	script.WriteString("  }\n")
	script.WriteString("  if ($choices.Length -eq 0) { $choices = @(")
	for index, word := range rootWords {
		if index > 0 {
			script.WriteString(", ")
		}
		script.WriteString(powerShellQuote(word))
	}
	script.WriteString(") }\n")
	script.WriteString("  $choices | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {\n")
	script.WriteString("    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)\n")
	script.WriteString("  }\n")
	script.WriteString("}\n")
	return script.String()
}

func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
