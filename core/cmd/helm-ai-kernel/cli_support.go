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
	fmt.Fprintln(out, "Protect an agent:")
	fmt.Fprintln(out, "  helm-ai-kernel setup claude-code --yes")
	fmt.Fprintln(out, "  helm-ai-kernel setup codex --yes")
	fmt.Fprintln(out, "  helm-ai-kernel setup --client cursor --print-config")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Check risk:")
	fmt.Fprintln(out, "  helm-ai-kernel scan --path . --preview out.md")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Verify:")
	fmt.Fprintln(out, "  helm-ai-kernel receipts tail --agent <id>")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "More:")
	fmt.Fprintln(out, "  helm-ai-kernel help --all")
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
