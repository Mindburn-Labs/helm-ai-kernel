package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func runTelemetrySurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "otel-config" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel telemetry otel-config [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("telemetry otel-config", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	config := telemetryConfig()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, config)
	}
	fmt.Fprintf(stdout, "OTel config service=%s authoritative=%t\n", config.ServiceName, config.Authoritative)
	return 0
}

func runCoexistenceSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "manifest" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel coexistence manifest [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("coexistence manifest", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	manifest := contracts.CoexistenceCapabilityManifest{
		ManifestID:      "helm-coexistence-oss",
		Authority:       "helm-native-receipts",
		BoundaryRole:    "inner-proof-bearing-execution-boundary",
		SupportedInputs: []string{"mcp", "openai-compatible-proxy", "framework-middleware", "gateway-export"},
		ExportSurfaces:  []string{"evidencepack", "dsse", "jws", "in-toto", "slsa", "sigstore", "otel-genai", "cloudevents"},
		ReceiptBindings: []string{"receipt_id", "record_hash", "sandbox_grant_hash", "authz_snapshot_hash"},
		GeneratedAt:     time.Now().UTC(),
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, manifest)
	}
	fmt.Fprintf(stdout, "Coexistence manifest: %s authority=%s\n", manifest.ManifestID, manifest.Authority)
	return 0
}

func runIntegrateSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "scaffold" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel integrate scaffold --framework <name> [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("integrate scaffold", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	framework := cmd.String("framework", "", "Framework name")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	if *framework == "" {
		fmt.Fprintln(stderr, "Error: --framework is required")
		return 2
	}
	scaffold := frameworkScaffold(*framework)
	if *jsonOutput {
		return writeSurfaceJSON(stdout, scaffold)
	}
	fmt.Fprintf(stdout, "Framework scaffold %s\n", scaffold.Framework)
	fmt.Fprintf(stdout, "  mode: %s\n", scaffold.Mode)
	fmt.Fprintf(stdout, "  routes: %s\n", strings.Join(scaffold.RequiredRoutes, ", "))
	return 0
}

func frameworkScaffold(framework string) contracts.FrameworkScaffold {
	name := strings.ToLower(strings.TrimSpace(framework))
	language := "typescript"
	switch name {
	case "langchain", "langgraph", "pydanticai", "autogen", "crewai":
		language = "python"
	case "semantic-kernel":
		language = "csharp"
	case "litellm", "n8n", "zapier-webhook", "raw-mcp", "openai-agents":
		language = "typescript"
	}
	return contracts.FrameworkScaffold{
		Framework:      name,
		Language:       language,
		Files:          []string{"middleware/helm-boundary." + languageExt(language), "README.md"},
		RequiredRoutes: []string{"/api/v1/mcp/authorize-call", "/api/v1/evidence/export", "/api/v1/evidence/verify"},
		Mode:           "pre-dispatch-required",
		Notes:          "Passive tracing alone is not HELM conformance; middleware must call HELM before tool dispatch.",
	}
}

func languageExt(language string) string {
	switch language {
	case "python":
		return "py"
	case "csharp":
		return "cs"
	default:
		return "ts"
	}
}
