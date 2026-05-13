package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/llm/gateway"
)

func init() {
	Register(Subcommand{
		Name:    "local",
		Aliases: []string{"l"},
		Usage:   "Validate a Local Inference Gateway provider profile",
		RunFn:   runLocalCmd,
	})
}

func runLocalCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Error: local requires a subcommand (e.g., 'up')")
		return 1
	}

	switch args[0] {
	case "up":
		return runLocalUp(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Error: unknown local subcommand %q\n", args[0])
		return 1
	}
}

func runLocalUp(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("local up", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var provider, baseURL, model, modelHash string
	cmd.StringVar(&provider, "provider", "", "Provider: ollama, llamacpp, vllm, lmstudio")
	cmd.StringVar(&baseURL, "base-url", "", "Provider base URL")
	cmd.StringVar(&model, "model", "", "Model name")
	cmd.StringVar(&modelHash, "model-hash", "", "Model hash, usually sha256:<hex>")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if provider == "" || model == "" {
		fmt.Fprintln(stderr, "Error: --provider and --model are required")
		return 2
	}

	router := gateway.NewGatewayRouter()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := router.RouteWithConfig(ctx, gateway.RouteConfig{
		Provider:  gateway.ProviderType(provider),
		BaseURL:   baseURL,
		ModelName: model,
		ModelHash: modelHash,
	}); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := router.HealthCheck(ctx); err != nil {
		fmt.Fprintf(stderr, "Error: provider health check failed: %v\n", err)
		return 1
	}

	active := router.ActiveProfile()
	fmt.Fprintf(stdout, "%sHELM Local Inference Gateway profile ready%s\n", ColorGreen, ColorReset)
	fmt.Fprintf(stdout, "  Provider:   %s\n", active.Provider)
	fmt.Fprintf(stdout, "  Base URL:   %s\n", active.BaseURL)
	fmt.Fprintf(stdout, "  Model:      %s\n", active.ModelName)
	if active.ModelHash != "" {
		fmt.Fprintf(stdout, "  Model hash: %s\n", active.ModelHash)
	}
	return 0
}
