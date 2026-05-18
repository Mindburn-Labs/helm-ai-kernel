package launchpad_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "../.."))
}

func TestReferencePacksVerifyOffline(t *testing.T) {
	root := repoRoot(t)
	for _, pack := range []string{
		"openclaw-local-container",
		"hermes-local-container",
		"codex-local-container",
	} {
		t.Run(pack, func(t *testing.T) {
			report, err := verifier.VerifyBundle(filepath.Join(root, "reference_packs", "launchpad", pack))
			if err != nil {
				t.Fatalf("VerifyBundle: %v", err)
			}
			if !report.Verified {
				t.Fatalf("reference pack did not verify: %s", report.Summary)
			}
		})
	}
}

func TestMissingModelSecretEscalates(t *testing.T) {
	root := repoRoot(t)
	previousModelGateway, hadModelGateway := os.LookupEnv("model_gateway")
	previousOpenRouter, hadOpenRouter := os.LookupEnv("OPENROUTER_API_KEY")
	if err := os.Unsetenv("model_gateway"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("OPENROUTER_API_KEY"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if hadModelGateway {
			_ = os.Setenv("model_gateway", previousModelGateway)
		}
		if hadOpenRouter {
			_ = os.Setenv("OPENROUTER_API_KEY", previousOpenRouter)
		}
	}()
	catalog, err := registry.LoadCatalog(root)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	app, ok := catalog.App("openclaw")
	if !ok {
		t.Fatal("openclaw app missing")
	}
	substrate, ok := catalog.Substrate("local-container")
	if !ok {
		t.Fatal("local-container substrate missing")
	}
	compiled, err := plan.CompileWithRoot(app, substrate, "test.operator", root)
	if err == nil {
		t.Fatal("expected missing secret to escalate with an error")
	}
	if compiled.KernelVerdict != "ESCALATE" || compiled.Status != "ESCALATED" || compiled.ReasonCode != "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		t.Fatalf("unexpected missing secret plan: %#v", compiled)
	}
	if compiled.Nodes["missing_secret"] != "OPENROUTER_API_KEY" {
		t.Fatalf("missing model gateway must name scoped env secret, got %#v", compiled.Nodes["missing_secret"])
	}
}

func TestUnknownMCPToolQuarantines(t *testing.T) {
	decision := mcp.Authorize(mcp.ServerRecord{}, mcp.CallRequest{
		ServerID:   "unknown",
		ToolName:   "shell.exec",
		SchemaHash: "sha256:test",
		Effect:     mcp.EffectSideEffect,
	})
	if decision.Verdict != "ESCALATE" || decision.Reason != "ERR_MCP_SERVER_QUARANTINED" {
		t.Fatalf("unknown MCP server should quarantine, got %#v", decision)
	}
}
