package runtime

import (
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
)

func baseContainerRequest(t *testing.T) ContainerRequest {
	t.Helper()
	return ContainerRequest{
		Plan: plan.LaunchPlan{
			LaunchID:           "launch-1",
			SandboxProfileHash: "sha256:sandbox",
			Nodes:              map[string]any{},
		},
		ImageDigest:    "example.com/launchpad/app@sha256:abc",
		WorkspaceMount: t.TempDir(),
		DryRun:         true,
	}
}

func TestPreflightNetworkDefaultDeny(t *testing.T) {
	req := baseContainerRequest(t)

	_, err := LocalContainerRuntime{NetworkDefault: "allow", FilesystemMode: "deny_by_default"}.Preflight(req)
	if err == nil {
		t.Fatal("expected non-deny network default to fail preflight")
	}
	if NetworkAllowed("api.example.com:443", nil) {
		t.Fatal("empty network allowlist should deny by default")
	}
	if !NetworkAllowed("https://openrouter.ai/api/v1", []string{"openrouter.ai:443"}) {
		t.Fatal("OpenRouter HTTPS URL should normalize to openrouter.ai:443")
	}
}

func TestPreflightBlocksHostFilesystemEscape(t *testing.T) {
	req := baseContainerRequest(t)
	req.WorkspaceMount = filepath.Clean("/etc")

	_, err := NewLocalContainerRuntime().Preflight(req)
	if err == nil {
		t.Fatal("expected host filesystem escape to fail preflight")
	}
}

func TestPreflightBlocksContainerPrivilegeEscalation(t *testing.T) {
	req := baseContainerRequest(t)
	req.Privileged = true

	_, err := NewLocalContainerRuntime().Preflight(req)
	if err == nil {
		t.Fatal("expected privileged container request to fail preflight")
	}
}

func TestPreflightBlocksRecursiveLaunch(t *testing.T) {
	req := baseContainerRequest(t)
	req.RecursiveLaunch = true

	_, err := NewLocalContainerRuntime().Preflight(req)
	if err == nil {
		t.Fatal("expected recursive launch request to fail preflight")
	}
}

func TestPreflightRestrictsEgressAllowlistToOpenRouter(t *testing.T) {
	req := baseContainerRequest(t)
	req.NetworkAllowlist = []string{"https://example.com"}

	_, err := NewLocalContainerRuntime().Preflight(req)
	if err == nil {
		t.Fatal("expected non-OpenRouter egress allowlist to fail preflight")
	}

	req.NetworkAllowlist = []string{"https://openrouter.ai/api/v1"}
	if _, err := NewLocalContainerRuntime().Preflight(req); err != nil {
		t.Fatalf("OpenRouter egress allowlist rejected: %v", err)
	}
}

func TestStartRequiresEgressProxyReceiptForOpenRouterAllowlist(t *testing.T) {
	req := baseContainerRequest(t)
	req.DryRun = false
	req.Command = []string{"/bin/sh"}
	req.Args = []string{"-lc", "true"}
	req.NetworkAllowlist = []string{"https://openrouter.ai/api/v1"}

	_, err := NewLocalContainerRuntime().Start(req)
	if err == nil {
		t.Fatal("expected OpenRouter allowlist without proxy receipt to fail closed")
	}

	req.EgressProxy = StaticEgressProxy{ProxyURL: "http://127.0.0.1:18080", ReceiptRef: "receipt://egress/launch-1"}
	handle, err := NewLocalContainerRuntime().Start(req)
	if err != nil {
		t.Skipf("Docker not available for egress proxy receipt test: %v", err)
	}
	if handle.EgressReceiptRef != "receipt://egress/launch-1" {
		t.Fatalf("egress receipt ref = %q", handle.EgressReceiptRef)
	}
}

func TestPreflightRedactsProjectedSecrets(t *testing.T) {
	req := baseContainerRequest(t)
	req.Secrets = map[string]string{
		"OPENROUTER_API_KEY": "sk-live-secret",
		"EMPTY":              "",
	}

	handle, err := NewLocalContainerRuntime().Preflight(req)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if handle.ProjectedSecrets["OPENROUTER_API_KEY"] != "[REDACTED]" {
		t.Fatalf("secret leaked in projected handle: %#v", handle.ProjectedSecrets)
	}
	if handle.ProjectedSecrets["EMPTY"] != "" {
		t.Fatalf("empty secret should stay empty, got %#v", handle.ProjectedSecrets)
	}
}
