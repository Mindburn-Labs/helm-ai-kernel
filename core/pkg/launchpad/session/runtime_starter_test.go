package session

import (
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lpruntime "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/runtime"
)

func TestRuntimeSecretsTokenBrokerDoesNotProjectRawProviderKey(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "sk-raw-provider")
	compiled := plan.LaunchPlan{
		ModelGatewayEnv:  []string{"OPENROUTER_API_KEY"},
		ModelGatewayMode: "token_broker",
	}

	secrets := runtimeSecrets(compiled, ExecuteOptions{
		RuntimeSecretEnv: map[string]string{
			"HELM_MODEL_GATEWAY_TOKEN": "broker-token",
			"HELM_MODEL_GATEWAY_URL":   "https://gateway.example",
		},
	})

	if _, leaked := secrets["OPENROUTER_API_KEY"]; leaked {
		t.Fatalf("token broker projected raw provider key: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_TOKEN"] != "broker-token" {
		t.Fatalf("broker token missing: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_URL"] != "https://gateway.example" {
		t.Fatalf("broker URL missing: %#v", secrets)
	}
}

func TestEgressProxyFromEnvStaticURL(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", "http://proxy.example:8080")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_RECEIPT_REF", "receipt:test")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE", "")

	proxy, err := egressProxyFromEnv("local-container", []string{"openrouter.ai"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	static, ok := proxy.(lpruntime.StaticEgressProxy)
	if !ok {
		t.Fatalf("expected StaticEgressProxy, got %T", proxy)
	}
	if static.ProxyURL != "http://proxy.example:8080" {
		t.Fatalf("proxy URL mismatch: %q", static.ProxyURL)
	}
	if static.ReceiptRef != "receipt:test" {
		t.Fatalf("receipt ref mismatch: %q", static.ReceiptRef)
	}
}

func TestEgressProxyFromEnvSidecarImage(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", "")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE", "ghcr.io/example/proxy@sha256:abc")

	proxy, err := egressProxyFromEnv("local-container", []string{"openrouter.ai"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sidecar, ok := proxy.(lpruntime.DockerSidecarEgressProxy)
	if !ok {
		t.Fatalf("expected DockerSidecarEgressProxy, got %T", proxy)
	}
	if sidecar.Image != "ghcr.io/example/proxy@sha256:abc" {
		t.Fatalf("image mismatch: %q", sidecar.Image)
	}
}

func TestEgressProxyFromEnvLocalContainerRefusesLoopbackDefault(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", "")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE", "")

	proxy, err := egressProxyFromEnv("local-container", []string{"openrouter.ai"})
	if err == nil {
		t.Fatalf("expected fail-fast error, got proxy %T", proxy)
	}
	msg := err.Error()
	for _, want := range []string{
		"local-container",
		"HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE",
		"HELM_LAUNCHPAD_EGRESS_PROXY_URL",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message missing %q: %s", want, msg)
		}
	}
}

func TestEgressProxyFromEnvNoAllowlistReturnsNil(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_URL", "")
	t.Setenv("HELM_LAUNCHPAD_EGRESS_PROXY_IMAGE", "")

	proxy, err := egressProxyFromEnv("local-container", nil)
	if err != nil {
		t.Fatalf("unexpected error with empty allowlist: %v", err)
	}
	if proxy != nil {
		t.Fatalf("expected nil proxy with empty allowlist, got %T", proxy)
	}
}
