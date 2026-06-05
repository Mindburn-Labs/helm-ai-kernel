package session

import (
	"os"
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
	if _, leaked := secrets["OPENAI_BASE_URL"]; leaked {
		t.Fatalf("token broker projected raw provider routing metadata: %#v", secrets)
	}
}

func TestRuntimeSecretsProjectsBYOProviderRoutingMetadata(t *testing.T) {
	compiled := plan.LaunchPlan{
		ModelGatewayEnv:  []string{"YI_API_KEY"},
		ModelGatewayMode: "external_byo",
	}

	secrets := runtimeSecrets(compiled, ExecuteOptions{
		RuntimeSecretEnv: map[string]string{"YI_API_KEY": "sk-yi"},
	})

	if secrets["YI_API_KEY"] != "sk-yi" {
		t.Fatalf("provider key missing: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_PROVIDER"] != "01-ai" {
		t.Fatalf("provider metadata missing: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_ENV"] != "YI_API_KEY" {
		t.Fatalf("provider env metadata missing: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_BASE_URL"] != "https://api.01.ai/v1" {
		t.Fatalf("provider base URL metadata missing: %#v", secrets)
	}
	if secrets["OPENAI_BASE_URL"] != "https://api.01.ai/v1" || secrets["OPENAI_API_BASE"] != "https://api.01.ai/v1" {
		t.Fatalf("OpenAI-compatible routing metadata missing: %#v", secrets)
	}
	if secrets["HELM_LAUNCHPAD_MODEL_PROVIDER"] != "01-ai" {
		t.Fatalf("compat provider metadata missing: %#v", secrets)
	}
}

func TestRuntimeSecretsProjectsDynamicProviderEndpointMetadata(t *testing.T) {
	compiled := plan.LaunchPlan{
		ModelGatewayEnv:  []string{"AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"},
		ModelGatewayMode: "external_byo",
	}

	secrets := runtimeSecrets(compiled, ExecuteOptions{
		RuntimeSecretEnv: map[string]string{
			"AZURE_OPENAI_API_KEY":  "sk-azure",
			"AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com/",
		},
	})

	if secrets["HELM_MODEL_GATEWAY_PROVIDER"] != "azure-openai" {
		t.Fatalf("provider metadata missing: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_BASE_URL"] != "https://example.openai.azure.com" {
		t.Fatalf("dynamic provider endpoint metadata missing: %#v", secrets)
	}
	if secrets["OPENAI_BASE_URL"] != "https://example.openai.azure.com" {
		t.Fatalf("OpenAI-compatible dynamic endpoint metadata missing: %#v", secrets)
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

func TestParseFilesystemMountDefaultTarget(t *testing.T) {
	m, err := parseFilesystemMount("app_state:rw", "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Name != "app_state" || m.ReadOnly || m.Target != "/var/lib/openclaw/app_state" {
		t.Fatalf("unexpected parse result: %+v", m)
	}
}

func TestParseFilesystemMountExplicitTarget(t *testing.T) {
	m, err := parseFilesystemMount("app_state:rw:/opt/openclaw/.openclaw", "openclaw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Name != "app_state" || m.ReadOnly || m.Target != "/opt/openclaw/.openclaw" {
		t.Fatalf("unexpected parse result: %+v", m)
	}
}

func TestParseFilesystemMountReadOnly(t *testing.T) {
	m, err := parseFilesystemMount("data:ro", "hermes")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.ReadOnly {
		t.Fatalf("expected read-only, got: %+v", m)
	}
}

func TestParseFilesystemMountRejectsRelativeTarget(t *testing.T) {
	if _, err := parseFilesystemMount("x:rw:relative/path", "app"); err == nil {
		t.Fatal("expected error for relative target")
	}
	if _, err := parseFilesystemMount("x:rw:/etc/../passwd", "app"); err == nil {
		t.Fatal("expected error for path with ..")
	}
}

func TestParseFilesystemMountRejectsInvalidMode(t *testing.T) {
	if _, err := parseFilesystemMount("x:weird", "app"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestMaterializeFilesystemMountsSkipsWorkspace(t *testing.T) {
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	compiled := plan.LaunchPlan{
		LaunchID:         "test-launch",
		AppID:            "demo",
		FilesystemMounts: []string{"workspace:rw"},
	}
	mounts, err := materializeFilesystemMounts(compiled, ExecuteOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("expected workspace to be skipped, got %d mounts", len(mounts))
	}
}

func TestMaterializeFilesystemMountsCreatesHostDirAndPassesTarget(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_HOME", root)
	compiled := plan.LaunchPlan{
		LaunchID: "abc-123",
		AppID:    "openclaw",
		FilesystemMounts: []string{
			"workspace:rw",
			"app_state:rw:/opt/openclaw/.openclaw",
		},
	}
	mounts, err := materializeFilesystemMounts(compiled, ExecuteOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount (workspace skipped), got %d", len(mounts))
	}
	m := mounts[0]
	if m.Name != "app_state" || m.Target != "/opt/openclaw/.openclaw" || m.ReadOnly {
		t.Fatalf("unexpected mount: %+v", m)
	}
	wantSource := root + "/state/abc-123/app_state"
	if m.Source != wantSource {
		t.Fatalf("source mismatch: got %q want %q", m.Source, wantSource)
	}
	if info, err := os.Stat(m.Source); err != nil || !info.IsDir() {
		t.Fatalf("host source dir not created: %v (info=%+v)", err, info)
	} else if info.Mode().Perm() != 0o777 {
		t.Fatalf("host source dir permissions = %o, want 777", info.Mode().Perm())
	}
}

func TestMaterializeFilesystemMountsDryRunDoesNotTouchFilesystem(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_HOME", root)
	compiled := plan.LaunchPlan{
		LaunchID:         "abc-123",
		AppID:            "hermes",
		FilesystemMounts: []string{"app_state:rw:/var/lib/hermes"},
	}
	mounts, err := materializeFilesystemMounts(compiled, ExecuteOptions{RuntimeDryRun: true})
	if err != nil {
		t.Fatalf("unexpected error in dry-run: %v", err)
	}
	if len(mounts) != 1 || mounts[0].Source != "" {
		t.Fatalf("dry-run should not create source dir, got: %+v", mounts)
	}
	if _, err := os.Stat(root + "/state/abc-123/app_state"); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not touch the filesystem, got err=%v", err)
	}
}
