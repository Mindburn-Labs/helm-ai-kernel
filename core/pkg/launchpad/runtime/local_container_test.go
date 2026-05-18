package runtime

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestLaunchOwnedEgressProxyWritesReceiptAndAllowsOpenRouterConnect(t *testing.T) {
	upstreamServer, upstreamClient := net.Pipe()
	defer upstreamClient.Close()
	proxy := LaunchOwnedEgressProxy{
		ListenAddr: "127.0.0.1:0",
		ReceiptDir: t.TempDir(),
		dialContext: func(_ context.Context, network string, address string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q", network)
			}
			if address != "api.openrouter.ai:443" {
				t.Fatalf("address = %q", address)
			}
			return upstreamServer, nil
		},
	}
	handle, err := proxy.Start(EgressProxyRequest{
		LaunchID:  "launch-1",
		Allowlist: []string{"api.openrouter.ai:443"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stopProxy(t, handle)
	if handle.ProxyURL == "" || handle.ReceiptRef == "" || handle.ReceiptDir == "" {
		t.Fatalf("incomplete proxy handle: %+v", handle)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(handle.ProxyURL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT api.openrouter.ai:443 HTTP/1.1\r\nHost: api.openrouter.ai:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	entries, err := os.ReadDir(handle.ReceiptDir)
	if err != nil {
		t.Fatalf("read receipt dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected egress proxy receipts")
	}
}

func TestLaunchOwnedEgressProxyDeniesUnknownDestination(t *testing.T) {
	proxy := LaunchOwnedEgressProxy{
		ListenAddr: "127.0.0.1:0",
		ReceiptDir: t.TempDir(),
		dialContext: func(_ context.Context, _ string, _ string) (net.Conn, error) {
			t.Fatal("denied destination should not be dialed")
			return nil, nil
		},
	}
	handle, err := proxy.Start(EgressProxyRequest{
		LaunchID:  "launch-1",
		Allowlist: []string{"openrouter.ai:443"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stopProxy(t, handle)
	conn, err := net.Dial("tcp", strings.TrimPrefix(handle.ProxyURL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestLaunchOwnedEgressProxyRejectsNonOpenRouterAllowlist(t *testing.T) {
	_, err := NewLaunchOwnedEgressProxy().Start(EgressProxyRequest{
		LaunchID:  "launch-1",
		Allowlist: []string{"example.com:443"},
	})
	if err == nil {
		t.Fatal("expected non-OpenRouter allowlist to fail")
	}
}

func TestDockerSidecarEgressProxyRequiresImmutableImage(t *testing.T) {
	_, err := DockerSidecarEgressProxy{Image: "ghcr.io/mindburn-labs/helm-launchpad/egress-proxy:latest"}.Start(EgressProxyRequest{
		LaunchID:  "launch-1",
		Allowlist: []string{"api.openrouter.ai:443"},
	})
	if err == nil || !strings.Contains(err.Error(), "image@sha256") {
		t.Fatalf("expected immutable image error, got %v", err)
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

func stopProxy(t *testing.T, handle EgressProxyHandle) {
	t.Helper()
	if handle.Stop != nil {
		if err := handle.Stop(); err != nil {
			t.Fatalf("stop proxy: %v", err)
		}
	}
}
