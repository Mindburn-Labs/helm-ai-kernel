package runtime

import (
	"bufio"
	"context"
	"encoding/json"
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

func TestPreflightRecordsBaselineIsolation(t *testing.T) {
	req := baseContainerRequest(t)

	handle, err := NewLocalContainerRuntime().Preflight(req)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if handle.Isolation.Mode != IsolationModeDockerDefault {
		t.Fatalf("isolation mode = %q", handle.Isolation.Mode)
	}
	if handle.Isolation.Hardened {
		t.Fatal("docker-default must not be marked hardened")
	}
	if handle.Isolation.HostileAgentGrade {
		t.Fatal("docker-default must not be marked hostile-agent grade")
	}
	if handle.Isolation.PayloadInspection != "opaque_connect" || handle.Isolation.NetworkProof != "destination_allowlist_only" {
		t.Fatalf("unexpected isolation proof labels: %#v", handle.Isolation)
	}
}

func TestPreflightRequiresConfiguredHardenedIsolation(t *testing.T) {
	req := baseContainerRequest(t)
	runtime := NewLocalContainerRuntime()
	runtime.IsolationMode = IsolationModeDockerRootlessUser
	runtime.DockerInfoProvider = func(string) (DockerIsolationInfo, error) {
		return DockerIsolationInfo{}, nil
	}

	handle, err := runtime.Preflight(req)
	if err == nil || !strings.Contains(err.Error(), "rootless") {
		t.Fatalf("expected rootless/userns isolation rejection, got %v", err)
	}
	if handle.Isolation.Mode != IsolationModeDockerRootlessUser || handle.Isolation.DetectionStatus != "unsupported" {
		t.Fatalf("denied isolation evidence missing: %#v", handle.Isolation)
	}
}

func TestPreflightAllowsGVisorRuntimeClass(t *testing.T) {
	req := baseContainerRequest(t)
	runtime := NewLocalContainerRuntime()
	runtime.IsolationMode = IsolationModeGVisor
	runtime.DockerInfoProvider = func(string) (DockerIsolationInfo, error) {
		return DockerIsolationInfo{Runtimes: []string{"runc", "runsc"}}, nil
	}

	handle, err := runtime.Preflight(req)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if handle.Isolation.RuntimeClass != "runsc" || !handle.Isolation.Hardened || !handle.Isolation.HostileAgentGrade {
		t.Fatalf("unexpected gVisor isolation evidence: %#v", handle.Isolation)
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

func TestContainerCommandDoesNotAddShellArgsToAppCommand(t *testing.T) {
	command, args := containerCommand([]string{"openclaw"}, nil)
	if got := strings.Join(command, " "); got != "openclaw" {
		t.Fatalf("command = %q", got)
	}
	if len(args) != 0 {
		t.Fatalf("args = %#v, want none for explicit app command", args)
	}

	command, args = containerCommand(nil, nil)
	if got := strings.Join(append(command, args...), " "); got != "/bin/sh -lc true" {
		t.Fatalf("default command = %q", got)
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
	assertEgressReceiptSubject(t, handle.ReceiptDir, "connect_allowed", map[string]any{
		"payload_inspection":   "opaque_connect",
		"network_proof":        "destination_allowlist_only",
		"token_broker_enabled": false,
	})
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

func assertEgressReceiptSubject(t *testing.T, dir, reason string, want map[string]any) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read receipt dir: %v", err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read receipt: %v", err)
		}
		var receipt struct {
			Subject map[string]any `json:"subject"`
		}
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatalf("decode receipt: %v", err)
		}
		if receipt.Subject["reason"] != reason {
			continue
		}
		for key, expected := range want {
			if receipt.Subject[key] != expected {
				t.Fatalf("receipt %s = %#v, want %#v in subject %#v", key, receipt.Subject[key], expected, receipt.Subject)
			}
		}
		return
	}
	t.Fatalf("receipt reason %q not found in %s", reason, dir)
}
