package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestCoverageIsolationProfileAndDockerInfoBranches(t *testing.T) {
	if err := ValidateIsolationMode("not-real"); err == nil {
		t.Fatal("expected invalid isolation mode error")
	}
	var nilErr *IsolationModeError
	if nilErr.Error() != "" || nilErr.Unwrap() != nil {
		t.Fatal("nil isolation error methods mismatch")
	}
	cause := errors.New("docker unavailable")
	modeErr := &IsolationModeError{Cause: cause}
	if modeErr.Error() != "docker unavailable" || modeErr.Unwrap() != cause {
		t.Fatalf("cause isolation error mismatch: %v", modeErr)
	}
	evidence, ok := IsolationEvidenceFromError(&IsolationModeError{Evidence: IsolationEvidence{Mode: "gvisor"}, Reason: "denied"})
	if !ok || evidence.Mode != "gvisor" {
		t.Fatalf("isolation evidence extraction mismatch: %#v ok=%v", evidence, ok)
	}
	if _, ok := IsolationEvidenceFromError(errors.New("plain")); ok {
		t.Fatal("plain error should not yield isolation evidence")
	}

	providerErr := errors.New("docker info failed")
	evidence, err := ResolveIsolationProfile(IsolationModeGVisor, "docker", func(string) (DockerIsolationInfo, error) {
		return DockerIsolationInfo{}, providerErr
	})
	if err == nil || evidence.DetectionStatus != "unavailable" || !strings.Contains(evidence.UnsupportedReason, "docker info failed") {
		t.Fatalf("provider error mismatch: evidence=%#v err=%v", evidence, err)
	}
	for _, tc := range []struct {
		mode string
		info DockerIsolationInfo
		want func(IsolationEvidence, error) bool
	}{
		{IsolationModeDockerRootlessUser, DockerIsolationInfo{Rootless: true}, func(e IsolationEvidence, err error) bool { return err == nil && e.Hardened && !e.HostileAgentGrade }},
		{IsolationModeDockerRootlessUser, DockerIsolationInfo{UserNamespaces: true}, func(e IsolationEvidence, err error) bool { return err == nil && e.Hardened }},
		{IsolationModeDockerECI, DockerIsolationInfo{ECI: true}, func(e IsolationEvidence, err error) bool { return err == nil && e.Hardened && e.HostileAgentGrade }},
		{IsolationModeGVisor, DockerIsolationInfo{Runtimes: []string{"runsc"}}, func(e IsolationEvidence, err error) bool {
			return err == nil && e.RuntimeClass == "runsc" && e.HostileAgentGrade
		}},
		{IsolationModeKataFirecracker, DockerIsolationInfo{Runtimes: []string{"kata-runtime"}}, func(e IsolationEvidence, err error) bool {
			return err == nil && e.RuntimeClass == "kata-fc" && e.HostileAgentGrade
		}},
		{IsolationModeDedicatedVM, DockerIsolationInfo{DedicatedVM: true}, func(e IsolationEvidence, err error) bool { return err == nil && e.DedicatedVM && e.HostileAgentGrade }},
	} {
		got, err := ResolveIsolationProfile(tc.mode, "docker", func(string) (DockerIsolationInfo, error) {
			return tc.info, nil
		})
		if !tc.want(got, err) {
			t.Fatalf("%s profile mismatch: %#v err=%v", tc.mode, got, err)
		}
	}
	for _, mode := range []string{IsolationModeDockerECI, IsolationModeGVisor, IsolationModeKataFirecracker, IsolationModeDedicatedVM} {
		if evidence, err := ResolveIsolationProfile(mode, "docker", func(string) (DockerIsolationInfo, error) { return DockerIsolationInfo{}, nil }); err == nil || evidence.DetectionStatus != "unsupported" {
			t.Fatalf("expected unsupported %s, got %#v err=%v", mode, evidence, err)
		}
	}
	t.Setenv("HELM_LAUNCHPAD_DOCKER_RUNTIME", "custom-runsc")
	if runtimeClassFromEnv("runsc") != "custom-runsc" {
		t.Fatal("runtime class override mismatch")
	}
	if !hasAnyRuntime([]string{"a", "b"}, "x", "b") || hasAnyRuntime([]string{"a"}, "x", "y") {
		t.Fatal("hasAnyRuntime mismatch")
	}
	for _, value := range []string{"1", "true", "yes", "on"} {
		t.Setenv("TRUTHY_TEST", value)
		if !truthyEnv("TRUTHY_TEST") {
			t.Fatalf("truthy env not detected for %q", value)
		}
	}
	t.Setenv("TRUTHY_TEST", "no")
	if truthyEnv("TRUTHY_TEST") {
		t.Fatal("false env should not be truthy")
	}

	dockerDir := t.TempDir()
	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
if [ "$1" = "info" ]; then
  printf '%s\n' '{"SecurityOptions":["name=rootless","userns","Enhanced Container Isolation"],"Runtimes":{"runsc":{},"runc":{}},"DefaultRuntime":"runc"}'
  exit 0
fi
exit 2
`)
	t.Setenv("PATH", dockerDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HELM_LAUNCHPAD_DOCKER_ECI", "0")
	t.Setenv("HELM_LAUNCHPAD_DEDICATED_VM", "1")
	info, err := DockerIsolationInfoFromCLI("")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Rootless || !info.UserNamespaces || !info.ECI || !info.DedicatedVM || info.DefaultRuntime != "runc" || !hasRuntime(info.Runtimes, "runsc") {
		t.Fatalf("docker info parse mismatch: %#v", info)
	}

	badDir := t.TempDir()
	writeExecutable(t, filepath.Join(badDir, "docker"), `#!/bin/sh
if [ "$1" = "info" ]; then
  echo '{'
  exit 0
fi
exit 1
`)
	t.Setenv("PATH", badDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := DockerIsolationInfoFromCLI("docker"); err == nil {
		t.Fatal("expected invalid docker info JSON error")
	}
	if _, err := DockerIsolationInfoFromCLI("definitely-missing-docker"); err == nil {
		t.Fatal("expected missing docker binary error")
	}
}

func TestCoverageLocalContainerHelpersAndStartBranches(t *testing.T) {
	r := NewLocalContainerRuntime()
	for _, mutate := range []func(*ContainerRequest){
		func(req *ContainerRequest) { req.WorkspaceMount = "" },
		func(req *ContainerRequest) { req.ImageDigest = "" },
		func(req *ContainerRequest) { req.Command = []string{"--cap-add=SYS_ADMIN"} },
		func(req *ContainerRequest) { req.Args = []string{"--security-opt=no-new-privileges"} },
		func(req *ContainerRequest) { req.Plan.Nodes = map[string]any{"recursive_launch": "true"} },
		func(req *ContainerRequest) { req.Plan.Nodes = map[string]any{"recursive_launch": true} },
	} {
		req := baseContainerRequest(t)
		mutate(&req)
		if _, err := r.Preflight(req); err == nil {
			t.Fatalf("expected preflight error for request %#v", req)
		}
	}
	if _, err := (LocalContainerRuntime{NetworkDefault: "deny", FilesystemMode: "allow"}).Preflight(baseContainerRequest(t)); err == nil {
		t.Fatal("expected filesystem mode preflight error")
	}
	req := baseContainerRequest(t)
	req.TokenBroker = true
	handle, err := r.Preflight(req)
	if err != nil {
		t.Fatal(err)
	}
	if !handle.Isolation.TokenBrokerEnabled {
		t.Fatal("token broker flag not reflected in preflight evidence")
	}

	if name, mode := parseFilesystemMount(""); name != "" || mode != "" {
		t.Fatalf("empty filesystem mount mismatch: %q/%q", name, mode)
	}
	if name, mode := parseFilesystemMount(" state : rw "); name != "state" || mode != "rw" {
		t.Fatalf("filesystem mount parse mismatch: %q/%q", name, mode)
	}
	if _, err := appStateRoot(""); err == nil {
		t.Fatal("expected appStateRoot launch id error")
	}
	t.Setenv("HELM_LAUNCHPAD_HOME", t.TempDir())
	stateRoot, err := appStateRoot("launch-state")
	if err != nil || !strings.HasSuffix(filepath.ToSlash(stateRoot), "/state/launch-state") {
		t.Fatalf("appStateRoot mismatch: %s err=%v", stateRoot, err)
	}
	mounts, env, err := projectAppStateMounts(plan.LaunchPlan{
		LaunchID:         "launch-state",
		AppID:            "app",
		StateDirEnv:      "APP_STATE_DIR",
		FilesystemMounts: []string{"workspace:rw", "cache:ro", "data:rw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 || !mounts[0].ReadOnly || mounts[1].ReadOnly || env["APP_STATE_DIR"] != "/var/lib/app/cache" {
		t.Fatalf("projected mounts mismatch: mounts=%#v env=%#v", mounts, env)
	}

	if err := waitForReadiness("container", []registry.HealthcheckSpec{{Type: "command"}}, time.Nanosecond, nil); err == nil {
		t.Fatal("expected readiness timeout with empty healthcheck command")
	}
	dockerDir := t.TempDir()
	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo true
  exit 0
fi
if [ "$1" = "exec" ]; then
  echo ok
  exit 0
fi
exit 0
`)
	t.Setenv("PATH", dockerDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if !containerRunning("container") {
		t.Fatal("fake container should be running")
	}
	if err := waitForReadiness("container", []registry.HealthcheckSpec{{Type: "command", Command: "ready"}}, 50*time.Millisecond, nil); err != nil {
		t.Fatalf("expected readiness success: %v", err)
	}
	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
if [ "$1" = "inspect" ]; then
  echo false
  exit 0
fi
exit 0
`)
	if containerRunning("container") {
		t.Fatal("fake container should not be running")
	}
	if err := waitForReadiness("container", []registry.HealthcheckSpec{{Type: "command", Command: "ready"}}, 50*time.Millisecond, nil); err == nil {
		t.Fatal("expected container exited readiness error")
	}

	command, args := containerCommand(nil, []string{"echo hi"})
	if strings.Join(command, " ") != "/bin/sh" || args[0] != "echo hi" {
		t.Fatalf("args-only command mismatch: %#v %#v", command, args)
	}
	redacted := redactedCommandOutput([]byte("hello secret"), []byte(" err secret"), map[string]string{"TOKEN": "secret"})
	if !strings.Contains(redacted, "[REDACTED]") || strings.Contains(redacted, "secret") {
		t.Fatalf("secret was not redacted: %q", redacted)
	}
	long := redactedCommandOutput([]byte(strings.Repeat("x", 3000)), nil, nil)
	if !strings.HasPrefix(long, "...[truncated]\n") || len(long) > 2100 {
		t.Fatalf("long output not truncated: len=%d", len(long))
	}
	var stopped bool
	cleanupEgressProxy(EgressProxyHandle{Stop: func() error {
		stopped = true
		return errors.New("ignored")
	}})
	if !stopped {
		t.Fatal("cleanup proxy did not invoke Stop")
	}
	for _, mount := range []string{"relative/path", "/", "/var/run/docker.sock", "/tmp/../etc"} {
		if err := validateWorkspaceMount(mount); err == nil {
			t.Fatalf("expected workspace mount %q to be rejected", mount)
		}
	}
	for _, values := range [][]string{{"--privileged"}, {"--cap-add"}, {"--security-opt"}, {"/run/docker.sock"}, {"safe"}} {
		got := containsPrivilegeEscalation(values)
		want := values[0] != "safe"
		if got != want {
			t.Fatalf("containsPrivilegeEscalation(%#v)=%v want=%v", values, got, want)
		}
	}

	req = baseContainerRequest(t)
	req.DryRun = false
	req.NetworkAllowlist = []string{"openrouter.ai:443"}
	req.EgressProxy = errorProxy{}
	if _, err := r.Start(req); err == nil {
		t.Fatal("expected egress proxy start error")
	}
	req.EgressProxy = incompleteProxy{}
	if _, err := r.Start(req); err == nil {
		t.Fatal("expected incomplete egress proxy handle error")
	}

	startDockerDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker-run.log")
	writeExecutable(t, filepath.Join(startDockerDir, "docker"), `#!/bin/sh
echo "$@" >> "$DOCKER_LOG"
if [ "$1" = "run" ]; then
  echo container-output
  exit 0
fi
exit 0
`)
	t.Setenv("PATH", startDockerDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_LOG", logPath)
	var autoStopped bool
	req = baseContainerRequest(t)
	req.DryRun = false
	req.Plan.AppID = "app"
	req.Plan.StateDirEnv = "APP_STATE_DIR"
	req.Secrets = map[string]string{"TOKEN": "secret"}
	req.Command = []string{"app"}
	req.NetworkAllowlist = []string{"openrouter.ai:443"}
	req.EgressProxy = goodProxy{stop: func() error {
		autoStopped = true
		return nil
	}}
	req.AdditionalMounts = []LaunchpadMount{{Name: "state", Source: t.TempDir(), Target: "/var/lib/app/state", ReadOnly: false}}
	req.AutoCleanup = true
	started, err := r.Start(req)
	if err != nil {
		t.Fatal(err)
	}
	if started.ContainerID == "" || started.EgressReceiptRef != "receipt:egress" || !autoStopped {
		t.Fatalf("start success handle mismatch: %#v stopped=%v", started, autoStopped)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--network launch-net", "-e TOKEN=secret", "-e APP_STATE_DIR=/var/lib/app/state", "-v", "app"} {
		if !strings.Contains(string(logData), want) {
			t.Fatalf("docker run log missing %q: %s", want, logData)
		}
	}

	writeExecutable(t, filepath.Join(startDockerDir, "docker"), `#!/bin/sh
if [ "$1" = "run" ]; then
  echo "stdout secret"
  echo "stderr secret" >&2
  exit 2
fi
exit 0
`)
	req = baseContainerRequest(t)
	req.DryRun = false
	req.Secrets = map[string]string{"TOKEN": "secret"}
	_, err = r.Start(req)
	if err == nil || !strings.Contains(err.Error(), "[REDACTED]") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("expected redacted command failure, got %v", err)
	}

	writeExecutable(t, filepath.Join(startDockerDir, "docker"), `#!/bin/sh
if [ "$1" = "run" ]; then
  echo detached-container
  exit 0
fi
if [ "$1" = "inspect" ]; then
  echo true
  exit 0
fi
if [ "$1" = "exec" ]; then
  echo ready
  exit 0
fi
exit 0
`)
	req = baseContainerRequest(t)
	req.DryRun = false
	req.Detached = true
	req.ReadinessTimeout = 50 * time.Millisecond
	req.Plan.Healthchecks = []registry.HealthcheckSpec{{Type: "command", Command: "ready"}}
	if _, err := r.Start(req); err != nil {
		t.Fatalf("expected detached readiness success with fake docker: %v", err)
	}
}

func TestCoverageEgressProxyAndNetworkBranches(t *testing.T) {
	if _, err := (StaticEgressProxy{}).Start(EgressProxyRequest{Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected missing static proxy URL error")
	}
	if _, err := (StaticEgressProxy{ProxyURL: "http://proxy"}).Start(EgressProxyRequest{Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected missing static proxy receipt error")
	}
	static, err := (StaticEgressProxy{ProxyURL: "http://proxy", ReceiptRef: "receipt"}).Start(EgressProxyRequest{
		Allowlist:          []string{"https://openrouter.ai"},
		PayloadInspection:  " custom-inspection ",
		NetworkProof:       " custom-proof ",
		TokenBrokerEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if static.PayloadInspection != "custom-inspection" || static.NetworkProof != "custom-proof" || !static.TokenBrokerEnabled {
		t.Fatalf("static proxy metadata mismatch: %#v", static)
	}
	if NetworkAllowed("http://openrouter.ai", []string{"openrouter.ai:80"}) != true || NetworkAllowed("example.com", []string{"openrouter.ai:443"}) {
		t.Fatal("network allowed normalization mismatch")
	}
	for _, item := range []struct {
		input string
		want  string
	}{
		{"", ""},
		{"https://OPENROUTER.ai/path", "openrouter.ai:443"},
		{"http://openrouter.ai/path", "openrouter.ai:80"},
		{"api.openrouter.ai", "api.openrouter.ai:443"},
		{"API.OPENROUTER.AI:443", "api.openrouter.ai:443"},
	} {
		if got := normalizeDestination(item.input); got != item.want {
			t.Fatalf("normalizeDestination(%q)=%q want=%q", item.input, got, item.want)
		}
	}

	fileRoot := t.TempDir()
	blocker := filepath.Join(fileRoot, "receipt-file")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLaunchOwnedEgressProxy().Start(EgressProxyRequest{LaunchID: "", Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected missing launch id error")
	}
	if _, err := NewLaunchOwnedEgressProxy().Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}, ReceiptDir: blocker}); err == nil {
		t.Fatal("expected receipt dir mkdir error")
	}
	if _, err := (LaunchOwnedEgressProxy{ListenAddr: "127.0.0.1:-1", ReceiptDir: t.TempDir()}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected invalid listen address error")
	}
	server := &egressProxyServer{
		launchID:     "launch",
		allowlist:    []string{"openrouter.ai:443"},
		receiptDir:   t.TempDir(),
		dialTimeout:  time.Millisecond,
		dialContext:  func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failed") },
		networkProof: "proof",
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://proxy", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported method status=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://proxy", nil)
	req.Host = "openrouter.ai:443"
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("dial failure status=%d", rec.Code)
	}
	upstreamA, upstreamB := net.Pipe()
	defer upstreamB.Close()
	server.dialContext = func(context.Context, string, string) (net.Conn, error) { return upstreamA, nil }
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodConnect, "http://proxy", nil)
	req.Host = "openrouter.ai:443"
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("hijack unavailable status=%d", rec.Code)
	}
	if ref := (&egressProxyServer{launchID: "launch", receiptDir: blocker}).writeReceipt("ALLOW", "dest", "write_error", nil); ref == "" {
		t.Fatal("receipt id should still be returned on write error")
	}
	if dir := defaultEgressReceiptDir("launch/id"); !strings.Contains(dir, safeFileComponent("launch/id")) {
		t.Fatalf("default receipt dir mismatch: %s", dir)
	}
	for _, item := range []struct {
		input string
		want  string
	}{
		{"sha256:abc/def", "abc-def"},
		{"...", "launch"},
		{"UP_ok-1.2", "UP_ok-1.2"},
	} {
		if got := safeFileComponent(item.input); got != item.want {
			t.Fatalf("safeFileComponent(%q)=%q want=%q", item.input, got, item.want)
		}
	}
}

func TestCoverageDockerSidecarProxyBranches(t *testing.T) {
	if _, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc"}).Start(EgressProxyRequest{Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected missing launch id error")
	}
	if _, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc"}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"example.com:443"}}); err == nil {
		t.Fatal("expected bad allowlist error")
	}
	if _, err := (DockerSidecarEgressProxy{}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected missing image error")
	}
	blocker := filepath.Join(t.TempDir(), "receipt-file")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc"}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}, ReceiptDir: blocker}); err == nil {
		t.Fatal("expected receipt dir error")
	}

	dockerDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
echo "$@" >> "$DOCKER_LOG"
if [ "$1" = "network" ] && [ "$2" = "create" ]; then
  echo net-created
  exit 0
fi
if [ "$1" = "run" ]; then
  echo proxy-container-id
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "connect" ]; then
  echo connected
  exit 0
fi
if [ "$1" = "rm" ]; then
  echo removed
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "rm" ]; then
  echo network-removed
  exit 0
fi
exit 0
`)
	t.Setenv("PATH", dockerDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_LOG", logPath)
	handle, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc", ReceiptDir: t.TempDir()}).Start(EgressProxyRequest{
		LaunchID:           "launch/sidecar",
		Allowlist:          []string{"openrouter.ai:443"},
		PayloadInspection:  "inspect",
		NetworkProof:       "proof",
		TokenBrokerEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if handle.ProxyContainerID != "proxy-container-id" || handle.NetworkName == "" || handle.ReceiptRef == "" || handle.ReceiptPath == "" || !handle.TokenBrokerEnabled {
		t.Fatalf("sidecar handle mismatch: %#v", handle)
	}
	if handle.ProxyImage != "image@sha256:abc" {
		t.Fatalf("sidecar proxy image = %q", handle.ProxyImage)
	}
	if _, err := os.Stat(handle.ReceiptPath); err != nil {
		t.Fatalf("sidecar receipt path not written: %v", err)
	}
	if err := handle.Stop(); err != nil {
		t.Fatalf("sidecar stop failed: %v", err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"network create", "run -d", "network connect", "rm -f"} {
		if !strings.Contains(string(logData), want) {
			t.Fatalf("docker log missing %q: %s", want, logData)
		}
	}
	if ref, _ := writeSidecarReceipt(blocker, "launch", "ALLOW", "write-error", nil); ref == "" {
		t.Fatal("sidecar receipt id should be returned on write failure")
	}

	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "create" ]; then
  echo create-failed
  exit 2
fi
exit 0
`)
	if _, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc", ReceiptDir: t.TempDir()}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected network create error")
	}
	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "create" ]; then exit 0; fi
if [ "$1" = "run" ]; then echo run-failed; exit 3; fi
exit 0
`)
	if _, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc", ReceiptDir: t.TempDir()}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected docker run error")
	}
	writeExecutable(t, filepath.Join(dockerDir, "docker"), `#!/bin/sh
if [ "$1" = "network" ] && [ "$2" = "create" ]; then exit 0; fi
if [ "$1" = "run" ]; then echo proxy-id; exit 0; fi
if [ "$1" = "network" ] && [ "$2" = "connect" ]; then echo connect-failed; exit 4; fi
exit 0
`)
	if _, err := (DockerSidecarEgressProxy{Image: "image@sha256:abc", ReceiptDir: t.TempDir()}).Start(EgressProxyRequest{LaunchID: "launch", Allowlist: []string{"openrouter.ai:443"}}); err == nil {
		t.Fatal("expected network connect error")
	}
}

type errorProxy struct{}

func (errorProxy) Start(EgressProxyRequest) (EgressProxyHandle, error) {
	return EgressProxyHandle{}, errors.New("proxy failed")
}

type incompleteProxy struct{}

func (incompleteProxy) Start(EgressProxyRequest) (EgressProxyHandle, error) {
	return EgressProxyHandle{ProxyURL: "http://proxy"}, nil
}

type goodProxy struct {
	stop func() error
}

func (p goodProxy) Start(req EgressProxyRequest) (EgressProxyHandle, error) {
	return EgressProxyHandle{
		ProxyURL:           "http://proxy:8080",
		ReceiptRef:         "receipt:egress",
		NetworkName:        "launch-net",
		ProxyContainerID:   "proxy-id",
		ProxyContainerName: "proxy-name",
		PayloadInspection:  payloadInspection(req.PayloadInspection),
		NetworkProof:       networkProof(req.NetworkProof),
		TokenBrokerEnabled: req.TokenBrokerEnabled,
		Stop:               p.stop,
	}, nil
}

func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}
