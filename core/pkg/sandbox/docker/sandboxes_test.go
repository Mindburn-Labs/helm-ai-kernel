package docker

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

func TestSandboxesRunnerConfigValidateArgsAndCommand(t *testing.T) {
	defaults := DefaultSandboxesConfig()
	if defaults.DockerBin != "docker" || defaults.DefaultTimeout != 30*time.Minute {
		t.Fatalf("DefaultSandboxesConfig() = %#v", defaults)
	}

	r := NewSandboxesRunner(SandboxesConfig{})
	if r.config.DockerBin != "docker" || r.config.DefaultTimeout != 30*time.Minute || r.clock == nil {
		t.Fatalf("NewSandboxesRunner(defaults) = %#v", r)
	}
	if r.WithClock(time.Now) != r {
		t.Fatal("WithClock() did not return receiver")
	}

	for _, tt := range []struct {
		name string
		spec *sandbox.SandboxSpec
		want string
	}{
		{"missing image", dockerSpec(func(s *sandbox.SandboxSpec) { s.Image = "" }), "image is required"},
		{"missing command", dockerSpec(func(s *sandbox.SandboxSpec) { s.Command = nil }), "command is required"},
		{"missing memory", dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.MemoryMB = 0 }), "memory limit is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := r.Validate(tt.spec); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
	if err := r.Validate(dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.Timeout = 0 })); err != nil {
		t.Fatalf("Validate() with default timeout error = %v", err)
	}
	zeroTimeoutRunner := &SandboxesRunner{}
	if err := zeroTimeoutRunner.Validate(dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.Timeout = 0 })); err == nil || !strings.Contains(err.Error(), "timeout is required") {
		t.Fatalf("Validate() zero timeout error = %v", err)
	}

	args := r.buildRunArgs(dockerSpec(func(s *sandbox.SandboxSpec) {
		s.Limits.CPUMillis = 750
		s.Limits.MaxProcesses = 8
		s.Limits.DiskMB = 64
		s.Env = map[string]string{"A": "B"}
		s.Mounts = []sandbox.Mount{{Source: "/host", Target: "/guest", ReadOnly: true}}
		s.WorkDir = "/workspace"
	}), "exec-1")
	for _, want := range []string{"--memory", "128m", "--cpus", "0.75", "--pids-limit", "8", "--storage-opt", "size=64M", "--network", "bridge", "--dns", "0.0.0.0", "-e", "A=B", "-v", "/host:/guest:ro", "-w", "/workspace"} {
		if !containsArg(args, want) {
			t.Fatalf("buildRunArgs() missing %q in %#v", want, args)
		}
	}

	args = r.buildRunArgs(dockerSpec(func(s *sandbox.SandboxSpec) {
		s.Network.Disabled = true
		s.Network.NetworkName = "ignored"
	}), "exec-2")
	if !containsPair(args, "--network", "none") {
		t.Fatalf("disabled named network args = %#v", args)
	}

	args = r.buildRunArgs(dockerSpec(func(s *sandbox.SandboxSpec) { s.Network.Disabled = true }), "exec-3")
	if !containsPair(args, "--network", "none") {
		t.Fatalf("disabled network args = %#v", args)
	}

	args = r.buildRunArgs(dockerSpec(func(s *sandbox.SandboxSpec) { s.Network.NetworkName = "egress-net" }), "exec-4")
	if !containsPair(args, "--network", "egress-net") {
		t.Fatalf("named network args = %#v", args)
	}

	cmd := r.buildCommand(context.Background(), "ps")
	if got := strings.Join(cmd.Args, " "); got != "docker ps" {
		t.Fatalf("buildCommand() args = %q", got)
	}
	socketRunner := NewSandboxesRunner(SandboxesConfig{DockerBin: "docker", DockerSocket: "/tmp/docker.sock"})
	cmd = socketRunner.buildCommand(context.Background(), "ps")
	if got := strings.Join(cmd.Args, " "); got != "docker -H unix:///tmp/docker.sock ps" {
		t.Fatalf("buildCommand(socket) args = %q", got)
	}
}

func TestSandboxesRunnerRunSnapshotInspectStopRemove(t *testing.T) {
	helper := makeDockerHelper(t)
	r := NewSandboxesRunner(SandboxesConfig{
		DockerBin:      helper,
		SnapshotDir:    "snapshots",
		RegistryPrefix: "registry.local",
		DefaultTimeout: 10 * time.Second,
	}).WithClock(fixedClock(time.Unix(200, 0), time.Unix(201, 0), time.Unix(202, 0), time.Unix(203, 0)))

	if _, _, err := r.Run(&sandbox.SandboxSpec{}); err == nil || !strings.Contains(err.Error(), "image is required") {
		t.Fatalf("Run() validation error = %v", err)
	}

	result, receipt, err := r.Run(dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.Timeout = 0 }))
	if err != nil {
		t.Fatalf("Run() success error = %v", err)
	}
	if string(result.Stdout) != "container-id\n" || !result.Success() || receipt.ExecutionID != "sbx-200000000000" {
		t.Fatalf("Run() success result %#v receipt %#v", result, receipt)
	}

	t.Setenv("DOCKER_HELPER_MODE", "exit2")
	result, receipt, err = r.Run(dockerSpec())
	if err != nil || receipt == nil || result.ExitCode != 2 {
		t.Fatalf("Run() exit2 = result %#v receipt %#v err %v", result, receipt, err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "exit137")
	result, receipt, err = r.Run(dockerSpec())
	if err != nil || receipt == nil || result.ExitCode != 137 || !result.OOMKilled {
		t.Fatalf("Run() exit137 = result %#v receipt %#v err %v", result, receipt, err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "sleep")
	result, receipt, err = r.Run(dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.Timeout = time.Nanosecond }))
	if err != nil || receipt == nil || result.ExitCode != -1 || !result.TimedOut {
		t.Fatalf("Run() timeout = result %#v receipt %#v err %v", result, receipt, err)
	}

	missing := NewSandboxesRunner(SandboxesConfig{DockerBin: filepath.Join(t.TempDir(), "missing-docker"), DefaultTimeout: time.Second})
	result, receipt, err = missing.Run(dockerSpec())
	if err == nil || !strings.Contains(err.Error(), "docker run failed") || result == nil || receipt != nil {
		t.Fatalf("Run() exec failure = result %#v receipt %#v err %v", result, receipt, err)
	}

	noSnapshotDir := NewSandboxesRunner(SandboxesConfig{DockerBin: helper})
	if _, err := noSnapshotDir.Snapshot("sandbox-1"); err == nil || !strings.Contains(err.Error(), "snapshot directory not configured") {
		t.Fatalf("Snapshot() without dir error = %v", err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "success")
	snapshot, err := r.Snapshot("sandbox-1")
	if err != nil {
		t.Fatalf("Snapshot() success error = %v", err)
	}
	if !strings.HasPrefix(snapshot.SnapshotID, "snap-sandbox-1-") || snapshot.SandboxID != "sandbox-1" || snapshot.CreatedAt.IsZero() {
		t.Fatalf("Snapshot() = %#v", snapshot)
	}

	t.Setenv("DOCKER_HELPER_MODE", "fail")
	if _, err := r.Snapshot("sandbox-1"); err == nil || !strings.Contains(err.Error(), "docker commit failed") {
		t.Fatalf("Snapshot() failure error = %v", err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "inspect-json")
	inspection, err := r.Inspect("sandbox-1")
	if err != nil {
		t.Fatalf("Inspect() success error = %v", err)
	}
	if inspection.SandboxID != "sandbox-1" || inspection.Raw["Id"] != "sandbox-1" || inspection.InspectedAt.IsZero() {
		t.Fatalf("Inspect() = %#v", inspection)
	}

	t.Setenv("DOCKER_HELPER_MODE", "inspect-bad-json")
	if _, err := r.Inspect("sandbox-1"); err == nil || !strings.Contains(err.Error(), "parse inspect output") {
		t.Fatalf("Inspect() bad JSON error = %v", err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "fail")
	if _, err := r.Inspect("sandbox-1"); err == nil || !strings.Contains(err.Error(), "docker inspect failed") {
		t.Fatalf("Inspect() command error = %v", err)
	}
	if err := r.Stop("sandbox-1", 5); err == nil || !strings.Contains(err.Error(), "docker stop") {
		t.Fatalf("Stop() failure error = %v", err)
	}
	if err := r.Remove("sandbox-1"); err == nil || !strings.Contains(err.Error(), "docker rm") {
		t.Fatalf("Remove() failure error = %v", err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "success")
	if err := r.Stop("sandbox-1", 5); err != nil {
		t.Fatalf("Stop() success error = %v", err)
	}
	if err := r.Remove("sandbox-1"); err != nil {
		t.Fatalf("Remove() success error = %v", err)
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func containsPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}
