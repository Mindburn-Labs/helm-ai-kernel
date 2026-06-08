package docker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

func TestDockerRunnerValidateAndRun(t *testing.T) {
	r := NewDockerRunner()
	if r.dockerBin != "docker" || r.clock == nil {
		t.Fatalf("NewDockerRunner() = %#v", r)
	}

	for _, tt := range []struct {
		name string
		spec *sandbox.SandboxSpec
		want string
	}{
		{"missing image", dockerSpec(func(s *sandbox.SandboxSpec) { s.Image = "" }), "image is required"},
		{"missing command", dockerSpec(func(s *sandbox.SandboxSpec) { s.Command = nil }), "command is required"},
		{"missing timeout", dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.Timeout = 0 }), "timeout is required"},
		{"missing memory", dockerSpec(func(s *sandbox.SandboxSpec) { s.Limits.MemoryMB = 0 }), "memory limit is required"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := r.Validate(tt.spec); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
	if err := r.Validate(dockerSpec()); err != nil {
		t.Fatalf("Validate() success error = %v", err)
	}

	if _, _, err := r.Run(&sandbox.SandboxSpec{}); err == nil || !strings.Contains(err.Error(), "image is required") {
		t.Fatalf("Run() validation error = %v", err)
	}

	helper := makeDockerHelper(t)
	r.dockerBin = helper
	r.clock = fixedClock(time.Unix(100, 0), time.Unix(101, 0))

	spec := dockerSpec(func(s *sandbox.SandboxSpec) {
		s.Limits.CPUMillis = 500
		s.Limits.MaxProcesses = 12
		s.Network.NetworkName = "egress-net"
		s.Labels = map[string]string{"launch_id": "launch-1"}
		s.Env = map[string]string{"A": "B"}
		s.Mounts = []sandbox.Mount{{Source: "/host", Target: "/guest", ReadOnly: true}}
		s.WorkDir = "/workspace"
		s.RuntimeClass = "runsc"
	})
	result, receipt, err := r.Run(spec)
	if err != nil {
		t.Fatalf("Run() success error = %v", err)
	}
	if string(result.Stdout) != "container-id\n" || string(result.Stderr) != "helper-stderr\n" || !result.Success() {
		t.Fatalf("Run() result = %#v", result)
	}
	if receipt.ExecutionID != "sandbox-100000000000" || receipt.ImageDigest != spec.Image || receipt.StdoutHash == "" || receipt.StderrHash == "" {
		t.Fatalf("receipt = %#v", receipt)
	}

	detached := dockerSpec(func(s *sandbox.SandboxSpec) {
		s.Detached = true
		s.Network.Disabled = true
	})
	if _, _, err := r.Run(detached); err != nil {
		t.Fatalf("Run() detached error = %v", err)
	}

	conflict := dockerSpec(func(s *sandbox.SandboxSpec) {
		s.Network.Disabled = true
		s.Network.NetworkName = "net"
	})
	if _, _, err := r.Run(conflict); err == nil || !strings.Contains(err.Error(), "network cannot be both disabled") {
		t.Fatalf("Run() network conflict error = %v", err)
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

	result, receipt, err = r.Run(dockerSpec(func(s *sandbox.SandboxSpec) {
		s.Detached = true
		s.Limits.Timeout = time.Nanosecond
	}))
	if err != nil || receipt == nil || result.ExitCode != -1 || !result.TimedOut {
		t.Fatalf("Run() detached timeout = result %#v receipt %#v err %v", result, receipt, err)
	}

	t.Setenv("DOCKER_HELPER_MODE", "success")
	r.dockerBin = filepath.Join(t.TempDir(), "missing-docker")
	result, receipt, err = r.Run(dockerSpec())
	if err == nil || !strings.Contains(err.Error(), "docker run failed") || receipt != nil || result == nil {
		t.Fatalf("Run() exec failure = result %#v receipt %#v err %v", result, receipt, err)
	}
}

func makeDockerHelper(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "docker-helper.sh")
	script := `#!/bin/sh
if [ "$1" = "-H" ]; then
  shift 2
fi
mode="${DOCKER_HELPER_MODE:-success}"
cmd="$1"
case "$mode" in
  sleep)
    sleep 1
    exit 0
    ;;
  exit2)
    echo "exit two" >&2
    exit 2
    ;;
  exit137)
    echo "oom" >&2
    exit 137
    ;;
  fail)
    echo "failed $cmd" >&2
    exit 1
    ;;
  inspect-json)
    if [ "$cmd" = "inspect" ]; then
      echo '{"Id":"sandbox-1","State":{"Running":true}}'
      exit 0
    fi
    ;;
  inspect-bad-json)
    if [ "$cmd" = "inspect" ]; then
      echo '{'
      exit 0
    fi
    ;;
esac
if [ "$cmd" = "inspect" ]; then
  echo '{"Id":"sandbox-1"}'
  exit 0
fi
echo "container-id"
echo "helper-stderr" >&2
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write docker helper: %v", err)
	}
	return path
}

func dockerSpec(opts ...func(*sandbox.SandboxSpec)) *sandbox.SandboxSpec {
	spec := &sandbox.SandboxSpec{
		Image:   "example.com/image@sha256:abc",
		Command: []string{"echo"},
		Args:    []string{"hello"},
		Limits: sandbox.ResourceLimits{
			MemoryMB: 128,
			Timeout:  time.Second,
		},
	}
	for _, opt := range opts {
		opt(spec)
	}
	return spec
}

func fixedClock(times ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if index >= len(times) {
			return times[len(times)-1]
		}
		t := times[index]
		index++
		return t
	}
}
