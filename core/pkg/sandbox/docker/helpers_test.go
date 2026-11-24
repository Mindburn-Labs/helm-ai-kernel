package docker

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

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
			// Generous so loaded CI machines never turn helper-script exec
			// into a spurious timeout; deliberate-timeout cases override
			// this with an explicit nanosecond limit.
			Timeout: 10 * time.Second,
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
