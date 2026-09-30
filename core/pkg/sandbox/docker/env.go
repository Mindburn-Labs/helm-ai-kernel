package docker

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

// envFlags passes environment variables to `docker run` by name only
// ("-e NAME"). Docker reads each value from its own environment, which
// commandEnv supplies, so no value lands in the docker process's argv:
// /proc/<pid>/cmdline and `ps` are readable by every local user (17-04).
func envFlags(env map[string]string) []string {
	flags := make([]string, 0, 2*len(env))
	for _, name := range slices.Sorted(maps.Keys(env)) {
		flags = append(flags, "-e", name)
	}
	return flags
}

// commandEnv is the docker CLI's environment: the caller's, plus env.
func commandEnv(env map[string]string) []string {
	out := os.Environ()
	for _, name := range slices.Sorted(maps.Keys(env)) {
		out = append(out, name+"="+env[name])
	}
	return out
}

// validateEnvNames rejects names that docker would parse as NAME=VALUE, which
// would put part of a value back into argv.
func validateEnvNames(env map[string]string) error {
	for name := range env {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return fmt.Errorf("sandbox spec: invalid environment variable name %q", name)
		}
	}
	return nil
}

// receiptSpec is the spec as recorded in an execution receipt. Receipts are
// evidence that gets stored, exported and logged, so env names are kept and
// values are not.
func receiptSpec(spec *sandbox.SandboxSpec) sandbox.SandboxSpec {
	out := *spec
	if spec.Env != nil {
		out.Env = make(map[string]string, len(spec.Env))
		for name := range spec.Env {
			out.Env[name] = "[REDACTED]"
		}
	}
	return out
}
