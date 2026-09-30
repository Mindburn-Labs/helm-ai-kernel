package docker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/secrettest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

const canary = "sk-or-CANARY-0f3a9c2e7b1d"

func secretSpec() *sandbox.SandboxSpec {
	return &sandbox.SandboxSpec{
		Image:   "example.com/app@sha256:abc",
		Command: []string{"/bin/true"},
		Env:     map[string]string{"OPENROUTER_API_KEY": canary},
		Limits:  sandbox.ResourceLimits{Timeout: time.Minute, MemoryMB: 64, CPUMillis: 100, MaxProcesses: 8},
		Network: sandbox.NetworkPolicy{Disabled: true},
	}
}

// 17-04: sandbox env values must not appear in the docker CLI's argv, which
// every local user can read, or in logs. They still reach docker by env.
func TestDockerRunnerKeepsSecretsOutOfArgvAndLogs(t *testing.T) {
	docker := secrettest.FakeExecutable(t, "docker", "")
	logs := secrettest.CaptureLogs(t)

	r := NewDockerRunner()
	r.dockerBin = docker.Path
	result, receipt, err := r.Run(secretSpec())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(struct{ Result, Receipt any }{result, receipt})

	argv := docker.Argv(t)
	secrettest.AssertAbsent(t, canary, map[string]string{"docker argv": argv, "logs": logs.String(), "result and receipt": string(out)})
	if receipt.Spec.Env["OPENROUTER_API_KEY"] != "[REDACTED]" {
		t.Fatalf("receipt lost the env name: %v", receipt.Spec.Env)
	}
	if !strings.Contains(argv, "[-e] [OPENROUTER_API_KEY]") {
		t.Fatalf("env var not passed by name: %s", argv)
	}
	if !strings.Contains(docker.Env(t), "OPENROUTER_API_KEY="+canary) {
		t.Fatal("secret no longer reaches docker's environment")
	}
}

func TestSandboxesRunnerKeepsSecretsOutOfArgvAndLogs(t *testing.T) {
	docker := secrettest.FakeExecutable(t, "docker", "")
	logs := secrettest.CaptureLogs(t)

	r := NewSandboxesRunner(SandboxesConfig{DockerBin: docker.Path})
	result, receipt, err := r.Run(secretSpec())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(struct{ Result, Receipt any }{result, receipt})

	secrettest.AssertAbsent(t, canary, map[string]string{"docker argv": docker.Argv(t), "logs": logs.String(), "result and receipt": string(out)})
	if !strings.Contains(docker.Env(t), "OPENROUTER_API_KEY="+canary) {
		t.Fatal("secret no longer reaches docker's environment")
	}
}

func TestEnvNamesThatWouldCarryValuesAreRejected(t *testing.T) {
	for _, name := range []string{"", "KEY=" + canary, "A\x00B"} {
		spec := secretSpec()
		spec.Env = map[string]string{name: "v"}
		if err := NewDockerRunner().Validate(spec); err == nil {
			t.Fatalf("DockerRunner accepted env name %q", name)
		}
		if err := NewSandboxesRunner(SandboxesConfig{}).Validate(spec); err == nil {
			t.Fatalf("SandboxesRunner accepted env name %q", name)
		}
	}
}
