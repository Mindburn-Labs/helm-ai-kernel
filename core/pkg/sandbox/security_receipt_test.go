package sandbox

import (
	"errors"
	"testing"
	"time"
)

func TestNewSandboxSecurityReceiptAcceptsPinnedCredentialFreeExecution(t *testing.T) {
	exec := baselineExecutionReceipt()

	receipt, err := NewSandboxSecurityReceipt(exec, "sha256:build", "sha256:poc", "sha256:verdict", "sha256:secrets", true)
	if err != nil {
		t.Fatalf("NewSandboxSecurityReceipt: %v", err)
	}
	if receipt.ExecutionID != exec.ExecutionID {
		t.Fatalf("execution id mismatch: %#v", receipt)
	}
	if receipt.SpecHash == "" || receipt.SandboxConfigHash == "" || receipt.MountedPathsHash == "" {
		t.Fatalf("receipt missing derived hashes: %#v", receipt)
	}
	if err := ValidateSandboxSecurityReceipt(exec, receipt); err != nil {
		t.Fatalf("ValidateSandboxSecurityReceipt: %v", err)
	}
}

func TestSandboxSecurityReceiptRejectsUnpinnedImage(t *testing.T) {
	exec := baselineExecutionReceipt()
	exec.Spec.Image = "ubuntu:latest"

	if _, err := NewSandboxSecurityReceipt(exec, "sha256:build", "sha256:poc", "sha256:verdict", "sha256:secrets", true); !errors.Is(err, errSandboxSecurityReceiptInvalid) {
		t.Fatalf("error = %v, want errSandboxSecurityReceiptInvalid", err)
	}
}

func TestSandboxSecurityReceiptRejectsUnrestrictedNetwork(t *testing.T) {
	exec := baselineExecutionReceipt()
	exec.Spec.Network.Disabled = false
	exec.Spec.Network.EgressAllowlist = nil

	if _, err := NewSandboxSecurityReceipt(exec, "sha256:build", "sha256:poc", "sha256:verdict", "sha256:secrets", true); !errors.Is(err, errSandboxSecurityReceiptInvalid) {
		t.Fatalf("error = %v, want errSandboxSecurityReceiptInvalid", err)
	}
}

func TestSandboxSecurityReceiptRejectsCredentialMaterial(t *testing.T) {
	exec := baselineExecutionReceipt()
	exec.Spec.Env["GITHUB_TOKEN"] = "redacted"

	if _, err := NewSandboxSecurityReceipt(exec, "sha256:build", "sha256:poc", "sha256:verdict", "sha256:secrets", true); !errors.Is(err, errSandboxCredentialMaterial) {
		t.Fatalf("error = %v, want errSandboxCredentialMaterial", err)
	}
}

func baselineExecutionReceipt() *ExecutionReceipt {
	started := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	spec := SandboxSpec{
		Image:   "registry.example/helm-verifier@sha256:abc123",
		Command: []string{"/bin/verify"},
		Args:    []string{"--finding", "finding-1"},
		Env:     map[string]string{"HELM_MODE": "verify"},
		Mounts: []Mount{{
			Source:   "/tmp/helm/repo",
			Target:   "/workspace/repo",
			ReadOnly: true,
		}},
		Limits: ResourceLimits{
			CPUMillis:    500,
			MemoryMB:     1024,
			DiskMB:       2048,
			Timeout:      time.Minute,
			MaxProcesses: 64,
		},
		Network: NetworkPolicy{
			Disabled: true,
		},
		WorkDir: "/workspace/repo",
	}
	return &ExecutionReceipt{
		ExecutionID: "exec-verify-1",
		Spec:        spec,
		Result:      Result{ExitCode: 0, Duration: time.Second},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		ImageDigest: "sha256:abc123",
		StdoutHash:  "sha256:stdout",
		StderrHash:  "sha256:stderr",
	}
}
