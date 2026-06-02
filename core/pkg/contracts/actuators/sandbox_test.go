package actuators

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestClassifyEffect(t *testing.T) {
	tests := map[string]EffectClass{
		"Create":      EffectLifecycleCreate,
		"Resume":      EffectLifecycleResume,
		"Pause":       EffectLifecycleTerminate,
		"Terminate":   EffectLifecycleTerminate,
		"Exec":        EffectExecShell,
		"ReadFile":    EffectFSRead,
		"ListFiles":   EffectFSRead,
		"WriteFile":   EffectFSWrite,
		"AllowEgress": EffectNetEgressChange,
		"Unknown":     EffectExecShell,
	}

	for method, want := range tests {
		if got := ClassifyEffect(method); got != want {
			t.Fatalf("ClassifyEffect(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestExecResultSuccess(t *testing.T) {
	tests := []struct {
		name string
		res  ExecResult
		want bool
	}{
		{"clean", ExecResult{ExitCode: 0}, true},
		{"non-zero", ExecResult{ExitCode: 1}, false},
		{"oom", ExecResult{ExitCode: 0, OOMKilled: true}, false},
		{"timed out", ExecResult{ExitCode: 0, TimedOut: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.res.Success(); got != tt.want {
				t.Fatalf("Success() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeSandboxSpecHashAndReceiptFragment(t *testing.T) {
	emptyHash := sha256.Sum256(nil)
	wantEmpty := "sha256:" + hex.EncodeToString(emptyHash[:])
	if got := ComputeSandboxSpecHash(nil); got != wantEmpty {
		t.Fatalf("ComputeSandboxSpecHash(nil) = %q, want %q", got, wantEmpty)
	}

	spec := &SandboxSpec{
		Runtime: "ubuntu@sha256:abc",
		Resources: ResourceSpec{
			CPUMillis:    500,
			MemoryMB:     256,
			DiskMB:       1024,
			Timeout:      time.Minute,
			MaxProcesses: 16,
		},
		Egress: EgressPolicy{
			DefaultAllowlist: []EgressRule{{Host: "example.com", Port: 443, Protocol: "tcp"}},
		},
		Mounts: []MountSpec{{Source: "src", Target: "/mnt/src", ReadOnly: true}},
	}

	specHash := ComputeSandboxSpecHash(spec)
	if !strings.HasPrefix(specHash, "sha256:") || specHash == wantEmpty {
		t.Fatalf("ComputeSandboxSpecHash(spec) = %q", specHash)
	}
	if computeFieldHash(spec.Resources) != computeFieldHash(spec.Resources) {
		t.Fatal("computeFieldHash() is not deterministic")
	}

	executedAt := time.Unix(1700000000, 0).UTC()
	req := &ExecRequest{Command: []string{"echo", "hello"}, WorkDir: "/workspace"}
	frag := ComputeReceiptFragment(req, []byte("out"), []byte("err"), "docker", executedAt, spec, EffectExecShell)

	if !strings.HasPrefix(frag.RequestHash, "sha256:") || !strings.HasPrefix(frag.StdoutHash, "sha256:") || !strings.HasPrefix(frag.StderrHash, "sha256:") {
		t.Fatalf("receipt hashes missing sha256 prefix: %#v", frag)
	}
	if frag.Provider != "docker" || !frag.ExecutedAt.Equal(executedAt) || frag.Effect != EffectExecShell {
		t.Fatalf("receipt identity fields = %#v", frag)
	}
	if frag.SandboxSpecHash != specHash || frag.ImageDigest != spec.Runtime {
		t.Fatalf("spec-bound fields = %#v", frag)
	}
	if frag.ResourceLimitsHash == "" || frag.EgressPolicyHash == "" || frag.MountManifestHash == "" {
		t.Fatalf("expected spec field hashes, got %#v", frag)
	}

	nilSpecFrag := ComputeReceiptFragment(req, nil, nil, "provider", executedAt, nil, EffectFSRead)
	if nilSpecFrag.SandboxSpecHash != wantEmpty || nilSpecFrag.ResourceLimitsHash != "" || nilSpecFrag.EgressPolicyHash != "" || nilSpecFrag.ImageDigest != "" {
		t.Fatalf("nil spec receipt fields = %#v", nilSpecFrag)
	}
}
