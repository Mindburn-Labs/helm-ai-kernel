package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

func TestWASISandbox_DenyByDefault(t *testing.T) {
	ctx := context.Background()
	cfg := SandboxConfig{
		MemoryLimitBytes: 16 * 1024 * 1024, // 16 MB
		CPUTimeLimit:     2 * time.Second,
		NetworkEnabled:   false,
	}

	sandbox, err := NewWASISandbox(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create WASI sandbox: %v", err)
	}
	defer func() { _ = sandbox.Close() }()

	// Test: Run with a pack that has no WASM content should error gracefully
	packRef := trust.PackRef{
		Name:      "test-pack",
		Hash:      "sha256:deadbeef",
		Certified: true,
	}

	_, err = sandbox.Run(ctx, packRef, []byte("hello"))
	if err == nil {
		t.Fatal("expected error when running unresolvable pack, got nil")
	}
	// Should contain resolution error, not a panic or crash
	if !containsAny(err.Error(), "resolve", "not yet implemented") {
		t.Fatalf("expected resolution error, got: %v", err)
	}
}

func TestWASISandbox_MemoryLimit(t *testing.T) {
	ctx := context.Background()
	cfg := SandboxConfig{
		MemoryLimitBytes: 1 * 1024 * 1024, // 1 MB — very tight
		CPUTimeLimit:     1 * time.Second,
	}

	sandbox, err := NewWASISandbox(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create WASI sandbox: %v", err)
	}
	defer func() { _ = sandbox.Close() }()

	// Validate the sandbox was created with correct config
	if sandbox.limits.MemoryLimitBytes != 1*1024*1024 {
		t.Fatalf("expected 1MB memory limit, got %d", sandbox.limits.MemoryLimitBytes)
	}
	if sandbox.limits.CPUTimeLimit != 1*time.Second {
		t.Fatalf("expected 1s CPU limit, got %v", sandbox.limits.CPUTimeLimit)
	}
}

func TestWASISandbox_Close(t *testing.T) {
	ctx := context.Background()
	cfg := SandboxConfig{
		MemoryLimitBytes: 8 * 1024 * 1024,
		CPUTimeLimit:     5 * time.Second,
	}

	sandbox, err := NewWASISandbox(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create WASI sandbox: %v", err)
	}

	// Close should not error
	if err := sandbox.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(sub) > 0 && contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
