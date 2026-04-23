package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Sandbox defines the isolation environment for executing packs.
// Must support strict resource limits and capability filtering.
type Sandbox interface {
	// Run executes a pack with the given input and returns the result.
	Run(ctx context.Context, packRef trust.PackRef, input []byte) ([]byte, error)

	// Close cleans up sandbox resources.
	Close(ctx context.Context) error
}

// SandboxConfig configures restrictions.
type SandboxConfig struct {
	MemoryLimitBytes int64
	CPUTimeLimit     time.Duration
	AllowedSyscalls  []string
	NetworkEnabled   bool
}

// InProcessSandbox is a developer-mode sandbox that runs code natively.
// WARNING: NOT SECURE. DO NOT USE IN PRODUCTION.
type InProcessSandbox struct{}

func NewInProcessSandbox() *InProcessSandbox {
	return &InProcessSandbox{}
}

func (s *InProcessSandbox) Run(ctx context.Context, packRef trust.PackRef, input []byte) ([]byte, error) {
	// Simulation of running a pack
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return []byte(fmt.Sprintf("echo: %s", string(input))), nil
	}
}

func (s *InProcessSandbox) Close(ctx context.Context) error {
	return nil
}

// WasiSandbox enforces strict confinement using WebAssembly (wazero).
type WasiSandbox struct {
	runtime  wazero.Runtime
	artStore artifacts.Store
	config   SandboxConfig
}

// NewWasiSandbox creates a secure WASI sandbox.
func NewWasiSandbox(ctx context.Context, artStore artifacts.Store, config SandboxConfig) (*WasiSandbox, error) {
	// Create runtime with memory limits
	rConfig := wazero.NewRuntimeConfig()
	if config.MemoryLimitBytes > 0 {
		pages := uint32(config.MemoryLimitBytes / 65536) // 64KB per page
		if pages == 0 {
			pages = 1
		}
		rConfig = rConfig.WithMemoryLimitPages(pages)
	}
	r := wazero.NewRuntimeWithConfig(ctx, rConfig)
	// Instantiate WASI
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate WASI: %w", err)
	}
	return &WasiSandbox{
		runtime:  r,
		artStore: artStore,
		config:   config,
	}, nil
}

// OutputMaxBytes is the maximum size of stdout+stderr output from a sandbox execution.
const OutputMaxBytes = 1024 * 1024 // 1MB

func (s *WasiSandbox) Run(ctx context.Context, packRef trust.PackRef, input []byte) ([]byte, error) {
	// 1. Fetch WASM binary from Artifact Store
	wasmBytes, err := s.artStore.Get(ctx, packRef.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to load WASM blob %s: %w", packRef.Hash, err)
	}

	// 2. Enforce time limit via context deadline
	execCtx := ctx
	if s.config.CPUTimeLimit > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, s.config.CPUTimeLimit)
		defer cancel()
	}

	// 3. Configure stdin/stdout/stderr capture
	var stdout, stderr bytes.Buffer
	moduleConfig := wazero.NewModuleConfig().
		WithStdin(bytes.NewReader(input)).
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithName("sandbox")

	// No filesystem, no network (WASI deny-by-default)

	// 4. Compile
	compiled, err := s.runtime.CompileModule(execCtx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compile WASM module: %w", err)
	}
	defer func() { _ = compiled.Close(execCtx) }()

	// 5. Instantiate+Run with enforced limits
	mod, err := s.runtime.InstantiateModule(execCtx, compiled, moduleConfig)
	if err != nil {
		// Check for context deadline exceeded (time limit)
		if execCtx.Err() != nil {
			return nil, &SandboxError{
				Code:    ErrComputeTimeExhausted,
				Message: fmt.Sprintf("WASI execution exceeded time limit (%s)", s.config.CPUTimeLimit),
			}
		}
		// Check for memory limit (wazero returns error on memory.grow failure)
		if isMemoryError(err) {
			return nil, &SandboxError{
				Code:    ErrComputeMemoryExhausted,
				Message: fmt.Sprintf("WASI execution exceeded memory limit (%d bytes)", s.config.MemoryLimitBytes),
			}
		}
		return nil, fmt.Errorf("WASI execution failed: %w", err)
	}
	defer func() { _ = mod.Close(execCtx) }()

	// 6. Enforce output size limits
	totalOutput := stdout.Len() + stderr.Len()
	if totalOutput > OutputMaxBytes {
		return nil, &SandboxError{
			Code:    ErrComputeOutputExhausted,
			Message: fmt.Sprintf("output size %d exceeds limit %d", totalOutput, OutputMaxBytes),
		}
	}

	return stdout.Bytes(), nil
}

func (s *WasiSandbox) Close(ctx context.Context) error {
	return s.runtime.Close(ctx)
}

// Deterministic error codes for sandbox violations.
const (
	ErrComputeTimeExhausted   = "ERR_COMPUTE_TIME_EXHAUSTED"
	ErrComputeMemoryExhausted = "ERR_COMPUTE_MEMORY_EXHAUSTED"
	ErrComputeOutputExhausted = "ERR_COMPUTE_OUTPUT_EXHAUSTED"
)

// SandboxError is a deterministic, typed error for sandbox limit violations.
type SandboxError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *SandboxError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// isMemoryError checks if the error is a memory limit violation.
func isMemoryError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "memory") &&
		(strings.Contains(msg, "limit") || strings.Contains(msg, "grow") || strings.Contains(msg, "exceeded"))
}
