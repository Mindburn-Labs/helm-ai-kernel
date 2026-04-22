package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

// MockActuator is an in-memory SandboxActuator for conformance testing.
// It simulates lifecycle, execution, and filesystem without any external dependencies.
type MockActuator struct {
	mu        sync.Mutex
	sandboxes map[string]*mockSandbox
	clock     func() time.Time
	nextID    int
	faults    *FaultConfig
}

type mockSandbox struct {
	handle *actuators.SandboxHandle
	spec   *actuators.SandboxSpec
	files  map[string][]byte
	logs   []actuators.LogEntry
}

// NewMockActuator creates a mock actuator for testing.
func NewMockActuator() *MockActuator {
	return &MockActuator{
		sandboxes: make(map[string]*mockSandbox),
		clock:     time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (m *MockActuator) WithClock(clock func() time.Time) *MockActuator {
	m.clock = clock
	return m
}

func (m *MockActuator) Provider() string {
	return "mock"
}

func (m *MockActuator) Create(_ context.Context, spec *actuators.SandboxSpec) (*actuators.SandboxHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	id := fmt.Sprintf("mock-sbx-%d", m.nextID)

	handle := &actuators.SandboxHandle{
		ID:        id,
		Provider:  "mock",
		Status:    actuators.StatusRunning,
		CreatedAt: m.clock(),
		Metadata: map[string]string{
			"runtime": spec.Runtime,
		},
	}

	m.sandboxes[id] = &mockSandbox{
		handle: handle,
		spec:   spec,
		files:  make(map[string][]byte),
		logs:   make([]actuators.LogEntry, 0),
	}

	return handle, nil
}

func (m *MockActuator) Resume(_ context.Context, id string) (*actuators.SandboxHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.faultResume(); err != nil {
		return nil, err
	}

	sbx, ok := m.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	if sbx.handle.Status == actuators.StatusTerminated {
		return nil, actuators.ErrSandboxTerminated
	}
	sbx.handle.Status = actuators.StatusRunning
	return sbx.handle, nil
}

func (m *MockActuator) Pause(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sbx, ok := m.sandboxes[id]
	if !ok {
		return actuators.ErrSandboxNotFound
	}
	if sbx.handle.Status == actuators.StatusTerminated {
		return actuators.ErrSandboxTerminated
	}
	sbx.handle.Status = actuators.StatusPaused
	return nil
}

func (m *MockActuator) Terminate(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sbx, ok := m.sandboxes[id]
	if !ok {
		return actuators.ErrSandboxNotFound
	}
	sbx.handle.Status = actuators.StatusTerminated
	return nil
}

func (m *MockActuator) Exec(_ context.Context, id string, req *actuators.ExecRequest) (*actuators.ExecResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.faultExec(); err != nil {
		return nil, err
	}

	sbx, ok := m.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}
	if sbx.handle.Status != actuators.StatusRunning {
		return nil, fmt.Errorf("sandbox %q is not running (status: %s)", id, sbx.handle.Status)
	}

	now := m.clock()

	// Handle timeout simulation.
	if req.Timeout > 0 && len(req.Command) > 0 && req.Command[0] == "sleep" {
		result := &actuators.ExecResult{
			ExitCode: -1,
			TimedOut: true,
			Duration: req.Timeout,
			Receipt:  actuators.ComputeReceiptFragment(req, nil, nil, "mock", now, sbx.spec, actuators.EffectExecShell),
		}
		return result, nil
	}

	// Simulate execution: for echo commands, produce expected output.
	var stdout []byte
	if len(req.Command) > 0 && req.Command[0] == "echo" {
		for i, arg := range req.Command[1:] {
			if i > 0 {
				stdout = append(stdout, ' ')
			}
			stdout = append(stdout, []byte(arg)...)
		}
		stdout = append(stdout, '\n')
	}

	duration := time.Millisecond // Simulated fast execution.
	receipt := actuators.ComputeReceiptFragment(req, stdout, nil, "mock", now, sbx.spec, actuators.EffectExecShell)

	result := &actuators.ExecResult{
		ExitCode: 0,
		Stdout:   stdout,
		Stderr:   nil,
		Duration: duration,
		Receipt:  receipt,
	}

	sbx.logs = append(sbx.logs, actuators.LogEntry{
		Timestamp: now,
		Stream:    "stdout",
		Line:      string(stdout),
	})

	return result, nil
}

func (m *MockActuator) ReadFile(_ context.Context, id string, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sbx, ok := m.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}

	data, ok := sbx.files[path]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", path)
	}
	return data, nil
}

func (m *MockActuator) WriteFile(_ context.Context, id string, path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sbx, ok := m.sandboxes[id]
	if !ok {
		return actuators.ErrSandboxNotFound
	}

	sbx.files[path] = make([]byte, len(data))
	copy(sbx.files[path], data)
	return nil
}

func (m *MockActuator) ListFiles(_ context.Context, id string, dir string) ([]actuators.FileEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sbx, ok := m.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}

	var entries []actuators.FileEntry
	for path, data := range sbx.files {
		entries = append(entries, actuators.FileEntry{
			Name:    path,
			Path:    path,
			IsDir:   false,
			Size:    int64(len(data)),
			ModTime: m.clock(),
		})
	}
	_ = dir // Mock does not filter by directory — conformance tests use full paths.
	return entries, nil
}

func (m *MockActuator) AllowEgress(_ context.Context, id string, _ []actuators.EgressRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.sandboxes[id]
	if !ok {
		return actuators.ErrSandboxNotFound
	}
	return nil // Mock accepts any egress rules.
}

func (m *MockActuator) Logs(_ context.Context, id string, opts *actuators.LogOptions) ([]actuators.LogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sbx, ok := m.sandboxes[id]
	if !ok {
		return nil, actuators.ErrSandboxNotFound
	}

	logs := sbx.logs
	if opts != nil && opts.Tail > 0 && len(logs) > opts.Tail {
		logs = logs[len(logs)-opts.Tail:]
	}
	return logs, nil
}

func (m *MockActuator) Preflight(ctx context.Context) (*actuators.PreflightReport, error) {
	return m.preflightWithFaults(ctx)
}

// ── Receipt computation verification ────────────────────────────

// verifyReceiptDeterminism runs the same command twice and returns true
// if the receipt hashes match. Exported for use in adapter tests.
func VerifyReceiptDeterminism(a actuators.SandboxActuator, req *actuators.ExecRequest) (bool, error) {
	ctx := context.Background()
	handle, err := a.Create(ctx, defaultSpec())
	if err != nil {
		return false, err
	}
	defer a.Terminate(ctx, handle.ID) //nolint:errcheck

	r1, err := a.Exec(ctx, handle.ID, req)
	if err != nil {
		return false, err
	}
	r2, err := a.Exec(ctx, handle.ID, req)
	if err != nil {
		return false, err
	}

	return r1.Receipt.RequestHash == r2.Receipt.RequestHash &&
		r1.Receipt.StdoutHash == r2.Receipt.StdoutHash, nil
}

// computeRequestHash is a test helper for verifying receipt fragments.
func computeRequestHash(req *actuators.ExecRequest) string {
	data, _ := json.Marshal(req)
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}
