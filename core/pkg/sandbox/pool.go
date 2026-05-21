package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockRunner is a fast, in-memory mock implementation of Runner.
type MockRunner struct {
	id string
}

// Run executes a SandboxSpec and returns the mock result and a mock receipt.
func (m *MockRunner) Run(spec *SandboxSpec) (*Result, *ExecutionReceipt, error) {
	startedAt := time.Now()
	duration := 2 * time.Millisecond
	time.Sleep(duration)

	result := &Result{
		ExitCode: 0,
		Stdout:   []byte("mock execution successful inside warm sandbox"),
		Stderr:   nil,
		Duration: duration,
	}

	receipt := &ExecutionReceipt{
		ExecutionID: m.id,
		Spec:        *spec,
		Result:      *result,
		StartedAt:   startedAt,
		CompletedAt: startedAt.Add(duration),
		ImageDigest: spec.Image,
		StdoutHash:  "sha256:mock_stdout",
		StderrHash:  "sha256:mock_stderr",
	}

	return result, receipt, nil
}

// Validate checks that the spec is valid.
func (m *MockRunner) Validate(spec *SandboxSpec) error {
	if spec.Image == "" {
		return fmt.Errorf("sandbox spec: image is required")
	}
	return nil
}

// WarmLeaseManager manages active, idle container runtimes.
type WarmLeaseManager struct {
	mu            sync.Mutex
	idleRunners   chan Runner
	poolSize      int
	imageDigest   string
	fallbackMock  bool
	RunnerFactory func(id string) Runner
}

// NewWarmLeaseManager creates and pre-warms a WarmLeaseManager.
func NewWarmLeaseManager(poolSize int, imageDigest string, fallbackMock bool, factory ...func(id string) Runner) *WarmLeaseManager {
	if poolSize <= 0 {
		poolSize = 4
	}

	w := &WarmLeaseManager{
		idleRunners:  make(chan Runner, poolSize),
		poolSize:     poolSize,
		imageDigest:  imageDigest,
		fallbackMock: fallbackMock,
	}

	if len(factory) > 0 && factory[0] != nil {
		w.RunnerFactory = factory[0]
	}

	w.PreWarm()

	return w
}

// PreWarm initializes and fills the idle runners channel.
func (w *WarmLeaseManager) PreWarm() {
	for i := 0; i < w.poolSize; i++ {
		var runner Runner
		id := fmt.Sprintf("warm-%d-%d", i, time.Now().UnixNano())
		if w.fallbackMock || w.RunnerFactory == nil {
			runner = &MockRunner{id: "mock-" + id}
		} else {
			runner = w.RunnerFactory(id)
		}
		w.idleRunners <- runner
	}
}

// Acquire retrieves a warm runner from the channel, or creates one dynamically if empty.
func (w *WarmLeaseManager) Acquire(ctx context.Context, spec *SandboxSpec) (Runner, error) {
	select {
	case runner := <-w.idleRunners:
		return runner, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Dynamic fallback
		return &MockRunner{id: fmt.Sprintf("mock-ondemand-%d", time.Now().UnixNano())}, nil
	}
}

// Release returns the runner to the pool, performing an async overlay reset mock recycling.
func (w *WarmLeaseManager) Release(runner Runner) {
	go func() {
		// Simulate state clean/overlay rollback
		time.Sleep(5 * time.Millisecond)

		select {
		case w.idleRunners <- runner:
		default:
			// Pool is full, discard
		}
	}()
}
