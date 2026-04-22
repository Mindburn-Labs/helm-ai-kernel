package proofmarket

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ProverNetwork is the interface for submitting proof tasks to external
// decentralized prover networks. Implementations handle the network-specific
// protocol (REST, gRPC, NATS, etc.) for task submission and result polling.
type ProverNetwork interface {
	// Submit sends a proof task to the network for proof generation.
	// The task's Status should transition to TaskPending on success.
	Submit(ctx context.Context, task *ProofTask) error

	// Poll checks the status of a previously submitted task.
	// Returns the ProofResult when the task is completed, or nil with
	// the task still in a non-terminal state (PENDING, PROVING).
	// Returns an error if the task is unknown or the network is unreachable.
	Poll(ctx context.Context, taskID string) (*ProofResult, error)

	// Network returns the network identifier for this prover.
	Network() Network
}

// MarketClient manages proof task submission across multiple decentralized
// prover networks. It supports network registration, preferred network
// selection with automatic fallback, and task lifecycle tracking.
//
// Thread-safe: all public methods are safe for concurrent use.
type MarketClient struct {
	networks map[Network]ProverNetwork
	fallback Network
	tasks    map[string]*ProofTask
	clock    func() time.Time
	mu       sync.RWMutex
}

// NewMarketClient creates a new MarketClient with LOCAL as the default fallback.
// Register prover networks via RegisterNetwork before submitting tasks.
func NewMarketClient() *MarketClient {
	return &MarketClient{
		networks: make(map[Network]ProverNetwork),
		fallback: NetworkLocal,
		tasks:    make(map[string]*ProofTask),
		clock:    time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (c *MarketClient) WithClock(clock func() time.Time) *MarketClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clock = clock
	return c
}

// RegisterNetwork adds a prover network to the client.
// If a network with the same identifier is already registered, it is replaced.
func (c *MarketClient) RegisterNetwork(net ProverNetwork) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.networks[net.Network()] = net
}

// Submit sends a proof task to the preferred network. If the preferred network
// is unavailable or fails, the client tries other registered networks. If all
// external networks fail, it falls back to the LOCAL prover.
//
// Returns an error only if no network (including fallback) can accept the task.
func (c *MarketClient) Submit(ctx context.Context, task *ProofTask, preferredNetwork Network) error {
	if task == nil {
		return fmt.Errorf("proofmarket: nil task")
	}
	if task.TaskID == "" {
		return fmt.Errorf("proofmarket: task_id is required")
	}

	c.mu.Lock()
	// Set submission time if not already set.
	if task.SubmittedAt.IsZero() {
		task.SubmittedAt = c.clock()
	}
	if task.Status == "" {
		task.Status = TaskPending
	}
	c.mu.Unlock()

	// Try preferred network first.
	if err := c.trySubmit(ctx, task, preferredNetwork); err == nil {
		return nil
	}

	// Try all other registered networks (excluding preferred and LOCAL fallback).
	c.mu.RLock()
	networks := make([]Network, 0, len(c.networks))
	for netID := range c.networks {
		if netID != preferredNetwork && netID != c.fallback {
			networks = append(networks, netID)
		}
	}
	c.mu.RUnlock()

	for _, netID := range networks {
		if err := c.trySubmit(ctx, task, netID); err == nil {
			return nil
		}
	}

	// Fall back to LOCAL.
	if preferredNetwork != c.fallback {
		if err := c.trySubmit(ctx, task, c.fallback); err == nil {
			return nil
		}
	}

	return fmt.Errorf("proofmarket: no available network accepted the task %q", task.TaskID)
}

// trySubmit attempts to submit a task to a specific network.
func (c *MarketClient) trySubmit(ctx context.Context, task *ProofTask, netID Network) error {
	c.mu.RLock()
	net, ok := c.networks[netID]
	c.mu.RUnlock()
	if !ok {
		return fmt.Errorf("proofmarket: network %q not registered", netID)
	}

	if err := net.Submit(ctx, task); err != nil {
		return fmt.Errorf("proofmarket: network %q rejected task: %w", netID, err)
	}

	// Track the task on successful submission.
	c.mu.Lock()
	c.tasks[task.TaskID] = task
	c.mu.Unlock()

	return nil
}

// Poll checks the status of a previously submitted task by querying the
// prover network. Returns the ProofResult when complete, or an error if
// the task is unknown or the network is unreachable.
func (c *MarketClient) Poll(ctx context.Context, taskID string) (*ProofResult, error) {
	c.mu.RLock()
	task, ok := c.tasks[taskID]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("proofmarket: unknown task %q", taskID)
	}

	// Check deadline expiry.
	c.mu.RLock()
	now := c.clock()
	c.mu.RUnlock()
	if !task.Deadline.IsZero() && now.After(task.Deadline) {
		c.mu.Lock()
		task.Status = TaskExpired
		c.mu.Unlock()
		return nil, fmt.Errorf("proofmarket: task %q expired", taskID)
	}

	// Poll all registered networks for the result.
	c.mu.RLock()
	networks := make([]ProverNetwork, 0, len(c.networks))
	for _, net := range c.networks {
		networks = append(networks, net)
	}
	c.mu.RUnlock()

	for _, net := range networks {
		result, err := net.Poll(ctx, taskID)
		if err != nil {
			continue
		}
		if result != nil {
			c.mu.Lock()
			task.Status = TaskCompleted
			c.mu.Unlock()
			return result, nil
		}
	}

	return nil, nil
}

// GetTask returns a tracked task by its ID.
// Returns the task and true if found, or nil and false if not tracked.
func (c *MarketClient) GetTask(taskID string) (*ProofTask, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	task, ok := c.tasks[taskID]
	return task, ok
}
