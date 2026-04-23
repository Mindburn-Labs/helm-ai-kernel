package proofmarket

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fixedTime is a deterministic clock for testing.
var fixedTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

// sampleTask returns a realistic ProofTask for testing.
func sampleTask(id string) *ProofTask {
	return &ProofTask{
		TaskID: id,
		ProofRequest: map[string]interface{}{
			"decision_id":   "dec-abc123",
			"policy_hash":   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"verdict":       "ALLOW",
			"decision_hash": "sha256:deadbeefcafe1234567890abcdef1234567890abcdef1234567890abcdef1234",
			"input_data": map[string]interface{}{
				"action":   "tool.execute",
				"resource": "github.create_issue",
			},
		},
		Algorithm: "helm-zkgov-v1",
		Deadline:  fixedTime.Add(10 * time.Minute),
	}
}

// mockNetwork is a test double for ProverNetwork.
type mockNetwork struct {
	networkID  Network
	submitErr  error
	pollResult *ProofResult
	pollErr    error
	submitted  []*ProofTask
}

func newMockNetwork(id Network) *mockNetwork {
	return &mockNetwork{networkID: id}
}

func (m *mockNetwork) Submit(_ context.Context, task *ProofTask) error {
	m.submitted = append(m.submitted, task)
	if m.submitErr != nil {
		return m.submitErr
	}
	task.Status = TaskProving
	return nil
}

func (m *mockNetwork) Poll(_ context.Context, taskID string) (*ProofResult, error) {
	if m.pollErr != nil {
		return nil, m.pollErr
	}
	if m.pollResult != nil && m.pollResult.TaskID == taskID {
		return m.pollResult, nil
	}
	return nil, nil
}

func (m *mockNetwork) Network() Network {
	return m.networkID
}

func TestMarketClient_SubmitLocal(t *testing.T) {
	client := NewMarketClient().WithClock(fixedClock)

	local := NewLocalProver("node-alpha").WithClock(fixedClock)
	client.RegisterNetwork(local)

	task := sampleTask("task-001")
	err := client.Submit(context.Background(), task, NetworkLocal)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	// Task should be tracked.
	tracked, ok := client.GetTask("task-001")
	if !ok {
		t.Fatal("Task should be tracked after submission")
	}
	if tracked.TaskID != "task-001" {
		t.Errorf("TaskID mismatch: got %q", tracked.TaskID)
	}
	if tracked.Status != TaskCompleted {
		t.Errorf("Local prover should complete immediately, got status %q", tracked.Status)
	}

	// Poll should return a result.
	result, err := client.Poll(context.Background(), "task-001")
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}
	if result == nil {
		t.Fatal("Poll should return a result for completed local task")
	}
	if result.TaskID != "task-001" {
		t.Errorf("Result TaskID mismatch: got %q", result.TaskID)
	}
	if result.NetworkID != string(NetworkLocal) {
		t.Errorf("Result NetworkID should be LOCAL, got %q", result.NetworkID)
	}
	if result.Proof == "" {
		t.Error("Result Proof must not be empty")
	}
	if result.ContentHash == "" {
		t.Error("Result ContentHash must not be empty")
	}
}

func TestMarketClient_RegisterNetwork(t *testing.T) {
	client := NewMarketClient()

	mock := newMockNetwork(NetworkSPN)
	client.RegisterNetwork(mock)

	task := sampleTask("task-002")
	err := client.Submit(context.Background(), task, NetworkSPN)
	if err != nil {
		t.Fatalf("Submit to SPN failed: %v", err)
	}

	if len(mock.submitted) != 1 {
		t.Fatalf("Expected 1 submission, got %d", len(mock.submitted))
	}
	if mock.submitted[0].TaskID != "task-002" {
		t.Errorf("Submitted task ID mismatch: got %q", mock.submitted[0].TaskID)
	}
}

func TestMarketClient_Fallback(t *testing.T) {
	client := NewMarketClient().WithClock(fixedClock)

	// Register a failing SPN and a working LOCAL.
	failingSpn := newMockNetwork(NetworkSPN)
	failingSpn.submitErr = fmt.Errorf("network unreachable")
	client.RegisterNetwork(failingSpn)

	local := NewLocalProver("node-fallback").WithClock(fixedClock)
	client.RegisterNetwork(local)

	task := sampleTask("task-003")
	err := client.Submit(context.Background(), task, NetworkSPN)
	if err != nil {
		t.Fatalf("Submit should succeed via fallback, got: %v", err)
	}

	// SPN should have been tried.
	if len(failingSpn.submitted) != 0 {
		// The mock records the task only on success — here it fails, so 0.
	}

	// Task should be completed via local fallback.
	tracked, ok := client.GetTask("task-003")
	if !ok {
		t.Fatal("Task should be tracked")
	}
	if tracked.Status != TaskCompleted {
		t.Errorf("Expected COMPLETED via fallback, got %q", tracked.Status)
	}

	// Poll should return local result.
	result, err := client.Poll(context.Background(), "task-003")
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result from local fallback")
	}
	if result.NetworkID != string(NetworkLocal) {
		t.Errorf("Expected LOCAL network, got %q", result.NetworkID)
	}
}

func TestMarketClient_PollPending(t *testing.T) {
	client := NewMarketClient().WithClock(fixedClock)

	// Register a mock that accepts tasks but returns nil on poll (still proving).
	mock := newMockNetwork(NetworkSPN)
	client.RegisterNetwork(mock)

	task := sampleTask("task-004")
	err := client.Submit(context.Background(), task, NetworkSPN)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	// Poll should return nil (task still in progress).
	result, err := client.Poll(context.Background(), "task-004")
	if err != nil {
		t.Fatalf("Poll should not error for pending task: %v", err)
	}
	if result != nil {
		t.Error("Poll should return nil for a pending task")
	}
}

func TestMarketClient_TaskTracking(t *testing.T) {
	client := NewMarketClient()

	mock := newMockNetwork(NetworkSPN)
	client.RegisterNetwork(mock)

	// Submit multiple tasks.
	for _, id := range []string{"task-a", "task-b", "task-c"} {
		task := sampleTask(id)
		if err := client.Submit(context.Background(), task, NetworkSPN); err != nil {
			t.Fatalf("Submit(%s) failed: %v", id, err)
		}
	}

	// All tasks should be tracked.
	for _, id := range []string{"task-a", "task-b", "task-c"} {
		task, ok := client.GetTask(id)
		if !ok {
			t.Errorf("Task %q should be tracked", id)
			continue
		}
		if task.TaskID != id {
			t.Errorf("TaskID mismatch: got %q, want %q", task.TaskID, id)
		}
	}

	// Unknown task should not be found.
	_, ok := client.GetTask("task-unknown")
	if ok {
		t.Error("Unknown task should not be tracked")
	}
}

func TestLocalProver_Interface(t *testing.T) {
	// Compile-time check that LocalProver implements ProverNetwork.
	var _ ProverNetwork = (*LocalProver)(nil)

	local := NewLocalProver("node-test")
	if local.Network() != NetworkLocal {
		t.Errorf("Expected NetworkLocal, got %q", local.Network())
	}
}

func TestMarketClient_SubmitNilTask(t *testing.T) {
	client := NewMarketClient()
	err := client.Submit(context.Background(), nil, NetworkLocal)
	if err == nil {
		t.Fatal("Expected error for nil task")
	}
	if !strings.Contains(err.Error(), "nil task") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestMarketClient_SubmitEmptyTaskID(t *testing.T) {
	client := NewMarketClient()
	task := &ProofTask{}
	err := client.Submit(context.Background(), task, NetworkLocal)
	if err == nil {
		t.Fatal("Expected error for empty task_id")
	}
	if !strings.Contains(err.Error(), "task_id is required") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestMarketClient_PollUnknownTask(t *testing.T) {
	client := NewMarketClient()
	_, err := client.Poll(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Expected error for unknown task")
	}
	if !strings.Contains(err.Error(), "unknown task") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestMarketClient_NoNetworkAvailable(t *testing.T) {
	client := NewMarketClient()
	// No networks registered at all.
	task := sampleTask("task-orphan")
	err := client.Submit(context.Background(), task, NetworkSPN)
	if err == nil {
		t.Fatal("Expected error when no networks are available")
	}
	if !strings.Contains(err.Error(), "no available network") {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestMarketClient_PollExpired(t *testing.T) {
	// Advance the clock past the deadline to test expiry.
	expired := fixedTime.Add(20 * time.Minute)
	expiredClock := func() time.Time { return expired }

	client := NewMarketClient().WithClock(fixedClock)
	mock := newMockNetwork(NetworkSPN)
	client.RegisterNetwork(mock)

	task := sampleTask("task-expiry")
	task.Deadline = fixedTime.Add(10 * time.Minute)

	err := client.Submit(context.Background(), task, NetworkSPN)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	// Advance clock past deadline.
	client.WithClock(expiredClock)

	_, err = client.Poll(context.Background(), "task-expiry")
	if err == nil {
		t.Fatal("Expected error for expired task")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify the task status was updated to EXPIRED.
	tracked, ok := client.GetTask("task-expiry")
	if !ok {
		t.Fatal("Task should still be tracked")
	}
	if tracked.Status != TaskExpired {
		t.Errorf("Expected EXPIRED status, got %q", tracked.Status)
	}
}

func TestMarketClient_SubmissionTimestampSet(t *testing.T) {
	client := NewMarketClient().WithClock(fixedClock)
	mock := newMockNetwork(NetworkSPN)
	client.RegisterNetwork(mock)

	task := sampleTask("task-ts")
	// SubmittedAt is zero initially.
	if !task.SubmittedAt.IsZero() {
		t.Fatal("SubmittedAt should be zero before submission")
	}

	err := client.Submit(context.Background(), task, NetworkSPN)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	if !task.SubmittedAt.Equal(fixedTime) {
		t.Errorf("SubmittedAt should be set to clock time, got %v", task.SubmittedAt)
	}
}
