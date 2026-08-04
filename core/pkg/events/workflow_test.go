package events

import "testing"

func TestWorkflowEventCatalog(t *testing.T) {
	want := []string{
		"helm.workflow.started.v1",
		"helm.workflow.node.started.v1",
		"helm.workflow.node.completed.v1",
		"helm.workflow.node.failed.v1",
		"helm.workflow.completed.v1",
		"helm.workflow.failed.v1",
	}
	got := WorkflowEventTypes()
	if len(got) != len(want) {
		t.Fatalf("catalog has %d workflow event types, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event type %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestWorkflowNodeEventsBindAttemptAndHashes(t *testing.T) {
	meta := testMeta("correlation-1")
	meta.RunID = "run-1"

	started := NewWorkflowNodeStarted(meta, "workflow-1", "research", "attempt-1", 1, "sha256:input")
	if started.Meta.EventType != WorkflowNodeStarted {
		t.Fatalf("event type = %q, want %q", started.Meta.EventType, WorkflowNodeStarted)
	}
	for key, want := range map[string]any{
		"workflow_id": "workflow-1",
		"step_id":     "research",
		"attempt_id":  "attempt-1",
		"attempt":     1,
		"input_hash":  "sha256:input",
	} {
		if got := started.Fields[key]; got != want {
			t.Errorf("started[%q] = %v, want %v", key, got, want)
		}
	}

	completed := NewWorkflowNodeCompleted(meta, "workflow-1", "research", "attempt-1", 1, "sha256:output")
	if got := completed.Fields["output_hash"]; got != "sha256:output" {
		t.Errorf("output_hash = %v, want sha256:output", got)
	}
}

func TestWorkflowFailuresUseReasonCodesNotProse(t *testing.T) {
	events := []LifecycleEvent{
		NewWorkflowNodeFailed(testMeta("correlation-1"), "workflow-1", "research", "attempt-1", 1, "MODEL_TIMEOUT", true),
		NewWorkflowFailed(testMeta("correlation-1"), "workflow-1", "CHECKER_REJECTED"),
	}

	for _, event := range events {
		if event.Fields["reason_code"] == "" {
			t.Errorf("%s has no reason_code", event.Meta.EventType)
		}
		for _, key := range []string{"reason", "message", "detail", "error", "failure_reason"} {
			if _, present := event.Fields[key]; present {
				t.Errorf("%s exports free-text field %q", event.Meta.EventType, key)
			}
		}
	}
}
