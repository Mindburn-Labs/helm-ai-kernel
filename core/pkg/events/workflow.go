package events

// Workflow and node-attempt lifecycle events. Attempt identity and content
// hashes make retries and data flow auditable without exporting node payloads.
const (
	WorkflowStarted       = "helm.workflow.started.v1"
	WorkflowNodeStarted   = "helm.workflow.node.started.v1"
	WorkflowNodeCompleted = "helm.workflow.node.completed.v1"
	WorkflowNodeFailed    = "helm.workflow.node.failed.v1"
	WorkflowCompleted     = "helm.workflow.completed.v1"
	WorkflowFailed        = "helm.workflow.failed.v1"
)

// WorkflowEventTypes returns the workflow types in lifecycle order.
func WorkflowEventTypes() []string {
	return []string{
		WorkflowStarted,
		WorkflowNodeStarted,
		WorkflowNodeCompleted,
		WorkflowNodeFailed,
		WorkflowCompleted,
		WorkflowFailed,
	}
}

func NewWorkflowStarted(meta EventMeta, workflowID, definitionHash string) LifecycleEvent {
	return newEvent(meta, WorkflowStarted, map[string]any{
		"workflow_id":     workflowID,
		"definition_hash": definitionHash,
	})
}

func NewWorkflowNodeStarted(
	meta EventMeta,
	workflowID, stepID, attemptID string,
	attempt int,
	inputHash string,
) LifecycleEvent {
	return newEvent(meta, WorkflowNodeStarted, map[string]any{
		"workflow_id": workflowID,
		"step_id":     stepID,
		"attempt_id":  attemptID,
		"attempt":     attempt,
		"input_hash":  inputHash,
	})
}

func NewWorkflowNodeCompleted(
	meta EventMeta,
	workflowID, stepID, attemptID string,
	attempt int,
	outputHash string,
) LifecycleEvent {
	return newEvent(meta, WorkflowNodeCompleted, map[string]any{
		"workflow_id": workflowID,
		"step_id":     stepID,
		"attempt_id":  attemptID,
		"attempt":     attempt,
		"output_hash": outputHash,
	})
}

func NewWorkflowNodeFailed(
	meta EventMeta,
	workflowID, stepID, attemptID string,
	attempt int,
	reasonCode string,
	retryable bool,
) LifecycleEvent {
	return newEvent(meta, WorkflowNodeFailed, map[string]any{
		"workflow_id": workflowID,
		"step_id":     stepID,
		"attempt_id":  attemptID,
		"attempt":     attempt,
		"reason_code": reasonCode,
		"retryable":   retryable,
	})
}

func NewWorkflowCompleted(meta EventMeta, workflowID, resultHash string) LifecycleEvent {
	return newEvent(meta, WorkflowCompleted, map[string]any{
		"workflow_id": workflowID,
		"result_hash": resultHash,
	})
}

func NewWorkflowFailed(meta EventMeta, workflowID, reasonCode string) LifecycleEvent {
	return newEvent(meta, WorkflowFailed, map[string]any{
		"workflow_id": workflowID,
		"reason_code": reasonCode,
	})
}
