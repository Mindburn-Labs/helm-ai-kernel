package effectgraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/intentcompiler"
)

// PolicyEvaluator is the interface the graph evaluator uses to get verdicts.
// Guardian implements this via EvaluateDecision + IssueExecutionIntent.
type PolicyEvaluator interface {
	// EvaluateStep evaluates a single plan step and returns a decision.
	EvaluateStep(ctx context.Context, step *contracts.PlanStep, actor string) (*contracts.DecisionRecord, error)

	// IssueIntent issues a signed execution intent for an ALLOW decision.
	IssueIntent(ctx context.Context, decision *contracts.DecisionRecord, step *contracts.PlanStep) (*contracts.AuthorizedExecutionIntent, error)
}

// GraphEvaluator evaluates entire PlanSpec DAGs through a policy evaluator.
type GraphEvaluator struct {
	policy   PolicyEvaluator
	profiler *intentcompiler.SandboxProfiler
}

// NewGraphEvaluator creates a new evaluator backed by the given policy evaluator.
func NewGraphEvaluator(policy PolicyEvaluator) *GraphEvaluator {
	return &GraphEvaluator{
		policy:   policy,
		profiler: intentcompiler.NewSandboxProfiler(),
	}
}

// Evaluate processes an entire DAG, producing per-node verdicts.
// Nodes are evaluated in topological order. DENY verdicts cascade to dependents.
func (e *GraphEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error) {
	if req.Plan == nil || req.Plan.DAG == nil {
		return nil, fmt.Errorf("plan or DAG is nil")
	}

	dag := req.Plan.DAG

	// Topological sort.
	sorted, err := intentcompiler.TopologicalSort(dag)
	if err != nil {
		return nil, fmt.Errorf("topological sort: %w", err)
	}

	// Build step index.
	stepIndex := make(map[string]*contracts.PlanStep, len(dag.Nodes))
	for i := range dag.Nodes {
		stepIndex[dag.Nodes[i].ID] = &dag.Nodes[i]
	}

	// Build reverse dependency map: step → steps that depend on it.
	dependents := make(map[string][]string)
	for _, edge := range dag.Edges {
		dependents[edge.From] = append(dependents[edge.From], edge.To)
	}

	// Build forward dependency map: step → steps it depends on.
	dependencies := make(map[string][]string)
	for _, edge := range dag.Edges {
		dependencies[edge.To] = append(dependencies[edge.To], edge.From)
	}

	result := &EvaluationResult{
		Verdicts: make(map[string]*NodeVerdict, len(dag.Nodes)),
	}

	deniedSet := make(map[string]bool)

	// Evaluate each node in topological order.
	for _, stepID := range sorted {
		step := stepIndex[stepID]
		if step == nil {
			continue
		}

		verdict := &NodeVerdict{StepID: stepID}

		// Check if blocked by upstream DENY.
		var blockedBy []string
		for _, dep := range dependencies[stepID] {
			if deniedSet[dep] {
				blockedBy = append(blockedBy, dep)
			}
		}

		if len(blockedBy) > 0 {
			// Cascade: blocked by upstream denial.
			verdict.BlockedBy = blockedBy
			verdict.Decision = &contracts.DecisionRecord{
				Verdict:    string(contracts.VerdictDeny),
				Reason:     fmt.Sprintf("blocked by denied upstream: %v", blockedBy),
				ReasonCode: "UPSTREAM_DENIED",
			}
			deniedSet[stepID] = true
			result.Verdicts[stepID] = verdict
			result.BlockedSteps = append(result.BlockedSteps, stepID)
			continue
		}

		// Evaluate through policy.
		decision, err := e.policy.EvaluateStep(ctx, step, req.Actor)
		if err != nil {
			return nil, fmt.Errorf("evaluate step %s: %w", stepID, err)
		}
		verdict.Decision = decision

		switch contracts.Verdict(decision.Verdict) {
		case contracts.VerdictAllow:
			// Issue intent.
			intent, err := e.policy.IssueIntent(ctx, decision, step)
			if err != nil {
				return nil, fmt.Errorf("issue intent for step %s: %w", stepID, err)
			}
			verdict.Intent = intent

			// Assign execution profile.
			backend, profile := e.profiler.AssignProfile(step)
			verdict.Profile = &ExecutionProfile{
				Backend:     backend,
				ProfileName: profile,
			}
			result.AllowedSteps = append(result.AllowedSteps, stepID)

		case contracts.VerdictDeny:
			deniedSet[stepID] = true
			result.DeniedSteps = append(result.DeniedSteps, stepID)

		case contracts.VerdictEscalate:
			result.EscalateSteps = append(result.EscalateSteps, stepID)

		default:
			return nil, fmt.Errorf("unknown verdict %q for step %s", decision.Verdict, stepID)
		}

		result.Verdicts[stepID] = verdict
	}

	// Compute graph hash.
	graphHash, err := computeGraphHash(result.Verdicts, sorted)
	if err != nil {
		return nil, fmt.Errorf("compute graph hash: %w", err)
	}
	result.GraphHash = graphHash

	// Build truth summary.
	result.TruthSummary = buildTruthSummary(dag, result)

	return result, nil
}

// computeGraphHash creates a deterministic hash over all verdicts in order.
func computeGraphHash(verdicts map[string]*NodeVerdict, order []string) (string, error) {
	type verdictEntry struct {
		StepID  string `json:"step_id"`
		Verdict string `json:"verdict"`
		Reason  string `json:"reason_code"`
	}

	entries := make([]verdictEntry, 0, len(order))
	for _, id := range order {
		v := verdicts[id]
		if v == nil || v.Decision == nil {
			continue
		}
		entries = append(entries, verdictEntry{
			StepID:  id,
			Verdict: v.Decision.Verdict,
			Reason:  v.Decision.ReasonCode,
		})
	}

	data, err := canonicalize.JCS(entries)
	if err != nil {
		return "", err
	}

	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// buildTruthSummary aggregates truth annotations from all plan steps.
func buildTruthSummary(dag *contracts.DAG, result *EvaluationResult) *contracts.TruthAnnotation {
	summary := &contracts.TruthAnnotation{Confidence: 1.0}

	for _, node := range dag.Nodes {
		stepAnnotation := &contracts.TruthAnnotation{
			Unknowns:    node.Unknowns,
			Assumptions: node.Assumptions,
			FactSet:     node.FactSet,
		}
		summary = summary.Merge(stepAnnotation)
	}

	// Reduce confidence for denied/blocked steps.
	denied := len(result.DeniedSteps) + len(result.BlockedSteps)
	total := len(dag.Nodes)
	if total > 0 && denied > 0 {
		ratio := float64(total-denied) / float64(total)
		if summary.Confidence > ratio {
			summary.Confidence = ratio
		}
	}

	return summary
}
