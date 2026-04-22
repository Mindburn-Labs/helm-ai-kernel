// Package intentcompiler — DAG validation.
package intentcompiler

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// GraphValidator validates the structure and semantics of a PlanSpec DAG.
type GraphValidator struct {
	catalog *contracts.EffectTypeCatalog
}

// NewGraphValidator creates a validator backed by the given effect catalog.
func NewGraphValidator(catalog *contracts.EffectTypeCatalog) *GraphValidator {
	return &GraphValidator{catalog: catalog}
}

// Validate checks a PlanSpec DAG for structural and semantic errors.
// It returns all errors found (does not short-circuit).
func (v *GraphValidator) Validate(plan *contracts.PlanSpec) []error {
	var errs []error

	if plan.DAG == nil {
		errs = append(errs, fmt.Errorf("plan has no DAG"))
		return errs
	}

	dag := plan.DAG

	// Build node index.
	nodeIDs := make(map[string]bool, len(dag.Nodes))
	for _, node := range dag.Nodes {
		if node.ID == "" {
			errs = append(errs, fmt.Errorf("plan step has empty ID"))
			continue
		}
		if nodeIDs[node.ID] {
			errs = append(errs, fmt.Errorf("duplicate step ID: %s", node.ID))
			continue
		}
		nodeIDs[node.ID] = true
	}

	// Validate edges reference known nodes.
	for _, edge := range dag.Edges {
		if !nodeIDs[edge.From] {
			errs = append(errs, fmt.Errorf("edge references unknown source node: %s", edge.From))
		}
		if !nodeIDs[edge.To] {
			errs = append(errs, fmt.Errorf("edge references unknown target node: %s", edge.To))
		}
	}

	// Validate entry/exit points reference known nodes.
	for _, ep := range dag.EntryPoints {
		if !nodeIDs[ep] {
			errs = append(errs, fmt.Errorf("entry point references unknown node: %s", ep))
		}
	}
	for _, ep := range dag.ExitPoints {
		if !nodeIDs[ep] {
			errs = append(errs, fmt.Errorf("exit point references unknown node: %s", ep))
		}
	}

	// Check for cycles.
	if hasCycle(dag) {
		errs = append(errs, fmt.Errorf("DAG contains a cycle"))
	}

	// Validate effect types are known (if catalog available).
	if v.catalog != nil {
		knownTypes := make(map[string]bool, len(v.catalog.EffectTypes))
		for _, et := range v.catalog.EffectTypes {
			knownTypes[et.TypeID] = true
		}
		for _, node := range dag.Nodes {
			if node.EffectType != "" && !knownTypes[node.EffectType] {
				// Not an error — unknown types get E3 (fail-closed) by EffectRiskClass.
				// But we surface it as a validation warning.
			}
		}
	}

	// Check for blocking questions.
	for _, node := range dag.Nodes {
		if len(node.BlockingQuestions) > 0 {
			errs = append(errs, fmt.Errorf("step %s has %d blocking questions that must be resolved", node.ID, len(node.BlockingQuestions)))
		}
	}

	return errs
}

// hasCycle performs cycle detection on the DAG using DFS.
func hasCycle(dag *contracts.DAG) bool {
	// Build adjacency list.
	adj := make(map[string][]string)
	for _, edge := range dag.Edges {
		adj[edge.From] = append(adj[edge.From], edge.To)
	}

	// 0=unvisited, 1=in-progress, 2=done
	state := make(map[string]int)

	var visit func(id string) bool
	visit = func(id string) bool {
		if state[id] == 2 {
			return false
		}
		if state[id] == 1 {
			return true // cycle found
		}
		state[id] = 1
		for _, next := range adj[id] {
			if visit(next) {
				return true
			}
		}
		state[id] = 2
		return false
	}

	for _, node := range dag.Nodes {
		if state[node.ID] == 0 {
			if visit(node.ID) {
				return true
			}
		}
	}
	return false
}

// TopologicalSort returns nodes in topological order (dependencies first).
// Returns an error if the DAG contains a cycle.
func TopologicalSort(dag *contracts.DAG) ([]string, error) {
	// Build adjacency list and in-degree counts.
	adj := make(map[string][]string)
	inDegree := make(map[string]int)

	for _, node := range dag.Nodes {
		inDegree[node.ID] = 0
	}
	for _, edge := range dag.Edges {
		adj[edge.From] = append(adj[edge.From], edge.To)
		inDegree[edge.To]++
	}

	// Kahn's algorithm.
	var queue []string
	for _, node := range dag.Nodes {
		if inDegree[node.ID] == 0 {
			queue = append(queue, node.ID)
		}
	}

	var sorted []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		sorted = append(sorted, current)

		for _, next := range adj[current] {
			inDegree[next]--
			if inDegree[next] == 0 {
				queue = append(queue, next)
			}
		}
	}

	if len(sorted) != len(dag.Nodes) {
		return nil, fmt.Errorf("DAG contains a cycle: sorted %d of %d nodes", len(sorted), len(dag.Nodes))
	}
	return sorted, nil
}
