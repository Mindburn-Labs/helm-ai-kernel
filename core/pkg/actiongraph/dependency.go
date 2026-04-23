package actiongraph

import "fmt"

// DependencyGraph tracks work items and their dependency edges to enable
// topological ordering for safe execution sequencing.
type DependencyGraph struct {
	items map[string]*WorkItem
}

// NewDependencyGraph returns an empty dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		items: make(map[string]*WorkItem),
	}
}

// Add inserts a work item into the graph. Returns an error if a work item
// with the same ItemID already exists.
func (g *DependencyGraph) Add(item *WorkItem) error {
	if _, exists := g.items[item.ItemID]; exists {
		return fmt.Errorf("actiongraph: duplicate item ID %q", item.ItemID)
	}
	g.items[item.ItemID] = item
	return nil
}

// TopologicalSort returns work item IDs in a valid execution order that
// respects all DependsOn constraints. Returns an error if the graph
// contains a cycle.
func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	// Kahn's algorithm.
	inDegree := make(map[string]int, len(g.items))
	dependents := make(map[string][]string, len(g.items))

	for id := range g.items {
		inDegree[id] = 0
	}

	for id, item := range g.items {
		for _, dep := range item.DependsOn {
			if _, ok := g.items[dep]; !ok {
				return nil, fmt.Errorf("actiongraph: item %q depends on unknown item %q", id, dep)
			}
			dependents[dep] = append(dependents[dep], id)
			inDegree[id]++
		}
	}

	// Seed the queue with zero-indegree nodes.
	queue := make([]string, 0, len(g.items))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	var sorted []string
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		sorted = append(sorted, node)

		for _, dep := range dependents[node] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(sorted) != len(g.items) {
		return nil, fmt.Errorf("actiongraph: dependency cycle detected")
	}

	return sorted, nil
}
