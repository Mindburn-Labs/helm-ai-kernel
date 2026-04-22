package prg

import (
	"sort"
)

// Compiler converts high-level policy bundles into a PRG.
type Compiler struct {
	// Options for strictness, etc.
}

func NewCompiler() (*Compiler, error) {
	return &Compiler{}, nil
}

func (c *Compiler) Compile(reqs RequirementSet) (*Graph, error) {
	g := NewGraph()
	if err := g.AddRule(reqs.ID, reqs); err != nil {
		return nil, err
	}

	// Deterministic validation: sort keys
	keys := make([]string, 0, len(g.Rules))
	for k := range g.Rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Check for cycles (stub for now as we have no edges yet)
	// In V2, we'd add 'DependsOn' to Requirement and build edges.

	return g, nil
}
