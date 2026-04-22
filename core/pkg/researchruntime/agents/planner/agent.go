package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/agents"
)

// PlannerAgent takes a MissionSpec and produces a WorkGraph (DAG of research tasks).
type PlannerAgent struct {
	LLM agents.LLMClient
}

// New creates a PlannerAgent backed by the given LLMClient.
func New(llm agents.LLMClient) *PlannerAgent {
	return &PlannerAgent{LLM: llm}
}

// Role returns the worker role for this agent.
func (a *PlannerAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerPlanner
}

// Execute unmarshals a MissionSpec from input, calls the LLM to produce a WorkGraph,
// validates the graph, and returns it as JSON.
func (a *PlannerAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var spec researchruntime.MissionSpec
	if err := json.Unmarshal(input, &spec); err != nil {
		return nil, fmt.Errorf("planner: unmarshal mission spec: %w", err)
	}

	systemPrompt := `You are a research mission planner. Given a mission specification, produce a work graph (DAG) ` +
		`of research tasks. Each node has: id, role (one of: web-scout, source-harvester, fact-verifier, ` +
		`synthesizer, editor, publisher), title, purpose, depends_on (list of node IDs), deadline_sec, required (bool).

Return ONLY valid JSON matching this schema:
{"mission_id":"...","version":"1","nodes":[...],"edges":[{"from":"id1","to":"id2","kind":"depends"}]}`

	userPrompt := fmt.Sprintf("Mission: %s\nObjective: %s\nTopics: %v\nQuery seeds: %v",
		spec.Title, spec.Thesis, spec.Topics, spec.QuerySeeds)

	response, err := a.LLM.Complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("planner: llm: %w", err)
	}

	var graph researchruntime.WorkGraph
	if err := json.Unmarshal([]byte(response), &graph); err != nil {
		return nil, fmt.Errorf("planner: parse work graph: %w", err)
	}
	graph.MissionID = spec.MissionID

	return json.Marshal(graph)
}
