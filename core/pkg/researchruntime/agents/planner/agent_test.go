package planner

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLLM struct {
	response string
	err      error
}

func (m *mockLLM) Complete(_ context.Context, _, _ string) (string, error) {
	return m.response, m.err
}

func TestPlannerAgent_Role(t *testing.T) {
	a := New(nil)
	assert.Equal(t, researchruntime.WorkerPlanner, a.Role())
}

func TestPlannerAgent_ProducesWorkGraph(t *testing.T) {
	graphJSON := `{"mission_id":"m1","version":"1","nodes":[{"id":"s1","role":"web-scout","title":"Search","purpose":"Find sources","depends_on":[],"deadline_sec":60,"required":true}],"edges":[]}`
	llm := &mockLLM{response: graphJSON}
	a := New(llm)

	spec, _ := json.Marshal(researchruntime.MissionSpec{MissionID: "m1", Title: "Test Mission"})
	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, spec)
	require.NoError(t, err)

	var g researchruntime.WorkGraph
	require.NoError(t, json.Unmarshal(out, &g))
	assert.Equal(t, "m1", g.MissionID)
	assert.NotEmpty(t, g.Nodes)
	assert.Equal(t, "1", g.Version)
}

func TestPlannerAgent_OverridesMissionID(t *testing.T) {
	// LLM returns a graph with a different mission_id — planner must overwrite it with spec's.
	graphJSON := `{"mission_id":"wrong","version":"1","nodes":[{"id":"n1","role":"web-scout","title":"T","purpose":"P","required":true}],"edges":[]}`
	a := New(&mockLLM{response: graphJSON})

	spec, _ := json.Marshal(researchruntime.MissionSpec{MissionID: "correct", Title: "T"})
	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "correct"}, spec)
	require.NoError(t, err)

	var g researchruntime.WorkGraph
	require.NoError(t, json.Unmarshal(out, &g))
	assert.Equal(t, "correct", g.MissionID)
}

func TestPlannerAgent_InvalidInputReturnsError(t *testing.T) {
	a := New(&mockLLM{})
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal mission spec")
}

func TestPlannerAgent_LLMErrorReturnsError(t *testing.T) {
	a := New(&mockLLM{err: errors.New("rate limited")})
	spec, _ := json.Marshal(researchruntime.MissionSpec{MissionID: "m1"})
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "llm")
}

func TestPlannerAgent_InvalidLLMJSONReturnsError(t *testing.T) {
	a := New(&mockLLM{response: "I cannot produce JSON right now."})
	spec, _ := json.Marshal(researchruntime.MissionSpec{MissionID: "m1"})
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse work graph")
}
