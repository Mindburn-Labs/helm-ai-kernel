package editor

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

func TestEditorAgent_Role(t *testing.T) {
	a := New(nil)
	assert.Equal(t, researchruntime.WorkerEditor, a.Role())
}

func TestEditorAgent_PassingScore(t *testing.T) {
	llmResp := `{"score":0.85,"passed":true,"notes":["Well cited","Clear structure"],"breakdown":{"clarity":0.9,"citation_coverage":0.8,"coherence":0.85,"factual_grounding":0.8,"completeness":0.9}}`
	a := New(&mockLLM{response: llmResp})

	in := editorInput{
		Title:  "AI Research Paper",
		BodyMD: "# Introduction\n\nThis paper explores [s1].\n\n## Conclusion\n\nResults confirmed.",
		Sources: []researchruntime.SourceSnapshot{
			{SourceID: "s1", URL: "https://arxiv.org/abs/1234", Title: "Prior Work"},
		},
	}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result EditorResult
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, 0.85, result.Score.Score)
	assert.True(t, result.Score.Passed)
	assert.Equal(t, 0.7, result.Score.Threshold)
	assert.Equal(t, string(researchruntime.WorkerEditor), result.Score.Stage)
	assert.NotEmpty(t, result.Score.Breakdown)
	assert.Contains(t, result.Issues, "Well cited")
}

func TestEditorAgent_FailingScore(t *testing.T) {
	llmResp := `{"score":0.45,"passed":false,"notes":["Missing citations","Incoherent structure"],"breakdown":{"clarity":0.4,"citation_coverage":0.3,"coherence":0.5,"factual_grounding":0.5,"completeness":0.6}}`
	a := New(&mockLLM{response: llmResp})

	in := editorInput{
		Title:  "Bad Draft",
		BodyMD: "Some text without citations.",
	}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result EditorResult
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, 0.45, result.Score.Score)
	assert.False(t, result.Score.Passed)
	assert.Len(t, result.Issues, 2)
}

func TestEditorAgent_InvalidInputReturnsError(t *testing.T) {
	a := New(&mockLLM{})
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal input")
}

func TestEditorAgent_LLMErrorReturnsError(t *testing.T) {
	a := New(&mockLLM{err: errors.New("model overloaded")})
	in := editorInput{Title: "Draft", BodyMD: "Body text."}
	input, _ := json.Marshal(in)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "llm")
}

func TestEditorAgent_InvalidLLMJSONReturnsError(t *testing.T) {
	a := New(&mockLLM{response: "The draft needs improvement in several areas..."})
	in := editorInput{Title: "Draft", BodyMD: "Body."}
	input, _ := json.Marshal(in)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse result")
}
