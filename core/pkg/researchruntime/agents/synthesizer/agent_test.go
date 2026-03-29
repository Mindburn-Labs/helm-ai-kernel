package synthesizer

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

func TestSynthesizerAgent_Role(t *testing.T) {
	a := New(nil)
	assert.Equal(t, researchruntime.WorkerSynthesizer, a.Role())
}

func TestSynthesizerAgent_HappyPath(t *testing.T) {
	llmResp := `{"title":"AI Safety Research","abstract":"This paper examines AI safety approaches.","body_md":"# Introduction\n\nAI safety is critical [s1].\n\n## Methods\n\nWe reviewed [s2] extensively."}`
	a := New(&mockLLM{response: llmResp})

	in := synthInput{
		Sources: []researchruntime.SourceSnapshot{
			{SourceID: "s1", URL: "https://example.com/1", Title: "Source 1"},
			{SourceID: "s2", URL: "https://example.com/2", Title: "Source 2"},
		},
		Outline: "1. Introduction\n2. Methods\n3. Results\n4. Conclusion",
	}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result SynthesisResult
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "AI Safety Research", result.Title)
	assert.NotEmpty(t, result.Abstract)
	assert.NotEmpty(t, result.BodyMD)
	assert.Contains(t, result.BodyMD, "Introduction")
}

func TestSynthesizerAgent_InvalidInputReturnsError(t *testing.T) {
	a := New(&mockLLM{})
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal input")
}

func TestSynthesizerAgent_LLMErrorReturnsError(t *testing.T) {
	a := New(&mockLLM{err: errors.New("context deadline exceeded")})
	in := synthInput{Outline: "1. Intro"}
	input, _ := json.Marshal(in)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "llm")
}

func TestSynthesizerAgent_InvalidLLMJSONReturnsError(t *testing.T) {
	a := New(&mockLLM{response: "Here is your research paper..."})
	in := synthInput{Outline: "1. Intro"}
	input, _ := json.Marshal(in)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse result")
}

func TestSynthesizerAgent_EmptySourcesAllowed(t *testing.T) {
	llmResp := `{"title":"Empty Paper","abstract":"No sources.","body_md":"# Title\n\nNo sources were found."}`
	a := New(&mockLLM{response: llmResp})

	in := synthInput{Sources: nil, Outline: "1. Intro"}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result SynthesisResult
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "Empty Paper", result.Title)
}
