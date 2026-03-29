package verifier

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

func TestVerifierAgent_Role(t *testing.T) {
	a := New(nil)
	assert.Equal(t, researchruntime.WorkerFactVerifier, a.Role())
}

func TestVerifierAgent_AllowVerdict(t *testing.T) {
	llmResp := `{"verdict":"allow","issues":[]}`
	a := New(&mockLLM{response: llmResp})

	in := verifierInput{
		Sources: []researchruntime.SourceSnapshot{
			{SourceID: "s1", URL: "https://example.com", Title: "Example"},
		},
		Claims: []string{"The sky is blue."},
	}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result VerificationResult
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "allow", result.Verdict)
	assert.Empty(t, result.Issues)
}

func TestVerifierAgent_DenyVerdictWithIssues(t *testing.T) {
	llmResp := `{"verdict":"deny","issues":[{"claim":"Water boils at 90°C at sea level","source_id":"s1","contradiction":"Source states water boils at 100°C at sea level"}]}`
	a := New(&mockLLM{response: llmResp})

	in := verifierInput{
		Sources: []researchruntime.SourceSnapshot{
			{SourceID: "s1", URL: "https://science.example.com", Title: "Chemistry Facts"},
		},
		Claims: []string{"Water boils at 90°C at sea level."},
	}
	input, _ := json.Marshal(in)

	out, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.NoError(t, err)

	var result VerificationResult
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "deny", result.Verdict)
	require.Len(t, result.Issues, 1)
	assert.Equal(t, "s1", result.Issues[0].SourceID)
	assert.NotEmpty(t, result.Issues[0].Contradiction)
}

func TestVerifierAgent_InvalidInputReturnsError(t *testing.T) {
	a := New(&mockLLM{})
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{}, []byte("not-json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal input")
}

func TestVerifierAgent_LLMErrorReturnsError(t *testing.T) {
	a := New(&mockLLM{err: errors.New("rate limited")})
	in := verifierInput{Claims: []string{"some claim"}}
	input, _ := json.Marshal(in)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "llm")
}

func TestVerifierAgent_InvalidLLMJSONReturnsError(t *testing.T) {
	a := New(&mockLLM{response: "I cannot verify right now."})
	in := verifierInput{Claims: []string{"claim"}}
	input, _ := json.Marshal(in)
	_, err := a.Execute(context.Background(), &researchruntime.TaskLease{MissionID: "m1"}, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse result")
}
