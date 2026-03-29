package editor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/agents"
)

// EditorAgent scores a draft on multiple dimensions using an LLM rubric.
type EditorAgent struct {
	LLM agents.LLMClient
}

// New creates an EditorAgent backed by the given LLMClient.
func New(llm agents.LLMClient) *EditorAgent {
	return &EditorAgent{LLM: llm}
}

// Role returns the worker role for this agent.
func (a *EditorAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerEditor
}

// editorInput is the JSON input shape for the Editor agent.
type editorInput struct {
	Title   string                           `json:"title"`
	BodyMD  string                           `json:"body_md"`
	Sources []researchruntime.SourceSnapshot `json:"sources"`
}

// editorLLMResult is the intermediate LLM response shape.
type editorLLMResult struct {
	Score     float64        `json:"score"`
	Passed    bool           `json:"passed"`
	Notes     []string       `json:"notes"`
	Breakdown map[string]any `json:"breakdown"`
}

// EditorResult wraps the ScoreRecord with any editorial issues found.
type EditorResult struct {
	Score  researchruntime.ScoreRecord `json:"score"`
	Issues []string                    `json:"issues"`
}

const editorSystemPrompt = `You are a senior research editor. Score the draft paper on a 0.0–1.0 scale.

Evaluate: clarity (0-1), citation coverage (0-1), logical coherence (0-1), factual grounding (0-1), and completeness (0-1).
The overall score is the average of these dimensions.
A paper passes if overall score >= 0.7.

Return ONLY valid JSON in this exact format:
{"score":0.85,"passed":true,"notes":["note1","note2"],"breakdown":{"clarity":0.9,"citation_coverage":0.8,"coherence":0.85,"factual_grounding":0.8,"completeness":0.9}}`

// Execute scores the draft using the LLM rubric and returns an EditorResult.
func (a *EditorAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var in editorInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("editor: unmarshal input: %w", err)
	}

	userPrompt := buildEditorPrompt(in)

	response, err := a.LLM.Complete(ctx, editorSystemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("editor: llm: %w", err)
	}

	var llmResult editorLLMResult
	if err := json.Unmarshal([]byte(response), &llmResult); err != nil {
		return nil, fmt.Errorf("editor: parse result: %w", err)
	}

	scoreRecord := researchruntime.ScoreRecord{
		Stage:      string(researchruntime.WorkerEditor),
		Score:      llmResult.Score,
		Threshold:  0.7,
		Passed:     llmResult.Passed,
		Notes:      llmResult.Notes,
		Breakdown:  llmResult.Breakdown,
		RecordedAt: time.Now().UTC(),
	}

	result := EditorResult{
		Score:  scoreRecord,
		Issues: llmResult.Notes,
	}

	return json.Marshal(result)
}

func buildEditorPrompt(in editorInput) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "TITLE: %s\n\nDRAFT BODY:\n%s\n\n", in.Title, in.BodyMD)
	sb.WriteString("CITED SOURCES:\n")
	for _, s := range in.Sources {
		title := s.Title
		if title == "" {
			title = s.URL
		}
		fmt.Fprintf(&sb, "- source_id=%s title=%q url=%s\n", s.SourceID, title, s.URL)
	}
	return sb.String()
}
