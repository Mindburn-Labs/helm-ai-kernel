package synthesizer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/agents"
)

// SynthesizerAgent uses an LLM to produce a research paper body from sources and an outline.
type SynthesizerAgent struct {
	LLM agents.LLMClient
}

// New creates a SynthesizerAgent backed by the given LLMClient.
func New(llm agents.LLMClient) *SynthesizerAgent {
	return &SynthesizerAgent{LLM: llm}
}

// Role returns the worker role for this agent.
func (a *SynthesizerAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerSynthesizer
}

// synthInput is the JSON input shape for the Synthesizer agent.
type synthInput struct {
	Sources []researchruntime.SourceSnapshot `json:"sources"`
	Outline string                           `json:"outline"`
}

// SynthesisResult is the JSON output of the Synthesizer agent.
type SynthesisResult struct {
	Title    string `json:"title"`
	Abstract string `json:"abstract"`
	BodyMD   string `json:"body_md"`
}

const synthesizerSystemPrompt = `You are a research synthesis assistant. You will receive a research outline and a set of source documents.
Write a well-structured research paper body in Markdown based on the outline.
Cite sources using [source_id] notation inline.

Return ONLY valid JSON in this exact format:
{"title":"...","abstract":"...","body_md":"..."}

Where:
- "title" is a concise, informative title for the paper
- "abstract" is a 2-3 sentence summary of the paper
- "body_md" is the full Markdown body following the outline sections`

// Execute parses the synthesis input, calls the LLM, and returns a SynthesisResult.
func (a *SynthesizerAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var in synthInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("synthesizer: unmarshal input: %w", err)
	}

	userPrompt := buildSynthesizerPrompt(in)

	response, err := a.LLM.Complete(ctx, synthesizerSystemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("synthesizer: llm: %w", err)
	}

	var result SynthesisResult
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("synthesizer: parse result: %w", err)
	}

	return json.Marshal(result)
}

func buildSynthesizerPrompt(in synthInput) string {
	var sb strings.Builder
	sb.WriteString("OUTLINE:\n")
	sb.WriteString(in.Outline)
	sb.WriteString("\n\nSOURCE DOCUMENTS:\n")
	for _, s := range in.Sources {
		title := s.Title
		if title == "" {
			title = s.URL
		}
		snip := ""
		if s.Metadata != nil {
			if v, ok := s.Metadata["text_snip"].(string); ok {
				snip = v
			}
		}
		fmt.Fprintf(&sb, "source_id=%s title=%q url=%s\n%s\n---\n", s.SourceID, title, s.URL, snip)
	}
	return sb.String()
}
