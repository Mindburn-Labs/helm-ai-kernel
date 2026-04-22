package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/agents"
)

// VerifierAgent checks claims against source snippets using an LLM, reporting
// contradictions and returning a verdict.
type VerifierAgent struct {
	LLM agents.LLMClient
}

// New creates a VerifierAgent backed by the given LLMClient.
func New(llm agents.LLMClient) *VerifierAgent {
	return &VerifierAgent{LLM: llm}
}

// Role returns the worker role for this agent.
func (a *VerifierAgent) Role() researchruntime.WorkerRole {
	return researchruntime.WorkerFactVerifier
}

// verifierInput is the JSON input shape for the Verifier agent.
type verifierInput struct {
	Sources []researchruntime.SourceSnapshot `json:"sources"`
	Claims  []string                         `json:"claims"`
}

// contradiction describes a single detected claim/source conflict.
type contradiction struct {
	Claim        string `json:"claim"`
	SourceID     string `json:"source_id"`
	Contradiction string `json:"contradiction"`
}

// VerificationResult is the JSON output of the Verifier agent.
type VerificationResult struct {
	Verdict string          `json:"verdict"` // "allow" or "deny"
	Issues  []contradiction `json:"issues"`
}

const verifierSystemPrompt = `You are a fact-verification assistant. You will be given a list of claims and a set of source snippets.
For each claim, check whether any source contradicts it.

Return ONLY valid JSON in this exact format:
{"verdict":"allow","issues":[]}

Where:
- "verdict" is "allow" if no contradictions found, "deny" if any contradiction found
- "issues" is an array of objects: {"claim":"...","source_id":"...","contradiction":"..."}

Be concise. Only report genuine contradictions, not mere lack of confirmation.`

// Execute parses claims and sources, calls the LLM to verify, and returns a VerificationResult.
func (a *VerifierAgent) Execute(ctx context.Context, task *researchruntime.TaskLease, input []byte) ([]byte, error) {
	var in verifierInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("verifier: unmarshal input: %w", err)
	}

	userPrompt := buildVerifierPrompt(in)

	response, err := a.LLM.Complete(ctx, verifierSystemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("verifier: llm: %w", err)
	}

	var result VerificationResult
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("verifier: parse result: %w", err)
	}

	return json.Marshal(result)
}

func buildVerifierPrompt(in verifierInput) string {
	var sb strings.Builder
	sb.WriteString("CLAIMS TO VERIFY:\n")
	for i, c := range in.Claims {
		fmt.Fprintf(&sb, "%d. %s\n", i+1, c)
	}
	sb.WriteString("\nSOURCE SNIPPETS:\n")
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
