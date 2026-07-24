package agentruntime

import (
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// ComposedRequest is the exact, deterministic reconstruction of one durable
// model request: the references recorded in model_call_requested resolved
// against the log, with the toolset that was effective for that call.
// Because the log is append-only and references resolve to immutable
// settled content, recomposition is byte-stable forever — the same
// property that makes prompt-prefix caching and replay auditable.
type ComposedRequest struct {
	TurnID    string           `json:"turn_id"`
	CallIndex int              `json:"call_index"`
	Model     ModelRef         `json:"model"`
	Params    ModelParams      `json:"params"`
	Messages  []Message        `json:"messages"`
	Tools     []ToolDescriptor `json:"tools"`
}

// CanonicalBytes returns the RFC 8785 canonical encoding of the request —
// the deterministic byte form whose stability is pinned by golden tests.
func (r *ComposedRequest) CanonicalBytes() ([]byte, error) {
	b, err := canonicalize.JCS(r)
	if err != nil {
		return nil, fmt.Errorf("agentruntime: canonicalize composed request: %w", err)
	}
	return b, nil
}

// Hash returns "sha256:" + hex(SHA-256(CanonicalBytes())).
func (r *ComposedRequest) Hash() (string, error) {
	h, err := canonicalize.CanonicalHash(r)
	if err != nil {
		return "", fmt.Errorf("agentruntime: hash composed request: %w", err)
	}
	return sha256Prefix + h, nil
}

// ComposeRequest rebuilds the durable model request for callIndex purely
// from the log. It fails if the log is corrupt or if no
// model_call_requested with that index exists.
func ComposeRequest(events []Event, callIndex int) (*ComposedRequest, error) {
	state, err := ReduceEvents(events)
	if err != nil {
		return nil, fmt.Errorf("agentruntime: cannot compose from corrupt log: %w", err)
	}
	if state == nil {
		return nil, fmt.Errorf("agentruntime: empty log")
	}
	var req *ModelCallRequested
	for i := range events {
		if events[i].Type == EventModelCallRequested && events[i].CallRequested.CallIndex == callIndex {
			req = events[i].CallRequested
			break
		}
	}
	if req == nil {
		return nil, fmt.Errorf("agentruntime: no model_call_requested with call_index %d", callIndex)
	}
	var messages []Message
	for _, ref := range req.MessageRefs {
		ms, err := state.ResolveRef(ref)
		if err != nil {
			return nil, fmt.Errorf("agentruntime: resolve ref %q: %w", ref, err)
		}
		messages = append(messages, ms...)
	}
	return &ComposedRequest{
		TurnID:    state.TurnID,
		CallIndex: callIndex,
		Model:     req.Model,
		Params:    req.Params,
		Messages:  messages,
		Tools:     state.EffectiveTools(callIndex),
	}, nil
}
