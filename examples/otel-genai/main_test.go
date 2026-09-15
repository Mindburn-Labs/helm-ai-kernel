package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestSmoke runs the example end-to-end and asserts that the printed output
// contains every OTel GenAI key the plan requires, plus the helm.* keys, plus
// the cross-reference statement showing helm correlation_id == gen_ai.tool.call.id.
//
// This is the C2 acceptance gate from is-helm-ai-kernel-state-robust-sloth.md:
//
//	"a receipt's correlation_id is recoverable from the matching OTel trace
//	 via gen_ai.tool.call.id"
func TestSmoke(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatalf("run: %v", err)
	}

	out := buf.String()

	// Required OTel GenAI semconv attribute keys. gen_ai.system is legacy and
	// gen_ai.provider.name is its current upstream replacement; the kernel emits
	// both for one major version, so both must appear.
	required := []string{
		"gen_ai.system",
		"gen_ai.provider.name",
		"gen_ai.request.model",
		"gen_ai.response.model",
		"gen_ai.response.id",
		"gen_ai.operation.name",
		"gen_ai.tool.name",
		"gen_ai.tool.call.id",
		"gen_ai.usage.input_tokens",
		"gen_ai.usage.output_tokens",
		"gen_ai.response.finish_reason",
		// helm-specific governance namespace.
		"helm.verdict",
		"helm.reason_code",
		"helm.policy_id",
		"helm.proof_node_id",
		"helm.correlation_id",
		"helm.receipt_id",
		"helm.tenant_id",
	}
	for _, k := range required {
		if !strings.Contains(out, k) {
			t.Errorf("missing key %q in output:\n%s", k, out)
		}
	}

	// Upstream names a tool span "{operation} {tool name}". The example still
	// passes the legacy tool_call operation, so this also covers the mapping.
	if !strings.Contains(out, "Span: execute_tool search_web") {
		t.Errorf("expected span name \"execute_tool search_web\", got:\n%s", out)
	}
	if !strings.Contains(out, "helm correlation_id == gen_ai.tool.call.id:") {
		t.Errorf("missing cross-reference statement in output:\n%s", out)
	}
}
