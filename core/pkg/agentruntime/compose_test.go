package agentruntime

import (
	"strings"
	"testing"
)

// composeFixture builds a deterministic two-call turn with a mid-turn
// toolset extension that only affects call 1.
func composeFixture(t *testing.T) []Event {
	t.Helper()
	return chain(t, []Event{
		evCreated("turn-x"),
		evCallReq("turn-x", 0, "input"),
		evCallDone("turn-x", 0, assistantWithToolCall("tc1", "builtin:read_file", `{"path":"/etc/hosts"}`)),
		evInv(t, "turn-x", "tc1", "builtin:read_file", `{"path":"/etc/hosts"}`, ModeSync),
		evResult("turn-x", "tc1", ResultOK, "127.0.0.1 localhost"),
		evToolsExt("turn-x", 1, "skill:web", ToolDescriptor{ToolID: "mcp:web:search", Description: "Search the web"}),
		evCallReq("turn-x", 1, "input", "assistant:0", "tool_result:tc1"),
		evCallDone("turn-x", 1, assistantText("all done")),
		evComplete("turn-x"),
	})
}

func TestComposeRequestResolvesReferences(t *testing.T) {
	events := composeFixture(t)
	req, err := ComposeRequest(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.TurnID != "turn-x" || req.CallIndex != 1 {
		t.Fatalf("request identity = %+v", req)
	}
	if len(req.Messages) != 3 {
		t.Fatalf("composed %d messages, want 3", len(req.Messages))
	}
	if req.Messages[0].Role != RoleUser || req.Messages[0].Content != "hello" {
		t.Fatalf("message 0 = %+v", req.Messages[0])
	}
	if req.Messages[1].Role != RoleAssistant || len(req.Messages[1].ToolCalls) != 1 {
		t.Fatalf("message 1 = %+v", req.Messages[1])
	}
	if req.Messages[2].Role != RoleTool || req.Messages[2].ToolCallID != "tc1" || req.Messages[2].Content != "127.0.0.1 localhost" {
		t.Fatalf("message 2 = %+v", req.Messages[2])
	}
	if req.Model.Name != "claude-test-1" {
		t.Fatalf("model = %+v", req.Model)
	}
}

func TestComposeRequestHistoricalToolsets(t *testing.T) {
	events := composeFixture(t)
	req0, err := ComposeRequest(events, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, td := range req0.Tools {
		if td.ToolID == "mcp:web:search" {
			t.Fatal("call 0 must reconstruct with its historical toolset (no extension)")
		}
	}
	req1, err := ComposeRequest(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, td := range req1.Tools {
		if td.ToolID == "mcp:web:search" {
			found = true
		}
	}
	if !found {
		t.Fatal("call 1 must see the extended toolset")
	}
}

// TestComposeRequestGolden pins the exact canonical bytes and hash of a
// recomposed request. Byte-stability is the prefix-cache and replay
// contract: if this test breaks, the recomposition format changed and
// every historical reconstruction claim must be re-reviewed.
func TestComposeRequestGolden(t *testing.T) {
	events := composeFixture(t)
	req0, err := ComposeRequest(events, 0)
	if err != nil {
		t.Fatal(err)
	}
	b0, err := req0.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const wantBytes0 = `{"call_index":0,"messages":[{"content":"hello","role":"user"}],"model":{"name":"claude-test-1","provider":"anthropic"},"params":{"max_tokens":1024},"tools":[{"description":"Read a file","requires_permission":false,"tool_id":"builtin:read_file"},{"description":"Write a file","requires_permission":true,"tool_id":"builtin:write_file"}],"turn_id":"turn-x"}`
	if string(b0) != wantBytes0 {
		t.Fatalf("canonical bytes drifted:\n got %s\nwant %s", b0, wantBytes0)
	}
	h0, err := req0.Hash()
	if err != nil {
		t.Fatal(err)
	}
	const wantHash0 = "sha256:299708c143181a91c06f639ba93e16bb44734510f193473f83880d0d70bc7bc7"
	if h0 != wantHash0 {
		t.Fatalf("hash drifted: got %s want %s", h0, wantHash0)
	}

	req1, err := ComposeRequest(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := req1.Hash()
	if err != nil {
		t.Fatal(err)
	}
	const wantHash1 = "sha256:b334fb2aa11290d6c583ccd1a849067974c916bec17162e9ed58a3bacbf92b4f"
	if h1 != wantHash1 {
		t.Fatalf("hash drifted: got %s want %s", h1, wantHash1)
	}

	// Recomposition is deterministic: composing twice yields identical bytes.
	b0again, err := req0.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(b0) != string(b0again) {
		t.Fatal("recomposition is not deterministic")
	}
}

func TestComposeRequestErrors(t *testing.T) {
	events := composeFixture(t)
	if _, err := ComposeRequest(events, 7); err == nil || !strings.Contains(err.Error(), "call_index 7") {
		t.Fatalf("want missing call error, got %v", err)
	}
	corrupt := append([]Event(nil), events...)
	corrupt[1].Seq = 42
	if _, err := ComposeRequest(corrupt, 0); err == nil {
		t.Fatal("composed from a corrupt log")
	}
	if _, err := ComposeRequest(nil, 0); err == nil {
		t.Fatal("composed from an empty log")
	}
}
