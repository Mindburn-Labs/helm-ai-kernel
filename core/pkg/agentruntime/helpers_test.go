package agentruntime

import (
	"encoding/json"
	"testing"
	"time"
)

var testBase = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func at(sec int) time.Time { return testBase.Add(time.Duration(sec) * time.Second) }

func testTools() []ToolDescriptor {
	return []ToolDescriptor{
		{ToolID: "builtin:read_file", Description: "Read a file", RequiresPermission: false},
		{ToolID: "builtin:write_file", Description: "Write a file", RequiresPermission: true},
	}
}

func evCreated(turnID string) Event {
	e := NewEvent(turnID, EventTurnCreated, at(0))
	e.Created = &TurnCreated{
		AgentID:       "agent:test",
		Model:         ModelRef{Provider: "anthropic", Name: "claude-test-1"},
		MaxModelCalls: 4,
		Input:         []Message{{Role: RoleUser, Content: "hello"}},
		Tools:         testTools(),
	}
	return e
}

func evCallReq(turnID string, idx int, refs ...string) Event {
	e := NewEvent(turnID, EventModelCallRequested, at(1+idx*10))
	e.CallRequested = &ModelCallRequested{
		CallIndex:   idx,
		Model:       ModelRef{Provider: "anthropic", Name: "claude-test-1"},
		Params:      ModelParams{MaxTokens: intPtr(1024)},
		MessageRefs: refs,
	}
	return e
}

func intPtr(v int) *int { return &v }

func evCallDone(turnID string, idx int, msg Message) Event {
	e := NewEvent(turnID, EventModelCallCompleted, at(2+idx*10))
	e.CallCompleted = &ModelCallCompleted{
		CallIndex:  idx,
		Message:    msg,
		Usage:      Usage{InputTokens: 10, OutputTokens: 5},
		StopReason: StopEndTurn,
	}
	if len(msg.ToolCalls) > 0 {
		e.CallCompleted.StopReason = StopToolCalls
	}
	return e
}

func evCallFailed(turnID string, idx int, class string) Event {
	e := NewEvent(turnID, EventModelCallFailed, at(3+idx*10))
	e.CallFailed = &ModelCallFailed{CallIndex: idx, Class: class, Message: "boom", Retryable: true}
	return e
}

func evPermReq(turnID, id, tool string) Event {
	e := NewEvent(turnID, EventToolPermissionRequired, at(40))
	e.PermRequired = &ToolPermissionRequired{ToolCallID: id, ToolID: tool, Requirement: "kernel-verdict"}
	return e
}

func evPermRes(turnID, id, decision string) Event {
	e := NewEvent(turnID, EventToolPermissionResolved, at(41))
	e.PermResolved = &ToolPermissionResolved{ToolCallID: id, Decision: decision, DecidedBy: "kernel", VerdictRef: "decision:test-1"}
	return e
}

func evInv(t *testing.T, turnID, id, tool, args, mode string) Event {
	t.Helper()
	e := NewEvent(turnID, EventToolInvocationRequested, at(50))
	h, err := ComputeArgsHash(json.RawMessage(args))
	if err != nil {
		t.Fatalf("ComputeArgsHash: %v", err)
	}
	e.InvRequested = &ToolInvocationRequested{
		ToolCallID: id,
		ToolID:     tool,
		Args:       json.RawMessage(args),
		ArgsHash:   h,
		Mode:       mode,
	}
	return e
}

func evResult(turnID, id, status, content string) Event {
	e := NewEvent(turnID, EventToolResult, at(60))
	e.ToolResult = &ToolResult{ToolCallID: id, Status: status, Content: content}
	return e
}

func evSuspend(turnID, reason string, asyncIDs, permIDs []string) Event {
	e := NewEvent(turnID, EventTurnSuspended, at(70))
	e.Suspended = &TurnSuspended{Reason: reason, PendingAsyncToolCallIDs: asyncIDs, OutstandingPermissionToolCallIDs: permIDs}
	return e
}

func evResume(turnID string) Event {
	e := NewEvent(turnID, EventTurnResumed, at(71))
	e.Resumed = &TurnResumed{Reason: "external input arrived"}
	return e
}

func evComplete(turnID string) Event {
	e := NewEvent(turnID, EventTurnCompleted, at(80))
	e.Completed = &TurnCompleted{Outcome: "success"}
	return e
}

func evFail(turnID string) Event {
	e := NewEvent(turnID, EventTurnFailed, at(81))
	e.Failed = &TurnFailed{Class: "agent_error", Message: "gave up"}
	return e
}

func evCancel(turnID string) Event {
	e := NewEvent(turnID, EventTurnCancelled, at(82))
	e.Cancelled = &TurnCancelled{Reason: "user stop"}
	return e
}

func evToolsExt(turnID string, firstAffected int, source string, tools ...ToolDescriptor) Event {
	e := NewEvent(turnID, EventToolsExtended, at(90))
	e.ToolsExtended = &ToolsExtended{Tools: tools, FirstAffectedModelCallIndex: firstAffected, Source: source}
	return e
}

// chain assigns Seq and PrevHash so a built event slice is a well-formed
// in-memory log.
func chain(t *testing.T, events []Event) []Event {
	t.Helper()
	prev := ""
	for i := range events {
		events[i].Seq = uint64(i)
		events[i].PrevHash = prev
		h, err := HashEvent(&events[i])
		if err != nil {
			t.Fatalf("HashEvent: %v", err)
		}
		prev = h
	}
	return events
}

func assistantText(text string) Message {
	return Message{Role: RoleAssistant, Content: text}
}

func assistantWithToolCall(id, tool, args string) Message {
	return Message{
		Role:    RoleAssistant,
		Content: "calling a tool",
		ToolCalls: []ToolCall{
			{ToolCallID: id, ToolID: tool, Args: json.RawMessage(args)},
		},
	}
}

// happyToolTurn is a complete legal turn with one permitted tool call and
// two model calls.
func happyToolTurn(t *testing.T) []Event {
	t.Helper()
	return chain(t, []Event{
		evCreated("turn-happy"),
		evCallReq("turn-happy", 0, "input"),
		evCallDone("turn-happy", 0, assistantWithToolCall("tc1", "builtin:write_file", `{"path":"/tmp/x"}`)),
		evPermReq("turn-happy", "tc1", "builtin:write_file"),
		evPermRes("turn-happy", "tc1", DecisionAllow),
		evInv(t, "turn-happy", "tc1", "builtin:write_file", `{"path":"/tmp/x"}`, ModeSync),
		evResult("turn-happy", "tc1", ResultOK, "written"),
		evCallReq("turn-happy", 1, "input", "assistant:0", "tool_result:tc1"),
		evCallDone("turn-happy", 1, assistantText("done")),
		evComplete("turn-happy"),
	})
}

// mustReduce folds events and fails the test on error.
func mustReduce(t *testing.T, events []Event) *State {
	t.Helper()
	s, err := ReduceEvents(events)
	if err != nil {
		t.Fatalf("ReduceEvents: %v", err)
	}
	return s
}
