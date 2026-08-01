package agentruntime

import (
	"strings"
	"testing"
)

func TestReducerHappyPath(t *testing.T) {
	events := happyToolTurn(t)
	s := mustReduce(t, events)
	if s.Status != StatusCompleted {
		t.Fatalf("status = %s, want completed", s.Status)
	}
	if !s.Terminal() {
		t.Fatal("completed turn must be terminal")
	}
	if s.Events != len(events) {
		t.Fatalf("folded %d events, want %d", s.Events, len(events))
	}
	if s.ModelCallsRequested != 2 || s.ModelCallsCompleted != 2 {
		t.Fatalf("model calls requested/completed = %d/%d, want 2/2", s.ModelCallsRequested, s.ModelCallsCompleted)
	}
	if len(s.ToolResultMeta) != 1 || s.ToolResultMeta["tc1"].Status != ResultOK {
		t.Fatalf("tool results = %+v", s.ToolResultMeta)
	}
	if s.TotalUsage.InputTokens != 20 || s.TotalUsage.OutputTokens != 10 {
		t.Fatalf("usage = %+v", s.TotalUsage)
	}
}

// TestReducerTransitionTable is the executable transition table: every
// row builds an event sequence that must be rejected by the reducer, plus
// rows that must be accepted. If the reducer rejects a candidate, the
// store can never write it — illegal states are unrepresentable on disk.
func TestReducerTransitionTable(t *testing.T) {
	created := func() Event { return evCreated("turn-t") }

	cases := []struct {
		name    string
		build   func(t *testing.T) []Event
		wantErr string // empty means the sequence must be ACCEPTED
	}{
		{
			name:    "first event not turn_created",
			build:   func(t *testing.T) []Event { return chain(t, []Event{evCallReq("turn-t", 0, "input")}) },
			wantErr: "first event must be turn_created",
		},
		{
			name: "first event seq not zero",
			build: func(t *testing.T) []Event {
				evs := chain(t, []Event{created()})
				evs[0].Seq = 7
				return evs
			},
			wantErr: "seq 0",
		},
		{
			name: "event after terminal",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantText("done")),
					evComplete("turn-t"),
					evCancel("turn-t"),
				})
			},
			wantErr: "terminal",
		},
		{
			name: "turn_id mismatch",
			build: func(t *testing.T) []Event {
				evs := chain(t, []Event{created(), evCallReq("turn-t", 0, "input")})
				evs[1].TurnID = "turn-other"
				return chain(t, evs)
			},
			wantErr: "turn_id mismatch",
		},
		{
			name: "seq gap",
			build: func(t *testing.T) []Event {
				evs := chain(t, []Event{created(), evCallReq("turn-t", 0, "input")})
				evs[1].Seq = 5
				return evs
			},
			wantErr: "seq mismatch",
		},
		{
			name:    "second turn_created",
			build:   func(t *testing.T) []Event { return chain(t, []Event{created(), created()}) },
			wantErr: "seq 0",
		},
		{
			name: "model call while one open",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evCallReq("turn-t", 0, "input"), evCallReq("turn-t", 1, "input")})
			},
			wantErr: "still open",
		},
		{
			name: "call index out of order",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evCallReq("turn-t", 3, "input")})
			},
			wantErr: "out of order",
		},
		{
			name: "budget exhausted",
			build: func(t *testing.T) []Event {
				c := created()
				c.Created.MaxModelCalls = 1
				return chain(t, []Event{
					c,
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantText("done")),
					evCallReq("turn-t", 1, "input", "assistant:0"),
				})
			},
			wantErr: "budget exhausted",
		},
		{
			name: "new model call with open invocation",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeAsync),
					evCallReq("turn-t", 1, "input"),
				})
			},
			wantErr: "still open",
		},
		{
			name: "new model call with outstanding permission",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evPermReq("turn-t", "tc1", "builtin:write_file"),
					evCallReq("turn-t", 1, "input"),
				})
			},
			wantErr: "outstanding",
		},
		{
			name: "unresolvable assistant ref",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evCallReq("turn-t", 0, "input", "assistant:5")})
			},
			wantErr: "unresolvable message ref",
		},
		{
			name: "unresolvable tool result ref",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evCallReq("turn-t", 0, "tool_result:nope")})
			},
			wantErr: "unresolvable message ref",
		},
		{
			name: "completion without open call",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evCallDone("turn-t", 0, assistantText("x"))})
			},
			wantErr: "no open model call",
		},
		{
			name: "failure with wrong index",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evCallReq("turn-t", 0, "input"), evCallFailed("turn-t", 1, FailProvider)})
			},
			wantErr: "no open model call",
		},
		{
			name: "invocation of unknown tool call",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantText("x")),
					evInv(t, "turn-t", "tc9", "builtin:read_file", `{}`, ModeSync),
				})
			},
			wantErr: "never requested by the model",
		},
		{
			name: "duplicate invocation",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeSync),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeSync),
				})
			},
			wantErr: "already invoked",
		},
		{
			name: "result without invocation",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evResult("turn-t", "tc1", ResultOK, "x"),
				})
			},
			wantErr: "no open invocation",
		},
		{
			name: "permission resolve without required",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evPermRes("turn-t", "tc1", DecisionAllow),
				})
			},
			wantErr: "no outstanding permission",
		},
		{
			name: "denied tool is never invoked",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evPermReq("turn-t", "tc1", "builtin:write_file"),
					evPermRes("turn-t", "tc1", DecisionDeny),
					evInv(t, "turn-t", "tc1", "builtin:write_file", `{}`, ModeSync),
				})
			},
			wantErr: "denied",
		},
		{
			name: "denied synthetic result must be error",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evPermReq("turn-t", "tc1", "builtin:write_file"),
					evPermRes("turn-t", "tc1", DecisionDeny),
					evResult("turn-t", "tc1", ResultOK, "sneaky"),
				})
			},
			wantErr: "denied tool call may only receive an error result",
		},
		{
			name: "denied synthetic error result accepted",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evPermReq("turn-t", "tc1", "builtin:write_file"),
					evPermRes("turn-t", "tc1", DecisionDeny),
					evResult("turn-t", "tc1", ResultError, "denied by kernel verdict decision:test-1"),
					evCallReq("turn-t", 1, "input", "assistant:0", "tool_result:tc1"),
					evCallDone("turn-t", 1, assistantText("ok")),
					evComplete("turn-t"),
				})
			},
			wantErr: "",
		},
		{
			name: "permission-gated tool requires durable allow",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:write_file", `{}`, ModeSync),
				})
			},
			wantErr: "requires permission",
		},
		{
			name: "suspend with nothing pending",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantText("x")),
					evSuspend("turn-t", "nap", nil, nil),
				})
			},
			wantErr: "nothing pending",
		},
		{
			name: "suspend snapshot mismatch",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeAsync),
					evSuspend("turn-t", "nap", []string{"tcOTHER"}, nil),
				})
			},
			wantErr: "does not match pending state",
		},
		{
			name: "suspend with open sync invocation",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeSync),
					evSuspend("turn-t", "nap", nil, nil),
				})
			},
			wantErr: "sync invocation",
		},
		{
			name: "resume when not suspended",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evResume("turn-t")})
			},
			wantErr: "only a suspended turn",
		},
		{
			name: "suspend resume cycle accepted",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeAsync),
					evSuspend("turn-t", "waiting on async tool", []string{"tc1"}, nil),
					evResume("turn-t"),
					evResult("turn-t", "tc1", ResultOK, "async done"),
					evCallReq("turn-t", 1, "input", "assistant:0", "tool_result:tc1"),
					evCallDone("turn-t", 1, assistantText("fin")),
					evComplete("turn-t"),
				})
			},
			wantErr: "",
		},
		{
			name: "complete with unsettled tool call",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evComplete("turn-t"),
				})
			},
			wantErr: "unsettled",
		},
		{
			name:    "complete with no model call",
			build:   func(t *testing.T) []Event { return chain(t, []Event{created(), evComplete("turn-t")}) },
			wantErr: "no completed model call",
		},
		{
			name: "tools_extended cannot rewrite history",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evToolsExt("turn-t", 0, "skill:web", ToolDescriptor{ToolID: "mcp:web:search", Description: "Search"}),
				})
			},
			wantErr: "rewrite call history",
		},
		{
			name: "tools_extended duplicate tool",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evToolsExt("turn-t", 0, "skill:x", ToolDescriptor{ToolID: "builtin:read_file", Description: "dup"}),
				})
			},
			wantErr: "already in the toolset",
		},
		{
			name: "cancel from suspended accepted",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeAsync),
					evSuspend("turn-t", "waiting", []string{"tc1"}, nil),
					evCancel("turn-t"),
				})
			},
			wantErr: "",
		},
		{
			name: "fail from running accepted",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{created(), evFail("turn-t")})
			},
			wantErr: "",
		},
		{
			name: "permission for stale call rejected",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallDone("turn-t", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
					evInv(t, "turn-t", "tc1", "builtin:read_file", `{}`, ModeSync),
					evResult("turn-t", "tc1", ResultOK, "ok"),
					evCallReq("turn-t", 1, "input", "assistant:0", "tool_result:tc1"),
					evCallDone("turn-t", 1, assistantWithToolCall("tc2", "builtin:write_file", `{}`)),
					evPermReq("turn-t", "tc1", "builtin:read_file"),
				})
			},
			wantErr: "stale model call",
		},
		{
			name: "model call failed then reissued accepted",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					created(),
					evCallReq("turn-t", 0, "input"),
					evCallFailed("turn-t", 0, FailInterrupted),
					evCallReq("turn-t", 1, "input"),
					evCallDone("turn-t", 1, assistantText("recovered")),
					evComplete("turn-t"),
				})
			},
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := tc.build(t)
			_, err := ReduceEvents(events)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("sequence should be ACCEPTED, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("sequence should be REJECTED with %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestReducerPurity proves Reduce never mutates the input state: folding
// an event must leave the previous state bit-identical, so a rejected
// append can never corrupt the in-memory view of the log either.
func TestReducerPurity(t *testing.T) {
	prefix := chain(t, []Event{
		evCreated("turn-p"),
		evCallReq("turn-p", 0, "input"),
		evCallDone("turn-p", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
	})
	s1 := mustReduce(t, prefix)
	usageBefore := s1.TotalUsage
	openBefore := len(s1.OpenInvocations)
	knownBefore := len(s1.KnownToolCallIDs)

	next := evInv(t, "turn-p", "tc1", "builtin:read_file", `{}`, ModeSync)
	next.Seq = uint64(len(prefix))
	s2, err := Reduce(s1, next)
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	if len(s2.OpenInvocations) != 1 {
		t.Fatal("s2 should have one open invocation")
	}
	if s1.TotalUsage != usageBefore || len(s1.OpenInvocations) != openBefore || len(s1.KnownToolCallIDs) != knownBefore {
		t.Fatal("Reduce mutated its input state")
	}
}

// TestValidateAppendIsTheGate proves the append gate folds existing +
// candidates exactly like a full-log reduce, and that a rejected batch
// yields no state.
func TestValidateAppendIsTheGate(t *testing.T) {
	existing := chain(t, []Event{evCreated("turn-g"), evCallReq("turn-g", 0, "input")})
	bad := evCallReq("turn-g", 1, "input") // illegal: call 0 still open
	bad.Seq = 2
	if _, err := ValidateAppend(existing, bad); err == nil {
		t.Fatal("ValidateAppend accepted an illegal candidate")
	}
	good := evCallDone("turn-g", 0, assistantText("ok"))
	good.Seq = 2
	s, err := ValidateAppend(existing, good)
	if err != nil {
		t.Fatalf("ValidateAppend rejected a legal candidate: %v", err)
	}
	if s.ModelCallsCompleted != 1 {
		t.Fatalf("state = %+v", s)
	}
}
