package agentruntime

import (
	"testing"
)

// TestRecoveryMatrix is the executable form of the documented
// crash-recovery truth table. Each cell builds the log a crash would
// leave behind and asserts the exact planned actions.
func TestRecoveryMatrix(t *testing.T) {
	openModelCall := func(t *testing.T) []Event {
		return chain(t, []Event{
			evCreated("turn-r"),
			evCallReq("turn-r", 0, "input"),
			evCallDone("turn-r", 0, assistantText("first")),
			evCallReq("turn-r", 1, "input", "assistant:0"),
			// crash: call 1 never closed
		})
	}
	openSyncTool := func(t *testing.T) []Event {
		return chain(t, []Event{
			evCreated("turn-r"),
			evCallReq("turn-r", 0, "input"),
			evCallDone("turn-r", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
			evInv(t, "turn-r", "tc1", "builtin:read_file", `{}`, ModeSync),
			// crash: sync tool may have executed
		})
	}
	openAsyncTool := func(t *testing.T) []Event {
		return chain(t, []Event{
			evCreated("turn-r"),
			evCallReq("turn-r", 0, "input"),
			evCallDone("turn-r", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
			evInv(t, "turn-r", "tc1", "builtin:read_file", `{}`, ModeAsync),
			// crash: async tool still running elsewhere
		})
	}

	cases := []struct {
		name  string
		build func(t *testing.T) []Event
		want  []RecoveryActionKind
	}{
		{
			name:  "terminal turn needs nothing",
			build: func(t *testing.T) []Event { return happyToolTurn(t) },
			want:  nil,
		},
		{
			name: "clean in-flight turn needs nothing",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					evCreated("turn-r"),
					evCallReq("turn-r", 0, "input"),
					evCallDone("turn-r", 0, assistantText("ok")),
				})
			},
			want: nil,
		},
		{
			name:  "interrupted model call closes and reissues against budget",
			build: openModelCall,
			want:  []RecoveryActionKind{ActionCloseInterruptedModelCall, ActionReissueModelCall},
		},
		{
			name:  "interrupted sync tool is indeterminate and never re-executed",
			build: openSyncTool,
			want:  []RecoveryActionKind{ActionMarkToolIndeterminate},
		},
		{
			name:  "interrupted async tool stays pending and snapshot is appended",
			build: openAsyncTool,
			want:  []RecoveryActionKind{ActionLeaveAsyncPending, ActionAppendSuspensionSnapshot},
		},
		{
			name: "outstanding permission survives crash with snapshot",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					evCreated("turn-r"),
					evCallReq("turn-r", 0, "input"),
					evCallDone("turn-r", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
					evPermReq("turn-r", "tc1", "builtin:write_file"),
					// crash before the decision
				})
			},
			want: []RecoveryActionKind{ActionAppendSuspensionSnapshot},
		},
		{
			name: "already suspended async work only stays pending",
			build: func(t *testing.T) []Event {
				evs := openAsyncTool(t)
				evs = append(evs, evSuspend("turn-r", "waiting", []string{"tc1"}, nil))
				return chain(t, evs)
			},
			want: []RecoveryActionKind{ActionLeaveAsyncPending},
		},
		{
			name: "mixed crash: sync indeterminate, async pending, snapshot",
			build: func(t *testing.T) []Event {
				return chain(t, []Event{
					evCreated("turn-r"),
					evCallReq("turn-r", 0, "input"),
					evCallDone("turn-r", 0, Message{
						Role:    RoleAssistant,
						Content: "two tools",
						ToolCalls: []ToolCall{
							{ToolCallID: "tc1", ToolID: "builtin:read_file", Args: []byte(`{}`)},
							{ToolCallID: "tc2", ToolID: "builtin:read_file", Args: []byte(`{}`)},
						},
					}),
					evInv(t, "turn-r", "tc1", "builtin:read_file", `{}`, ModeSync),
					evInv(t, "turn-r", "tc2", "builtin:read_file", `{}`, ModeAsync),
				})
			},
			want: []RecoveryActionKind{ActionMarkToolIndeterminate, ActionLeaveAsyncPending, ActionAppendSuspensionSnapshot},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions, err := PlanRecovery(tc.build(t))
			if err != nil {
				t.Fatalf("PlanRecovery: %v", err)
			}
			if len(actions) != len(tc.want) {
				t.Fatalf("got %d actions %+v, want %d %v", len(actions), actions, len(tc.want), tc.want)
			}
			for i, kind := range tc.want {
				if actions[i].Kind != kind {
					t.Fatalf("action %d = %s, want %s", i, actions[i].Kind, kind)
				}
				if actions[i].Reason == "" {
					t.Fatalf("action %d missing documented reason", i)
				}
			}
		})
	}
}

// TestRecoveryActionsApplyCleanly proves the planned recovery actions can
// actually be turned into events the reducer gate accepts: recovery never
// requires breaking the state machine.
func TestRecoveryActionsApplyCleanly(t *testing.T) {
	// Interrupted sync tool -> indeterminate result is gate-legal.
	log := chain(t, []Event{
		evCreated("turn-a"),
		evCallReq("turn-a", 0, "input"),
		evCallDone("turn-a", 0, assistantWithToolCall("tc1", "builtin:read_file", `{}`)),
		evInv(t, "turn-a", "tc1", "builtin:read_file", `{}`, ModeSync),
	})
	actions, err := PlanRecovery(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionMarkToolIndeterminate {
		t.Fatalf("actions = %+v", actions)
	}
	fix := evResult("turn-a", "tc1", ResultIndeterminate, "interrupted by crash; may have executed; not re-executed")
	fix.Seq = uint64(len(log))
	if _, err := ValidateAppend(log, fix); err != nil {
		t.Fatalf("indeterminate fix rejected by gate: %v", err)
	}

	// Interrupted model call -> close + reissue is gate-legal and charges
	// the budget (the re-issue is the next call index).
	log2 := chain(t, []Event{
		evCreated("turn-b"),
		evCallReq("turn-b", 0, "input"),
	})
	close_ := evCallFailed("turn-b", 0, FailInterrupted)
	close_.Seq = uint64(len(log2))
	reissue := evCallReq("turn-b", 1, "input")
	reissue.Seq = uint64(len(log2) + 1)
	s, err := ValidateAppend(log2, close_, reissue)
	if err != nil {
		t.Fatalf("model-call recovery rejected by gate: %v", err)
	}
	if s.ModelCallsRequested != 2 {
		t.Fatalf("re-issue must charge the budget: requested = %d", s.ModelCallsRequested)
	}
}

func TestPlanRecoveryCorruptLogFailsLoud(t *testing.T) {
	log := chain(t, []Event{
		evCreated("turn-c"),
		evCallReq("turn-c", 0, "input"),
	})
	log[1].Seq = 9 // corrupt
	if _, err := PlanRecovery(log); err == nil {
		t.Fatal("recovery planned for a corrupt log")
	}
}
