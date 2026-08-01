package agentruntime

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regression: P1 TOOL_REQUEST_BINDING_BYPASS — an invocation used to be
// accepted on a matching tool_call_id alone, so it could name a tool the
// model never asked for (one with no descriptor, hence no permission gate)
// or carry args no permission was decided over.
func TestInvocationMustBindToTheModelsRequest(t *testing.T) {
	prefix := []Event{
		evCreated("turn-bind"),
		evCallReq("turn-bind", 0, "input"),
		evCallDone("turn-bind", 0, assistantWithToolCall("tc1", "builtin:write_file", `{"path":"/tmp/x"}`)),
		evPermReq("turn-bind", "tc1", "builtin:write_file"),
		evPermRes("turn-bind", "tc1", DecisionAllow),
	}

	cases := []struct {
		name string
		tool string
		args string
		want string
	}{
		// The attack: swap in a tool_id with no descriptor. toolDescriptor
		// returned nil, so RequiresPermission was never consulted.
		{"ungated tool substituted", "builtin:exec", `{"path":"/tmp/x"}`, "was requested for tool"},
		{"known but different tool", "builtin:read_file", `{"path":"/tmp/x"}`, "was requested for tool"},
		{"args swapped", "builtin:write_file", `{"path":"/etc/shadow"}`, "args do not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := chain(t, append(append([]Event{}, prefix...),
				evInv(t, "turn-bind", "tc1", tc.tool, tc.args, ModeSync)))
			_, err := ReduceEvents(events)
			if err == nil {
				t.Fatalf("invocation of %s with args %s was accepted; want rejection", tc.tool, tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}

	// The matching invocation still folds.
	ok := chain(t, append(append([]Event{}, prefix...),
		evInv(t, "turn-bind", "tc1", "builtin:write_file", `{"path":"/tmp/x"}`, ModeSync)))
	mustReduce(t, ok)
}

// Regression: P1 FORGED_PERMISSION_ALLOW — verdict_ref is optional on the
// event, so an allow appended by anything other than the kernel used to
// satisfy the permission gate. A gated tool now needs an allow that cites a
// kernel verdict.
func TestGatedToolNeedsAnAllowCarryingAVerdict(t *testing.T) {
	forged := NewEvent("turn-forge", EventToolPermissionResolved, at(41))
	forged.PermResolved = &ToolPermissionResolved{
		ToolCallID: "tc1",
		Decision:   DecisionAllow,
		DecidedBy:  "kernel",
		// VerdictRef deliberately absent.
	}

	events := chain(t, []Event{
		evCreated("turn-forge"),
		evCallReq("turn-forge", 0, "input"),
		evCallDone("turn-forge", 0, assistantWithToolCall("tc1", "builtin:write_file", `{"path":"/tmp/x"}`)),
		evPermReq("turn-forge", "tc1", "builtin:write_file"),
		forged,
		evInv(t, "turn-forge", "tc1", "builtin:write_file", `{"path":"/tmp/x"}`, ModeSync),
	})
	_, err := ReduceEvents(events)
	if err == nil {
		t.Fatal("a forged allow without a verdict reference authorized a gated tool")
	}
	if !strings.Contains(err.Error(), "content-addressed kernel verdict_ref") {
		t.Fatalf("error = %v, want the missing-verdict rejection", err)
	}

	// An ungated tool needs no permission at all, so it is unaffected.
	ungated := chain(t, []Event{
		evCreated("turn-ungated"),
		evCallReq("turn-ungated", 0, "input"),
		evCallDone("turn-ungated", 0, assistantWithToolCall("tc1", "builtin:read_file", `{"path":"/tmp/x"}`)),
		evInv(t, "turn-ungated", "tc1", "builtin:read_file", `{"path":"/tmp/x"}`, ModeSync),
	})
	mustReduce(t, ungated)
}

func TestModelCannotIntroduceAnUnavailableTool(t *testing.T) {
	events := chain(t, []Event{
		evCreated("turn-unknown-tool"),
		evCallReq("turn-unknown-tool", 0, "input"),
		evCallDone("turn-unknown-tool", 0, assistantWithToolCall("tc1", "builtin:exec", `{}`)),
	})
	_, err := ReduceEvents(events)
	if err == nil || !strings.Contains(err.Error(), "was not available") {
		t.Fatalf("unknown model tool accepted: %v", err)
	}
}

func TestPermissionRequirementMustNameDurableTool(t *testing.T) {
	events := chain(t, []Event{
		evCreated("turn-permission-bind"),
		evCallReq("turn-permission-bind", 0, "input"),
		evCallDone("turn-permission-bind", 0, assistantWithToolCall("tc1", "builtin:write_file", `{}`)),
		evPermReq("turn-permission-bind", "tc1", "builtin:read_file"),
	})
	_, err := ReduceEvents(events)
	if err == nil || !strings.Contains(err.Error(), "want \"builtin:write_file\"") {
		t.Fatalf("mismatched permission requirement accepted: %v", err)
	}
}

// Regression: P2 RECOVERY_REISSUE_EXHAUSTED_BUDGET — PlanRecovery always
// planned a reissue after closing an interrupted call, even when that call
// took the final budget slot, so the plan contained an action the reducer
// would reject and the turn could never be recovered.
func TestRecoveryDoesNotPlanAnImpossibleReissue(t *testing.T) {
	// MaxModelCalls is 4 in the fixture; open call 3 is the last slot.
	events := []Event{evCreated("turn-budget")}
	for i := 0; i < 3; i++ {
		events = append(events,
			evCallReq("turn-budget", i, "input"),
			evCallDone("turn-budget", i, assistantText("still going")))
	}
	events = append(events, evCallReq("turn-budget", 3, "input")) // open at crash
	events = chain(t, events)

	actions, err := PlanRecovery(events)
	if err != nil {
		t.Fatalf("PlanRecovery: %v", err)
	}
	var kinds []RecoveryActionKind
	for _, a := range actions {
		kinds = append(kinds, a.Kind)
	}
	for _, k := range kinds {
		if k == ActionReissueModelCall {
			t.Fatalf("planned a reissue with the budget exhausted; actions = %v", kinds)
		}
	}
	found := false
	for _, k := range kinds {
		if k == ActionFailTurnBudgetExhausted {
			found = true
		}
	}
	if !found {
		t.Fatalf("actions = %v, want %s", kinds, ActionFailTurnBudgetExhausted)
	}

	// With a slot left, the reissue is still the plan.
	spare := chain(t, []Event{
		evCreated("turn-spare"),
		evCallReq("turn-spare", 0, "input"),
	})
	spareActions, err := PlanRecovery(spare)
	if err != nil {
		t.Fatalf("PlanRecovery: %v", err)
	}
	reissue := false
	for _, a := range spareActions {
		if a.Kind == ActionReissueModelCall {
			reissue = true
		}
	}
	if !reissue {
		t.Fatalf("budget remained but no reissue was planned: %+v", spareActions)
	}
}

// Regression: P2 CROSS_STORE_APPEND_RACE — Append serialized on a per-Store
// mutex only, so two Store values over one directory could read the same
// head and assign the same Seq, forking the chain. Distinct Stores stand in
// for distinct processes; the file lock is what has to serialize them.
func TestConcurrentStoresDoNotDuplicateSeq(t *testing.T) {
	dir := t.TempDir()
	seed, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := seed.Append("turn-race", evCreated("turn-race")); err != nil {
		t.Fatalf("seed append: %v", err)
	}

	const writers, each = 4, 5
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			st, err := OpenStore(dir) // a separate Store: separate mutex
			if err != nil {
				errs <- err
				return
			}
			for i := 0; i < each; i++ {
				// tools_extended is legal from any running state as long as it
				// affects a future model call, so every writer's append is
				// expected to be accepted — which is what puts them in
				// contention for the next Seq.
				ev := evToolsExt("turn-race", 1, fmt.Sprintf("w%d-%d", w, i),
					ToolDescriptor{ToolID: fmt.Sprintf("ext:w%d-%d", w, i), Description: "ext"})
				if _, err := st.Append("turn-race", ev); err != nil {
					errs <- fmt.Errorf("w%d append %d: %w", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	loaded, _, err := seed.Load("turn-race")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) < 2 {
		t.Fatalf("only %d events landed; the race test proved nothing", len(loaded))
	}
	seen := map[uint64]bool{}
	prev := ""
	for i, ev := range loaded {
		if seen[ev.Seq] {
			t.Fatalf("duplicate seq %d at index %d — the chain forked", ev.Seq, i)
		}
		seen[ev.Seq] = true
		if ev.Seq != uint64(i) {
			t.Fatalf("event %d carries seq %d; seqs must be dense and ordered", i, ev.Seq)
		}
		if ev.PrevHash != prev {
			t.Fatalf("event %d prev_hash %q breaks the chain (want %q)", i, ev.PrevHash, prev)
		}
		h, err := HashEvent(&loaded[i])
		if err != nil {
			t.Fatalf("HashEvent: %v", err)
		}
		prev = h
	}
}

func TestLoadWaitsForCrossProcessLock(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append("turn-read-lock", evCreated("turn-read-lock")); err != nil {
		t.Fatal(err)
	}
	path, err := store.pathFor("turn-read-lock")
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockTurnFile(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := store.Load("turn-read-lock")
		done <- err
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("Load returned while append lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Load after unlock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Load remained blocked after append lock was released")
	}
}
