package agentruntime

import (
	"strings"
	"testing"
	"time"
)

func TestEventValidateValidSamples(t *testing.T) {
	valid := happyToolTurn(t)
	valid = append(valid,
		evToolsExt("turn-happy", 2, "skill:web", ToolDescriptor{ToolID: "mcp:web:search", Description: "Search", RequiresPermission: true}),
		evSuspend("turn-happy", "waiting", []string{"tc9"}, nil),
		evResume("turn-happy"),
		evFail("turn-happy"),
		evCancel("turn-happy"),
	)
	for i, ev := range valid {
		if err := ev.Validate(); err != nil {
			t.Errorf("event %d (%s) should validate: %v", i, ev.Type, err)
		}
	}
}

func TestEventValidateInvalid(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Event)
		wantErr string
	}{
		{"schema version", func(e *Event) { e.SchemaVersion = 2 }, "unsupported schema_version"},
		{"bad turn id", func(e *Event) { e.TurnID = "../escape" }, "invalid turn_id"},
		{"zero time", func(e *Event) { e.At = time.Time{} }, "missing event timestamp"},
		{"missing payload", func(e *Event) { e.Created = nil }, "missing payload"},
		{"two payloads", func(e *Event) { e.Resumed = &TurnResumed{Reason: "x"} }, "exactly its own payload"},
		{"bad prev hash", func(e *Event) { e.PrevHash = "md5:abc" }, "malformed prev_hash"},
		{"budget zero", func(e *Event) { e.Created.MaxModelCalls = 0 }, "max_model_calls"},
		{"empty input", func(e *Event) { e.Created.Input = nil }, "at least one input"},
		{"dup tools", func(e *Event) { e.Created.Tools = append(e.Created.Tools, e.Created.Tools[0]) }, "duplicate tool_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := evCreated("turn-v")
			tc.mutate(&ev)
			err := ev.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestEventValidateEnums(t *testing.T) {
	ev := evResult("turn-v", "tc1", "weird", "x")
	if err := ev.Validate(); err == nil || !strings.Contains(err.Error(), "unknown result status") {
		t.Fatalf("want unknown status error, got %v", err)
	}
	ind := evResult("turn-v", "tc1", ResultIndeterminate, "")
	if err := ind.Validate(); err == nil || !strings.Contains(err.Error(), "explanatory content") {
		t.Fatalf("want indeterminate content error, got %v", err)
	}
	badRef := evCallReq("turn-v", 0, "assistant:x")
	if err := badRef.Validate(); err == nil || !strings.Contains(err.Error(), "invalid message ref") {
		t.Fatalf("want bad ref error, got %v", err)
	}
}

func TestInvocationArgsHashBinding(t *testing.T) {
	ev := evInv(t, "turn-v", "tc1", "builtin:read_file", `{"path":"/a"}`, ModeSync)
	ev.InvRequested.ArgsHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := ev.Validate(); err == nil || !strings.Contains(err.Error(), "args_hash does not match") {
		t.Fatalf("want args_hash mismatch error, got %v", err)
	}
	// Canonicalization binds: semantically identical, textually different
	// args must hash identically.
	h1, err := ComputeArgsHash([]byte(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeArgsHash([]byte(`{ "b": 2, "a": 1 }`))
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("canonical args hash unstable: %s vs %s", h1, h2)
	}
}

func TestHashEventChainSensitivity(t *testing.T) {
	a := evCreated("turn-v")
	b := evCreated("turn-v")
	ha, err := HashEvent(&a)
	if err != nil {
		t.Fatal(err)
	}
	b.PrevHash = ha
	hb1, err := HashEvent(&b)
	if err != nil {
		t.Fatal(err)
	}
	b.PrevHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	hb2, err := HashEvent(&b)
	if err != nil {
		t.Fatal(err)
	}
	if hb1 == hb2 {
		t.Fatal("event hash must cover prev_hash (chain binding)")
	}
}
