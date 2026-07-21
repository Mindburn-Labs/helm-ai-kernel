package harness

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// parseFixture runs a testdata NDJSON file through an adapter parser the same
// way the supervisor does, and reports the lines the parser rejected.
func parseFixture(t *testing.T, name string, parse lineParser) ([]Event, int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var events []Event
	dropped := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		parsed, err := parse(line)
		if err != nil {
			dropped++
			continue
		}
		events = append(events, parsed...)
	}
	return events, dropped
}

func TestParseClaudeStream(t *testing.T) {
	events, dropped := parseFixture(t, "claude_stream.ndjson", parseClaudeLine)
	if dropped != 0 {
		t.Fatalf("dropped %d lines from a well-formed stream", dropped)
	}

	kinds := map[EventKind]int{}
	for _, event := range events {
		kinds[event.Kind]++
	}
	for kind, want := range map[EventKind]int{
		EventStarted:    1,
		EventMessage:    2, // one assistant text block, one final result
		EventToolCall:   1,
		EventToolResult: 1,
		EventUsage:      2, // one on the assistant message, one on the result
	} {
		if kinds[kind] != want {
			t.Errorf("%s events = %d, want %d", kind, kinds[kind], want)
		}
	}

	if events[0].NativeSessionID != "sess-claude-1" {
		t.Errorf("session id = %q, want sess-claude-1", events[0].NativeSessionID)
	}
	if events[0].ObservedModel != "claude-opus-4-8" {
		t.Errorf("observed model = %q, want claude-opus-4-8", events[0].ObservedModel)
	}

	var call Event
	var final Event
	for _, event := range events {
		switch {
		case event.Kind == EventToolCall:
			call = event
		case event.Kind == EventMessage && event.Final:
			final = event
		}
	}
	if call.ToolName != "Read" || call.ToolCallID != "toolu_1" {
		t.Errorf("tool call = %+v, want Read/toolu_1", call)
	}
	if !bytes.Contains(call.ToolInput, []byte("/tree/main_test.go")) {
		t.Errorf("tool input = %s, want the vendor payload verbatim", call.ToolInput)
	}
	if final.Text != "Fixed the assertion." {
		t.Errorf("final message = %q", final.Text)
	}
}

func TestParseCodexStream(t *testing.T) {
	events, dropped := parseFixture(t, "codex_stream.ndjson", parseCodexLine)
	if dropped != 0 {
		t.Fatalf("dropped %d lines from a well-formed stream", dropped)
	}

	kinds := map[EventKind]int{}
	for _, event := range events {
		kinds[event.Kind]++
	}
	for kind, want := range map[EventKind]int{
		EventStarted:    1,
		EventMessage:    2, // one agent message, one task_complete
		EventToolCall:   1,
		EventToolResult: 1,
		EventUsage:      1,
	} {
		if kinds[kind] != want {
			t.Errorf("%s events = %d, want %d", kind, kinds[kind], want)
		}
	}

	if events[0].NativeSessionID != "sess-codex-1" {
		t.Errorf("session id = %q, want sess-codex-1", events[0].NativeSessionID)
	}
	if events[0].ObservedModel != "gpt-5-codex" {
		t.Errorf("observed model = %q, want gpt-5-codex", events[0].ObservedModel)
	}

	for _, event := range events {
		if event.Kind == EventToolResult && event.ExitCode != 1 {
			t.Errorf("tool result exit code = %d, want 1", event.ExitCode)
		}
	}
}

// TestObservedModelStaysEmptyWhenUndisclosed is the route-proof invariant: a
// model that was requested but never observed must not be reported as observed,
// because a silent fallback to a different model is exactly what the field
// exists to expose.
func TestObservedModelStaysEmptyWhenUndisclosed(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		parse   lineParser
	}{
		{"claude", "claude_no_model.ndjson", parseClaudeLine},
		{"codex", "codex_no_model.ndjson", parseCodexLine},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events, dropped := parseFixture(t, tt.fixture, tt.parse)
			if dropped != 0 {
				t.Fatalf("dropped %d lines", dropped)
			}
			if len(events) == 0 {
				t.Fatal("fixture produced no events")
			}
			for _, event := range events {
				if event.ObservedModel != "" {
					t.Errorf("%s event reports ObservedModel %q, but the stream never disclosed a model",
						event.Kind, event.ObservedModel)
				}
			}
		})
	}
}

func TestParseRejectsMalformedLines(t *testing.T) {
	for name, parse := range map[string]lineParser{"claude": parseClaudeLine, "codex": parseCodexLine} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte("this is not json")); err == nil {
				t.Error("malformed line parsed without error; it would be silently discarded")
			}
			// A well-formed frame of an unknown type is not a gap in the run's
			// evidence, so it yields no events and no error.
			events, err := parse([]byte(`{"type":"something_new","msg":{"type":"something_new"}}`))
			if err != nil {
				t.Errorf("unknown frame type returned an error: %v", err)
			}
			if len(events) != 0 {
				t.Errorf("unknown frame type produced %d events, want 0", len(events))
			}
		})
	}
}

func TestClaudeErrorResultBecomesErrorEvent(t *testing.T) {
	events, err := parseClaudeLine([]byte(`{"type":"result","subtype":"error","is_error":true,"session_id":"s","result":"tool budget exceeded"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 || events[0].Kind != EventError {
		t.Fatalf("events = %+v, want a single EventError", events)
	}
	if events[0].Text != "tool budget exceeded" {
		t.Errorf("error text = %q", events[0].Text)
	}
}

func TestClaudeAcceptsStringMessageContent(t *testing.T) {
	events, err := parseClaudeLine([]byte(`{"type":"assistant","session_id":"s","message":{"model":"m","content":"plain text"}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 || events[0].Text != "plain text" {
		t.Fatalf("events = %+v, want one message carrying the string content", events)
	}
}

// TestStreamThroughSupervisorStampsRoute runs a fixture through the real
// supervisor, so the credential route, the parse path, and the completion
// guarantee are exercised together without a vendor CLI.
func TestStreamThroughSupervisorStampsRoute(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("testdata", "codex_stream.ndjson"))
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}

	evs := runProcess(context.Background(), processSpec{
		binary:          "/bin/cat",
		args:            []string{fixture},
		credentialRoute: "route-openai",
		parse:           parseCodexLine,
	})
	all, completed := drain(t, evs)

	if completed.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", completed.ExitCode)
	}
	if completed.DroppedLines != 0 {
		t.Errorf("DroppedLines = %d, want 0", completed.DroppedLines)
	}
	if len(all) < 6 {
		t.Fatalf("got %d events, want the full fixture plus completion", len(all))
	}
	for _, event := range all {
		if event.CredentialRoute != "route-openai" {
			t.Errorf("%s event carries route %q, want route-openai", event.Kind, event.CredentialRoute)
		}
	}
}

// TestClaudeReadonlyProbeRefusesUnenforceableBuild: an unenforced readonly claim
// is worse than no claim, so the adapter refuses the run instead of downgrading.
func TestClaudeReadonlyProbeRefusesUnenforceableBuild(t *testing.T) {
	tests := []struct {
		name    string
		help    string
		wantErr bool
	}{
		{
			name: "all flags present",
			help: "Usage: claude [options]\n  --permission-mode <mode>\n  --setting-sources <sources>\n" +
				"  --strict-mcp-config\n  --disable-slash-commands\n",
			wantErr: false,
		},
		{
			name:    "older build without strict mcp config",
			help:    "Usage: claude [options]\n  --permission-mode <mode>\n  --setting-sources <sources>\n  --disable-slash-commands\n",
			wantErr: true,
		},
		{
			name:    "build with no readonly flags at all",
			help:    "Usage: claude [options]\n  --print\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			adapter := &ClaudeAdapter{
				helpCommand: func(context.Context, string) ([]byte, error) {
					calls++
					return []byte(tt.help), nil
				},
			}

			err := adapter.probeReadonlySupport(context.Background(), "claude")
			if tt.wantErr {
				if !errors.Is(err, ErrReadonlyUnsupported) {
					t.Fatalf("err = %v, want ErrReadonlyUnsupported", err)
				}
			} else if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}

			// Memoized: the binary does not change under a running kernel, and a
			// probe per run would put an exec on every readonly spawn.
			if err2 := adapter.probeReadonlySupport(context.Background(), "claude"); !errors.Is(err2, err) && err2 != err {
				t.Errorf("second probe returned a different result: %v vs %v", err2, err)
			}
			if calls != 1 {
				t.Errorf("help probe ran %d times, want 1", calls)
			}
		})
	}
}

func TestClaudeReadonlyProbeFailsClosedWhenHelpFails(t *testing.T) {
	adapter := &ClaudeAdapter{
		helpCommand: func(context.Context, string) ([]byte, error) {
			return nil, errors.New("exec: no such file")
		},
	}
	if err := adapter.probeReadonlySupport(context.Background(), "claude"); !errors.Is(err, ErrReadonlyUnsupported) {
		t.Errorf("err = %v, want ErrReadonlyUnsupported; an unanswerable probe must not admit the run", err)
	}
}

func TestRunRefusesUnresolvableBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-vendor-cli")
	spec := RunSpec{Tree: t.TempDir(), Prompt: "hi", Access: AccessWorkspaceWrite}

	claude := &ClaudeAdapter{Binary: missing}
	if _, err := claude.Run(context.Background(), spec); !errors.Is(err, ErrAdapterNotFound) {
		t.Errorf("claude err = %v, want ErrAdapterNotFound", err)
	}
	codex := &CodexAdapter{Binary: missing}
	if _, err := codex.Run(context.Background(), spec); !errors.Is(err, ErrAdapterNotFound) {
		t.Errorf("codex err = %v, want ErrAdapterNotFound", err)
	}
}

func TestCapabilityProfileSupports(t *testing.T) {
	for _, caps := range []CapabilityProfile{claudeCapabilities(), codexCapabilities()} {
		for _, access := range []AccessProfile{AccessReadonly, AccessWorkspaceWrite, AccessFull} {
			if !caps.Supports(access) {
				t.Errorf("%v does not support %s", caps.SupportedAccessProfiles, access)
			}
		}
		if caps.Supports(AccessProfile("wide-open")) {
			t.Error("capability profile admits an unknown access profile")
		}
	}
}

func TestAdaptersImplementTheInterface(t *testing.T) {
	var _ Adapter = (*ClaudeAdapter)(nil)
	var _ Adapter = (*CodexAdapter)(nil)

	if id := (&ClaudeAdapter{}).ID(); id != claudeAdapterID {
		t.Errorf("claude adapter id = %q", id)
	}
	if id := (&CodexAdapter{}).ID(); id != codexAdapterID {
		t.Errorf("codex adapter id = %q", id)
	}
}
