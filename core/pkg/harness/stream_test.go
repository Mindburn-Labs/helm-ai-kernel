package harness

import (
	"bytes"
	"context"
	"encoding/json"
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
		{"primeagent", "primeagent_no_model.ndjson", parsePrimeAgentLine},
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
	for name, parse := range map[string]lineParser{
		"claude":     parseClaudeLine,
		"codex":      parseCodexLine,
		"primeagent": parsePrimeAgentLine,
	} {
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
	runtime := t.TempDir()
	missing := filepath.Join(runtime, "no-such-vendor-cli")
	spec := RunSpec{
		Tree:    filepath.Join(runtime, "tree"),
		HomeDir: filepath.Join(runtime, "home"),
		Prompt:  "hi",
		Access:  AccessWorkspaceWrite,
	}

	claude := &ClaudeAdapter{Binary: missing}
	if _, err := claude.Run(context.Background(), spec); !errors.Is(err, ErrAdapterNotFound) {
		t.Errorf("claude err = %v, want ErrAdapterNotFound", err)
	}
	codex := &CodexAdapter{Binary: missing}
	if _, err := codex.Run(context.Background(), spec); !errors.Is(err, ErrAdapterNotFound) {
		t.Errorf("codex err = %v, want ErrAdapterNotFound", err)
	}
	prime := &PrimeAgentAdapter{Binary: missing}
	if _, err := prime.Run(context.Background(), spec); !errors.Is(err, ErrAdapterNotFound) {
		t.Errorf("prime-agent err = %v, want ErrAdapterNotFound", err)
	}
}

func TestAdaptersRefuseInvalidScopedHomeBeforeBinaryResolution(t *testing.T) {
	runtime := t.TempDir()
	tree := filepath.Join(runtime, "tree")
	missing := filepath.Join(runtime, "no-such-vendor-cli")
	adapters := []Adapter{
		&ClaudeAdapter{Binary: missing},
		&CodexAdapter{Binary: missing},
		&PrimeAgentAdapter{Binary: missing},
	}
	for _, tc := range []struct {
		name string
		spec RunSpec
		want error
	}{
		{
			name: "missing home",
			spec: RunSpec{Tree: tree, Prompt: "hi", Access: AccessWorkspaceWrite},
			want: ErrHomeDirRequired,
		},
		{
			name: "home inside tree",
			spec: RunSpec{Tree: tree, HomeDir: filepath.Join(tree, "home"), Prompt: "hi", Access: AccessWorkspaceWrite},
			want: ErrHomeDirInsideTree,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, adapter := range adapters {
				if _, err := adapter.Run(context.Background(), tc.spec); !errors.Is(err, tc.want) {
					t.Errorf("%s Run error = %v, want %v", adapter.ID(), err, tc.want)
				}
			}
		})
	}
}

// TestCapabilityProfileSupports pins each adapter's admitted access profiles
// individually rather than asserting every adapter admits all three. A vendor
// that cannot enforce a posture must be visibly unable to, not averaged in with
// the ones that can.
func TestCapabilityProfileSupports(t *testing.T) {
	all := []AccessProfile{AccessReadonly, AccessWorkspaceWrite, AccessFull}
	for _, tt := range []struct {
		name string
		caps CapabilityProfile
		want []AccessProfile
	}{
		{"claude", claudeCapabilities(), all},
		{"codex", codexCapabilities(), all},
		// Prime Agent has one model-facing tool and it executes arbitrary
		// Python. There is no readonly posture to admit.
		{"primeagent", primeAgentCapabilities(), []AccessProfile{AccessWorkspaceWrite, AccessFull}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			supported := map[AccessProfile]bool{}
			for _, access := range tt.want {
				supported[access] = true
				if !tt.caps.Supports(access) {
					t.Errorf("%v does not support %s", tt.caps.SupportedAccessProfiles, access)
				}
			}
			for _, access := range all {
				if !supported[access] && tt.caps.Supports(access) {
					t.Errorf("%v admits %s, which it cannot enforce", tt.caps.SupportedAccessProfiles, access)
				}
			}
			if tt.caps.Supports(AccessProfile("wide-open")) {
				t.Error("capability profile admits an unknown access profile")
			}
		})
	}
}

func TestAdaptersImplementTheInterface(t *testing.T) {
	var _ Adapter = (*ClaudeAdapter)(nil)
	var _ Adapter = (*CodexAdapter)(nil)
	var _ Adapter = (*PrimeAgentAdapter)(nil)

	if id := (&ClaudeAdapter{}).ID(); id != claudeAdapterID {
		t.Errorf("claude adapter id = %q", id)
	}
	if id := (&CodexAdapter{}).ID(); id != codexAdapterID {
		t.Errorf("codex adapter id = %q", id)
	}
	if id := (&PrimeAgentAdapter{}).ID(); id != primeAgentAdapterID {
		t.Errorf("prime-agent adapter id = %q", id)
	}
}

func TestParsePrimeAgentStream(t *testing.T) {
	events, dropped := parseFixture(t, "primeagent_stream.ndjson", parsePrimeAgentLine)
	if dropped != 0 {
		t.Fatalf("dropped %d lines from a well-formed stream", dropped)
	}

	kinds := map[EventKind]int{}
	for _, event := range events {
		kinds[event.Kind]++
	}
	for kind, want := range map[EventKind]int{
		EventStarted:    1,
		EventMessage:    3, // two assistant text blocks, one final agent_end
		EventToolCall:   1,
		EventToolResult: 1,
		EventUsage:      2, // one per completed assistant message
	} {
		if kinds[kind] != want {
			t.Errorf("%s events = %d, want %d", kind, kinds[kind], want)
		}
	}

	if events[0].Kind != EventStarted {
		t.Fatalf("first event kind = %s, want %s", events[0].Kind, EventStarted)
	}
	if events[0].NativeSessionID != "sess-prime-1" {
		t.Errorf("session id = %q, want sess-prime-1", events[0].NativeSessionID)
	}
	// The vendor's session header names no model, so unlike claude and codex the
	// started event cannot disclose one. Backfilling it from RunSpec.Model is
	// exactly what ObservedModel exists to prevent.
	if events[0].ObservedModel != "" {
		t.Errorf("started event ObservedModel = %q, want empty: the header discloses no model",
			events[0].ObservedModel)
	}

	var firstMessage *Event
	for i := range events {
		if events[i].Kind == EventMessage {
			firstMessage = &events[i]
			break
		}
	}
	if firstMessage == nil {
		t.Fatal("no message event")
	}
	if firstMessage.ObservedModel != "gpt-5.1-codex" {
		t.Errorf("first message ObservedModel = %q, want gpt-5.1-codex", firstMessage.ObservedModel)
	}

	for _, event := range events {
		if event.Kind == EventToolResult && event.ExitCode != 1 {
			t.Errorf("tool result exit code = %d, want 1 for an errored cell", event.ExitCode)
		}
	}
}

// TestPrimeAgentPrefersTheAnsweringModel pins the route proof: when the provider
// answers with a different model than the one requested, the answering model is
// what the run recorded.
func TestPrimeAgentPrefersTheAnsweringModel(t *testing.T) {
	events, _ := parseFixture(t, "primeagent_stream.ndjson", parsePrimeAgentLine)
	found := false
	for _, event := range events {
		if event.ObservedModel == "gpt-5.1-codex-2026-08" {
			found = true
		}
	}
	if !found {
		t.Error("no event reported the responseModel; a silent model substitution would go unrecorded")
	}
}

// TestPrimeAgentToolInputIsAlwaysPythonSource records what this adapter's tool
// evidence actually is. The vendor exposes one model-facing tool, so a tool call
// says the agent ran this Python and nothing about which files it touched. The
// compensating evidence is the worktree diff, not this stream.
func TestPrimeAgentToolInputIsAlwaysPythonSource(t *testing.T) {
	events, _ := parseFixture(t, "primeagent_stream.ndjson", parsePrimeAgentLine)
	calls := 0
	for _, event := range events {
		if event.Kind != EventToolCall {
			continue
		}
		calls++
		if event.ToolName != "ipython" {
			t.Errorf("tool name = %q, want ipython", event.ToolName)
		}
		var input map[string]any
		if err := json.Unmarshal(event.ToolInput, &input); err != nil {
			t.Fatalf("tool input is not an object: %v", err)
		}
		if _, ok := input["code"]; !ok {
			t.Errorf("tool input keys = %v, want a code key", input)
		}
	}
	if calls == 0 {
		t.Fatal("fixture produced no tool calls")
	}
}

// TestPrimeAgentTurnEndDoesNotDuplicateMessageEnd pins the de-duplication
// choice: three frame types carry the same assistant message, and mapping more
// than one would double-count both its text and its token usage.
func TestPrimeAgentTurnEndDoesNotDuplicateMessageEnd(t *testing.T) {
	message := `{"role":"assistant","model":"m","content":[{"type":"text","text":"hi"}],"usage":{"input":1,"output":2},"stopReason":"stop"}`

	for _, frame := range []string{"turn_start", "message_start", "message_update", "turn_end"} {
		line := []byte(`{"type":"` + frame + `","message":` + message + `}`)
		events, err := parsePrimeAgentLine(line)
		if err != nil {
			t.Fatalf("%s: %v", frame, err)
		}
		if len(events) != 0 {
			t.Errorf("%s produced %d events, want 0: message_end already reports this message", frame, len(events))
		}
	}

	events, err := parsePrimeAgentLine([]byte(`{"type":"message_end","message":` + message + `}`))
	if err != nil {
		t.Fatalf("message_end: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("message_end produced %d events, want 2 (message, usage)", len(events))
	}
}

// TestPrimeAgentRefusesReadonly is the INV-023 case for this adapter. The vendor
// has one model-facing tool and it executes arbitrary Python, so there is no
// readonly posture to enforce and none is claimed. Unlike a help probe, this
// refusal is a constant comparison and has no failure mode that admits the run.
func TestPrimeAgentRefusesReadonly(t *testing.T) {
	if primeAgentCapabilities().Supports(AccessReadonly) {
		t.Error("capability profile admits readonly, which the vendor cannot enforce")
	}
	if primeAgentCapabilities().ReadonlyMechanism != ReadonlyNone {
		t.Errorf("readonly mechanism = %q, want %q",
			primeAgentCapabilities().ReadonlyMechanism, ReadonlyNone)
	}

	runtime := t.TempDir()
	spec := RunSpec{
		Tree:    filepath.Join(runtime, "tree"),
		HomeDir: filepath.Join(runtime, "home"),
		Prompt:  "hi",
		Access:  AccessReadonly,
	}
	adapter := &PrimeAgentAdapter{Binary: filepath.Join(runtime, "no-such-cli")}
	if _, err := adapter.Run(context.Background(), spec); !errors.Is(err, ErrReadonlyUnsupported) {
		t.Errorf("err = %v, want ErrReadonlyUnsupported", err)
	}
	if _, err := primeAgentArgs(spec, "/tmp/d.sock"); !errors.Is(err, ErrReadonlyUnsupported) {
		t.Errorf("args err = %v, want ErrReadonlyUnsupported", err)
	}
}

// TestPrimeAgentRefusesConfigOverrides pins that vendor config assignments are
// refused rather than dropped. The vendor has no per-invocation assignment flag,
// and silently ignoring them leaves a run that reads as configured and is not.
func TestPrimeAgentRefusesConfigOverrides(t *testing.T) {
	runtime := t.TempDir()
	spec := RunSpec{
		Tree:            filepath.Join(runtime, "tree"),
		HomeDir:         filepath.Join(runtime, "home"),
		Prompt:          "hi",
		Access:          AccessWorkspaceWrite,
		ConfigOverrides: []string{"sandbox_mode=\"read-only\""},
	}
	adapter := &PrimeAgentAdapter{Binary: filepath.Join(runtime, "no-such-cli")}
	if _, err := adapter.Run(context.Background(), spec); !errors.Is(err, ErrConfigOverridesUnsupported) {
		t.Errorf("err = %v, want ErrConfigOverridesUnsupported", err)
	}
}

// TestPrimeAgentVersionProbeReadsStderr pins why this adapter cannot use
// probeVersion: the vendor rebinds stdout to stderr for every non-interactive
// mode before printing its version, and HELM always spawns non-interactively.
func TestPrimeAgentVersionProbeReadsStderr(t *testing.T) {
	ctx := context.Background()

	stderrOnly := func(context.Context, string) ([]byte, error) {
		return []byte("\n0.8.1\n"), nil
	}
	if got := primeAgentVersion(ctx, stderrOnly, "prime-agent"); got != "0.8.1" {
		t.Errorf("version = %q, want 0.8.1", got)
	}

	failing := func(context.Context, string) ([]byte, error) {
		return nil, errors.New("exec: no such file")
	}
	if got := primeAgentVersion(ctx, failing, "prime-agent"); got != "" {
		t.Errorf("version = %q, want empty: a CLI that will not answer is not assumed to have a version", got)
	}

	adapter := &PrimeAgentAdapter{Binary: filepath.Join(t.TempDir(), "no-such-cli"), versionCommand: failing}
	if _, err := adapter.Discover(ctx); !errors.Is(err, ErrAdapterNotFound) {
		t.Errorf("discover err = %v, want ErrAdapterNotFound", err)
	}
}

// TestPrimeAgentDaemonSocketIsRunScoped pins the thing the whole adapter turns
// on. Left to itself the vendor resolves its supervisor socket under the system
// temporary directory keyed by uid, so a governed run would attach to whatever
// supervisor the operator's own session left running and inherit its
// environment, including provider credentials HELM scrubbed but never set.
func TestPrimeAgentDaemonSocketIsRunScoped(t *testing.T) {
	first, cleanupFirst, err := primeAgentDaemonSocket()
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer cleanupFirst()

	second, cleanupSecond, err := primeAgentDaemonSocket()
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer cleanupSecond()

	if first == second {
		t.Error("two runs resolved the same socket path; they would share one supervisor")
	}
	if len(first) > maxUnixSocketPath {
		t.Errorf("socket path %q is %d bytes, over the %d-byte sun_path limit",
			first, len(first), maxUnixSocketPath)
	}
	if _, err := os.Stat(filepath.Dir(first)); err != nil {
		t.Errorf("socket directory was not created: %v", err)
	}

	cleanupFirst()
	if _, err := os.Stat(filepath.Dir(first)); !os.IsNotExist(err) {
		t.Errorf("cleanup left the socket directory behind: %v", err)
	}

	runtime := t.TempDir()
	spec := RunSpec{
		Tree:    filepath.Join(runtime, "tree"),
		HomeDir: filepath.Join(runtime, "home"),
		Prompt:  "hi",
		Access:  AccessWorkspaceWrite,
	}
	args, err := primeAgentArgs(spec, second)
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	if !argvHasFlagValue(args, "--daemon-socket", second) {
		t.Errorf("argv %v does not pin --daemon-socket to %q", args, second)
	}
}

// TestPrimeAgentSocketPathFitsRealisticEnvelopes pins the reason the socket does
// not live in the scoped HOME. A worktree envelope carries a run id and an
// attempt id, and the vendor neither shortens nor hashes a socket path it was
// given, so the obvious placement would put ordinary runs over sun_path.
func TestPrimeAgentSocketPathFitsRealisticEnvelopes(t *testing.T) {
	home := filepath.Join(t.TempDir(), "workspaces", "run-01HXQ8Z3", "attempt-02", "home")
	inHome := filepath.Join(home, ".prime", "agent", "daemon.sock")
	if len(inHome) <= maxUnixSocketPath {
		t.Skipf("this host's temp root is short enough (%d bytes) to hide the constraint", len(inHome))
	}

	socket, cleanup, err := primeAgentDaemonSocket()
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer cleanup()
	if len(socket) > maxUnixSocketPath {
		t.Errorf("socket path %q is %d bytes; the adapter must fit where the scoped HOME cannot",
			socket, len(socket))
	}
}

// TestPrimeAgentCleanupPreservesTheTerminalEvent pins that interposing cleanup
// on the event stream adds and drops nothing: exactly one EventCompleted still
// precedes exactly one close.
func TestPrimeAgentCleanupPreservesTheTerminalEvent(t *testing.T) {
	src := make(chan Event, 3)
	src <- Event{Kind: EventStarted}
	src <- Event{Kind: EventMessage, Text: "hi"}
	src <- Event{Kind: EventCompleted, ExitCode: 0}
	close(src)

	cleaned := false
	var got []Event
	for event := range withCleanup(src, func() { cleaned = true }) {
		got = append(got, event)
	}

	if !cleaned {
		t.Error("cleanup did not run after the source closed")
	}
	if len(got) != 3 {
		t.Fatalf("forwarded %d events, want 3", len(got))
	}
	completed := 0
	for _, event := range got {
		if event.Kind == EventCompleted {
			completed++
		}
	}
	if completed != 1 {
		t.Errorf("EventCompleted count = %d, want exactly 1", completed)
	}
	if got[len(got)-1].Kind != EventCompleted {
		t.Errorf("last event = %s, want %s", got[len(got)-1].Kind, EventCompleted)
	}
}

// argvHasFlagValue reports whether argv carries flag immediately followed by
// value.
func argvHasFlagValue(args []string, flag, value string) bool {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}
