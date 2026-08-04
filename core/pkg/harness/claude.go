package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// claudeBinary is the default executable name resolved from PATH.
const claudeBinary = "claude"

// claudeAdapterID is the stable adapter identifier.
const claudeAdapterID = "claude-code"

// claudeReadonlyFlags are the flags that turn AccessReadonly from a label into
// an enforced posture: plan mode denies write tools, an empty setting-source set
// stops the operator's own settings from re-granting them, strict MCP config
// admits no server the run did not declare, and disabling slash commands closes
// the path that re-enters the CLI with different permissions.
var claudeReadonlyFlags = []string{
	"--permission-mode",
	"--setting-sources",
	"--strict-mcp-config",
	"--disable-slash-commands",
}

// ClaudeAdapter runs the Claude Code CLI as a HELM-owned child process.
//
// The zero value is usable and resolves the CLI from PATH.
type ClaudeAdapter struct {
	// Binary overrides the executable resolved from PATH.
	Binary string

	// helpCommand runs the readonly capability probe. It exists so the probe
	// can be exercised without the vendor CLI installed.
	helpCommand func(ctx context.Context, binary string) ([]byte, error)

	probeOnce sync.Once
	probeErr  error
}

// ID implements Adapter.
func (a *ClaudeAdapter) ID() string { return claudeAdapterID }

// claudeCapabilities is the adapter's declaration of what the vendor CLI can be
// held to.
func claudeCapabilities() CapabilityProfile {
	return CapabilityProfile{
		// Plan mode is an in-process permission gate, not an OS sandbox: the
		// process retains the ability to write and is asked not to. That is a
		// weaker guarantee than a filesystem sandbox and is recorded as such,
		// because the scoped tree — not this flag — is the real boundary.
		ReadonlyMechanism: ReadonlyPermissionDeny,
		MCPInjection:      true,
		// UNVERIFIED AGAINST A LIVE CLI — inherited empirical posture, re-prove
		// before any claim depends on it.
		//
		// Claude does not sandbox its MCP servers, so an injected server is
		// reachable at workspace_write as well as full. This flag is only about
		// profiles BELOW full; readonly is handled upstream of it by injecting no
		// servers at all (--strict-mcp-config with no --mcp-config), so readonly
		// is not the case this flag decides.
		//
		// Contrast codex, which declares true: its seatbelt cancels the server's
		// call back out to its host below full access.
		MCPInjectionRequiresFullAccess: false,
		SupportedAccessProfiles: []AccessProfile{
			AccessReadonly,
			AccessWorkspaceWrite,
			AccessFull,
		},
	}
}

// Discover implements Adapter.
func (a *ClaudeAdapter) Discover(ctx context.Context) (Manifest, error) {
	binary, err := resolveBinary(a.Binary, claudeBinary)
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{
		AdapterID:    a.ID(),
		Binary:       binary,
		Version:      probeVersion(ctx, binary),
		Capabilities: claudeCapabilities(),
	}, nil
}

// Run implements Adapter.
func (a *ClaudeAdapter) Run(ctx context.Context, spec RunSpec) (<-chan Event, error) {
	if err := validateRunSpec(spec, claudeCapabilities()); err != nil {
		return nil, err
	}
	binary, err := resolveBinary(a.Binary, claudeBinary)
	if err != nil {
		return nil, err
	}
	if spec.Access == AccessReadonly {
		if err := a.probeReadonlySupport(ctx, binary); err != nil {
			return nil, err
		}
	}
	args, err := claudeArgs(spec)
	if err != nil {
		return nil, err
	}
	return runProcess(ctx, processSpec{
		binary:          binary,
		args:            args,
		dir:             spec.Tree,
		env:             ComposeEnv(CleanEnv(), spec),
		credentialRoute: spec.Credential.ID,
		parse:           parseClaudeLine,
	}), nil
}

// probeReadonlySupport verifies that the installed CLI actually accepts the
// flags that constrain a readonly run.
//
// Readonly is a claim HELM makes on a receipt, and an unenforced claim is worse
// than no claim: an operator reading it would conclude the tree could not have
// been written. Argument parsers of this kind accept unknown flags silently in
// some builds and repackagings, so the posture is checked against the installed
// binary's own help output before the run is admitted, and a build that cannot
// enforce it is refused rather than downgraded.
//
// The result is memoized: the binary does not change under a running kernel, and
// a probe per run would put an exec on the hot path of every readonly spawn.
func (a *ClaudeAdapter) probeReadonlySupport(ctx context.Context, binary string) error {
	a.probeOnce.Do(func() {
		out, err := a.help(ctx, binary)
		if err != nil {
			a.probeErr = fmt.Errorf("%w: %s: help probe failed: %v", ErrReadonlyUnsupported, binary, err)
			return
		}
		var missing []string
		for _, flag := range claudeReadonlyFlags {
			if !bytes.Contains(out, []byte(flag)) {
				missing = append(missing, flag)
			}
		}
		if len(missing) > 0 {
			a.probeErr = fmt.Errorf("%w: %s does not accept %s",
				ErrReadonlyUnsupported, binary, strings.Join(missing, ", "))
		}
	})
	return a.probeErr
}

func (a *ClaudeAdapter) help(ctx context.Context, binary string) ([]byte, error) {
	if a.helpCommand != nil {
		return a.helpCommand(ctx, binary)
	}
	cmd := exec.CommandContext(ctx, binary, "--help")
	cmd.Env = CleanEnv()
	// Help output goes to stdout on some builds and stderr on others; both are
	// collected so a probe never fails for the wrong reason.
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if buf.Len() > 0 {
		return buf.Bytes(), nil
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// claudeArgs builds the argv for one run.
func claudeArgs(spec RunSpec) ([]string, error) {
	args := []string{
		"-p", composePrompt(spec.Instructions, spec.Prompt),
		"--output-format", "stream-json",
		"--verbose",
	}

	switch spec.Access {
	case AccessReadonly:
		args = append(args,
			"--permission-mode", "plan",
			// An empty setting-source list, not an omitted flag: omitting it
			// lets the CLI load the operator's user and project settings, which
			// can re-grant exactly the tools plan mode just denied.
			"--setting-sources", "",
			"--strict-mcp-config",
			"--disable-slash-commands",
		)
	case AccessWorkspaceWrite:
		args = append(args, "--permission-mode", "acceptEdits")
	case AccessFull:
		args = append(args, "--permission-mode", "bypassPermissions")
	default:
		return nil, fmt.Errorf("%w: %q", ErrAccessUnsupported, spec.Access)
	}

	if model := strings.TrimSpace(spec.Model); model != "" {
		args = append(args, "--model", model)
	}
	if session := strings.TrimSpace(spec.ResumeSessionID); session != "" {
		args = append(args, "--resume", session)
	}
	return args, nil
}

// claudeFrame is one NDJSON record of the stream-json output format.
type claudeFrame struct {
	Type      string         `json:"type"`
	Subtype   string         `json:"subtype"`
	SessionID string         `json:"session_id"`
	Model     string         `json:"model"`
	Message   *claudeMessage `json:"message"`
	Usage     *claudeUsage   `json:"usage"`
	Result    string         `json:"result"`
	IsError   bool           `json:"is_error"`
}

type claudeMessage struct {
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
	Usage   *claudeUsage    `json:"usage"`
}

type claudeBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
}

type claudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// parseClaudeLine converts one NDJSON line into events. An error marks the line
// unparseable so the supervisor can count it; a well-formed frame of an
// unrecognized type yields no events and is not an error, since a vendor adding
// a frame type is not a gap in the run's evidence.
func parseClaudeLine(line []byte) ([]Event, error) {
	var frame claudeFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		return nil, fmt.Errorf("harness: claude frame: %w", err)
	}

	session := frame.SessionID
	// ObservedModel is read only from what the stream disclosed. RunSpec.Model
	// is deliberately not consulted here.
	model := frame.Model
	if model == "" && frame.Message != nil {
		model = frame.Message.Model
	}

	switch frame.Type {
	case "system":
		if frame.Subtype != "init" {
			return nil, nil
		}
		return []Event{{
			Kind:            EventStarted,
			NativeSessionID: session,
			ObservedModel:   model,
		}}, nil

	case "assistant":
		return claudeAssistantEvents(frame, session, model), nil

	case "user":
		return claudeToolResultEvents(frame, session), nil

	case "result":
		return claudeResultEvents(frame, session, model), nil

	default:
		return nil, nil
	}
}

func claudeAssistantEvents(frame claudeFrame, session, model string) []Event {
	if frame.Message == nil {
		return nil
	}
	var events []Event
	for _, block := range claudeBlocks(frame.Message.Content) {
		switch block.Type {
		case "text":
			if strings.TrimSpace(block.Text) == "" {
				continue
			}
			events = append(events, Event{
				Kind:            EventMessage,
				Text:            block.Text,
				NativeSessionID: session,
				ObservedModel:   model,
			})
		case "tool_use":
			events = append(events, Event{
				Kind:            EventToolCall,
				ToolName:        block.Name,
				ToolCallID:      block.ID,
				ToolInput:       block.Input,
				NativeSessionID: session,
				ObservedModel:   model,
			})
		}
	}
	if usage := frame.Message.Usage; usage != nil {
		events = append(events, Event{
			Kind:            EventUsage,
			InputTokens:     usage.InputTokens,
			OutputTokens:    usage.OutputTokens,
			NativeSessionID: session,
			ObservedModel:   model,
		})
	}
	return events
}

func claudeToolResultEvents(frame claudeFrame, session string) []Event {
	if frame.Message == nil {
		return nil
	}
	var events []Event
	for _, block := range claudeBlocks(frame.Message.Content) {
		if block.Type != "tool_result" {
			continue
		}
		events = append(events, Event{
			Kind:            EventToolResult,
			ToolCallID:      block.ToolUseID,
			NativeSessionID: session,
		})
	}
	return events
}

func claudeResultEvents(frame claudeFrame, session, model string) []Event {
	var events []Event
	if frame.IsError {
		events = append(events, Event{
			Kind:            EventError,
			Text:            frame.Result,
			NativeSessionID: session,
			ObservedModel:   model,
		})
	} else if strings.TrimSpace(frame.Result) != "" {
		events = append(events, Event{
			Kind:            EventMessage,
			Final:           true,
			Text:            frame.Result,
			NativeSessionID: session,
			ObservedModel:   model,
		})
	}
	if frame.Usage != nil {
		events = append(events, Event{
			Kind:            EventUsage,
			InputTokens:     frame.Usage.InputTokens,
			OutputTokens:    frame.Usage.OutputTokens,
			NativeSessionID: session,
			ObservedModel:   model,
		})
	}
	return events
}

// claudeBlocks decodes a message content payload, which is an array of blocks on
// most frames and a bare string on some. A shape this package did not expect
// yields no blocks rather than an error: a frame HELM can read partially is
// still better evidence than a line counted as dropped.
func claudeBlocks(raw json.RawMessage) []claudeBlock {
	if len(raw) == 0 {
		return nil
	}
	var blocks []claudeBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil && text != "" {
		return []claudeBlock{{Type: "text", Text: text}}
	}
	return nil
}
