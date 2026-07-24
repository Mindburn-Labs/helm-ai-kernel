package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// codexBinary is the default executable name resolved from PATH.
const codexBinary = "codex"

// codexAdapterID is the stable adapter identifier.
const codexAdapterID = "codex-cli"

// CodexAdapter runs the Codex CLI as a HELM-owned child process.
//
// The zero value is usable and resolves the CLI from PATH.
type CodexAdapter struct {
	// Binary overrides the executable resolved from PATH.
	Binary string
}

// ID implements Adapter.
func (a *CodexAdapter) ID() string { return codexAdapterID }

// codexCapabilities is the adapter's declaration of what the vendor CLI can be
// held to.
func codexCapabilities() CapabilityProfile {
	return CapabilityProfile{
		// Codex confines the run with an OS-level sandbox rather than an
		// in-process permission check, so a readonly run is constrained even if
		// the agent decides otherwise.
		ReadonlyMechanism: ReadonlyFSSandbox,
		MCPInjection:      true,
		// UNVERIFIED AGAINST A LIVE CLI — inherited empirical posture, re-prove
		// before any claim depends on it.
		//
		// The seatbelt restricts IPC and network reach, not just the filesystem.
		// Under `workspace-write` in headless exec it cancels an injected MCP
		// server's connection back out to its host, so the server registers and
		// then silently answers nothing. Only full access lets that call through.
		//
		// Declaring false here would be the dangerous direction: preflight would
		// admit a delegation setup at workspace_write that looks governed and
		// silently does nothing.
		MCPInjectionRequiresFullAccess: true,
		SupportedAccessProfiles: []AccessProfile{
			AccessReadonly,
			AccessWorkspaceWrite,
			AccessFull,
		},
	}
}

// Discover implements Adapter.
func (a *CodexAdapter) Discover(ctx context.Context) (Manifest, error) {
	binary, err := resolveBinary(a.Binary, codexBinary)
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{
		AdapterID:    a.ID(),
		Binary:       binary,
		Version:      probeVersion(ctx, binary),
		Capabilities: codexCapabilities(),
	}, nil
}

// Run implements Adapter.
func (a *CodexAdapter) Run(ctx context.Context, spec RunSpec) (<-chan Event, error) {
	if err := validateRunSpec(spec, codexCapabilities()); err != nil {
		return nil, err
	}
	binary, err := resolveBinary(a.Binary, codexBinary)
	if err != nil {
		return nil, err
	}

	var args []string
	if strings.TrimSpace(spec.ResumeSessionID) != "" {
		args, err = codexResumeArgs(spec)
	} else {
		args, err = codexExecArgs(spec)
	}
	if err != nil {
		return nil, err
	}

	return runProcess(ctx, processSpec{
		binary:          binary,
		args:            args,
		dir:             spec.Tree,
		env:             ComposeEnv(CleanEnv(), spec),
		credentialRoute: spec.Credential.ID,
		parse:           parseCodexLine,
	}), nil
}

// codexSandboxMode maps an access profile onto the CLI's sandbox vocabulary.
func codexSandboxMode(access AccessProfile) (string, error) {
	switch access {
	case AccessReadonly:
		return "read-only", nil
	case AccessWorkspaceWrite:
		return "workspace-write", nil
	case AccessFull:
		return "danger-full-access", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrAccessUnsupported, access)
	}
}

// codexExecArgs builds the argv for a fresh run.
func codexExecArgs(spec RunSpec) ([]string, error) {
	sandbox, err := codexSandboxMode(spec.Access)
	if err != nil {
		return nil, err
	}

	args := []string{
		"exec",
		"--json",
		"--sandbox", sandbox,
		// The tree is a detached git worktree, which the CLI's repo check does
		// not always recognize as a repository. Without this it refuses to start
		// in exactly the isolated tree HELM created for it.
		"--skip-git-repo-check",
	}
	if model := strings.TrimSpace(spec.Model); model != "" {
		args = append(args, "-m", model)
	}
	args = appendConfigsThenImages(args, spec)
	// The prompt goes after "--" so a prompt beginning with a dash is read as
	// text and not as a flag.
	return append(args, "--", composePrompt(spec.Instructions, spec.Prompt)), nil
}

// codexResumeArgs builds the argv for continuing a prior session.
//
// This is a separate builder rather than a branch inside codexExecArgs because
// the resume subcommand does not accept --sandbox. Passing it there is not a
// no-op that degrades gracefully: the CLI rejects the unknown flag and the run
// never starts, or on builds that tolerate it the sandbox silently reverts to
// the default. The mode therefore rides as a config override, which resume does
// accept.
func codexResumeArgs(spec RunSpec) ([]string, error) {
	sandbox, err := codexSandboxMode(spec.Access)
	if err != nil {
		return nil, err
	}

	args := []string{
		"exec", "resume", strings.TrimSpace(spec.ResumeSessionID),
		"--json",
		"--skip-git-repo-check",
	}
	if model := strings.TrimSpace(spec.Model); model != "" {
		args = append(args, "-m", model)
	}
	args = appendConfigsThenImages(args, spec, codexSandboxOverride(sandbox))
	return append(args, "--", composePrompt(spec.Instructions, spec.Prompt)), nil
}

// codexSandboxOverride renders the sandbox mode as a config assignment.
//
// The value keeps its literal double quotes because -c parses values as TOML,
// where a bare word is not a string. Dropping them turns the override into a
// parse the CLI discards, which reverts the run to the default sandbox — the
// exact silent widening this override exists to prevent.
func codexSandboxOverride(mode string) string {
	return fmt.Sprintf("sandbox_mode=%q", mode)
}

// appendConfigsThenImages appends every -c override before any -i image.
//
// The ordering is load-bearing. -i is variadic: it keeps consuming following
// arguments as image paths, so a -c that lands after it is swallowed as an
// image filename rather than applied as configuration. The override is then
// silently absent from the run — and since the sandbox mode travels as a -c on
// the resume path, the flag most likely to be lost that way is the one that
// bounds what the run can touch.
func appendConfigsThenImages(args []string, spec RunSpec, trailing ...string) []string {
	for _, override := range spec.ConfigOverrides {
		if override = strings.TrimSpace(override); override != "" {
			args = append(args, "-c", override)
		}
	}
	// HELM's own overrides are emitted after the caller's so that a caller
	// cannot shadow them: the CLI resolves repeated keys last-wins.
	for _, override := range trailing {
		args = append(args, "-c", override)
	}
	for _, image := range spec.Images {
		if image = strings.TrimSpace(image); image != "" {
			args = append(args, "-i", image)
		}
	}
	return args
}

// codexFrame is one JSONL record of the --json output format.
type codexFrame struct {
	ID  string          `json:"id"`
	Msg json.RawMessage `json:"msg"`
}

type codexMessage struct {
	Type string `json:"type"`

	// session_configured
	SessionID string `json:"session_id"`
	Model     string `json:"model"`

	// agent_message, error, stream_error
	Message string `json:"message"`

	// exec_command_begin / exec_command_end
	CallID   string   `json:"call_id"`
	Command  []string `json:"command"`
	ExitCode *int     `json:"exit_code"`

	// mcp_tool_call_begin / end
	Tool string `json:"tool"`

	// token_count
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`

	// task_complete
	LastAgentMessage string `json:"last_agent_message"`
}

// parseCodexLine converts one JSONL line into events. An error marks the line
// unparseable; a well-formed frame of an unrecognized type yields no events and
// is not an error.
func parseCodexLine(line []byte) ([]Event, error) {
	var frame codexFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		return nil, fmt.Errorf("harness: codex frame: %w", err)
	}
	if len(frame.Msg) == 0 {
		return nil, nil
	}
	var msg codexMessage
	if err := json.Unmarshal(frame.Msg, &msg); err != nil {
		return nil, fmt.Errorf("harness: codex message: %w", err)
	}

	switch msg.Type {
	case "session_configured":
		// ObservedModel comes only from what the stream disclosed. A run whose
		// stream never named a model keeps an empty ObservedModel, because the
		// requested model is a request and not an observation.
		return []Event{{
			Kind:            EventStarted,
			NativeSessionID: msg.SessionID,
			ObservedModel:   msg.Model,
		}}, nil

	case "agent_message":
		if strings.TrimSpace(msg.Message) == "" {
			return nil, nil
		}
		return []Event{{Kind: EventMessage, Text: msg.Message}}, nil

	case "exec_command_begin":
		return []Event{{
			Kind:       EventToolCall,
			ToolName:   "exec",
			ToolCallID: msg.CallID,
			Text:       strings.Join(msg.Command, " "),
		}}, nil

	case "exec_command_end":
		event := Event{Kind: EventToolResult, ToolName: "exec", ToolCallID: msg.CallID}
		if msg.ExitCode != nil {
			event.ExitCode = *msg.ExitCode
		}
		return []Event{event}, nil

	case "mcp_tool_call_begin":
		return []Event{{Kind: EventToolCall, ToolName: msg.Tool, ToolCallID: msg.CallID}}, nil

	case "mcp_tool_call_end":
		return []Event{{Kind: EventToolResult, ToolName: msg.Tool, ToolCallID: msg.CallID}}, nil

	case "token_count":
		return []Event{{
			Kind:         EventUsage,
			InputTokens:  msg.InputTokens,
			OutputTokens: msg.OutputTokens,
		}}, nil

	case "error", "stream_error":
		return []Event{{Kind: EventError, Text: msg.Message}}, nil

	case "task_complete":
		return []Event{{Kind: EventMessage, Final: true, Text: msg.LastAgentMessage}}, nil

	default:
		return nil, nil
	}
}
