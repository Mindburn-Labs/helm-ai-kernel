package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// primeAgentBinary is the default executable name resolved from PATH.
const primeAgentBinary = "prime-agent"

// primeAgentAdapterID is the stable adapter identifier.
const primeAgentAdapterID = "prime-agent"

// primeAgentGatewayProvider is the provider name HELM writes into the vendor's
// model catalog. RunSpec.Model must be "<provider>/<id>" for a pinned run.
const primeAgentGatewayProvider = "helm"

// maxUnixSocketPath is the usable sun_path length, taken as the shortest across
// supported hosts: darwin allows 104 bytes including the terminator, linux 108.
// A longer path does not fail loudly — the bind happens inside a detached
// daemon whose stdio is discarded, so the client sees only a connect timeout —
// so the adapter checks it before spawn.
const maxUnixSocketPath = 103

// PrimeAgentAdapter runs the Prime Agent CLI as a HELM-owned child process.
//
// The zero value is usable and resolves the CLI from PATH.
//
// What this adapter governs. HELM chooses the argv, the environment, the cwd
// and the scoped HOME; pins the vendor's supervisor socket inside that HOME so
// no pre-existing daemon serves the run; pins inference at a HELM gateway
// through a model catalog it wrote; and refuses tree-supplied extensions,
// skills, prompt templates and themes. It reads the vendor's JSON event stream
// into Events carrying the session id, the observed model, token accounting,
// and every tool call the host loop reported.
//
// What it does not govern. Prime Agent exposes one model-facing tool, an
// IPython cell, whose input is arbitrary Python executed in a persistent kernel
// subprocess. Every file write, shell command and MCP call happens inside that
// kernel and is never presented to the vendor's own host as a request it could
// deny. HELM intercepts the spawn and the stream. It does not intercept a
// single effect. The tool events recorded here say "the agent ran this Python",
// not which files changed; the compensating evidence is the worktree diff.
//
// There is no permission system to hook, no sandbox mode to select, and no
// readonly posture to enforce, so AccessReadonly is refused rather than
// downgraded. AccessWorkspaceWrite and AccessFull are the same run: the tree
// and the scoped HOME are the only boundary either one gets.
//
// Process ownership is one level shallower here than for codex or claude. In
// every headless mode the agent loop runs in a daemon worker the CLI spawns
// detached, outside the process group process.go created, and shell commands
// started from a kernel cell are placed in their own session again. HELM's
// group contains only the client, so a long-running shell started from inside a
// cell can outlive a killed run. Pinning the daemon socket keeps that daemon
// per-run and started from HELM's own composed environment; it does not close
// the teardown gap.
type PrimeAgentAdapter struct {
	// Binary overrides the executable resolved from PATH.
	Binary string

	// AllowKernelBootstrap admits a run whose scoped HOME has no Python kernel.
	// See primeAgentKernelProvisioned for what that concedes.
	AllowKernelBootstrap bool

	// versionCommand runs the version probe. It exists so the probe can be
	// exercised without the vendor CLI installed.
	versionCommand func(ctx context.Context, binary string) ([]byte, error)
}

// ID implements Adapter.
func (a *PrimeAgentAdapter) ID() string { return primeAgentAdapterID }

// primeAgentCapabilities is the adapter's declaration of what the vendor CLI
// can be held to.
func primeAgentCapabilities() CapabilityProfile {
	return CapabilityProfile{
		// The vendor offers no readonly posture, and this is a property of its
		// design rather than of a build. Its only model-facing tool is an
		// IPython cell; there is no read tool and no write tool to allow or
		// deny, just one tool that is a language runtime. The achievable tool
		// sets are that cell or nothing at all, and an agent with no tools is
		// not an inspection-only run — labelling it readonly would be a
		// different false claim.
		ReadonlyMechanism: ReadonlyNone,
		// There is no per-run MCP flag. The vendor's integrations are Python
		// skills gated on OAuth credentials in the agent directory, and a fresh
		// scoped HOME has none. Declaring true would let preflight admit a
		// delegation setup that silently does nothing.
		MCPInjection:                   false,
		MCPInjectionRequiresFullAccess: false,
		SupportedAccessProfiles: []AccessProfile{
			AccessWorkspaceWrite,
			AccessFull,
		},
	}
}

// Discover implements Adapter.
func (a *PrimeAgentAdapter) Discover(ctx context.Context) (Manifest, error) {
	binary, err := resolveBinary(a.Binary, primeAgentBinary)
	if err != nil {
		return Manifest{}, err
	}
	return Manifest{
		AdapterID:    a.ID(),
		Binary:       binary,
		Version:      primeAgentVersion(ctx, a.versionCommand, binary),
		Capabilities: primeAgentCapabilities(),
	}, nil
}

// Run implements Adapter.
func (a *PrimeAgentAdapter) Run(ctx context.Context, spec RunSpec) (<-chan Event, error) {
	// Checked before validateRunSpec so the caller gets this sentinel rather
	// than the generic ErrAccessUnsupported that would fall out of the
	// capability set. Unlike a help probe, a constant comparison has no failure
	// mode that could admit the run.
	if spec.Access == AccessReadonly {
		return nil, fmt.Errorf(
			"%w: %s has one model-facing tool and it is an arbitrary-code Python kernel; "+
				"no flag, tool set, or extension makes a run inspection-only",
			ErrReadonlyUnsupported, primeAgentAdapterID)
	}
	if len(spec.ConfigOverrides) > 0 {
		return nil, fmt.Errorf("%w: %s has no per-invocation config assignment flag",
			ErrConfigOverridesUnsupported, primeAgentAdapterID)
	}
	if err := validateRunSpec(spec, primeAgentCapabilities()); err != nil {
		return nil, err
	}
	binary, err := resolveBinary(a.Binary, primeAgentBinary)
	if err != nil {
		return nil, err
	}
	if !a.AllowKernelBootstrap {
		if err := primeAgentKernelProvisioned(spec); err != nil {
			return nil, err
		}
	}
	// Written before spawn because the child reads its model catalog at
	// startup. A later refusal leaves the file behind, which is harmless: it
	// lives in the scoped HOME the envelope disposes of.
	if err := writePrimeAgentGateway(spec); err != nil {
		return nil, err
	}
	socket, cleanup, err := primeAgentDaemonSocket()
	if err != nil {
		return nil, err
	}
	args, err := primeAgentArgs(spec, socket)
	if err != nil {
		cleanup()
		return nil, err
	}
	env, err := primeAgentEnv(spec)
	if err != nil {
		cleanup()
		return nil, err
	}

	return withCleanup(runProcess(ctx, processSpec{
		binary:          binary,
		args:            args,
		dir:             spec.Tree,
		env:             env,
		credentialRoute: spec.Credential.ID,
		parse:           parsePrimeAgentLine,
	}), cleanup), nil
}

// primeAgentVersion asks the CLI for its version over both output streams.
//
// probeVersion cannot be used here. The CLI rebinds stdout to stderr for every
// non-interactive mode before it prints its version, and HELM spawns with stdin
// on /dev/null, so the mode is never interactive and the version never reaches
// stdout. probeVersion reads stdout alone and would report an empty version for
// every installed build.
//
// The version flag is safe to run: it is excluded from the CLI's early daemon
// launch, so it starts no supervisor, and it exits before any kernel work.
func primeAgentVersion(ctx context.Context, run func(context.Context, string) ([]byte, error), binary string) string {
	if run == nil {
		run = primeAgentVersionCommand
	}
	out, err := run(ctx, binary)
	if err != nil {
		// A CLI that will not disclose its version leaves Manifest.Version
		// empty rather than receiving an assumed one.
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

func primeAgentVersionCommand(ctx context.Context, binary string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, "--version")
	cmd.Env = CleanEnv()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if buf.Len() > 0 {
		return buf.Bytes(), nil
	}
	return nil, err
}

// primeAgentAgentDir is the vendor's configuration root for one run.
func primeAgentAgentDir(homeDir string) string {
	return filepath.Join(homeDir, ".prime", "agent")
}

// primeAgentKernelProvisioned refuses a run whose scoped HOME has no Python
// kernel and whose caller named no existing one.
//
// A fresh scoped HOME has no kernel environment, so the first cell the agent
// executes would install a Python toolchain and a set of packages over the
// network, from inside the envelope, with none of it in the run's evidence. The
// offline flag does not cover this: the vendor reads it nowhere in its kernel
// bootstrap. Bootstrap once out of band and pass PRIME_AGENT_KERNEL_PYTHON in
// ExtraEnv, or set AllowKernelBootstrap to accept the fetch.
func primeAgentKernelProvisioned(spec RunSpec) error {
	if strings.TrimSpace(spec.ExtraEnv["PRIME_AGENT_KERNEL_PYTHON"]) != "" {
		return nil
	}
	python := filepath.Join(primeAgentAgentDir(spec.HomeDir), "kernel-venv", "bin", "python")
	if _, err := os.Stat(python); err != nil {
		return fmt.Errorf("%w: %s has no kernel at %s and ExtraEnv names no PRIME_AGENT_KERNEL_PYTHON",
			ErrKernelUnprovisioned, primeAgentAdapterID, python)
	}
	return nil
}

// primeAgentDaemonSocket creates a per-run directory holding the vendor's
// supervisor socket, and returns the socket path with the cleanup that removes
// it.
//
// Pinning this socket is the thing the whole adapter turns on. Left to itself
// the CLI resolves its socket under the system temporary directory, keyed by
// uid and not by HOME, so a governed run would attach to whatever supervisor
// the operator's own session left running. That supervisor spawns the agent
// worker with its own environment as the base and the client's merged over the
// top — and ScrubProviderEnv removes a variable by omitting it, while an
// omitted key cannot override a set one. A provider key HELM scrubbed but never
// set would survive into the run. Scoping HOME does not separate the two,
// because the vendor's default socket path does not contain HOME.
//
// The socket does not live in the scoped HOME, which would otherwise be the
// obvious place. A unix socket path must fit in sun_path, and a scoped HOME is
// a worktree envelope path with a run id and an attempt id in it; adding
// "/.prime/agent/daemon.sock" puts realistic runs over the limit, and the
// vendor does not shorten or hash a path it was given. A short per-run
// directory keeps the guarantee that matters — no shared supervisor, and an
// environment composed by HELM — without depending on how deep the envelope
// sits. The directory is created 0700 and randomly named, so it is reachable by
// the same uid that could already read the scoped HOME and no other.
func primeAgentDaemonSocket() (socket string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "helm-prime-agent-")
	if err != nil {
		return "", nil, fmt.Errorf("harness: prime-agent daemon socket directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	// Deliberately terse: every byte here is a byte the temporary directory
	// prefix cannot use.
	socket = filepath.Join(dir, "d.sock")
	if len(socket) > maxUnixSocketPath {
		cleanup()
		return "", nil, fmt.Errorf("%w: %q is %d bytes, over the %d-byte sun_path limit; TMPDIR is too deep for a unix socket",
			ErrHomeDirRequired, socket, len(socket), maxUnixSocketPath)
	}
	return socket, cleanup, nil
}

// withCleanup forwards every event from src and runs done once src closes.
//
// The forwarded channel keeps the Adapter contract: this goroutine adds and
// drops nothing, so exactly one EventCompleted still precedes exactly one
// close. Cleanup is bound to the stream rather than to process.go because the
// supervisor owns the process tree contract, and a per-adapter temporary
// directory is not its concern.
func withCleanup(src <-chan Event, done func()) <-chan Event {
	out := make(chan Event, eventBuffer)
	go func() {
		defer close(out)
		defer done()
		for event := range src {
			out <- event
		}
	}()
	return out
}

// primeAgentArgs builds the argv for one run.
func primeAgentArgs(spec RunSpec, socket string) ([]string, error) {
	switch spec.Access {
	case AccessWorkspaceWrite, AccessFull:
		// The CLI has no access vocabulary. Both profiles produce the same
		// argv; the tree and the scoped HOME are the whole boundary.
	case AccessReadonly:
		return nil, fmt.Errorf("%w: %q", ErrReadonlyUnsupported, spec.Access)
	default:
		return nil, fmt.Errorf("%w: %q", ErrAccessUnsupported, spec.Access)
	}

	agentDir := primeAgentAgentDir(spec.HomeDir)
	args := []string{
		// argv[0] must be a flag. The CLI dispatches its first argument as a
		// subcommand, and shutdown, stop, status and update are all public
		// names, so a prompt must never lead.
		"--mode", "json",
		"--cwd", spec.Tree,
		"--daemon-socket", socket,
		"--session-dir", filepath.Join(agentDir, "sessions"),
		// Suppresses the model-catalog refresh, the update check and the
		// telemetry post. It does not cover the Python kernel bootstrap.
		"--offline",
		// The tree is content under review, and the CLI auto-discovers
		// extensions and skills from its cwd. Both load executable code into
		// the governed run — Python skills are installed into the kernel
		// environment. The tree under review does not get to load code into the
		// run that reviews it. Context files are deliberately still allowed:
		// they are prompt text, and they are already inside the captured diff.
		"--no-extensions",
		"--no-skills",
		"--no-prompt-templates",
		"--no-themes",
	}

	if model := strings.TrimSpace(spec.Model); model != "" {
		// Passed through verbatim. Synthesizing a provider prefix from the
		// credential route would make HELM decide a route the caller did not
		// name, which is the divergence Event.ObservedModel exists to catch.
		args = append(args, "--model", model)
	}
	if session := strings.TrimSpace(spec.ResumeSessionID); session != "" {
		// Only when non-empty: a bare resume flag is the interactive browse
		// selector, which the CLI refuses non-interactively.
		args = append(args, "--resume", session)
	}
	for _, image := range spec.Images {
		if image = strings.TrimSpace(image); image != "" {
			// The prefix is unconditional so an image path beginning with a
			// dash still parses as a file argument rather than a flag.
			args = append(args, "@"+image)
		}
	}

	// Everything after the terminator is positional, so a prompt beginning with
	// a dash is read as text. Exactly one message: the CLI consumes the first
	// as the prompt and sends every remaining one as an additional turn.
	return append(args, "--", composePrompt(spec.Instructions, spec.Prompt)), nil
}

// primeAgentEnv composes the child environment, then applies HELM's own
// overrides after the caller's ExtraEnv so a caller cannot shadow them.
//
// None of these names is provider-shaped, so none is removed by the scrub, and
// none carries an endpoint: the gateway reaches the child as configuration, not
// as an environment variable.
func primeAgentEnv(spec RunSpec) ([]string, error) {
	env, err := ComposeEnv(CleanEnv(), spec)
	if err != nil {
		return nil, err
	}
	agentDir := primeAgentAgentDir(spec.HomeDir)
	for _, kv := range [][2]string{
		// The CLI otherwise resolves its agent directory through the home
		// lookup, which falls back to the passwd entry when HOME is unset.
		// Pinning it explicitly means the vendor's config, credential cache,
		// kernel environment and HELM's model catalog cannot resolve to the
		// operator's real agent directory under any fallback.
		{"PRIME_AGENT_CODING_AGENT_DIR", agentDir},
		{"PRIME_AGENT_SESSION_DIR", filepath.Join(agentDir, "sessions")},
		// Telemetry ships on and posts to a third party. All four independent
		// kills are set, because a governed run must not depend on one flag's
		// spelling surviving a vendor refactor.
		{"PI_OFFLINE", "1"},
		{"PI_SKIP_VERSION_CHECK", "1"},
		{"DO_NOT_TRACK", "1"},
		{"PRIME_AGENT_TELEMETRY", "0"},
	} {
		env = setEnv(env, kv[0], kv[1])
	}
	return env, nil
}

// primeAgentCatalog is the vendor's models.json, written by HELM.
type primeAgentCatalog struct {
	Providers map[string]primeAgentProvider `json:"providers"`
}

type primeAgentProvider struct {
	BaseURL    string                   `json:"baseUrl"`
	API        string                   `json:"api"`
	APIKey     string                   `json:"apiKey"`
	AuthHeader bool                     `json:"authHeader"`
	Headers    map[string]string        `json:"headers,omitempty"`
	Models     []primeAgentCatalogEntry `json:"models"`
}

type primeAgentCatalogEntry struct {
	ID string `json:"id"`
}

// writePrimeAgentGateway writes the model catalog that pins the run's inference
// at RunSpec.ModelGateway.
//
// The endpoint travels as a file inside the scoped HOME rather than as an
// environment variable on purpose. env.go treats a base-URL redirect as
// credential-class and scrubs it, including out of ExtraEnv, and that fence is
// not widened here: nothing in this path sets a provider-shaped variable. The
// catalog names the credential by environment-variable name, and that name is
// the one route ComposeEnv already sanctions.
//
// The scoped HOME is a sibling of the tree, so the file is outside the captured
// diff.
func writePrimeAgentGateway(spec RunSpec) error {
	gateway := spec.ModelGateway
	if !gateway.pinned() {
		// Unpinned: the child resolves providers itself, and the run proves
		// nothing about where its inference went.
		return nil
	}

	credential := strings.TrimSpace(spec.Credential.EnvVar)
	if credential == "" {
		return fmt.Errorf("%w: a pinned gateway needs Credential.EnvVar to name the variable the child reads",
			ErrModelGatewayIncomplete)
	}

	models := primeAgentGatewayModels(gateway, spec.Model)
	if len(models) == 0 {
		return fmt.Errorf("%w: neither ModelGateway.Models nor RunSpec.Model names a model to serve",
			ErrModelGatewayIncomplete)
	}

	entries := make([]primeAgentCatalogEntry, 0, len(models))
	for _, id := range models {
		entries = append(entries, primeAgentCatalogEntry{ID: id})
	}

	payload, err := json.MarshalIndent(primeAgentCatalog{
		Providers: map[string]primeAgentProvider{
			primeAgentGatewayProvider: {
				BaseURL: strings.TrimSpace(gateway.BaseURL),
				API:     "openai-completions",
				// Resolved by the vendor as an environment-variable name.
				APIKey:     credential,
				AuthHeader: true,
				Headers:    gateway.Headers,
				Models:     entries,
			},
		},
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("harness: prime-agent model catalog: %w", err)
	}

	agentDir := primeAgentAgentDir(spec.HomeDir)
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		return fmt.Errorf("harness: prime-agent agent directory: %w", err)
	}
	path := filepath.Join(agentDir, "models.json")
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("harness: prime-agent model catalog: %w", err)
	}
	return nil
}

// primeAgentGatewayModels resolves the model ids the catalog will serve,
// accepting RunSpec.Model in its "<provider>/<id>" selector form.
func primeAgentGatewayModels(gateway ModelGateway, requested string) []string {
	var models []string
	for _, id := range gateway.Models {
		if id = strings.TrimSpace(id); id != "" {
			models = append(models, id)
		}
	}
	if len(models) > 0 {
		return models
	}
	if id := primeAgentModelID(requested); id != "" {
		return []string{id}
	}
	return nil
}

// primeAgentModelID strips the provider prefix and the trailing thinking level
// from a model selector, leaving the id the catalog must contain.
func primeAgentModelID(selector string) string {
	id := strings.TrimSpace(selector)
	if id == "" {
		return ""
	}
	if _, rest, ok := strings.Cut(id, "/"); ok {
		id = rest
	}
	// A trailing ":<level>" is a reasoning-effort suffix, not part of the id.
	if base, _, ok := strings.Cut(id, ":"); ok {
		id = base
	}
	return strings.TrimSpace(id)
}

// primeAgentFrame is one JSON line of the vendor's json output mode. The first
// line is a session header; every later line is one agent session event.
type primeAgentFrame struct {
	Type string `json:"type"`

	// session header
	ID string `json:"id"`

	// message_start / message_update / message_end / turn_end
	Message *primeAgentMessage `json:"message"`

	// agent_end
	Messages []primeAgentMessage `json:"messages"`

	// tool_execution_start / _update / _end
	ToolCallID string          `json:"toolCallId"`
	ToolName   string          `json:"toolName"`
	Args       json.RawMessage `json:"args"`
	IsError    bool            `json:"isError"`
}

type primeAgentMessage struct {
	Role          string           `json:"role"`
	Content       json.RawMessage  `json:"content"`
	Model         string           `json:"model"`
	ResponseModel string           `json:"responseModel"`
	Usage         *primeAgentUsage `json:"usage"`
	StopReason    string           `json:"stopReason"`
	ErrorMessage  string           `json:"errorMessage"`
}

type primeAgentUsage struct {
	Input  int `json:"input"`
	Output int `json:"output"`
}

type primeAgentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// parsePrimeAgentLine converts one JSON line into events. An error marks the
// line unparseable so the supervisor can count it; a well-formed frame of an
// unrecognized type yields no events and is not an error.
//
// Three frame types carrying a message are deliberately dropped. message_start,
// message_update and turn_end all repeat the same assistant message that
// message_end reports, so mapping them would emit the same text and the same
// usage two or three times. message_end is the one frame per assistant message
// that is both final and complete.
func parsePrimeAgentLine(line []byte) ([]Event, error) {
	var frame primeAgentFrame
	if err := json.Unmarshal(line, &frame); err != nil {
		return nil, fmt.Errorf("harness: prime-agent frame: %w", err)
	}

	switch frame.Type {
	case "session":
		// The header names no model, so ObservedModel stays empty here and
		// first appears on the first assistant message. NativeSessionID rides
		// only on this event: the vendor does not repeat it per frame, and
		// remembering it would make this parser stateful.
		return []Event{{Kind: EventStarted, NativeSessionID: frame.ID}}, nil

	case "message_end":
		return primeAgentMessageEvents(frame.Message), nil

	case "tool_execution_start":
		return []Event{{
			Kind:       EventToolCall,
			ToolName:   frame.ToolName,
			ToolCallID: frame.ToolCallID,
			// Recorded verbatim. In practice this is nearly always the vendor's
			// one built-in tool and a Python source string: the evidence says
			// the agent ran this code, not which files it changed.
			ToolInput: frame.Args,
		}}, nil

	case "tool_execution_end":
		event := Event{
			Kind:       EventToolResult,
			ToolName:   frame.ToolName,
			ToolCallID: frame.ToolCallID,
		}
		if frame.IsError {
			// A convention, not a process status: the vendor reports a boolean
			// for a tool that threw, and there is no exit code behind it.
			event.ExitCode = 1
		}
		return []Event{event}, nil

	case "agent_end":
		// Final marks the vendor's terminal turn. Under the vendor's autonomous
		// mode each host-injected continuation ends its own agent turn, so more
		// than one may appear; Final is advisory, and EventCompleted from
		// process.go remains the single terminal event per run. This adapter
		// never enables that mode.
		for i := len(frame.Messages) - 1; i >= 0; i-- {
			message := frame.Messages[i]
			if message.Role != "assistant" {
				continue
			}
			text := primeAgentText(message.Content)
			if strings.TrimSpace(text) == "" {
				continue
			}
			return []Event{{
				Kind:          EventMessage,
				Final:         true,
				Text:          text,
				ObservedModel: primeAgentModel(message),
			}}, nil
		}
		return nil, nil

	default:
		return nil, nil
	}
}

func primeAgentMessageEvents(message *primeAgentMessage) []Event {
	if message == nil || message.Role != "assistant" {
		// Tool-result and user messages are already covered by the
		// tool_execution frames.
		return nil
	}
	model := primeAgentModel(*message)

	switch message.StopReason {
	case "error", "aborted":
		text := message.ErrorMessage
		if strings.TrimSpace(text) == "" {
			text = message.StopReason
		}
		return []Event{{Kind: EventError, Text: text, ObservedModel: model}}
	}

	var events []Event
	for _, block := range primeAgentBlocks(message.Content) {
		if block.Type != "text" || strings.TrimSpace(block.Text) == "" {
			continue
		}
		events = append(events, Event{
			Kind:          EventMessage,
			Text:          block.Text,
			ObservedModel: model,
		})
	}
	if usage := message.Usage; usage != nil {
		events = append(events, Event{
			Kind:          EventUsage,
			InputTokens:   usage.Input,
			OutputTokens:  usage.Output,
			ObservedModel: model,
		})
	}
	return events
}

// primeAgentModel reads the model the stream disclosed, preferring the model
// the provider actually answered with over the one that was requested.
// RunSpec.Model is deliberately not consulted.
func primeAgentModel(message primeAgentMessage) string {
	if model := strings.TrimSpace(message.ResponseModel); model != "" {
		return model
	}
	return message.Model
}

func primeAgentText(raw json.RawMessage) string {
	var parts []string
	for _, block := range primeAgentBlocks(raw) {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			parts = append(parts, block.Text)
		}
	}
	return strings.Join(parts, "")
}

// primeAgentBlocks decodes a message content payload. A shape this package did
// not expect yields no blocks rather than an error: a frame HELM can read
// partially is still better evidence than a line counted as dropped.
func primeAgentBlocks(raw json.RawMessage) []primeAgentBlock {
	if len(raw) == 0 {
		return nil
	}
	var blocks []primeAgentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil && text != "" {
		return []primeAgentBlock{{Type: "text", Text: text}}
	}
	return nil
}
