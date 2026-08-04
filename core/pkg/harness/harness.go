// Package harness spawns a vendor coding-agent CLI as a child process HELM
// owns, rather than installing hooks into a client the operator launched.
//
// The distinction is parenthood. A hook reports what the vendor client chose to
// disclose and governs only the tool classes that happen to route through it; a
// child process is one HELM chose the argv for, chose the environment for, and
// can kill. Every downstream claim depends on that: an Autonomy Envelope binds
// a run HELM can identify, an EffectPermit is scoped to a principal HELM
// selected, and a receipt written to ProofGraph is only evidence if the run it
// describes could not have reached a credential or a directory HELM did not
// hand it.
//
// This package composes with core/pkg/worktree: the Tree is the child's cwd and
// the scoped HomeDir is its HOME. Three files carry the guarantees —
// env.go fences credentials, process.go owns the process tree, and the adapters
// translate a RunSpec into vendor argv and a vendor stream back into Events.
//
// Prior art: razzant/claudexor (MIT). Reimplemented for HELM.
package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Sentinel errors. Callers match with errors.Is; adapters wrap with %w.
var (
	// ErrAdapterNotFound reports that the vendor CLI could not be resolved.
	ErrAdapterNotFound = errors.New("harness: vendor CLI not found")

	// ErrReadonlyUnsupported reports that the installed vendor CLI cannot
	// enforce AccessReadonly. The run is refused rather than downgraded: a
	// readonly label on an unenforced run is worse than no label.
	ErrReadonlyUnsupported = errors.New("harness: readonly access is not enforceable by this vendor CLI")

	// ErrAccessUnsupported reports that the adapter does not implement the
	// requested access profile.
	ErrAccessUnsupported = errors.New("harness: access profile unsupported by adapter")

	// ErrTreeRequired reports a RunSpec with no execution tree. A run without a
	// tree would inherit the parent's cwd, which is the isolation this package
	// exists to provide.
	ErrTreeRequired = errors.New("harness: run spec requires an execution tree")

	// ErrPromptRequired reports a RunSpec with neither prompt nor instructions.
	ErrPromptRequired = errors.New("harness: run spec requires a prompt")
)

// AccessProfile is the write authority a run is granted over its tree.
type AccessProfile string

const (
	// AccessReadonly permits inspection only. Adapters must refuse the run when
	// the installed CLI cannot enforce this.
	AccessReadonly AccessProfile = "readonly"

	// AccessWorkspaceWrite permits writes inside the tree.
	AccessWorkspaceWrite AccessProfile = "workspace_write"

	// AccessFull removes the vendor's own gating. The tree and scoped HOME
	// remain the only boundary.
	AccessFull AccessProfile = "full"
)

// ReadonlyMechanism names how a vendor CLI actually enforces AccessReadonly.
// The mechanism matters to evidence: an OS sandbox and a prompt-time permission
// check fail differently, and a receipt that records only "readonly" cannot
// distinguish them.
type ReadonlyMechanism string

const (
	// ReadonlyFSSandbox is kernel- or OS-level filesystem confinement.
	ReadonlyFSSandbox ReadonlyMechanism = "fs_sandbox"

	// ReadonlyPermissionDeny is the vendor's in-process permission gate
	// refusing write tools.
	ReadonlyPermissionDeny ReadonlyMechanism = "permission_deny"

	// ReadonlyToolAllowlist is a restricted tool set with no write tool in it.
	ReadonlyToolAllowlist ReadonlyMechanism = "tool_allowlist"

	// ReadonlyNone means the vendor offers no readonly posture at all.
	ReadonlyNone ReadonlyMechanism = "none"
)

// CapabilityProfile is an adapter's declaration of what its vendor CLI can
// actually be held to. It is a claim about the vendor, not a promise that this
// adapter already exercises every capability.
type CapabilityProfile struct {
	// ReadonlyMechanism is how AccessReadonly is enforced, if at all.
	ReadonlyMechanism ReadonlyMechanism

	// MCPInjection reports whether HELM can hand the CLI an MCP server set for
	// the duration of one run.
	MCPInjection bool

	// MCPInjectionRequiresFullAccess reports whether injected MCP servers are
	// only reliably invocable under AccessFull. When true, an injected server
	// combined with a narrower profile is a configuration that looks governed
	// and is not.
	MCPInjectionRequiresFullAccess bool

	// SupportedAccessProfiles is the closed set this adapter will admit.
	SupportedAccessProfiles []AccessProfile
}

// Supports reports whether the profile is in the adapter's admitted set.
func (c CapabilityProfile) Supports(profile AccessProfile) bool {
	for _, p := range c.SupportedAccessProfiles {
		if p == profile {
			return true
		}
	}
	return false
}

// Manifest is what Discover learned about the installed vendor CLI.
type Manifest struct {
	// AdapterID matches Adapter.ID.
	AdapterID string

	// Binary is the resolved absolute path actually spawned.
	Binary string

	// Version is the version string the CLI disclosed. Empty when the CLI did
	// not disclose one; it is never guessed from the adapter's expectations.
	Version string

	// Capabilities is the adapter's declared capability profile.
	Capabilities CapabilityProfile
}

// CredentialRoute is the single provider credential a run is authorized to use.
//
// Exactly one route reaches the child. Everything else is scrubbed by
// ScrubProviderEnv, so a run cannot silently fall back to a second provider the
// operator happened to have configured, and the route recorded on each Event is
// the route that was actually available.
type CredentialRoute struct {
	// ID is the stable route label stamped onto every Event of the run.
	ID string

	// EnvVar is the one environment variable name handed to the child.
	EnvVar string

	// Secret is the credential material. It is never logged by this package.
	Secret string
}

// String returns only the route id, so a CredentialRoute formatted with %v or
// %s cannot leak Secret into a log line or an error string.
func (r CredentialRoute) String() string { return r.ID }

// RunSpec is one governed run of a vendor CLI.
type RunSpec struct {
	// Prompt is the task handed to the agent.
	Prompt string

	// Instructions is standing guidance folded into the prompt. See
	// composePrompt for why it is not a vendor system-prompt flag.
	Instructions string

	// Tree is the isolated git worktree and the child's cwd.
	Tree string

	// HomeDir is the scoped HOME. It must be a sibling of Tree, never a child,
	// or vendor session and credential files land inside the captured diff.
	HomeDir string

	// Access is the write authority granted for this run.
	Access AccessProfile

	// Model is the model HELM requested. It is never used to populate
	// Event.ObservedModel.
	Model string

	// ResumeSessionID continues a prior vendor session. Adapters build a
	// distinct argv for this path.
	ResumeSessionID string

	// ConfigOverrides are vendor config assignments in "key=value" form.
	ConfigOverrides []string

	// Images are file paths attached to the prompt.
	Images []string

	// ExtraEnv is additional child environment. Provider credential and
	// base-URL variables are dropped from it: Credential is the only sanctioned
	// way to hand a provider secret to a run.
	ExtraEnv map[string]string

	// Credential is the one route the child receives.
	Credential CredentialRoute
}

// EventKind is the closed classification of a harness event.
type EventKind string

const (
	// EventStarted is the vendor disclosing that its session is live.
	EventStarted EventKind = "started"

	// EventMessage is assistant text.
	EventMessage EventKind = "message"

	// EventToolCall is the agent invoking a tool.
	EventToolCall EventKind = "tool_call"

	// EventToolResult is a tool returning.
	EventToolResult EventKind = "tool_result"

	// EventUsage is a token accounting frame.
	EventUsage EventKind = "usage"

	// EventError is a failure the vendor reported, or a failure of the harness
	// itself to spawn or supervise the child.
	EventError EventKind = "error"

	// EventCompleted is the terminal event. Exactly one is emitted per run, on
	// every path, and the channel closes after it.
	EventCompleted EventKind = "completed"
)

// Event is one observation from a governed run.
type Event struct {
	// Kind classifies the event.
	Kind EventKind

	// Final marks the vendor's terminal turn.
	Final bool

	// Text is assistant text, or an error description on EventError.
	Text string

	// ToolName and ToolCallID identify an EventToolCall or EventToolResult.
	ToolName   string
	ToolCallID string

	// ToolInput is the tool argument payload exactly as the vendor emitted it.
	ToolInput []byte

	// ObservedModel is the model the vendor stream actually disclosed.
	//
	// It is left empty when the stream never named one. It is never backfilled
	// from RunSpec.Model: a silent fallback to a different model is precisely
	// what route proof exists to catch, and copying the request over the
	// observation would erase the evidence.
	ObservedModel string

	// NativeSessionID is the vendor's own session identifier, needed to resume.
	NativeSessionID string

	// CredentialRoute is the id of the route selected before spawn. It is
	// stamped on every event of the run, including events produced after a
	// vendor-internal retry, so each one stays attributable.
	CredentialRoute string

	// InputTokens and OutputTokens carry EventUsage accounting.
	InputTokens  int
	OutputTokens int

	// ExitCode is the child's exit status on EventCompleted, or the invoked
	// tool's exit status on EventToolResult. It is -1 when the child was
	// signalled or never started.
	ExitCode int

	// DroppedLines counts stdout lines the adapter could not parse, reported on
	// EventCompleted. Unparseable output is surfaced, never silently discarded:
	// a stream HELM could not read is a gap in the run's evidence.
	DroppedLines int

	// Stderr is a bounded tail of the child's stderr, reported on
	// EventCompleted.
	Stderr []string

	// Err carries the harness-level failure on EventError and EventCompleted.
	Err error
}

// Adapter is one vendor coding-agent CLI, spawned and owned by HELM.
type Adapter interface {
	// ID is the stable adapter identifier.
	ID() string

	// Discover resolves the installed CLI and reports what it can be held to.
	Discover(ctx context.Context) (Manifest, error)

	// Run spawns the CLI and streams its events.
	//
	// An error is returned only for a refusal made before the child exists —
	// an unresolvable binary, an unsupported access profile, or a readonly
	// posture the installed CLI cannot enforce. Once the adapter has committed
	// to a run it returns a channel, and every terminating path on that channel
	// ends in exactly one EventCompleted followed by close.
	//
	// The caller must drain the channel until it closes.
	Run(ctx context.Context, spec RunSpec) (<-chan Event, error)
}

// resolveBinary resolves an adapter's executable, preferring an explicit
// override over a PATH lookup of the default name.
func resolveBinary(override, fallback string) (string, error) {
	bin := strings.TrimSpace(override)
	if bin == "" {
		bin = fallback
	}
	if strings.ContainsRune(bin, filepath.Separator) {
		abs, err := filepath.Abs(bin)
		if err != nil {
			return "", fmt.Errorf("%w: %s: %v", ErrAdapterNotFound, bin, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("%w: %s: %v", ErrAdapterNotFound, abs, err)
		}
		return abs, nil
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrAdapterNotFound, bin, err)
	}
	return path, nil
}

// probeVersion asks the CLI for its version. A CLI that will not answer leaves
// Manifest.Version empty rather than receiving an assumed value.
func probeVersion(ctx context.Context, binary string) string {
	cmd := exec.CommandContext(ctx, binary, "--version")
	cmd.Env = CleanEnv()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// validateRunSpec enforces the invariants every adapter shares.
func validateRunSpec(spec RunSpec, caps CapabilityProfile) error {
	if strings.TrimSpace(spec.Tree) == "" {
		return ErrTreeRequired
	}
	if strings.TrimSpace(spec.Prompt) == "" && strings.TrimSpace(spec.Instructions) == "" {
		return ErrPromptRequired
	}
	if !caps.Supports(spec.Access) {
		return fmt.Errorf("%w: %q", ErrAccessUnsupported, spec.Access)
	}
	return nil
}

// composePrompt folds Instructions into the prompt.
//
// Neither vendor exposes an equivalent per-invocation system-prompt flag on its
// non-interactive path, so instructions ride inside the prompt where they mean
// the same thing for both adapters and appear in the argv HELM recorded. A
// vendor-specific flag would let the two adapters disagree about what a run was
// actually told, which is not a difference a receipt could later resolve.
func composePrompt(instructions, prompt string) string {
	instructions = strings.TrimSpace(instructions)
	prompt = strings.TrimSpace(prompt)
	switch {
	case instructions == "":
		return prompt
	case prompt == "":
		return instructions
	default:
		return instructions + "\n\n" + prompt
	}
}
