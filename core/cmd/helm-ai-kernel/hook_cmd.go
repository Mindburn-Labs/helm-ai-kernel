// quantum_posture: hook decision receipts are signed with the classical
// Ed25519 workstation seed resolved via workstation_signing.go; no
// post-quantum or hybrid primitives are used in this file.

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/actioninbox"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

var (
	hookStdin            = io.Reader(os.Stdin)
	hookNow              = func() time.Time { return time.Now().UTC() }
	errHookPolicyProfile = errors.New("hook policy profile unavailable")
)

type hookOptions struct {
	Client              string
	DataDir             string
	PolicyProfile       string
	PolicyProfileSHA256 string
	SigningSeedFile     string
	JSON                bool
}

type preToolPayload struct {
	ToolName       string         `json:"tool_name"`
	ToolNameCamel  string         `json:"toolName"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolInputCamel map[string]any `json:"toolInput"`
	Args           map[string]any `json:"args"`
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
}

type hookDecisionOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type hookClassification struct {
	ShouldDecide            bool
	Class                   string
	Target                  string
	Action                  string
	ToolID                  string
	Reason                  string
	Metadata                map[string]string
	RequiresShellPermission bool
}

func init() {
	Register(Subcommand{
		Name:  "hook",
		Usage: "Handle local agent client hooks",
		RunFn: runHookCmd,
	})
}

func runHookCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHookUsage(stderr)
		return 2
	}
	switch args[0] {
	case "pre-tool":
		return runHookPreToolCmd(args[1:], hookStdin, stdout, stderr)
	case "help", "--help", "-h":
		printHookUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "hook: unknown subcommand %q\n", args[0])
		printHookUsage(stderr)
		return 2
	}
}

func runHookPreToolCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts := hookOptions{DataDir: defaultSetupDataDir()}
	fs := flag.NewFlagSet("hook pre-tool", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.Client, "client", "", "Client name: claude-code, codex, hermes, or deepseek")
	fs.StringVar(&opts.DataDir, "data-dir", opts.DataDir, "Directory for HELM local state")
	fs.StringVar(&opts.PolicyProfile, "policy-profile", "", "Policy profile JSON path")
	fs.StringVar(&opts.PolicyProfileSHA256, "policy-profile-sha256", "", "Approved SHA-256 digest for the policy profile")
	fs.StringVar(&opts.SigningSeedFile, "signing-seed-file", "", "Path to 0600 file containing a 32-byte Ed25519 seed as hex")
	fs.BoolVar(&opts.JSON, "json", false, "Reserved for structured diagnostics")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client, err := normalizeSetupTarget(opts.Client)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	opts.Client = client
	if strings.TrimSpace(opts.DataDir) != "" {
		if abs, err := filepath.Abs(opts.DataDir); err == nil {
			opts.DataDir = abs
		}
	}
	payload, err := decodePreToolPayload(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
		return 2
	}
	classifications := classifyPreToolPayloads(payload)
	if len(classifications) == 0 {
		// An unclassified call is successful progress, so it breaks any
		// consecutive-denial run without changing the fail-closed policy path.
		recordHookDoomLoopOutcome(opts, payload, hookClassification{}, false, stderr)
		return 0
	}
	for _, decision := range classifications {
		receipt, err := buildHookDecisionReceipt(opts, payload, decision)
		if err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: %v\n", err)
			tripped, run := recordHookDoomLoopOutcome(opts, payload, decision, true, stderr)
			if errors.Is(err, errHookPolicyProfile) {
				return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run, failClosedSteeringText(
					"HELM denied operation: policy profile is unavailable",
					actioninbox.ReasonPolicyProfileUnavailable,
					"HELM cannot load or verify the selected workstation policy profile, so the operation fails closed.",
					"Do not retry until the policy profile and its approved digest are restored.",
					"Escalate to the human operator; policy profile repair is an operator action.",
				)))
			}
			return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run, failClosedSteeringText(
				"HELM denied operation: local receipt signer is unavailable",
				actioninbox.ReasonSignerUnavailable,
				"HELM cannot sign a local decision receipt, so the operation fails closed.",
				"Do not retry until the signer is fixed. Run helm-ai-kernel doctor or helm-ai-kernel setup, or pass --signing-seed-file.",
				"Escalate to the human operator; signer repair is an operator action, not an agent action.",
			)))
		}
		receiptPath, err := writeDecisionReceipt("", filepath.Join(opts.DataDir, "receipts", "hooks"), receipt)
		if err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: write receipt: %v\n", err)
			tripped, run := recordHookDoomLoopOutcome(opts, payload, decision, true, stderr)
			return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run, failClosedSteeringText(
				"HELM denied operation: receipt persistence is unavailable",
				actioninbox.ReasonReceiptPersistence,
				"HELM cannot persist the signed decision receipt, so the operation fails closed.",
				"Do not retry until receipt storage is fixed; check the data directory is writable.",
				"Escalate to the human operator; storage repair is an operator action, not an agent action.",
			)))
		}
		if receipt.Verdict == contracts.WorkstationVerdictDeny {
			// The receipt has already been persisted. The breaker only enriches
			// the denial text after repeated identical failures; it never
			// decides the effect or bypasses receipt generation.
			tripped, run := recordHookDoomLoopOutcome(opts, payload, decision, true, stderr)
			feedback := actioninbox.DenyFeedbackFor(receipt.ReasonCode, receipt.CreatedAt)
			return emitHookDenyOrFail(stdout, stderr, opts.Client, withDoomLoopSteering(tripped, decision, run,
				fmt.Sprintf("HELM denied %s: %s (receipt: %s) %s",
					decision.Reason, receipt.ReasonCode, receiptPath, actioninbox.RenderSteeringText(feedback))))
		}
	}
	// A fully allowed multi-effect call is successful progress only after
	// every current-main classification has produced a signed receipt.
	recordHookDoomLoopOutcome(opts, payload, hookClassification{}, false, stderr)
	return 0
}

// withDoomLoopSteering appends circuit-breaker escalation guidance to an
// already-denied outcome when the breaker has latched for this call signature.
// The base denial (policy or fail-closed) is always preserved; the breaker
// only adds steering, never authority.
func withDoomLoopSteering(tripped bool, classification hookClassification, runLength int, base string) string {
	if !tripped {
		return base
	}
	return base + " " + doomLoopSteeringText(classification, runLength)
}

// failClosedSteeringText keeps the operator-facing prefix intact and appends
// model-actionable steering guidance.
func failClosedSteeringText(prefix, code, explanation, remediation, escalation string) string {
	return prefix + " " + actioninbox.RenderSteeringText(actioninbox.DenialRecord{
		SchemaVersion: actioninbox.DenyFeedbackSchemaVersion,
		ReasonCode:    code,
		Explanation:   explanation,
		Remediation:   remediation,
		Escalation:    escalation,
		DecidedAt:     hookNow(),
	})
}

// doomLoopSteeringText renders circuit-breaker escalation guidance. The
// breaker only enriches a denial that already exists; it never authorizes and
// never denies on its own.
func doomLoopSteeringText(classification hookClassification, runLength int) string {
	d := actioninbox.DenialRecord{
		SchemaVersion: actioninbox.DenyFeedbackSchemaVersion,
		ReasonCode:    actioninbox.ReasonDoomLoopDetected,
		Explanation: fmt.Sprintf("The identical call (%s via %s) has now been denied %d consecutive times in this session; the doom-loop circuit breaker is forcing escalation.",
			classification.Action, classification.ToolID, runLength),
		Remediation: "Stop retrying the identical call. Change the approach, gather the missing information, or abandon the attempt.",
		Escalation:  "Ask the human operator to review the repeated denials and either take over or adjust policy.",
		DecidedAt:   hookNow(),
	}
	return actioninbox.RenderSteeringText(d)
}

func emitHookDenyOrFail(stdout, stderr io.Writer, client, reason string) int {
	if client == "hermes" {
		if err := writeHermesHookBlock(stdout, reason); err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
			return hermesBlockExitCode
		}
		// Hermes honors {"action":"block"} and treats exit 2 as a block even
		// when stdout is empty. Claude hookSpecificOutput + exit 0 is not a
		// Hermes block — that combination is fail-open.
		return hermesBlockExitCode
	}
	if client == "deepseek" {
		if err := writeDeepSeekHookDeny(stdout, reason); err != nil {
			fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
			return deepseekBlockExitCode
		}
		// DeepSeek stays an adapter: native {kind:"deny"} and DSH
		// hook-protocol exit 2 are the stock-bridge deny shape. Claude
		// hookSpecificOutput + exit 0 is not that adapter shape. This is
		// not a HELM-native agent runtime.
		return deepseekBlockExitCode
	}
	if err := writeHookDeny(stdout, reason); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: emit denial: %v\n", err)
		return 2
	}
	return 0
}

func writeHookDeny(stdout io.Writer, reason string) error {
	out := hookDecisionOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
	return json.NewEncoder(stdout).Encode(out)
}

func writeHermesHookBlock(stdout io.Writer, reason string) error {
	return json.NewEncoder(stdout).Encode(hermesHookBlock{
		Action:  "block",
		Message: reason,
	})
}

func writeDeepSeekHookDeny(stdout io.Writer, reason string) error {
	return json.NewEncoder(stdout).Encode(deepseekHookDeny{
		Kind:   "deny",
		Reason: reason,
	})
}

const hermesBlockExitCode = 2
const deepseekBlockExitCode = 2

type hermesHookBlock struct {
	Action  string `json:"action"`
	Message string `json:"message"`
}

type deepseekHookDeny struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// hermesPreToolCallBlocks mirrors the NousResearch/hermes-agent shell hook
// interpreter (agent/shell_hooks.py): exit 2 blocks; stdout {"action":"block"}
// or Claude-style {"decision":"block"} blocks. Claude Code hookSpecificOutput
// JSON with exit 0 is valid JSON that is not a block directive, so Hermes
// proceeds. This function exists so tests can prove that fail-open shape.
func hermesPreToolCallBlocks(stdout string, exitCode int) bool {
	if exitCode == hermesBlockExitCode {
		return true
	}
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return false
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		return false
	}
	if action, _ := data["action"].(string); action == "block" {
		return true
	}
	if decision, _ := data["decision"].(string); decision == "block" {
		return true
	}
	return false
}

// deepseekPreToolBlocks mirrors DeepSeek Harness adapter visibility for a
// shell-hook hop: native {"kind":"deny"} is a PreToolDecision.deny, and DSH
// hook-protocol exit 2 is a block. Claude Code hookSpecificOutput JSON with
// exit 0 is valid JSON that is not that adapter shape, so DeepSeek proceeds.
// This function exists so tests can prove that fail-open shape.
func deepseekPreToolBlocks(stdout string, exitCode int) bool {
	if exitCode == deepseekBlockExitCode {
		return true
	}
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return false
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		return false
	}
	if kind, _ := data["kind"].(string); kind == "deny" {
		return true
	}
	return false
}

func printHookUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: helm-ai-kernel hook pre-tool --client <claude-code|codex|hermes|deepseek> [--data-dir DIR] [--policy-profile PATH --policy-profile-sha256 SHA256] [--signing-seed-file PATH]")
}

// hookDoomLoopFile is the on-disk circuit-breaker state for the pre-tool
// hook. The hook process is stateless between invocations, so the identical-
// denial run is persisted per session under the HELM data dir. The state is
// advisory evidence for the breaker only; losing it never weakens the base
// policy decision path, which remains fail-closed on its own.
type hookDoomLoopFile struct {
	Sessions map[string]*hookDoomLoopSession `json:"sessions"`
}

// hookDoomLoopSession tracks one session's consecutive-denial run. The trip
// latch is keyed per call signature (TrippedSignatures), never per session:
// a changed approach (different signature) is always evaluated fresh, while
// retrying an already-tripped identical call keeps the escalation steering.
type hookDoomLoopSession struct {
	LastSignature     string          `json:"last_signature"`
	RunLength         int             `json:"run_length"`
	TrippedSignatures map[string]bool `json:"tripped_signatures,omitempty"`
	TripCount         int             `json:"trip_count,omitempty"`
	LastTrippedAt     *time.Time      `json:"last_tripped_at,omitempty"`
	LastSeenAt        time.Time       `json:"last_seen_at"`
}

const (
	// hookDoomLoopStateTTL prunes idle sessions from the state file.
	hookDoomLoopStateTTL = 24 * time.Hour
	// hookDoomLoopMaxSessions bounds the state file (oldest LastSeenAt is
	// evicted first).
	hookDoomLoopMaxSessions = 128
	// hookDoomLoopMaxTrippedSignatures bounds the per-session latch map so
	// the persisted state cannot grow without bound. Eviction is
	// deterministic (lexicographically smallest signature); an evicted
	// signature simply re-trips after another threshold run of denials.
	hookDoomLoopMaxTrippedSignatures = 64
	// hookDoomLoopLockWait bounds how long a hook waits for the state lock
	// before giving up (the breaker is advisory; the policy path proceeds).
	hookDoomLoopLockWait = 2 * time.Second
	// hookDoomLoopMaxStateBytes bounds reads of locally tampered state.
	hookDoomLoopMaxStateBytes = 1 << 20
)

// hookSessionKey maps a client-supplied session ID to a fixed-size state
// key (sha256 hex). This bounds JSON map-key size regardless of ID length
// and keeps raw client identifiers out of the persisted state.
func hookSessionKey(sessionID string) string {
	sum := sha256.Sum256([]byte("helm-hook-doomloop-session\x00" + sessionID))
	return hex.EncodeToString(sum[:])
}

// recordDenied counts one final fail-closed denial for the signature and
// reports whether the breaker has latched for THIS signature, plus the current
// run length. A fully allowed hook outcome resets the run and never trips it.
func (s *hookDoomLoopSession) recordDenied(signature string, now time.Time) (bool, int) {
	if s.LastSignature == signature {
		s.RunLength++
	} else {
		s.LastSignature = signature
		s.RunLength = 1
	}
	if s.RunLength >= actioninbox.DefaultDoomLoopThreshold {
		if s.TrippedSignatures == nil {
			s.TrippedSignatures = map[string]bool{}
		}
		if !s.TrippedSignatures[signature] {
			if len(s.TrippedSignatures) >= hookDoomLoopMaxTrippedSignatures {
				// Bounded latch map: evict the deterministic victim
				// (smallest key). An evicted signature re-trips after
				// another threshold run of consecutive denials.
				victim := ""
				for k := range s.TrippedSignatures {
					if victim == "" || k < victim {
						victim = k
					}
				}
				delete(s.TrippedSignatures, victim)
			}
			s.TrippedSignatures[signature] = true
			s.TripCount++
			s.LastTrippedAt = &now
		}
	}
	return s.TrippedSignatures[signature], s.RunLength
}

// recordAllowed breaks the consecutive-denial run: a successful call means
// the agent is making progress, not looping. It never sets a latch.
func (s *hookDoomLoopSession) recordAllowed() {
	s.LastSignature = ""
	s.RunLength = 0
}

// recordHookDoomLoopOutcome records one final classified outcome (denied or
// allowed) for the session and reports whether the breaker has latched for
// this call signature. A signer/profile/receipt persistence failure is a final
// fail-closed denial and therefore counts. The read-modify-write is serialized
// with a lock file so concurrent hook processes cannot lose updates.
//
// Advisory note: the session ID is supplied by the agent client payload and
// is not authenticated — a client rotating session IDs could evade the
// breaker. The breaker is defense-in-depth UX steering on top of the
// authoritative fail-closed policy path, not a security boundary.
func recordHookDoomLoopOutcome(opts hookOptions, payload preToolPayload, classification hookClassification, denied bool, stderr io.Writer) (bool, int) {
	if strings.TrimSpace(opts.DataDir) == "" {
		// No local state dir (e.g. HOME-less environment): the breaker is
		// disabled rather than writing state into the caller's CWD.
		return false, 0
	}
	inputHash, err := canonicalize.CanonicalHash(payload.ToolInput)
	if err != nil {
		// Advisory state must never conflate an input it cannot identify.
		return false, 0
	}
	signature := actioninbox.SignatureFor(classification.ToolID, classification.Action, classification.Target+":"+inputHash)
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		// No session identity: unrelated invocations must never share a
		// breaker bucket (a shared "_default" key would let one session's
		// denials falsely trip another's). Without a session ID the
		// breaker cannot attribute the run, so it stays out of the way —
		// same rule as DenyCascade: empty session never collides.
		return false, 0
	}
	// The session ID is client-supplied and unauthenticated; map it to a
	// fixed-size key so oversized IDs cannot bloat the persisted state
	// (keys are always 64 hex chars, preserving the bounded-state
	// guarantee) and raw client identifiers are never written to disk.
	sessionKey := hookSessionKey(sessionID)
	statePath := filepath.Join(opts.DataDir, "state", "hook-doomloop.json")
	unlock, ok := acquireHookDoomLoopLock(statePath+".lock", stderr)
	if !ok {
		return false, 0
	}
	defer unlock()

	now := hookNow()
	state := loadHookDoomLoopState(statePath, stderr)
	pruneHookDoomLoopSessions(state, now)
	sess, ok := state.Sessions[sessionKey]
	if !ok || sess == nil {
		if !denied {
			// No recorded run for this session and nothing to reset:
			// avoid creating breaker state for never-denied sessions.
			return false, 0
		}
		sess = &hookDoomLoopSession{}
		state.Sessions[sessionKey] = sess
	}
	sess.LastSeenAt = now
	var trippedB bool
	var runN int
	if denied {
		trippedB, runN = sess.recordDenied(signature, now)
	} else {
		sess.recordAllowed()
	}
	if err := saveHookDoomLoopState(statePath, state); err != nil {
		// Best-effort persistence: the base policy decision path is
		// unaffected and remains fail-closed; log and continue.
		fmt.Fprintf(stderr, "hook pre-tool: persist doom-loop state: %v\n", err)
	}
	return trippedB, runN
}

// pruneHookDoomLoopSessions drops sessions idle beyond the TTL and evicts
// the oldest sessions beyond the cap, keeping the state file bounded.
// Nil session entries (defensive: valid JSON can carry nulls) are dropped.
func pruneHookDoomLoopSessions(state *hookDoomLoopFile, now time.Time) {
	for id, sess := range state.Sessions {
		if sess == nil || sess.LastSeenAt.IsZero() || now.Sub(sess.LastSeenAt) > hookDoomLoopStateTTL {
			delete(state.Sessions, id)
		}
	}
	for len(state.Sessions) > hookDoomLoopMaxSessions {
		var oldestID string
		var oldest time.Time
		for id, sess := range state.Sessions {
			if sess == nil {
				oldestID = id
				break
			}
			if oldestID == "" || sess.LastSeenAt.Before(oldest) {
				oldestID, oldest = id, sess.LastSeenAt
			}
		}
		delete(state.Sessions, oldestID)
	}
}

// acquireHookDoomLoopLock takes the state lock as an OS-level advisory
// lock (flock / LockFileEx). The OS releases it on process exit, so a
// crashed holder can never leave a stale lock and no age-based reclaim can
// ever delete a live holder's lock. On contention past hookDoomLoopLockWait
// it reports ok=false; callers must treat the breaker update as skipped
// (advisory) and continue on the authoritative policy path.
func acquireHookDoomLoopLock(lockPath string, stderr io.Writer) (unlock func(), ok bool) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop lock dir: %v\n", err)
		return nil, false
	}
	unlock, held, err := hookDoomLoopFlock(lockPath, time.Now().Add(hookDoomLoopLockWait))
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop lock: %v\n", err)
		return nil, false
	}
	if !held {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state lock busy; skipping breaker update\n")
		return nil, false
	}
	return unlock, true
}

func loadHookDoomLoopState(path string, stderr io.Writer) *hookDoomLoopFile {
	state := &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "hook pre-tool: read doom-loop state: %v\n", err)
		}
		return state
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, hookDoomLoopMaxStateBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: read doom-loop state: %v\n", err)
		return state
	}
	if len(raw) > hookDoomLoopMaxStateBytes {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state exceeds %d bytes, starting fresh\n", hookDoomLoopMaxStateBytes)
		return state
	}
	if err := json.Unmarshal(raw, state); err != nil {
		fmt.Fprintf(stderr, "hook pre-tool: doom-loop state unreadable, starting fresh: %v\n", err)
		return &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	}
	if state.Sessions == nil {
		fmt.Fprintln(stderr, "hook pre-tool: doom-loop state has no sessions map, starting fresh")
		return &hookDoomLoopFile{Sessions: map[string]*hookDoomLoopSession{}}
	}
	// Valid JSON can still carry null session values ("sessions":{"s":null});
	// drop them so no later traversal can dereference a nil session.
	for id, sess := range state.Sessions {
		if sess == nil {
			delete(state.Sessions, id)
		}
	}
	return state
}

func saveHookDoomLoopState(path string, state *hookDoomLoopFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hook-doomloop-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	// Windows rename does not replace an existing destination. The hook
	// state lock serializes writers; remove-and-rename is sufficient for
	// this advisory state file.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpName, path)
}

func decodePreToolPayload(stdin io.Reader) (preToolPayload, error) {
	var payload preToolPayload
	dec := json.NewDecoder(stdin)
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode hook payload: %w", err)
	}
	if payload.ToolName == "" {
		payload.ToolName = payload.ToolNameCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.ToolInputCamel
	}
	if payload.ToolInput == nil {
		payload.ToolInput = payload.Args
	}
	if payload.ToolInput == nil {
		payload.ToolInput = map[string]any{}
	}
	return payload, nil
}

func classifyPreToolPayload(payload preToolPayload) hookClassification {
	classifications := classifyPreToolPayloads(payload)
	if len(classifications) == 0 {
		return hookClassification{}
	}
	return classifications[0]
}

func classifyPreToolPayloads(payload preToolPayload) []hookClassification {
	tool := strings.TrimSpace(payload.ToolName)
	switch {
	case strings.EqualFold(tool, "Bash"), strings.EqualFold(tool, "terminal"):
		command := inputString(payload.ToolInput, "command", "cmd")
		// Structural (AST-based) pre-flight classification. The classifier is
		// advisory input only: it decides whether the command reaches the
		// existing signed decision path; the permit/receipt verdict is still
		// produced by workstation.Decide, fail-closed as before.
		scan := shellscan.ClassifyAt(command, payload.CWD)
		classifications := make([]hookClassification, 0, len(scan.EffectFacts)+2)
		for _, fact := range scan.EffectFacts {
			if classification, ok := hookClassificationFromShellscanFact(fact, scan); ok {
				classifications = append(classifications, classification)
				continue
			}
			// A future scanner fact must never become an ungoverned effect just
			// because this hook has not learned its dedicated policy class yet.
			classifications = append(classifications, hookClassification{
				ShouldDecide: true,
				Class:        "shell-operate",
				Target:       command,
				Action:       "shell_operate",
				ToolID:       "shell",
				Reason:       "unrecognized shell effect fact",
				Metadata:     shellscanReceiptMetadata(scan),
			})
		}
		if scan.RequiresShellDecision {
			classifications = append(classifications, shellscanGenericClassification(command, scan))
		}
		return appendRequiredShellPermission(classifications, command)
	case strings.HasPrefix(tool, "mcp_"):
		// Claude/Codex emit mcp__server__tool. Hermes has used that shape and
		// the older mcp_server_tool form. mcp__ is a prefix of mcp_.
		if isHelmSelfMCPTool(tool) {
			return nil
		}
		return []hookClassification{{
			ShouldDecide: true,
			Class:        "mcp",
			Target:       tool,
			Action:       "mcp_tool_call",
			ToolID:       tool,
			Reason:       "MCP tool call",
		}}
	// DeepSeek Harness emits lowercase bash/write/edit; EqualFold matches those.
	case strings.EqualFold(tool, "Edit"), strings.EqualFold(tool, "Write"), strings.EqualFold(tool, "MultiEdit"), strings.EqualFold(tool, "apply_patch"), strings.EqualFold(tool, "write_file"), strings.EqualFold(tool, "patch"):
		target := inputString(payload.ToolInput, "file_path", "path", "target_file")
		if target == "" && (strings.EqualFold(tool, "apply_patch") || strings.EqualFold(tool, "patch")) {
			target = sensitiveApplyPatchTarget(inputString(payload.ToolInput, "command", "cmd", "patch", "diff"))
		}
		if target == "" && (strings.EqualFold(tool, "apply_patch") || strings.EqualFold(tool, "patch")) {
			target = "apply_patch"
		}
		if isSensitiveWriteTarget(target) {
			return []hookClassification{{
				ShouldDecide: true,
				Class:        "sensitive-file-write",
				Target:       target,
				Action:       "file_write",
				ToolID:       tool,
				Reason:       "sensitive file write",
			}}
		}
	}
	return nil
}

func hookClassificationFromShellscanFact(fact shellscan.EffectFact, scan shellscan.Result) (hookClassification, bool) {
	metadata := shellscanReceiptMetadata(scan)
	switch fact.Class {
	case "network":
		return hookClassification{
			ShouldDecide: true,
			Class:        "network",
			Target:       fact.Target,
			Action:       fact.Action,
			ToolID:       "network.egress",
			Reason:       fact.Reason,
			Metadata:     metadata,
		}, true
	case "secret":
		return hookClassification{
			ShouldDecide: true,
			Class:        "secret",
			Target:       fact.Target,
			Action:       fact.Action,
			ToolID:       "secret.read",
			Reason:       fact.Reason,
			Metadata:     metadata,
		}, true
	default:
		return hookClassification{}, false
	}
}

func shellscanGenericClassification(command string, scan shellscan.Result) hookClassification {
	class := "shell-operate"
	target := command
	action := "shell_operate"
	reason := "shell operation: " + scan.Reason
	if scan.SensitiveTarget != "" {
		class = "sensitive-file-write"
		target = scan.SensitiveTarget
		action = "file_write"
		reason = "sensitive file operation"
	}
	return hookClassification{
		ShouldDecide:            true,
		Class:                   class,
		Target:                  target,
		Action:                  action,
		ToolID:                  "shell",
		Reason:                  reason,
		Metadata:                shellscanReceiptMetadata(scan),
		RequiresShellPermission: scan.RequiresShellPermission,
	}
}

func appendRequiredShellPermission(classifications []hookClassification, command string) []hookClassification {
	if len(classifications) == 0 {
		return nil
	}
	decisions := make([]hookClassification, 0, len(classifications)+1)
	for _, classification := range classifications {
		decisions = append(decisions, classification)
		if classification.RequiresShellPermission {
			decisions = append(decisions, hookClassification{
				ShouldDecide: true,
				Class:        "shell-operate",
				Target:       command,
				Action:       "shell_operate",
				ToolID:       "shell",
				Reason:       "compound shell operation",
				Metadata:     classification.Metadata,
			})
		}
	}
	return decisions
}

func buildHookDecisionReceipt(opts hookOptions, payload preToolPayload, classification hookClassification) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	effectType, effectMode, defaultAction, defaultTool := workstation.EffectDefaults(classification.Class)
	action := firstNonEmptyString(classification.Action, defaultAction)
	toolID := firstNonEmptyString(classification.ToolID, payload.ToolName, defaultTool)
	targetFingerprint := fingerprintHookTarget(classification.Target)
	profile, profileDigest, err := workstation.LoadPolicyProfileFileWithDigest(opts.PolicyProfile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errHookPolicyProfile, err)
	}
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		approvedDigest := strings.TrimSpace(opts.PolicyProfileSHA256)
		if approvedDigest == "" {
			return nil, fmt.Errorf("%w: custom policy profile has no approved digest", errHookPolicyProfile)
		}
		if approvedDigest != profileDigest {
			return nil, fmt.Errorf("%w: custom policy profile digest does not match installed configuration", errHookPolicyProfile)
		}
	}
	requestID, err := newHookRequestID()
	if err != nil {
		return nil, fmt.Errorf("generate hook request ID: %w", err)
	}
	req := contracts.WorkstationDecisionRequest{
		RequestID:    requestID,
		RunID:        firstNonEmptyString(payload.SessionID, "hook-pre-tool"),
		ActorID:      "agent.local",
		WorkspaceID:  firstNonEmptyString(payload.CWD, "local-workstation"),
		AgentSurface: opts.Client,
		ToolID:       toolID,
		Action:       action,
		EffectType:   effectType,
		EffectMode:   effectMode,
		Target:       classification.Target,
		OccurredAt:   hookNow(),
		Metadata: map[string]string{
			"client": opts.Client,
			"tool":   payload.ToolName,
		},
	}
	for key, value := range classification.Metadata {
		req.Metadata[key] = value
	}
	seed, err := resolveWorkstationSigningSeed(opts.DataDir, "", opts.SigningSeedFile)
	if err != nil {
		return nil, fmt.Errorf("load workstation signing key: %w", err)
	}
	persistedMetadata := map[string]string{
		"target_binding": "sha256:utf-8",
	}
	if profileDigest != "" {
		persistedMetadata["policy_profile_sha256"] = profileDigest
	}
	if effectType == contracts.EffectTypeWorkstationMCPToolCall {
		canonicalInput, err := canonicalize.JCS(payload.ToolInput)
		if err != nil {
			return nil, fmt.Errorf("canonicalize MCP tool input: %w", err)
		}
		persistedMetadata["mcp_input_binding"] = "jcs-sha256"
		persistedMetadata["mcp_input_sha256"] = canonicalize.ComputeArtifactHash(canonicalInput)
	}
	return workstation.Decide(profile, req, workstation.DecisionOptions{
		SigningSeed:       seed,
		PersistedTarget:   targetFingerprint,
		PersistedMetadata: persistedMetadata,
	})
}

func newHookRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "hook_" + hex.EncodeToString(value[:]), nil
}

func fingerprintHookTarget(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func shellscanReceiptMetadata(scan shellscan.Result) map[string]string {
	commands := make([]string, 0, len(scan.Commands))
	for _, command := range scan.Commands {
		entry := command.Name
		if command.Via != "" {
			entry += " via " + command.Via
		}
		commands = append(commands, entry)
	}
	return map[string]string{
		"shellscan.parse_ok": strconv.FormatBool(scan.ParseOK),
		"shellscan.signals":  strings.Join(scan.Signals, ","),
		"shellscan.commands": strings.Join(commands, ","),
	}
}

func inputString(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := input[key]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func sensitiveApplyPatchTarget(command string) string {
	for _, line := range strings.Split(command, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:"} {
			if strings.HasPrefix(line, prefix) {
				target := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if isSensitiveWriteTarget(target) {
					return target
				}
			}
		}
	}
	return ""
}

func isHelmSelfMCPTool(tool string) bool {
	t := strings.ToLower(tool)
	return strings.Contains(t, "helm-ai-kernel") || strings.Contains(t, "helm_ai_kernel") || strings.Contains(t, "helm-ai-kernel-governance")
}

func isSensitiveWriteTarget(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	sensitive := []string{
		".env",
		".pem",
		".key",
		"id_rsa",
		"id_ed25519",
		".git/",
		".git\\",
		".claude/settings.json",
		".codex/hooks.json",
		".hermes/config.yaml",
		".dsh/hooks.json",
		".dsh/cordis.patch.yml",
		".claude\\settings.json",
		".codex\\hooks.json",
		".hermes\\config.yaml",
		".dsh\\hooks.json",
		".dsh\\cordis.patch.yml",
	}
	for _, needle := range sensitive {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}
