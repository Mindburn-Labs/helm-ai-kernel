// Package patchdelivery governs the moment an agent run's work product is
// applied to a live project tree.
//
// Not to be confused with core/pkg/delivery, which is progressive RELEASE
// rollout (shadow, canary, blue-green, SLO promotion gates). That package
// delivers a release to an environment; this one delivers a patch to a working
// tree. They share a verb and nothing else.
//
// The unit of work is a patch captured from an isolated worktree (see
// core/pkg/worktree) against a recorded BaseSHA. Between capture and apply, the
// live tree moves: other agents land changes, the operator edits files, CI
// rewrites generated code. A patch that was true when it was captured may be
// false by the time anyone wants it. So the apply path re-proves the patch
// against a clean base immediately before it is allowed to touch anything.
//
// The distinction this package exists to preserve is between a patch that is
// PROVEN undeliverable and a patch whose deliverability is UNKNOWN. They both
// block, but they are not the same fact and must not be collapsed into one
// boolean. See VerifyRecord.
//
// Prior art: razzant/claudexor (MIT). Reimplemented for HELM.
package patchdelivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GateSpec is one deterministic check executed inside the throwaway
// verification tree. Gates are run with the verification tree as cwd, so a gate
// observes the patched base and nothing else.
type GateSpec struct {
	// Name identifies the gate in refusal text and receipts.
	Name string
	// Command and Args are executed directly. There is no shell: a gate is an
	// argv, not a string to be word-split, so a repo-supplied gate name cannot
	// smuggle a second command through a semicolon.
	Command string
	Args    []string
	// Timeout bounds a single gate. Zero means defaultGateTimeout.
	Timeout time.Duration
}

const defaultGateTimeout = 10 * time.Minute

// VerifyRecord is the evidence produced by FinalVerify. Its two pointer fields
// carry a tri-state each, and that tri-state is the entire point of the type.
//
// AppliedCleanly:
//
//   - false — the patch was PROVEN not to apply to a clean base. This is a
//     fact about the patch, not about the verifier. No override can unblock it,
//     because no authority makes a conflicting patch apply.
//   - nil — the verifier itself failed (git missing, disk full, timeout,
//     cancelled). The patch was never proven against a clean base, so it blocks
//     fail-closed. But nothing was proven AGAINST it either, so an operator who
//     accepts the risk may unblock it.
//   - true — the patch applied to a clean checkout of BaseSHA.
//
// GatesPassed:
//
//   - nil — no gates were configured. Distinct from passing. A patch that
//     applied cleanly with zero gates has been checked for deliverability and
//     for nothing else; reporting that as "gates passed" would manufacture
//     evidence that does not exist.
//   - false — gates ran and did not pass, or a gate could not be executed at
//     all. Reason distinguishes the two; the boolean stays fail-closed either
//     way, because a gate that did not run did not pass.
//   - true — every configured gate exited zero.
//
// The rule the whole package encodes: an override may bypass UNKNOWN, never
// PROVEN-FALSE.
type VerifyRecord struct {
	Attempted      bool   `json:"attempted"`
	AppliedCleanly *bool  `json:"applied_cleanly,omitempty"`
	GatesPassed    *bool  `json:"gates_passed,omitempty"`
	Reason         string `json:"reason,omitempty"`
	DurationMS     int64  `json:"duration_ms"`
	BaseSHA        string `json:"base_sha,omitempty"`
}

// ProvenUndeliverable reports whether the record carries a proven conflict.
// This is the one state no operator authority can clear.
func (r VerifyRecord) ProvenUndeliverable() bool {
	return r.AppliedCleanly != nil && !*r.AppliedCleanly
}

// Unknown reports whether the verifier failed to establish deliverability
// either way. Blocks fail-closed, but is override-eligible.
func (r VerifyRecord) Unknown() bool {
	return r.AppliedCleanly == nil
}

// Blocks reports whether this record forbids an apply on its own.
func (r VerifyRecord) Blocks() bool {
	if r.Unknown() || r.ProvenUndeliverable() {
		return true
	}
	return r.GatesPassed != nil && !*r.GatesPassed
}

// FinalVerify re-proves a patch against a clean checkout of baseSHA immediately
// before the caller intends to mutate the live tree.
//
// It creates a THROWAWAY git worktree at baseSHA outside the repository,
// applies the patch there, runs the configured gates in that fresh tree, and
// tears the whole thing down. Nothing it does touches the live tree — a patch
// that cannot survive a clean base must never reach one.
//
// The returned error is reserved for arguments the function cannot act on at
// all. Every outcome that produced evidence — including verifier failure —
// comes back as a VerifyRecord with a nil error, because the tri-state in the
// record is the answer, not an exception.
func FinalVerify(ctx context.Context, repoRoot string, patch []byte, baseSHA string, gates []GateSpec) (VerifyRecord, error) {
	start := time.Now()
	rec := VerifyRecord{Attempted: true, BaseSHA: baseSHA}
	stamp := func() VerifyRecord {
		rec.DurationMS = time.Since(start).Milliseconds()
		return rec
	}

	if strings.TrimSpace(repoRoot) == "" {
		return VerifyRecord{}, errors.New("delivery: repo root is required")
	}
	// No base means there is no clean tree to prove anything against. This is
	// UNKNOWN, not a conflict: the patch may well be fine, we simply cannot say.
	if strings.TrimSpace(baseSHA) == "" {
		rec.Reason = "no base sha recorded; cannot verify against a clean base"
		return stamp(), nil
	}

	// Outside the repository, so the verification tree never appears in the
	// project's own git status and is never swept by a clean in the live tree.
	scratch, err := os.MkdirTemp("", "helm-delivery-verify-")
	if err != nil {
		rec.Reason = redactSecrets(fmt.Sprintf("could not create verification scratch: %v", err))
		return stamp(), nil
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	tree := filepath.Join(scratch, "tree")
	if _, err := runGit(ctx, repoRoot, "worktree", "add", "--detach", tree, baseSHA); err != nil {
		rec.Reason = redactSecrets(fmt.Sprintf("could not materialize a clean base at %s: %v", baseSHA, err))
		return stamp(), nil
	}
	defer func() {
		// Best-effort teardown in the same order worktree.Dispose uses: drop the
		// registration, then the files, then reconcile.
		_, _ = runGit(context.WithoutCancel(ctx), repoRoot, "worktree", "remove", "--force", tree)
		_, _ = runGit(context.WithoutCancel(ctx), repoRoot, "worktree", "prune")
	}()

	if applied, reason, ok := applyPatch(ctx, tree, patch); !ok {
		// applyPatch already separated "git rejected the patch" from "git could
		// not run"; propagate that distinction verbatim.
		rec.AppliedCleanly = applied
		rec.Reason = reason
		return stamp(), nil
	}

	yes := true
	rec.AppliedCleanly = &yes

	if len(gates) == 0 {
		// Deliberately leaves GatesPassed nil. See the type comment.
		rec.Reason = "patch applies to a clean base; no gates configured, so nothing else was verified"
		return stamp(), nil
	}

	for _, gate := range gates {
		if err := runGate(ctx, tree, gate); err != nil {
			no := false
			rec.GatesPassed = &no
			rec.Reason = redactSecrets(err.Error())
			return stamp(), nil
		}
	}

	pass := true
	rec.GatesPassed = &pass
	rec.Reason = fmt.Sprintf("patch applies to a clean base and %d gate(s) passed", len(gates))
	return stamp(), nil
}

// applyPatch applies patch inside tree.
//
// It returns (appliedCleanly, reason, ok). ok is true only when the patch
// applied. When ok is false, appliedCleanly is either a pointer to false — git
// ran and rejected the patch, a proven conflict — or nil, meaning git never
// delivered a verdict and deliverability is unknown.
func applyPatch(ctx context.Context, tree string, patch []byte) (*bool, string, bool) {
	if len(patch) == 0 {
		// An empty patch applies to anything, vacuously. Whether an empty work
		// product should be delivered at all is an eligibility question
		// (OutcomeFacts.NoChanges), not a deliverability one.
		return nil, "", true
	}

	cmd := exec.CommandContext(ctx, "git", "apply", "--binary", "-")
	cmd.Dir = tree
	cmd.Stdin = bytes.NewReader(patch)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return nil, "", true
	}

	// A cancelled or timed-out context means we interrupted git, not that git
	// judged the patch. That is UNKNOWN however git happened to exit.
	if ctx.Err() != nil {
		return nil, redactSecrets(fmt.Sprintf("verification interrupted before the patch could be judged: %v", ctx.Err())), false
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// git ran to completion and refused the patch. This is the proven
		// conflict: a fact about the patch that no authority can override.
		no := false
		return &no, redactSecrets(fmt.Sprintf("patch does not apply to a clean base: %s", oneLine(stderr.String()))), false
	}

	// git could not be started at all (missing binary, permissions, fork
	// failure). Nothing was proven about the patch in either direction.
	return nil, redactSecrets(fmt.Sprintf("verifier could not run git apply: %v", err)), false
}

// runGate executes one gate in the verification tree. Any non-nil error means
// the gate did not pass, and the message states whether it failed or could not
// be run at all.
func runGate(ctx context.Context, tree string, gate GateSpec) error {
	if strings.TrimSpace(gate.Command) == "" {
		return fmt.Errorf("gate %q has no command", gate.Name)
	}
	timeout := gate.Timeout
	if timeout <= 0 {
		timeout = defaultGateTimeout
	}
	gateCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(gateCtx, gate.Command, gate.Args...)
	cmd.Dir = tree
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if gateCtx.Err() != nil {
		return fmt.Errorf("gate %q did not pass: it exceeded its %s budget", gate.Name, timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("gate %q failed: %s", gate.Name, oneLine(out.String()))
	}
	// Fail-closed: a gate that could not be executed has not passed. The
	// wording keeps that honest rather than claiming it failed on its merits.
	return fmt.Errorf("gate %q did not pass: it could not be executed: %v", gate.Name, err)
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, oneLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// secretShaped matches token formats that must never reach a Reason string.
// Reasons are copied into receipts and EvidencePacks, so an error message that
// happens to quote a credential would persist it into signed evidence.
//
// Git object ids are deliberately NOT matched: a bare 40-hex SHA is evidence,
// not a secret, and redacting it would destroy the record's usefulness.
var secretShaped = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{16,}`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}`),
	regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[=:]\s*\S+`),
}

// redactSecrets removes secret-shaped tokens from text bound for a Reason.
func redactSecrets(s string) string {
	for _, re := range secretShaped {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
