// Package worktree provides isolated git-worktree execution trees for agent
// runs that HELM parents directly.
//
// The boundary this package draws is the difference between observing an agent
// and owning it. A hook reports what the agent chose to disclose; an isolated
// tree constrains where the agent can write and captures the result from git
// rather than from model narration.
//
// Not to be confused with core/pkg/envelope, the Autonomy Envelope — that is
// the signed runtime boundary CONTRACT a run binds to before effects execute.
// This package is the filesystem isolation a run EXECUTES in. A run has both:
// it binds an Autonomy Envelope and it executes in a Tree.
//
// Two placement rules carry the isolation and are enforced here rather than by
// convention:
//
//   - The harness cwd is the worktree at Tree.
//   - The harness HOME is HomeDir, a SIBLING of Tree, never a child. Vendor CLIs
//     write sessions, transcripts, plugin caches and credential material into
//     HOME; if that lived inside the worktree, `git add -A` would capture
//     credentials into a diff.
//
// Prior art: razzant/claudexor (MIT), packages/workspace. Ported to Go.
package worktree

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// safeSegment matches an id usable as exactly one path segment. A crafted id
// containing "../" would otherwise turn Dispose into an arbitrary recursive
// delete, so ids are validated before they ever reach filepath.Join.
var safeSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ErrUnsafeSegment is returned when a run or attempt id is not a single safe
// path segment.
var ErrUnsafeSegment = errors.New("worktree: id is not a safe path segment")

// Envelope is one isolated execution tree plus the scoped HOME that shields the
// operator's real vendor config from the run.
type Envelope struct {
	// Tree is the git worktree. This is the harness cwd.
	Tree string
	// HomeDir is the scoped HOME. Sibling of Tree, never inside it.
	HomeDir string
	// BaseSHA is the commit the worktree was created at. A captured diff is only
	// meaningful against this base, and delivery re-verifies against it.
	BaseSHA string

	root string
	repo string
}

// Options configures envelope creation.
type Options struct {
	// RepoRoot is the project git repository the envelope branches from.
	RepoRoot string
	// RunID and AttemptID name the envelope. Each must be a single safe segment.
	RunID     string
	AttemptID string
	// BaseRef is the ref to branch from. Defaults to HEAD.
	BaseRef string
	// RuntimeRoot is where envelopes are materialized. It MUST be outside
	// RepoRoot so envelope contents never appear in the project's own status.
	RuntimeRoot string
}

// Create materializes an envelope: a git worktree on a throwaway branch, plus a
// scoped HOME beside it.
func Create(opts Options) (*Envelope, error) {
	if !safeSegment.MatchString(opts.RunID) {
		return nil, fmt.Errorf("%w: run id %q", ErrUnsafeSegment, opts.RunID)
	}
	if !safeSegment.MatchString(opts.AttemptID) {
		return nil, fmt.Errorf("%w: attempt id %q", ErrUnsafeSegment, opts.AttemptID)
	}

	runtimeRoot, err := filepath.Abs(opts.RuntimeRoot)
	if err != nil {
		return nil, fmt.Errorf("worktree: resolve runtime root: %w", err)
	}
	repoRoot, err := filepath.Abs(opts.RepoRoot)
	if err != nil {
		return nil, fmt.Errorf("worktree: resolve repo root: %w", err)
	}
	// An envelope inside the project would be captured by the project's own git
	// status and could be swept by a `git clean` in the live tree.
	if isWithin(runtimeRoot, repoRoot) {
		return nil, fmt.Errorf("worktree: runtime root %q is inside repo root %q", runtimeRoot, repoRoot)
	}

	root := filepath.Join(runtimeRoot, "workspaces", opts.RunID, opts.AttemptID)
	// Defence in depth: even with validated segments, confirm the join landed
	// under the intended base before any mkdir.
	if !isWithin(root, runtimeRoot) {
		return nil, fmt.Errorf("%w: resolved path escapes runtime root", ErrUnsafeSegment)
	}

	baseRef := opts.BaseRef
	if baseRef == "" {
		baseRef = "HEAD"
	}
	baseSHA, err := gitOutput(repoRoot, "rev-parse", baseRef)
	if err != nil {
		return nil, fmt.Errorf("worktree: resolve base ref %q: %w", baseRef, err)
	}

	tree := filepath.Join(root, "tree")
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("worktree: create scoped home: %w", err)
	}

	// --detach: the tree needs no branch of its own. The work product is a diff
	// against BaseSHA, and a named branch per attempt would leave refs behind for
	// every candidate a race spawns.
	if _, err := gitOutput(repoRoot, "worktree", "add", "--detach", tree, baseSHA); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("worktree: add worktree: %w", err)
	}

	return &Envelope{
		Tree:    tree,
		HomeDir: home,
		BaseSHA: baseSHA,
		root:    root,
		repo:    repoRoot,
	}, nil
}

// CaptureDiff returns the envelope's work product as a unified diff against
// BaseSHA, including untracked files.
//
// The bytes are returned raw and unbuffered by any line scanner. This is
// load-bearing, not stylistic: bufio.Scanner (like Node's readline) splits on a
// lone \r and rejoins with \n, which silently rewrites CRLF content and corrupts
// the patch at the point of capture. A diff that cannot round-trip byte-for-byte
// is not evidence.
func (e *Envelope) CaptureDiff() ([]byte, error) {
	// Staging untracked files makes them visible to `git diff --cached` so a
	// newly created file is part of the work product rather than invisible.
	if _, err := gitOutput(e.Tree, "add", "-A"); err != nil {
		return nil, fmt.Errorf("worktree: stage work product: %w", err)
	}
	// --binary so binary changes survive; --cached against the base commit so the
	// diff is the full net change of this envelope.
	cmd := exec.Command("git", "diff", "--cached", "--binary", e.BaseSHA)
	cmd.Dir = e.Tree
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("worktree: capture diff: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Env returns the environment overrides that place the harness inside this
// envelope. Callers compose these over a scrubbed base environment; this
// function deliberately does not read os.Environ, so it cannot leak the
// operator's provider credentials into the child by accident.
func (e *Envelope) Env() map[string]string {
	return map[string]string{
		"HOME":              e.HomeDir,
		"XDG_CONFIG_HOME":   filepath.Join(e.HomeDir, ".config"),
		"CLAUDE_CONFIG_DIR": filepath.Join(e.HomeDir, ".claude"),
		"CODEX_HOME":        filepath.Join(e.HomeDir, ".codex"),
	}
}

// Dispose removes the worktree and the envelope directory. It is safe to call
// more than once.
func (e *Envelope) Dispose() error {
	// Best-effort worktree deregistration first; if this fails the directory
	// removal below still reclaims the space, and `git worktree prune` reconciles.
	_, _ = gitOutput(e.repo, "worktree", "remove", "--force", e.Tree)
	if err := os.RemoveAll(e.root); err != nil {
		return fmt.Errorf("worktree: remove root: %w", err)
	}
	_, _ = gitOutput(e.repo, "worktree", "prune")
	return nil
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// isWithin reports whether path is base or lives under it, comparing cleaned
// absolute paths so "/a/bc" is not treated as inside "/a/b".
func isWithin(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
