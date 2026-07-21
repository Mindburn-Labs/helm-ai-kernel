package patchdelivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// Fence describes the enforcement a mutation path routes through. A
// registration with an empty fence is a path that can write to a live tree with
// nothing in front of it, which is the condition this registry exists to make
// impossible to introduce quietly.
type Fence struct {
	// Eligibility means the path decides via Eligibility and honours the
	// Decision it returns.
	Eligibility bool `json:"eligibility"`
	// Preimage means the path captures the target preimage and re-checks it
	// around the mutation.
	Preimage bool `json:"preimage"`
	// Note is a short human description of the path.
	Note string `json:"note,omitempty"`
}

// Complete reports whether the fence covers both required enforcements.
func (f Fence) Complete() bool { return f.Eligibility && f.Preimage }

// Registration is one enumerated mutation path and its fence.
type Registration struct {
	Name  string `json:"name"`
	Fence Fence  `json:"fence"`
}

// MutationPathApplyProtected is this package's own mutation path.
//
// Every code path anywhere in the kernel that can mutate a live project tree on
// behalf of an agent run gets a name here and registers its fence. The registry
// is what makes "which code can write to a user's repository" an answerable
// question instead of an archaeology exercise.
const MutationPathApplyProtected = "delivery.ApplyProtected"

// RequiredMutationPaths is the release contract: every name listed here MUST be
// registered with a complete fence, and TestMutationPathsAreRegistered fails the
// build if one is missing.
//
// An unregistered mutation path is a release blocker. When a new writer is added
// (a CLI apply command, a control-API handler), add its name here and call
// Register from its own file — not from this one, so deleting the writer also
// deletes its registration and the test catches the stale entry.
func RequiredMutationPaths() []string {
	return []string{MutationPathApplyProtected}
}

var (
	mutationMu    sync.RWMutex
	mutationPaths = make(map[string]Fence)
)

// Register records a mutation path and the fence in front of it. Calling it
// twice for the same name overwrites, so a path cannot be registered once with
// a real fence and once with an empty one.
func Register(name string, fence Fence) {
	mutationMu.Lock()
	defer mutationMu.Unlock()
	mutationPaths[name] = fence
}

// Paths returns every registered mutation path, ordered by name.
func Paths() []Registration {
	mutationMu.RLock()
	defer mutationMu.RUnlock()
	out := make([]Registration, 0, len(mutationPaths))
	for name, fence := range mutationPaths {
		out = append(out, Registration{Name: name, Fence: fence})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func init() {
	Register(MutationPathApplyProtected, Fence{
		Eligibility: true,
		Preimage:    true,
		Note:        "applies a verified patch to a live project tree, all-or-nothing",
	})
}

// Preimage is the exact state of the files a patch intends to touch, captured
// before the mutation so the same state can be re-asserted at the moment of
// writing.
type Preimage struct {
	// Entries maps a repo-relative path to a content digest, or to absentMarker
	// when the file does not exist. Absence is state too: a patch that creates a
	// file assumes it is not already there.
	Entries map[string]string `json:"entries"`
	// Digest is the JCS-canonical hash of Entries, so two preimages compare as
	// one value regardless of map iteration order.
	Digest string `json:"digest"`
}

const absentMarker = "absent"

// Result reports what ApplyProtected did, and in particular whether the live
// tree was left modified.
type Result struct {
	// Applied is true only when the whole patch landed.
	Applied bool `json:"applied"`
	// TreeMutated reports honestly whether the live tree differs from its
	// preimage now. A refused forward apply leaves it false: git apply is
	// all-or-nothing, so a rejected patch wrote nothing. It is true after a
	// successful apply, and — the case that matters — it is also true when a
	// write could not be withdrawn, because then the operator owns a tree they
	// did not ask for and must be told.
	TreeMutated bool     `json:"tree_mutated"`
	Reason      string   `json:"reason,omitempty"`
	Preimage    string   `json:"preimage_digest,omitempty"`
	Paths       []string `json:"paths,omitempty"`
}

// ApplyProtected applies a patch to a live project tree.
//
// It captures the exact preimage of the files the patch touches, re-asserts
// that preimage immediately before writing, applies all-or-nothing, and reports
// TreeMutated honestly.
//
// It never performs a destructive rollback. Recovery is limited to reversing
// the exact patch that was written; it will not run a checkout or reset that
// would also destroy unrelated operator work living in the same tree.
//
// This function does NOT decide policy. Callers must obtain an allowing
// Decision from Eligibility first — see the registry comment above.
func ApplyProtected(ctx context.Context, repoRoot string, patch []byte) (Result, error) {
	pre, err := CapturePreimage(ctx, repoRoot, patch)
	if err != nil {
		return Result{}, err
	}
	return ApplyWithPreimage(ctx, repoRoot, patch, pre)
}

// CapturePreimage records the state of every path the patch touches.
//
// It is exported so a caller can straddle the window deliberately — show an
// operator a preview, wait for a decision, then apply against the preimage that
// was actually reviewed. ApplyWithPreimage refuses if the tree moved in between.
func CapturePreimage(ctx context.Context, repoRoot string, patch []byte) (Preimage, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return Preimage{}, fmt.Errorf("delivery: resolve repo root: %w", err)
	}
	paths, err := patchPaths(ctx, root, patch)
	if err != nil {
		return Preimage{}, err
	}
	return snapshot(root, paths)
}

// ApplyWithPreimage applies the patch only if the tree still matches pre.
func ApplyWithPreimage(ctx context.Context, repoRoot string, patch []byte, pre Preimage) (Result, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return Result{}, fmt.Errorf("delivery: resolve repo root: %w", err)
	}
	res := Result{Preimage: pre.Digest, Paths: sortedKeys(pre.Entries)}

	if len(patch) == 0 {
		res.Reason = "empty patch; nothing to apply"
		return res, nil
	}

	// Re-assert the preimage at the last possible moment. Anything that changed
	// one of these files since capture — another agent, a rebuild, the operator
	// — invalidates the patch's assumptions about what it is editing.
	now, err := snapshot(root, res.Paths)
	if err != nil {
		res.Reason = redactSecrets(fmt.Sprintf("could not re-read the target preimage: %v", err))
		return res, nil
	}
	if now.Digest != pre.Digest {
		res.Reason = fmt.Sprintf(
			"the target changed after the preimage was captured (%s -> %s); refusing to apply against a tree that moved underneath the patch: %s",
			shortSHA(pre.Digest), shortSHA(now.Digest), describeDrift(pre, now))
		return res, nil
	}

	// --check writes nothing. Failing here keeps the tree pristine and turns a
	// doomed apply into a refusal rather than a partial write.
	if out, err := gitApply(ctx, root, patch, "--check"); err != nil {
		res.Reason = redactSecrets(fmt.Sprintf("patch does not apply to the live tree: %s", oneLine(out)))
		return res, nil
	}

	applyOut, applyErr := gitApply(ctx, root, patch)
	if applyErr == nil {
		res.Applied = true
		res.TreeMutated = true
		res.Reason = fmt.Sprintf("applied %d path(s)", len(res.Paths))
		return res, nil
	}

	// The apply failed after --check passed. git apply is all-or-nothing, so the
	// expectation is that nothing was written — but expectation is not evidence,
	// so verify against the preimage rather than asserting it.
	after, snapErr := snapshot(root, res.Paths)
	if snapErr == nil && after.Digest == pre.Digest {
		res.Reason = redactSecrets(fmt.Sprintf("apply failed and the tree is unchanged: %s", oneLine(applyOut)))
		return res, nil
	}

	// Something was written. Withdraw exactly what this patch wrote — a reverse
	// of the same patch, never a checkout or reset, which would take unrelated
	// work with it.
	if _, revErr := gitApply(ctx, root, patch, "-R"); revErr == nil {
		if back, err := snapshot(root, res.Paths); err == nil && back.Digest == pre.Digest {
			res.Reason = redactSecrets(fmt.Sprintf(
				"apply failed partway and was withdrawn by reversing the same patch; the tree is back at its preimage: %s",
				oneLine(applyOut)))
			return res, nil
		}
	}

	// A written postimage could not be removed. This IS a mutation and the
	// operator must be told plainly; silently reporting "not applied" here would
	// leave them believing a tree is clean when it is not.
	res.TreeMutated = true
	res.Reason = redactSecrets(fmt.Sprintf(
		"apply failed partway and could NOT be withdrawn; the live tree at %s is modified and needs manual inspection of: %s (%s)",
		root, strings.Join(res.Paths, ", "), oneLine(applyOut)))
	return res, nil
}

// patchPaths asks git which paths the patch touches. Using git rather than
// parsing the diff ourselves keeps rename, mode and binary hunks in agreement
// with the tool that will actually do the applying.
func patchPaths(ctx context.Context, root string, patch []byte) ([]string, error) {
	if len(patch) == 0 {
		return nil, nil
	}
	out, err := gitApply(ctx, root, patch, "--numstat")
	if err != nil {
		return nil, fmt.Errorf("delivery: cannot read patch contents: %s", oneLine(out))
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		p := fields[len(fields)-1]
		// The patch is attacker-influenced input. git apply refuses to escape the
		// tree, but this code also reads and hashes these paths directly, so it
		// validates containment itself rather than inheriting the guarantee.
		if !withinRoot(filepath.Join(root, p), root) {
			return nil, fmt.Errorf("delivery: patch references a path outside the repository: %q", p)
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

func snapshot(root string, paths []string) (Preimage, error) {
	entries := make(map[string]string, len(paths))
	for _, p := range paths {
		full := filepath.Join(root, p)
		data, err := os.ReadFile(full)
		switch {
		case err == nil:
			entries[p] = "sha256:" + canonicalize.HashBytes(data)
		case errors.Is(err, os.ErrNotExist):
			entries[p] = absentMarker
		default:
			return Preimage{}, fmt.Errorf("delivery: read %s: %w", p, err)
		}
	}
	digest, err := canonicalize.CanonicalHash(entries)
	if err != nil {
		return Preimage{}, fmt.Errorf("delivery: hash preimage: %w", err)
	}
	return Preimage{Entries: entries, Digest: digest}, nil
}

// describeDrift names the paths that moved, so the refusal points at a file
// rather than at two opaque hashes.
func describeDrift(before, after Preimage) string {
	var moved []string
	for p, was := range before.Entries {
		if now, ok := after.Entries[p]; !ok || now != was {
			moved = append(moved, p)
		}
	}
	sort.Strings(moved)
	if len(moved) == 0 {
		return "no individual path identified"
	}
	return strings.Join(moved, ", ")
}

func gitApply(ctx context.Context, dir string, patch []byte, extra ...string) (string, error) {
	args := append([]string{"apply", "--binary"}, extra...)
	args = append(args, "-")
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(patch)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func withinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
