package github

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// prepareBranch checks the branch preconditions Prepare can read.
func (c *client) prepareBranch(ctx context.Context, info repoInfo, args branchArgs) error {
	if args.Head == info.DefaultBranch {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "head %q is the default branch", args.Head)
	}
	if _, err := c.getBranchHead(ctx, args.Head); err == nil {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s already exists", args.Head)
	} else if !isNotFound(err) {
		return err
	}
	if _, err := c.getCommit(ctx, args.BaseSHA); err != nil {
		if isNotFound(err) {
			return adapters.Refuse(contracts.ReasonPreconditionFailed, "base_sha %s is not a commit of the repository", args.BaseSHA)
		}
		return err
	}
	return nil
}

// dispatchBranch creates the blobs, a tree on base_sha's tree, a commit whose
// only parent is base_sha, and then refs/heads/{head}. Only the last write is
// visible: until the ref exists the new objects are unreachable, so any
// failure before it is NOT_SENT. An existing ref is never overwritten: the
// dispatch is SENT without a write, and Observe judges its content.
func (c *client) dispatchBranch(ctx context.Context, args branchArgs) adapters.DispatchResult {
	info, err := c.getRepo(ctx)
	if err != nil {
		return notSent(err)
	}
	if args.Head == info.DefaultBranch {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "head %q is the default branch", args.Head))
	}
	switch _, err := c.getBranchHead(ctx, args.Head); {
	case err == nil:
		return adapters.DispatchResult{Status: adapters.DispatchSent,
			Detail: "refs/heads/" + args.Head + " already exists and was not overwritten; Observe decides whether it is this effect"}
	case !isNotFound(err):
		return notSent(err)
	}
	base, err := c.getCommit(ctx, args.BaseSHA)
	if err != nil {
		if isNotFound(err) {
			return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "base_sha %s is not a commit of the repository", args.BaseSHA))
		}
		return notSent(err)
	}

	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(args.Files))
	for _, f := range args.Files {
		blob, err := c.post(ctx, "/git/blobs", map[string]string{"content": f.Content, "encoding": "utf-8"})
		if err != nil {
			return notSent(err)
		}
		if want := blobSHA1(f.Content); blob.SHA != want {
			return notSent(adapters.Refuse(contracts.ReasonReadbackMismatch, "GitHub stored %s as blob %s, want %s", f.Path, blob.SHA, want))
		}
		entries = append(entries, treeEntry{Path: f.Path, Mode: f.Mode, Type: "blob", SHA: blob.SHA})
	}
	tree, err := c.post(ctx, "/git/trees", map[string]any{"base_tree": base.Tree.SHA, "tree": entries})
	if err != nil {
		return notSent(err)
	}
	commit, err := c.post(ctx, "/git/commits", map[string]any{
		"message": args.Message,
		"tree":    tree.SHA,
		"parents": []string{args.BaseSHA},
	})
	if err != nil {
		return notSent(err)
	}
	var created gitRef
	err = c.call(ctx, http.MethodPost, c.repoPath("/git/refs"), nil,
		map[string]string{"ref": "refs/heads/" + args.Head, "sha": commit.SHA}, &created, c.a.maxResponseBytes)
	return writeResult(err)
}

// observeBranch is the read-back. SUCCEEDED needs all of: refs/heads/{head}
// points at a commit; its parents are exactly [base_sha]; the comparison
// base_sha...commit lists exactly the proposed paths; and each listed blob is
// the SHA-1 of the proposed content. Anything else is READBACK_MISMATCH; a
// read that fails is UNKNOWN.
func (c *client) observeBranch(ctx context.Context, args branchArgs) adapters.ObserveResult {
	ref := "refs/heads/" + args.Head
	result := &adapters.GitHubBranchResult{Ref: ref, BaseSHA: args.BaseSHA, FilesDigest: filesDigest(args.Files)}
	head, err := c.getBranchHead(ctx, args.Head)
	if isNotFound(err) {
		obs := c.observation()
		obs.GitHubBranch = result
		return settle(obs, ref+" does not exist")
	}
	if err != nil {
		return unknown(err)
	}
	result.CommitSHA = head
	commit, err := c.getCommit(ctx, head)
	if err != nil {
		return unknown(err)
	}
	mismatch := ""
	if len(commit.Parents) != 1 || commit.Parents[0].SHA != args.BaseSHA {
		parents := make([]string, 0, len(commit.Parents))
		for _, p := range commit.Parents {
			parents = append(parents, p.SHA)
		}
		mismatch = fmt.Sprintf("commit %s has parents %v, want [%s]", head, parents, args.BaseSHA)
	} else {
		var cmp comparison
		if err := c.call(ctx, http.MethodGet, c.repoPath("/compare/"+args.BaseSHA+"..."+head), nil, nil, &cmp, c.a.maxCompareBytes); err != nil {
			return unknown(err)
		}
		mismatch = compareFiles(cmp, args.Files)
	}
	obs := c.observation()
	obs.GitHubBranch = result
	return settle(obs, mismatch)
}

// compareFiles returns why a comparison is not exactly the proposed files,
// or "" when it is.
func compareFiles(cmp comparison, files []fileChange) string {
	want := map[string]string{}
	for _, f := range files {
		want[f.Path] = blobSHA1(f.Content)
	}
	var problems []string
	listed := map[string]bool{}
	for _, f := range cmp.Files {
		listed[f.Filename] = true
		sha, proposed := want[f.Filename]
		switch {
		case !proposed:
			problems = append(problems, fmt.Sprintf("%s is changed but not proposed", f.Filename))
		case f.Status != "added" && f.Status != "modified" && f.Status != "changed":
			problems = append(problems, fmt.Sprintf("%s is %s", f.Filename, f.Status))
		case f.SHA != sha:
			problems = append(problems, fmt.Sprintf("%s is blob %s, want %s", f.Filename, f.SHA, sha))
		}
	}
	for path := range want {
		if !listed[path] {
			problems = append(problems, fmt.Sprintf("%s is proposed but not changed", path))
		}
	}
	sort.Strings(problems)
	return strings.Join(problems, "; ")
}

// evidenceDigest is Observation.evidence_digest: SHA-256 over the read-back
// answers in the order they were read, each prefixed with its length as a
// big-endian uint64.
func evidenceDigest(bodies [][]byte) []byte {
	h := sha256.New()
	for _, b := range bodies {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	return h.Sum(nil)
}
