package github

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// preparePush binds a push to an existing non-default head at exactly base_sha.
// The PR base must be an existing, distinct branch of the same repository.
func (c *client) preparePush(ctx context.Context, info repoInfo, args branchArgs) error {
	if err := c.checkPushScope(ctx, info, args); err != nil {
		return err
	}
	head, err := c.getBranchHead(ctx, args.Head)
	if isNotFound(err) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s does not exist", args.Head)
	}
	if err != nil {
		return err
	}
	if head != args.BaseSHA {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s is at %s, not the approved base_sha %s", args.Head, head, args.BaseSHA)
	}
	return nil
}

func (c *client) checkPushScope(ctx context.Context, info repoInfo, args branchArgs) error {
	if args.Head == info.DefaultBranch || args.Head == args.Base {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "head %q is the default branch or equals base", args.Head)
	}
	if _, err := c.getBranchHead(ctx, args.Base); isNotFound(err) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "base branch %q does not exist", args.Base)
	} else if err != nil {
		return err
	}
	return nil
}

// dispatchPush creates unreachable Git objects, then advances the existing ref
// by an atomic GraphQL updateRefs mutation. beforeOid requires the ref to be
// exactly base_sha at the write, while force=false also requires fast-forward.
func (c *client) dispatchPush(ctx context.Context, args branchArgs) adapters.DispatchResult {
	info, err := c.getRepo(ctx)
	if err != nil {
		return notSent(err)
	}
	if err := c.checkPushScope(ctx, info, args); err != nil {
		return notSent(err)
	}
	if info.NodeID == "" {
		return notSent(adapters.Refuse(contracts.ReasonConnectorContractDrift, "repository has no node_id for conditional ref update"))
	}
	head, err := c.getBranchHead(ctx, args.Head)
	if isNotFound(err) {
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s does not exist", args.Head))
	}
	if err != nil {
		return notSent(err)
	}
	if head != args.BaseSHA {
		// A prior lost reply may have applied this very push. Never write again
		// before checking the actual ref, commit parent and file contents.
		observed := c.observePush(ctx, args)
		if observed.Outcome == adapters.OutcomeSucceeded {
			return adapters.DispatchResult{Status: adapters.DispatchSent, Detail: "approved push already present; no additional write"}
		}
		if observed.Outcome == adapters.OutcomeUnknown {
			return indefinite(adapters.Refuse(observed.Reason, "%s", observed.Detail))
		}
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s moved from approved base_sha; no write", args.Head))
	}
	commit, err := c.commitFiles(ctx, args.BaseSHA, args.Message, args.Files)
	if err != nil {
		return notSent(err)
	}
	// GitHub checks both the expected old OID and fast-forward at the mutation.
	var updated struct {
		Data struct {
			UpdateRefs *struct {
				ClientMutationID string `json:"clientMutationId"`
			} `json:"updateRefs"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	err = c.call(ctx, http.MethodPost, "/graphql", nil, map[string]any{
		"query": `mutation($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }`,
		"variables": map[string]any{"input": map[string]any{
			"clientMutationId": commit.SHA,
			"repositoryId":     info.NodeID,
			"refUpdates": []map[string]any{{
				"name":      "refs/heads/" + args.Head,
				"beforeOid": args.BaseSHA,
				"afterOid":  commit.SHA,
				"force":     false,
			}},
		}},
	}, &updated, c.a.maxResponseBytes)
	if err != nil {
		return writeResult(err)
	}
	if len(updated.Errors) != 0 {
		// updateRefs is atomic. A rejected beforeOid leaves this mutation
		// unapplied, but the ref can concurrently be moved by another writer.
		current, readErr := c.getBranchHead(ctx, args.Head)
		if readErr != nil {
			return indefinite(readErr)
		}
		if current == commit.SHA {
			return adapters.DispatchResult{Status: adapters.DispatchSent, Detail: "approved commit already occupies the ref"}
		}
		if current != args.BaseSHA {
			return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s moved during the conditional push", args.Head))
		}
		return notSent(adapters.Refuse(contracts.ReasonProviderError, "GitHub rejected the conditional ref update: %s", updated.Errors[0].Message))
	}
	if updated.Data.UpdateRefs == nil || updated.Data.UpdateRefs.ClientMutationID != commit.SHA {
		return indefinite(adapters.Refuse(contracts.ReasonConnectorContractDrift, "push acknowledgement did not echo the mutation identity"))
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

// observePush uses the existing branch result contract: exact ref, sole parent
// base_sha, proposed paths and blob IDs. A ref still at base_sha shows that
// this push has not become visible; a different commit is a mismatch.
func (c *client) observePush(ctx context.Context, args branchArgs) adapters.ObserveResult {
	head, err := c.getBranchHead(ctx, args.Head)
	if isNotFound(err) {
		obs := c.observation()
		obs.GitHubBranch = &adapters.GitHubBranchResult{Ref: "refs/heads/" + args.Head, BaseSHA: args.BaseSHA, FilesDigest: filesDigest(args.Files)}
		r := settle(obs, fmt.Sprintf("refs/heads/%s does not exist", args.Head))
		r.Absent = true
		return r
	}
	if err != nil {
		return unknown(err)
	}
	if head == args.BaseSHA {
		obs := c.observation()
		obs.GitHubBranch = &adapters.GitHubBranchResult{Ref: "refs/heads/" + args.Head, BaseSHA: args.BaseSHA, CommitSHA: head, FilesDigest: filesDigest(args.Files)}
		r := settle(obs, fmt.Sprintf("refs/heads/%s is still at approved base_sha", args.Head))
		r.Absent = true
		return r
	}
	commit, err := c.getCommit(ctx, head)
	if err != nil {
		return unknown(err)
	}
	result := c.observeBranch(ctx, args)
	if result.Observation != nil && result.Observation.GitHubBranch != nil && result.Observation.GitHubBranch.CommitSHA != head {
		return unknown(adapters.Refuse(contracts.ReasonProviderError, "branch head changed during push readback"))
	}
	if result.Outcome == adapters.OutcomeSucceeded && commit.Message != args.Message {
		return settle(result.Observation, "push commit message differs from approved arguments")
	}
	return result
}

// commitFiles creates the content-addressed objects for either branch creation
// or a conditional push. No ref points at them until the final ref write.
func (c *client) commitFiles(ctx context.Context, parentSHA, message string, files []fileChange) (gitObject, error) {
	base, err := c.getCommit(ctx, parentSHA)
	if isNotFound(err) {
		return gitObject{}, adapters.Refuse(contracts.ReasonPreconditionFailed, "base_sha %s is not a commit of the repository", parentSHA)
	}
	if err != nil {
		return gitObject{}, err
	}
	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]treeEntry, 0, len(files))
	for _, f := range files {
		blob, err := c.post(ctx, "/git/blobs", map[string]string{"content": f.Content, "encoding": "utf-8"})
		if err != nil {
			return gitObject{}, err
		}
		if want := blobSHA1(f.Content); blob.SHA != want {
			return gitObject{}, adapters.Refuse(contracts.ReasonReadbackMismatch, "GitHub stored %s as blob %s, want %s", f.Path, blob.SHA, want)
		}
		entries = append(entries, treeEntry{Path: f.Path, Mode: f.Mode, Type: "blob", SHA: blob.SHA})
	}
	tree, err := c.post(ctx, "/git/trees", map[string]any{"base_tree": base.Tree.SHA, "tree": entries})
	if err != nil {
		return gitObject{}, err
	}
	return c.post(ctx, "/git/commits", map[string]any{"message": message, "tree": tree.SHA, "parents": []string{parentSHA}})
}
