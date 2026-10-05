package github

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// mergeReply is the GitHub2026-03-10 asynchronous merge response. Pending and
// enqueued only acknowledge the request; neither proves the effect happened.
type mergeReply struct {
	Status  string `json:"status"`
	Details struct {
		Message         string `json:"message"`
		UUID            string `json:"uuid"`
		SHA             string `json:"sha"`
		ExpectedHeadSHA string `json:"expected_head_sha"`
		MergeMethod     string `json:"merge_method"`
		MergeAction     string `json:"merge_action"`
		BypassRules     bool   `json:"bypass_rules"`
	} `json:"details"`
}

func (c *client) getPull(ctx context.Context, number int64) (pullRequest, error) {
	var pr pullRequest
	err := c.call(ctx, http.MethodGet, c.repoPath(fmt.Sprintf("/pulls/%d", number)), nil, nil, &pr, c.a.maxResponseBytes)
	return pr, err
}

func (c *client) mergeMismatch(pr pullRequest, args mergeArgs) string {
	switch {
	case pr.Number != args.Number:
		return "the pull request number differs"
	case pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, c.repo.fullName()):
		return "the pull request head is not in the approved repository"
	case pr.Base.Repo == nil || !strings.EqualFold(pr.Base.Repo.FullName, c.repo.fullName()):
		return "the pull request base is not in the approved repository"
	case pr.Head.SHA != args.HeadSHA:
		return "the pull request head is not the approved SHA"
	case pr.Base.Ref != args.Base:
		return "the pull request base differs"
	case pr.Draft:
		return "the pull request is a draft"
	case len(pr.Stack) > 0 && !bytes.Equal(bytes.TrimSpace(pr.Stack), []byte("null")):
		// Async merges may also merge downstack PRs. One effect authorizes only
		// one PR; even a malformed or one-element stack is outside this contract.
		return "stacked pull requests require a separately authorized scope"
	}
	return ""
}

func (c *client) checkMerge(ctx context.Context, args mergeArgs) (pullRequest, error) {
	pr, err := c.getPull(ctx, args.Number)
	if isNotFound(err) {
		return pr, adapters.Refuse(contracts.ReasonPreconditionFailed, "pull request not found")
	}
	if err != nil {
		return pr, err
	}
	if why := c.mergeMismatch(pr, args); why != "" {
		return pr, adapters.Refuse(contracts.ReasonPreconditionFailed, "%s", why)
	}
	if pr.Merged {
		if pr.State != "closed" || !shaRE.MatchString(pr.MergeCommitSHA) {
			return pr, adapters.Refuse(contracts.ReasonConnectorContractDrift, "merged pull request has no valid closed/commit readback")
		}
	} else if pr.State != "open" {
		return pr, adapters.Refuse(contracts.ReasonPreconditionFailed, "pull request is closed without a merge")
	}
	return pr, nil
}

func (c *client) dispatchMerge(ctx context.Context, args mergeArgs) adapters.DispatchResult {
	pr, err := c.checkMerge(ctx, args)
	if err != nil {
		return notSent(err)
	}
	if pr.Merged {
		return adapters.DispatchResult{Status: adapters.DispatchSent, Detail: "already merged at the approved head; no additional write"}
	}
	var reply mergeReply
	err = c.call(ctx, http.MethodPut, c.repoPath(fmt.Sprintf("/pulls/%d/merge-async", args.Number)), nil, map[string]any{
		"sha": args.HeadSHA, "merge_method": args.MergeMethod, "merge_action": "default", "bypass_rules": false,
	}, &reply, c.a.maxResponseBytes)
	if err != nil {
		return writeResult(err)
	}
	bad := func(why string) adapters.DispatchResult {
		return indefinite(adapters.Refuse(contracts.ReasonConnectorContractDrift, "%s", why))
	}
	switch reply.Status {
	case "pending":
		if reply.Details.UUID == "" || reply.Details.ExpectedHeadSHA != args.HeadSHA || reply.Details.MergeMethod != args.MergeMethod || reply.Details.MergeAction != "default" || reply.Details.BypassRules {
			return bad("pending merge options differ from the approved request; reconcile without resubmitting")
		}
	case "enqueued":
		// The request has finished but the merge queue has not merged the PR.
	case "merged":
		if !shaRE.MatchString(reply.Details.SHA) {
			return bad("merge acknowledgement has no valid commit SHA")
		}
	case "failed":
		return notSent(adapters.Refuse(contracts.ReasonPreconditionFailed, "GitHub refused the asynchronous merge"))
	default:
		return bad("unrecognized asynchronous merge state")
	}
	if strings.TrimSpace(reply.Details.Message) == "" {
		return bad("async merge response is missing its required details")
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent, Detail: "merge request acknowledged; only authoritative readback establishes success"}
}

func (c *client) observeMerge(ctx context.Context, args mergeArgs) adapters.ObserveResult {
	pr, err := c.getPull(ctx, args.Number)
	if err != nil {
		return unknown(err)
	}
	obs := c.observation()
	obs.GitHubPullRequest = &adapters.GitHubPullRequestResult{URL: pr.HTMLURL, Number: pr.Number, NodeID: pr.NodeID, HeadRef: pr.Head.Ref, HeadSHA: pr.Head.SHA, BaseRef: pr.Base.Ref, Draft: pr.Draft, State: pr.State, Merged: pr.Merged, MergeCommitSHA: pr.MergeCommitSHA}
	if why := c.mergeMismatch(pr, args); why != "" {
		return settle(obs, why)
	}
	if pr.Merged {
		if pr.State != "closed" || !shaRE.MatchString(pr.MergeCommitSHA) {
			return settle(obs, "merged pull request has no valid closed/commit readback")
		}
		return settle(obs, "")
	}
	if pr.State == "closed" {
		return settle(obs, "pull request was closed without a merge")
	}
	if pr.State != "open" {
		return unknown(adapters.Refuse(contracts.ReasonConnectorContractDrift, "unknown pull request state"))
	}
	// Do not set Absent: a queued/pending merge must not cause another PUT.
	return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown, Detail: "pull request is still open; merge pending or queued"}
}
