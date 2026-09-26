package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// checkHeadAt refuses with PRECONDITION_FAILED unless refs/heads/{head}
// exists and points at sha.
func (c *client) checkHeadAt(ctx context.Context, head, sha string) error {
	got, err := c.getBranchHead(ctx, head)
	if isNotFound(err) {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s does not exist", head)
	}
	if err != nil {
		return err
	}
	if got != sha {
		return adapters.Refuse(contracts.ReasonPreconditionFailed, "refs/heads/%s is at %s, not the approved head_sha %s", head, got, sha)
	}
	return nil
}

// dispatchPullRequest re-reads the head, so a push after approval is caught,
// and then opens the draft pull request. An open pull request for the same
// head and base is not opened again: the dispatch is SENT without a write,
// and Observe decides whether it is this one.
func (c *client) dispatchPullRequest(ctx context.Context, args pullRequestArgs) adapters.DispatchResult {
	if err := c.checkHeadAt(ctx, args.Head, args.HeadSHA); err != nil {
		return notSent(err)
	}
	open, err := c.listPulls(ctx, args.Head, args.Base, "open")
	if err != nil {
		return notSent(err)
	}
	if len(open) > 0 {
		return adapters.DispatchResult{Status: adapters.DispatchSent,
			Detail: fmt.Sprintf("pull request #%d from %s into %s is already open; Observe decides whether it is this effect", open[0].Number, args.Head, args.Base)}
	}
	var created pullRequest
	err = c.call(ctx, http.MethodPost, c.repoPath("/pulls"), nil, map[string]any{
		"title": args.Title,
		"body":  args.Body,
		"head":  args.Head,
		"base":  args.Base,
		"draft": true,
	}, &created, c.a.maxResponseBytes)
	return writeResult(err)
}

// observePullRequest finds the pull request by head and base, preferring an
// open one. SUCCEEDED needs a draft from this repository, at head_sha, into
// base, with the proposed title; its state is recorded, not judged, because
// closing it later does not undo the effect. Anything else found is READBACK_MISMATCH
// with the URL recorded; none found is READBACK_MISMATCH with an empty
// result. A read that fails is UNKNOWN.
func (c *client) observePullRequest(ctx context.Context, args pullRequestArgs) adapters.ObserveResult {
	pulls, err := c.listPulls(ctx, args.Head, args.Base, "all")
	if err != nil {
		return unknown(err)
	}
	obs := c.observation()
	if len(pulls) == 0 {
		obs.GitHubPullRequest = &adapters.GitHubPullRequestResult{HeadRef: args.Head, BaseRef: args.Base}
		return settle(obs, fmt.Sprintf("no pull request from %s into %s", args.Head, args.Base))
	}
	// GitHub lists newest first; an open one is the candidate if there is
	// one, since at most one can be open per head and base.
	pr := pulls[0]
	for _, p := range pulls {
		if p.State == "open" {
			pr = p
			break
		}
	}
	obs.GitHubPullRequest = &adapters.GitHubPullRequestResult{
		URL:     pr.HTMLURL,
		Number:  pr.Number,
		NodeID:  pr.NodeID,
		HeadRef: pr.Head.Ref,
		HeadSHA: pr.Head.SHA,
		BaseRef: pr.Base.Ref,
		Draft:   pr.Draft,
		State:   pr.State,
	}
	var problems []string
	if !pr.Draft {
		problems = append(problems, "it is not a draft")
	}
	if pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, c.repo.fullName()) || pr.Head.Ref != args.Head {
		problems = append(problems, "its head is not "+args.Head+" of "+c.repo.fullName())
	}
	if pr.Head.SHA != args.HeadSHA {
		problems = append(problems, fmt.Sprintf("its head is at %s, want %s", pr.Head.SHA, args.HeadSHA))
	}
	if pr.Base.Ref != args.Base {
		problems = append(problems, fmt.Sprintf("its base is %s, want %s", pr.Base.Ref, args.Base))
	}
	if pr.Title != args.Title {
		problems = append(problems, "its title differs")
	}
	mismatch := ""
	if len(problems) > 0 {
		mismatch = fmt.Sprintf("pull request #%d: %s", pr.Number, strings.Join(problems, "; "))
	}
	return settle(obs, mismatch)
}
