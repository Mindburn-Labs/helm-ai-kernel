package github

import (
	"context"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// readRepository reads the default branch's head and, when args name one,
// a branch's head.
func (c *client) readRepository(ctx context.Context, args repositoryArgs) (*adapters.GitHubRepositoryResult, error) {
	info, err := c.getRepo(ctx)
	if err != nil {
		return nil, err
	}
	result := &adapters.GitHubRepositoryResult{DefaultBranch: info.DefaultBranch}
	if result.DefaultBranchSHA, err = c.getBranchHead(ctx, info.DefaultBranch); err != nil {
		return nil, err
	}
	if args.Branch == "" {
		return result, nil
	}
	result.Branch = args.Branch
	switch sha, err := c.getBranchHead(ctx, args.Branch); {
	case err == nil:
		result.BranchSHA, result.BranchExists = sha, true
	case !isNotFound(err):
		return nil, err
	}
	return result, nil
}

// dispatchRepository performs the read. It writes nothing, so every failure
// is NOT_SENT; the result is Observe's.
func (c *client) dispatchRepository(ctx context.Context, args repositoryArgs) adapters.DispatchResult {
	if _, err := c.readRepository(ctx, args); err != nil {
		return notSent(err)
	}
	return adapters.DispatchResult{Status: adapters.DispatchSent}
}

// observeRepository reads the repository again and returns the result. A read
// that fails is UNKNOWN.
func (c *client) observeRepository(ctx context.Context, args repositoryArgs) adapters.ObserveResult {
	result, err := c.readRepository(ctx, args)
	if err != nil {
		return unknown(err)
	}
	obs := c.observation()
	obs.GitHubRepository = result
	return settle(obs, "")
}
