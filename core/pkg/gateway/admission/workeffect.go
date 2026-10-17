package admission

// quantum_posture: SHA-256 identifies a governed work effect; no signing,
// signature verification or post-quantum claim is made here.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// ProposeWorkEffect admits a worker tool's intent using the verified work item,
// effect type, canonical target and intent digest as its identity (D8). A new
// transport request, session, episode, seat or framework does not authorize a
// second execution. The original attempt and its authority binding stay intact.
// Ordinary Propose and read-by-id retain their existing isolation contracts.
func (s *Service) ProposeWorkEffect(ctx context.Context, caller Caller, in ProposeInput) (Attempt, bool, error) {
	in, err := prepareWorkEffect(caller, in)
	if err != nil {
		return Attempt{}, false, err
	}
	return s.Propose(ctx, caller, in)
}

func prepareWorkEffect(caller Caller, in ProposeInput) (ProposeInput, error) {
	if err := checkCaller(caller); err != nil {
		return ProposeInput{}, err
	}
	if caller.Episode == nil {
		return ProposeInput{}, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "a work effect requires a verified episode claim")
	}
	var err error
	in, err = bindEpisode(caller.Episode, in)
	if err != nil {
		return ProposeInput{}, err
	}
	// Validate the original bytes before canonicalization: duplicate keys must
	// not disappear, and the closed effect schema and size bounds still apply.
	in.IdempotencyKey = "work:pending"
	if _, err := validateProposal(in); err != nil {
		return ProposeInput{}, err
	}
	in.Arguments, err = canonicalize.JCS(json.RawMessage(in.Arguments))
	if err != nil {
		return ProposeInput{}, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, "effect.arguments: %v", err)
	}
	in.workEffect = true
	in.IdempotencyKey = "work:" + hex.EncodeToString(workEffectDigest(caller, in))
	return in, nil
}

func workEffectDigest(caller Caller, in ProposeInput) []byte {
	target := in.Target
	switch in.EffectType {
	case effectargs.GitHubRepositoryGet, effectargs.GitHubBranchCreateFromChanges, effectargs.GitHubPullRequestCreateDraft, effectargs.GitHubPullRequestCreate, effectargs.GitHubPullRequestMerge:
		// GitHub owner/repository names are case-insensitive. Do not change
		// the stored target or the target against which mandates are evaluated.
		target = strings.ToLower(target)
	}
	intent := sha256.Sum256(in.Arguments)
	var m bytes.Buffer
	for _, part := range []string{"helm.gateway.v1.work-effect.v1", caller.TenantID, caller.WorkspaceID,
		caller.Episode.WorkItemID, in.EffectType, target} {
		field(&m, []byte(part))
	}
	field(&m, intent[:])
	sum := sha256.Sum256(m.Bytes())
	return sum[:]
}
