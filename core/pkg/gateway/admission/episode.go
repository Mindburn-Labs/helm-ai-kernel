package admission

// Worker episodes on attempts (HELM-752 K7, HELM-751 N1; docs/architecture/
// gateway-effect-api.md "Episode attempts"). A token minted for one bounded
// worker run carries it as a helm_episode claim, and the claim is the token's
// scope of work, never a request's:
//
//   - Propose records the claim's episode on the attempt, and takes the work
//     reference from the claim's work item (the attempt's case_id);
//   - reads by such a token see only the attempts of its own episode, whoever
//     else in the tenant made the rest.
//
// "Its own" means the episode and the principal the token names: an episode
// belongs to one seat, so an attempt of the same episode id proposed by another
// principal is not its own. A caller with no episode claim, the Control Plane's
// service principal among them, is held to neither: it reads every attempt of
// its tenant and workspace.

import (
	"regexp"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// claimIDPattern is what the token validator holds an id of the claim to
// (jwks claimID), and what the attempt row's CHECK holds it to.
var claimIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// validEpisode reports whether e is a claim the token layer can have produced.
func validEpisode(e *Episode) bool {
	return claimIDPattern.MatchString(e.EpisodeID) && claimIDPattern.MatchString(e.WorkItemID) &&
		(e.OrganizationVersionID == "" || claimIDPattern.MatchString(e.OrganizationVersionID))
}

// bindEpisode is a proposal under the caller's episode claim: the work
// reference is the claim's work item. A request that names a commitment, or a
// different case, is refused rather than corrected: the claim is the token's
// scope of work, and a caller that strays outside it is told so.
func bindEpisode(e *Episode, in ProposeInput) (ProposeInput, error) {
	if e == nil {
		return in, nil
	}
	switch {
	case in.CommitmentID != "":
		return in, refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"a token with an episode claim proposes under its work item, which a commitment does not replace")
	case in.CaseID != "" && in.CaseID != e.WorkItemID:
		return in, refuse(CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
			"a token with an episode claim proposes under its own work item only")
	}
	in.CaseID = e.WorkItemID
	return in, nil
}

// episodeScope is the episode a read is held to: the caller's own, or "" for a
// caller with no episode claim, which no episode restricts. The statements that
// read an attempt for a caller hold it to the attempts of that episode proposed
// by the caller's own principal:
//
//	AND ($4 = '' OR (episode_id = $4 AND requester_principal_id = $5))
//
// with $4 the episodeScope and $5 the caller's principal.
func episodeScope(c Caller) string {
	if c.Episode == nil {
		return ""
	}
	return c.Episode.EpisodeID
}
