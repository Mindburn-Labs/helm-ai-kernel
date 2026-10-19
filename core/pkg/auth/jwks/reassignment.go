package jwks

import (
	"encoding/json"
	"errors"
)

// ReassignmentClaim is a signed reference to a Kernel-owned live grant. It
// carries no attempt membership or execution authority; every use resolves
// the current generation and member row in Kernel's tenant ledger.
type ReassignmentClaim struct {
	Version           string                `json:"version"`
	GrantID           string                `json:"grant_id"`
	Generation        int64                 `json:"generation"`
	ManifestDigest    string                `json:"manifest_digest"`
	ApplicationDigest string                `json:"application_digest"`
	WorkItemID        string                `json:"work_item_id"`
	Recipient         ReassignmentRecipient `json:"recipient"`
}

type ReassignmentRecipient struct {
	EpisodeID   string `json:"episode_id"`
	SeatID      string `json:"seat_id"`
	PrincipalID string `json:"principal_id"`
	ActorID     string `json:"actor_id"`
	Profile     string `json:"profile"`
	Client      string `json:"client"`
}

func (c *ReassignmentClaim) UnmarshalJSON(data []byte) error {
	if len(data) > maxContinuationClaimBytes || closedObject(data, "version", "grant_id", "generation", "manifest_digest", "application_digest", "work_item_id", "recipient") != nil {
		return errors.New("helm_reassignment is not a closed object")
	}
	type plain ReassignmentClaim
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = ReassignmentClaim(decoded)
	return nil
}

func (r *ReassignmentRecipient) UnmarshalJSON(data []byte) error {
	if closedObject(data, "episode_id", "seat_id", "principal_id", "actor_id", "profile", "client") != nil {
		return errors.New("helm_reassignment recipient is not a closed object")
	}
	type plain ReassignmentRecipient
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = ReassignmentRecipient(decoded)
	return nil
}

func (c *ReassignmentClaim) validFor(claims *jwksClaims, config JWKSConfig) bool {
	if c == nil || c.Version != "helm.reassignment.v1" || !canonicalAttemptID(c.GrantID) || c.Generation < 1 ||
		!sha256Ref(c.ManifestDigest) || !sha256Ref(c.ApplicationDigest) ||
		claims.HelmEpisode == nil || c.WorkItemID != claims.HelmEpisode.WorkItemID ||
		c.Recipient.EpisodeID != claims.HelmEpisode.EpisodeID || c.Recipient.PrincipalID != claims.Subject ||
		!claimID.MatchString(c.Recipient.SeatID) || c.Recipient.PrincipalID != "agt:"+c.Recipient.SeatID ||
		claims.Act == nil || c.Recipient.ActorID != claims.Act.Sub {
		return false
	}
	switch c.Recipient.Profile {
	case "worker":
		return !config.RequireExecutor && config.RejectExecutor && claims.HelmExecutor == nil && c.Recipient.Client == ""
	case "executor":
		return config.RequireExecutor && claims.HelmExecutor != nil &&
			executorClient(c.Recipient.Client) && claims.HelmExecutor.Client == c.Recipient.Client
	default:
		return false
	}
}
