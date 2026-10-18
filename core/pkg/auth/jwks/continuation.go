package jwks

// quantum_posture: this is a structural JWT claim check; the existing RS256
// validator authenticates the token. No post-quantum signature is claimed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	maxContinuationClaimBytes = 4 << 10
	maxContinuationSources    = 16
	maxContinuationAttempts   = 48
)

// ContinuationClaim is a CP-issued, read/replay-only grant to the exact
// predecessor attempts named by a committed executor-client handoff. It never
// supplies a mandate, approval, permit, or authority to execute an old attempt.
type ContinuationClaim struct {
	Version               string                `json:"version"`
	HandoffRef            string                `json:"handoff_ref"`
	ReceiptDigest         string                `json:"receipt_digest"`
	HandoffRecordedAt     time.Time             `json:"handoff_recorded_at"`
	TenantID              string                `json:"tenant_id"`
	WorkspaceID           string                `json:"workspace_id"`
	OrganizationID        string                `json:"organization_id"`
	WorkItemID            string                `json:"work_item_id"`
	OrganizationVersionID string                `json:"organization_version_id"`
	CommitmentID          string                `json:"commitment_id"`
	PlanDigest            string                `json:"plan_digest"`
	AuthorityRevision     int64                 `json:"authority_revision"`
	TermsDigest           string                `json:"terms_digest"`
	Successor             ContinuationSuccessor `json:"successor"`
	Sources               []ContinuationSource  `json:"sources"`
}

type ContinuationSuccessor struct {
	EpisodeID   string `json:"episode_id"`
	SeatID      string `json:"seat_id"`
	PrincipalID string `json:"principal_id"`
	ActorID     string `json:"actor_id"`
}

type ContinuationSource struct {
	EpisodeID       string     `json:"episode_id"`
	SeatID          string     `json:"seat_id"`
	PrincipalID     string     `json:"principal_id"`
	ActorID         string     `json:"actor_id"`
	AdmissibleUntil *time.Time `json:"admissible_until"`
	SettledBefore   *time.Time `json:"settled_before"`
	AttemptIDs      []string   `json:"attempt_ids"`
}

func (c *ContinuationClaim) UnmarshalJSON(data []byte) error {
	if len(data) > maxContinuationClaimBytes || closedObject(data, "version", "handoff_ref", "receipt_digest", "handoff_recorded_at", "tenant_id", "workspace_id", "organization_id", "work_item_id", "organization_version_id", "commitment_id", "plan_digest", "authority_revision", "terms_digest", "successor", "sources") != nil {
		return errors.New("helm_continuation is not a closed object")
	}
	type plain ContinuationClaim
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = ContinuationClaim(decoded)
	return nil
}

func (s *ContinuationSuccessor) UnmarshalJSON(data []byte) error {
	if closedObject(data, "episode_id", "seat_id", "principal_id", "actor_id") != nil {
		return errors.New("helm_continuation successor is not a closed object")
	}
	type plain ContinuationSuccessor
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = ContinuationSuccessor(decoded)
	return nil
}

func (s *ContinuationSource) UnmarshalJSON(data []byte) error {
	if closedObject(data, "episode_id", "seat_id", "principal_id", "actor_id", "admissible_until", "settled_before", "attempt_ids") != nil {
		return errors.New("helm_continuation source is not a closed object")
	}
	type plain ContinuationSource
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = ContinuationSource(decoded)
	return nil
}

// closedObject requires every versioned member and rejects unknown or duplicate
// keys, including duplicates Go's normal JSON decoder silently replaces.
func closedObject(data []byte, names ...string) error {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("expected object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return errors.New("unknown or duplicate key")
		}
		seen[key] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("unterminated object")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if len(seen) != len(allowed) {
		return errors.New("missing key")
	}
	return nil
}

func (c *ContinuationClaim) validFor(claims *jwksClaims) bool {
	if c == nil || c.Version != "helm.continuation.v1" || !strings.HasPrefix(c.HandoffRef, "cp:executor-continuation:") ||
		!canonicalAttemptID(strings.TrimPrefix(c.HandoffRef, "cp:executor-continuation:")) || !sha256Ref(c.ReceiptDigest) ||
		c.HandoffRecordedAt.IsZero() ||
		c.TenantID != claims.TenantID || c.WorkspaceID != claims.WorkspaceID || !claimID.MatchString(c.OrganizationID) ||
		claims.HelmEpisode == nil || c.WorkItemID != claims.HelmEpisode.WorkItemID || c.OrganizationVersionID != claims.HelmEpisode.OrganizationVersionID ||
		!claimID.MatchString(c.CommitmentID) || !lowerHex64(c.PlanDigest) || c.AuthorityRevision < 1 || !sha256Ref(c.TermsDigest) ||
		c.Successor.EpisodeID != claims.HelmEpisode.EpisodeID || c.Successor.PrincipalID != claims.Subject ||
		c.Successor.SeatID == "" || c.Successor.PrincipalID != "agt:"+c.Successor.SeatID || claims.Act == nil || c.Successor.ActorID != claims.Act.Sub ||
		len(c.Sources) == 0 || len(c.Sources) > maxContinuationSources {
		return false
	}
	seenEpisode, seenAttempt, count := map[string]bool{}, map[string]bool{}, 0
	for _, source := range c.Sources {
		if !claimID.MatchString(source.EpisodeID) || source.EpisodeID == c.Successor.EpisodeID || seenEpisode[source.EpisodeID] ||
			!claimID.MatchString(source.SeatID) || source.SeatID != c.Successor.SeatID || source.PrincipalID != c.Successor.PrincipalID ||
			len(source.ActorID) > 512 || len(source.AttemptIDs) > 0 && source.ActorID == "" ||
			(source.AdmissibleUntil == nil) != (source.SettledBefore == nil) ||
			len(source.AttemptIDs) > 0 && source.AdmissibleUntil == nil {
			return false
		}
		if source.AdmissibleUntil != nil && (source.AdmissibleUntil.IsZero() || source.SettledBefore.IsZero() ||
			source.SettledBefore.Before(*source.AdmissibleUntil)) {
			return false
		}
		seenEpisode[source.EpisodeID] = true
		for _, id := range source.AttemptIDs {
			if !canonicalAttemptID(id) || seenAttempt[id] {
				return false
			}
			seenAttempt[id] = true
			count++
			if count > maxContinuationAttempts {
				return false
			}
		}
	}
	return count > 0
}

func sha256Ref(value string) bool {
	return strings.HasPrefix(value, "sha256:") && lowerHex64(strings.TrimPrefix(value, "sha256:"))
}

func lowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func canonicalAttemptID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if c < '0' || c > '9' && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
