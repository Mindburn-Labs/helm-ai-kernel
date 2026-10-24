package effectargs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// AuthorityWorkReassignmentGrant is a Kernel-owned, approval-gated delegation
// of retained work results. It does not confer authority to execute an effect.
const AuthorityWorkReassignmentGrant = "helm.authority.work_reassignment.grant.v1"
const AuthorityWorkReassignmentRevoke = "helm.authority.work_reassignment.revoke.v1"

const WorkReassignmentManifest = "helm.work-reassignment.v1"

// IsMandateFreeAuthority names the gateway's own authority operations. These
// still require a registered service proposer; widening requires a distinct
// human approval and step-up before an adapter can install anything.
func IsMandateFreeAuthority(effectType string) bool {
	return IsAuthorityPlan(effectType) || effectType == AuthorityWorkReassignmentGrant || effectType == AuthorityWorkReassignmentRevoke
}

// WorkReassignmentRevoke is an exact narrowing of one installed grant.
type WorkReassignmentRevoke struct {
	Schema     string `json:"schema"`
	OrgRef     string `json:"org_ref"`
	GrantID    string `json:"grant_id"`
	Generation int64  `json:"generation"`
	Reason     string `json:"reason"`
}

func ParseWorkReassignmentRevoke(raw []byte) (*WorkReassignmentRevoke, error) {
	if len(raw) > MaxBytes {
		return nil, invalid("reassignment revocation exceeds %d bytes", MaxBytes)
	}
	if err := CheckNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	if _, err := reassignmentObject(raw, "schema", "org_ref", "grant_id", "generation", "reason"); err != nil {
		return nil, err
	}
	var revoke WorkReassignmentRevoke
	if err := strictDecode(raw, &revoke); err != nil {
		return nil, err
	}
	if revoke.Schema != AuthorityWorkReassignmentRevoke || !ValidOrgRef(revoke.OrgRef) ||
		!reassignmentIDPattern.MatchString(revoke.GrantID) || revoke.Generation < 1 ||
		len(revoke.Reason) == 0 || len(revoke.Reason) > 1024 {
		return nil, invalid("reassignment revocation has an invalid scope or reason")
	}
	return &revoke, nil
}

const (
	maxReassignmentSources  = 16
	maxReassignmentAttempts = 48
)

var reassignmentIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var reassignmentClaimIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var reassignmentActorIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,256}$`)
var reassignmentDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// WorkReassignmentGrant is the closed, immutable input that a trusted CP
// producer submits to Kernel admission. The Kernel verifies every listed
// member against its own attempt ledger before installing a grant.
type WorkReassignmentGrant struct {
	Schema                    string                    `json:"schema"`
	ReassignmentID            string                    `json:"reassignment_id"`
	PredecessorReassignmentID string                    `json:"predecessor_reassignment_id,omitempty"`
	ManifestDigest            string                    `json:"manifest_digest"`
	DrainDigest               string                    `json:"drain_digest"`
	OrgRef                    string                    `json:"org_ref"`
	WorkItemID                string                    `json:"work_item_id"`
	OrganizationVersionID     string                    `json:"organization_version_id"`
	CommitmentID              string                    `json:"commitment_id"`
	TermsDigest               string                    `json:"terms_digest"`
	PlanDigest                string                    `json:"plan_digest"`
	AuthorityRevision         int64                     `json:"authority_revision"`
	ExpectedGeneration        int64                     `json:"expected_generation"`
	Generation                int64                     `json:"generation"`
	ExpiresAt                 time.Time                 `json:"expires_at"`
	Recipient                 WorkReassignmentRecipient `json:"recipient"`
	Sources                   []WorkReassignmentSource  `json:"sources"`
}

type WorkReassignmentRecipient struct {
	EpisodeID   string `json:"episode_id"`
	SeatID      string `json:"seat_id"`
	PrincipalID string `json:"principal_id"`
	ActorID     string `json:"actor_id"`
	Profile     string `json:"profile"`
	Client      string `json:"client"`
}

type WorkReassignmentSource struct {
	EpisodeID   string   `json:"episode_id"`
	SeatID      string   `json:"seat_id"`
	PrincipalID string   `json:"principal_id"`
	ActorID     string   `json:"actor_id"`
	Profile     string   `json:"profile"`
	AttemptIDs  []string `json:"attempt_ids"`
}

// ParseWorkReassignmentGrant checks the exact field names, bounds and
// principal/profile relationship. The general effect validator checks size,
// UTF-8 and duplicate keys before calling this function.
func ParseWorkReassignmentGrant(raw []byte) (*WorkReassignmentGrant, error) {
	if len(raw) > MaxBytes {
		return nil, invalid("reassignment grant exceeds %d bytes", MaxBytes)
	}
	if err := CheckNoDuplicateKeys(raw); err != nil {
		return nil, err
	}
	root, err := reassignmentObjectWithOptional(raw, "predecessor_reassignment_id", "schema", "reassignment_id", "manifest_digest", "drain_digest", "org_ref", "work_item_id", "organization_version_id", "commitment_id", "terms_digest", "plan_digest", "authority_revision", "expected_generation", "generation", "expires_at", "recipient", "sources")
	if err != nil {
		return nil, err
	}
	if _, err := reassignmentObject(root["recipient"], "episode_id", "seat_id", "principal_id", "actor_id", "profile", "client"); err != nil {
		return nil, invalid("recipient: %v", err)
	}
	// The digest is outside its own payload. It binds the exact closed
	// manifest fields after RFC 8785 canonicalization, independent of JSON
	// whitespace and object-key order.
	claimed := root["manifest_digest"]
	delete(root, "manifest_digest")
	withoutDigest, err := json.Marshal(root)
	if err != nil {
		return nil, invalid("manifest cannot be encoded")
	}
	canonical, err := canonicalize.JCS(withoutDigest)
	if err != nil {
		return nil, invalid("manifest cannot be canonicalized")
	}
	sum := sha256.Sum256(canonical)
	var declared string
	if err := json.Unmarshal(claimed, &declared); err != nil || declared != "sha256:"+hex.EncodeToString(sum[:]) {
		return nil, invalid("manifest_digest does not bind the manifest fields")
	}
	root["manifest_digest"] = claimed
	var sources []json.RawMessage
	if err := json.Unmarshal(root["sources"], &sources); err != nil || len(sources) == 0 || len(sources) > maxReassignmentSources {
		return nil, invalid("sources must name 1 to %d episodes", maxReassignmentSources)
	}
	for i, source := range sources {
		if _, err := reassignmentObject(source, "episode_id", "seat_id", "principal_id", "actor_id", "profile", "attempt_ids"); err != nil {
			return nil, invalid("sources[%d]: %v", i, err)
		}
	}
	var grant WorkReassignmentGrant
	if err := strictDecode(raw, &grant); err != nil {
		return nil, err
	}
	if grant.Schema != WorkReassignmentManifest || !reassignmentIDPattern.MatchString(grant.ReassignmentID) ||
		!reassignmentDigestPattern.MatchString(grant.ManifestDigest) || !reassignmentDigestPattern.MatchString(grant.DrainDigest) ||
		!ValidOrgRef(grant.OrgRef) || !reassignmentClaimIDPattern.MatchString(grant.WorkItemID) ||
		!reassignmentClaimIDPattern.MatchString(grant.OrganizationVersionID) ||
		!reassignmentClaimIDPattern.MatchString(grant.CommitmentID) ||
		!reassignmentDigestPattern.MatchString(grant.TermsDigest) || !sha256HexPattern.MatchString(grant.PlanDigest) ||
		grant.AuthorityRevision < 1 || grant.ExpectedGeneration < 0 || grant.Generation != grant.ExpectedGeneration+1 ||
		grant.ExpiresAt.IsZero() {
		return nil, invalid("reassignment grant has an invalid scope, digest, generation or expiry")
	}
	if _, present := root["predecessor_reassignment_id"]; present &&
		!reassignmentIDPattern.MatchString(grant.PredecessorReassignmentID) {
		return nil, invalid("predecessor_reassignment_id must name one exact grant")
	}
	r := grant.Recipient
	if !reassignmentClaimIDPattern.MatchString(r.EpisodeID) || !reassignmentClaimIDPattern.MatchString(r.SeatID) ||
		r.PrincipalID != "agt:"+r.SeatID || !reassignmentActorIDPattern.MatchString(r.ActorID) ||
		!slices.Contains([]string{"worker", "executor"}, r.Profile) || r.Profile == "worker" && r.Client != "" ||
		r.Profile == "executor" && !reassignmentClaimIDPattern.MatchString(r.Client) {
		return nil, invalid("recipient must bind one registered seat, actor and listener profile")
	}
	seenEpisodes, seenAttempts, count := map[string]bool{}, map[string]bool{}, 0
	for i, source := range grant.Sources {
		if !reassignmentClaimIDPattern.MatchString(source.EpisodeID) || source.EpisodeID == r.EpisodeID || seenEpisodes[source.EpisodeID] ||
			!reassignmentClaimIDPattern.MatchString(source.SeatID) || source.PrincipalID != "agt:"+source.SeatID ||
			(source.ActorID != "" && !reassignmentActorIDPattern.MatchString(source.ActorID)) ||
			(len(source.AttemptIDs) != 0 && source.ActorID == "") || source.Profile != r.Profile {
			return nil, invalid("sources[%d] has an invalid original identity or profile", i)
		}
		seenEpisodes[source.EpisodeID] = true
		for _, id := range source.AttemptIDs {
			if !reassignmentIDPattern.MatchString(id) || seenAttempts[id] {
				return nil, invalid("sources[%d] repeats or misnames an attempt", i)
			}
			seenAttempts[id] = true
			count++
		}
	}
	if count > maxReassignmentAttempts {
		return nil, invalid("grant must list at most %d unique attempts", maxReassignmentAttempts)
	}
	return &grant, nil
}

func reassignmentObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil || len(object) != len(keys) {
		return nil, fmt.Errorf("expected a closed object with %d fields", len(keys))
	}
	if err := exactKeys(object, keys, ""); err != nil {
		return nil, err
	}
	return object, nil
}

func reassignmentObjectWithOptional(raw []byte, optional string, keys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("expected a closed object")
	}
	if _, present := object[optional]; present {
		keys = append(keys, optional)
	}
	if len(object) != len(keys) {
		return nil, fmt.Errorf("expected a closed object with %d fields", len(keys))
	}
	if err := exactKeys(object, keys, ""); err != nil {
		return nil, err
	}
	return object, nil
}
