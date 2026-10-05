package server

import (
	"strings"
	"time"

	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// attemptProto renders a stored attempt on the wire.
func attemptProto(a admission.Attempt) *gatewayv1.EffectAttempt {
	out := &gatewayv1.EffectAttempt{
		AttemptId:            a.ID,
		IdempotencyKey:       a.IdempotencyKey,
		RequestDigest:        a.RequestDigest,
		RequesterPrincipalId: a.RequesterPrincipalID,
		MandateId:            a.MandateID,
		EffectType:           a.EffectType,
		Target:               a.Target,
		TargetDigest:         a.TargetDigest,
		ArgumentDigest:       a.ArgumentDigest,
		RiskClass:            riskProto(a.RiskClass),
		State:                stateProto(a.State),
		Outcome:              outcomeProto(a.Outcome),
		OutcomeBasis:         basisProto(a.OutcomeBasis),
		ReasonCode:           a.ReasonCode,
		Version:              a.Version,
		CreatedAt:            timestamppb.New(a.CreatedAt),
		UpdatedAt:            timestamppb.New(a.UpdatedAt),
		WorkspaceId:          a.WorkspaceID,
		RequesterActorId:     a.RequesterActorID,
	}
	if e := a.Episode; e != nil {
		out.Episode = &gatewayv1.EpisodeRef{EpisodeId: e.EpisodeID, WorkItemId: e.WorkItemID, OrganizationVersionId: e.OrganizationVersionID}
	}
	switch {
	case a.CommitmentID != "":
		out.WorkRef = &gatewayv1.EffectAttempt_CommitmentId{CommitmentId: a.CommitmentID}
	case a.CaseID != "":
		out.WorkRef = &gatewayv1.EffectAttempt_CaseId{CaseId: a.CaseID}
	}
	for _, q := range a.Quote {
		out.Quote = append(out.Quote, &gatewayv1.ResourceAmount{Unit: q.Unit, Amount: q.Amount})
	}
	if a.State == "ESCALATED" && a.ApprovalExpiresAt != nil {
		out.PendingApproval = &gatewayv1.PendingApproval{
			ApprovalDigest: a.ApprovalDigest,
			ExpiresAt:      timestamppb.New(*a.ApprovalExpiresAt),
		}
	}
	if ap := a.Approval; ap != nil {
		decision := gatewayv1.ApprovalDecision_APPROVAL_DECISION_REJECTED
		if ap.Decision == "APPROVED" {
			decision = gatewayv1.ApprovalDecision_APPROVAL_DECISION_APPROVED
		}
		out.Approval = &gatewayv1.Approval{
			ApproverPrincipalId: ap.ApproverPrincipalID, Decision: decision, ApprovalDigest: ap.ApprovalDigest,
			DecidedAt: timestamppb.New(ap.DecidedAt), Reason: ap.Reason, ApproverActorId: ap.ApproverActorID,
		}
	}
	if p := a.Permit; p != nil {
		permit := &gatewayv1.Permit{
			PermitId:       p.ID,
			ArgumentDigest: p.ArgumentDigest,
			ExpiresAt:      timestamppb.New(p.ExpiresAt),
			ClaimId:        p.ClaimID,
			VoidReasonCode: p.VoidReasonCode,
			ConsumedAt:     optionalTime(p.ConsumedAt),
		}
		for _, v := range p.AuthorityVersions {
			permit.AuthorityVersions = append(permit.AuthorityVersions, &gatewayv1.AuthorityVersion{
				Kind: rowKindProto(v.Kind), Key: v.Key, Version: v.Version,
			})
		}
		out.Permit = permit
	}
	for _, x := range a.Exposures {
		out.Exposures = append(out.Exposures, &gatewayv1.Exposure{
			LimitId: x.LimitID, BucketStart: optionalTime(x.BucketStart), Kind: exposureProto(x.Kind), Amount: x.Amount,
		})
	}
	if o := a.LatestObservation; o != nil {
		out.LatestObservation = observationProto(o)
	}
	if m := a.ModelCall; m != nil {
		out.ModelCall = &gatewayv1.ModelCallSettlement{
			Route: m.Route, State: settlementProto(m.State), CurrencyCode: m.CurrencyCode, HeldMicros: m.HeldMicros,
			EstimatedMicros: m.EstimatedMicros, ConfirmedMicros: m.ConfirmedMicros, BillableMicros: m.BillableMicros,
		}
	}
	return out
}

// observationProto renders an observation with its typed result, converting
// the adapter's plain mirrors into the generated messages.
func observationProto(o *admission.Observation) *gatewayv1.Observation {
	out := &gatewayv1.Observation{
		Source: o.Source, TrustClass: o.TrustClass, Outcome: outcomeProto(o.Outcome),
		EvidenceDigest: o.EvidenceDigest, ObservedAt: timestamppb.New(o.ObservedAt), ResultRef: o.ResultRef,
	}
	switch {
	case o.GitHubPullRequest != nil:
		r := o.GitHubPullRequest
		out.Result = &gatewayv1.Observation_GithubPullRequest{GithubPullRequest: &gatewayv1.GitHubPullRequestResult{
			Url: r.URL, Number: r.Number, NodeId: r.NodeID, HeadRef: r.HeadRef, HeadSha: r.HeadSHA, BaseRef: r.BaseRef,
			Draft: r.Draft, State: r.State, Merged: r.Merged, MergeCommitSha: r.MergeCommitSHA,
		}}
	case o.GitHubBranch != nil:
		r := o.GitHubBranch
		out.Result = &gatewayv1.Observation_GithubBranch{GithubBranch: &gatewayv1.GitHubBranchResult{
			Ref: r.Ref, CommitSha: r.CommitSHA, BaseSha: r.BaseSHA, FilesDigest: r.FilesDigest,
		}}
	case o.GitHubRepository != nil:
		r := o.GitHubRepository
		out.Result = &gatewayv1.Observation_GithubRepository{GithubRepository: &gatewayv1.GitHubRepositoryResult{
			DefaultBranch: r.DefaultBranch, DefaultBranchSha: r.DefaultBranchSHA, Branch: r.Branch, BranchSha: r.BranchSHA,
			BranchExists: r.BranchExists,
		}}
	case o.Artifact != nil:
		r := o.Artifact
		out.Result = &gatewayv1.Observation_Artifact{Artifact: &gatewayv1.ArtifactResult{
			SchemaId: r.SchemaID, ContentType: r.ContentType, CanonicalBytes: r.CanonicalBytes, Digest: r.Digest,
		}}
	}
	return out
}

func stopProto(s admission.Stop) *gatewayv1.Stop {
	var kind gatewayv1.StopScopeKind
	for k, v := range stopKinds {
		if v == s.ScopeKind {
			kind = k
		}
	}
	return &gatewayv1.Stop{
		StopId: s.ID, ScopeKind: kind, ScopeKey: s.ScopeKey, Reason: s.Reason, CreatedByPrincipalId: s.IssuedBy,
		CreatedAt: timestamppb.New(s.CreatedAt), ExpiresAt: optionalTime(s.ExpiresAt), LiftedAt: optionalTime(s.LiftedAt),
	}
}

func optionalTime(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func stateProto(state string) gatewayv1.EffectAttemptState {
	return gatewayv1.EffectAttemptState(gatewayv1.EffectAttemptState_value["EFFECT_ATTEMPT_STATE_"+state])
}

// stateName is the name an attempt state is stored under, the inverse of
// stateProto. UNSPECIFIED and a number outside the enum have none.
func stateName(state gatewayv1.EffectAttemptState) (string, bool) {
	name, known := gatewayv1.EffectAttemptState_name[int32(state)]
	if !known || state == gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_UNSPECIFIED {
		return "", false
	}
	return strings.TrimPrefix(name, "EFFECT_ATTEMPT_STATE_"), true
}

func riskProto(risk string) gatewayv1.RiskClass {
	return map[string]gatewayv1.RiskClass{
		"low": gatewayv1.RiskClass_RISK_CLASS_LOW, "medium": gatewayv1.RiskClass_RISK_CLASS_MEDIUM,
		"high": gatewayv1.RiskClass_RISK_CLASS_HIGH, "irreversible": gatewayv1.RiskClass_RISK_CLASS_IRREVERSIBLE,
	}[risk]
}

func outcomeProto(outcome string) gatewayv1.EffectOutcome {
	return gatewayv1.EffectOutcome(gatewayv1.EffectOutcome_value["EFFECT_OUTCOME_"+outcome])
}

func basisProto(basis string) gatewayv1.OutcomeBasis {
	return gatewayv1.OutcomeBasis(gatewayv1.OutcomeBasis_value["OUTCOME_BASIS_"+basis])
}

func settlementProto(state string) gatewayv1.SettlementState {
	return gatewayv1.SettlementState(gatewayv1.SettlementState_value["SETTLEMENT_STATE_"+state])
}

func rowKindProto(kind string) gatewayv1.AuthorityRowKind {
	return map[string]gatewayv1.AuthorityRowKind{
		"tenant": gatewayv1.AuthorityRowKind_AUTHORITY_ROW_KIND_TENANT, "principal": gatewayv1.AuthorityRowKind_AUTHORITY_ROW_KIND_PRINCIPAL,
		"mandate": gatewayv1.AuthorityRowKind_AUTHORITY_ROW_KIND_MANDATE, "effect_type": gatewayv1.AuthorityRowKind_AUTHORITY_ROW_KIND_EFFECT_TYPE,
		"limit": gatewayv1.AuthorityRowKind_AUTHORITY_ROW_KIND_LIMIT,
	}[kind]
}

func exposureProto(kind string) gatewayv1.ExposureKind {
	return map[string]gatewayv1.ExposureKind{
		"held": gatewayv1.ExposureKind_EXPOSURE_KIND_HELD, "estimated": gatewayv1.ExposureKind_EXPOSURE_KIND_ESTIMATED,
		"confirmed": gatewayv1.ExposureKind_EXPOSURE_KIND_CONFIRMED, "released": gatewayv1.ExposureKind_EXPOSURE_KIND_RELEASED,
	}[kind]
}
