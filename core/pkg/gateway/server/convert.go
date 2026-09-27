package server

import (
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
		out.LatestObservation = &gatewayv1.Observation{
			Source: o.Source, TrustClass: o.TrustClass, Outcome: outcomeProto(o.Outcome),
			EvidenceDigest: o.EvidenceDigest, ObservedAt: timestamppb.New(o.ObservedAt), ResultRef: o.ResultRef,
		}
	}
	return out
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
