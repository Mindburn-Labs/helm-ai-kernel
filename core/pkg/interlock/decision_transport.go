// Package interlock converts the core DecisionRecord into the protobuf form
// embedded by the EffectInterlock service.
package interlock

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	interlockapi "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interlock/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DecisionRecordToProto converts a core DecisionRecord to the additive
// EffectInterlock protobuf representation. Every field included in the v2
// signing envelope has an explicit wire representation, so callers can safely
// marshal and later verify a signed decision.
func DecisionRecordToProto(d *contracts.DecisionRecord) (*interlockapi.DecisionRecord, error) {
	if d == nil {
		return nil, fmt.Errorf("decision record is required")
	}
	riskWindow, err := riskAccumulationWindowToProto(d.RiskAccumulationWindow)
	if err != nil {
		return nil, err
	}

	p := &interlockapi.DecisionRecord{
		ProposalId:             d.ProposalID,
		StepId:                 d.StepID,
		PhenotypeHash:          d.PhenotypeHash,
		StateCursor:            d.StateCursor,
		EnvFingerprint:         d.EnvFingerprint,
		Verdict:                decisionVerdictToProto(d.Verdict),
		Reason:                 d.Reason,
		Signature:              []byte(d.Signature),
		DecisionHash:           d.PolicyDecisionHash,
		TrajectoryRiskScore:    d.TrajectoryRiskScore,
		SessionCentroidHash:    d.SessionCentroidHash,
		RiskAccumulationWindow: riskWindow,
		SubjectId:              d.SubjectID,
		Action:                 d.Action,
		Resource:               d.Resource,
		SignatureSchema:        d.SignatureSchema,
		SignatureType:          d.SignatureType,
		Id:                     d.ID,
		PolicyVersion:          d.PolicyVersion,
		EffectDigest:           d.EffectDigest,
		PolicyBackend:          d.PolicyBackend,
		PolicyContentHash:      d.PolicyContentHash,
		PolicyEpoch:            d.PolicyEpoch,
		PolicyDecisionHash:     d.PolicyDecisionHash,
		Snapshot:               d.Snapshot,
		ReasonCode:             d.ReasonCode,
		RequirementSetHash:     d.RequirementSetHash,
		SignatureText:          d.Signature,
		VerdictText:            d.Verdict,
		TenantId:               d.TenantID,
		WorkspaceId:            d.WorkspaceID,
		SessionId:              d.SessionID,
	}

	if !d.Timestamp.IsZero() {
		p.Timestamp = timestamppb.New(d.Timestamp.UTC())
		if err := p.Timestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("decision timestamp: %w", err)
		}
	}
	if d.InputContext != nil {
		inputContext, err := json.Marshal(d.InputContext)
		if err != nil {
			return nil, fmt.Errorf("marshal decision input context: %w", err)
		}
		p.InputContextJson = inputContext
	}
	if d.Intervention != nil {
		p.Intervention = &interlockapi.DecisionInterventionMetadata{
			Type:              string(d.Intervention.Type),
			ReasonCode:        d.Intervention.ReasonCode,
			WaitDurationNanos: int64(d.Intervention.WaitDuration),
			TokensSaved:       d.Intervention.TokensSaved,
		}
	}

	return p, nil
}

// DecisionRecordFromProto reconstructs the core DecisionRecord from an
// EffectInterlock message. New explicit fields take precedence over retained
// legacy slots so a v2 signature is verified against the same preimage.
func DecisionRecordFromProto(p *interlockapi.DecisionRecord) (*contracts.DecisionRecord, error) {
	if p == nil {
		return nil, fmt.Errorf("protobuf decision record is required")
	}

	var decisionTimestamp time.Time
	timestamp := p.GetTimestamp()
	if timestamp != nil {
		if err := timestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("decision timestamp: %w", err)
		}
		decisionTimestamp = timestamp.AsTime().UTC()
	}

	var inputContext map[string]any
	if len(p.GetInputContextJson()) > 0 {
		if err := json.Unmarshal(p.GetInputContextJson(), &inputContext); err != nil {
			return nil, fmt.Errorf("unmarshal decision input context: %w", err)
		}
	}

	policyDecisionHash := p.GetPolicyDecisionHash()
	if policyDecisionHash == "" {
		policyDecisionHash = p.GetDecisionHash()
	}
	signature := p.GetSignatureText()
	if signature == "" {
		signature = string(p.GetSignature())
	}
	verdict := p.GetVerdictText()
	if verdict == "" {
		verdict = decisionVerdictFromProto(p.GetVerdict())
	}

	d := &contracts.DecisionRecord{
		ID:                     p.GetId(),
		ProposalID:             p.GetProposalId(),
		StepID:                 p.GetStepId(),
		PhenotypeHash:          p.GetPhenotypeHash(),
		PolicyVersion:          p.GetPolicyVersion(),
		SubjectID:              p.GetSubjectId(),
		Action:                 p.GetAction(),
		Resource:               p.GetResource(),
		TenantID:               p.GetTenantId(),
		WorkspaceID:            p.GetWorkspaceId(),
		SessionID:              p.GetSessionId(),
		EffectDigest:           p.GetEffectDigest(),
		PolicyBackend:          p.GetPolicyBackend(),
		PolicyContentHash:      p.GetPolicyContentHash(),
		PolicyEpoch:            p.GetPolicyEpoch(),
		PolicyDecisionHash:     policyDecisionHash,
		StateCursor:            p.GetStateCursor(),
		Snapshot:               p.GetSnapshot(),
		EnvFingerprint:         p.GetEnvFingerprint(),
		Verdict:                verdict,
		Reason:                 p.GetReason(),
		ReasonCode:             p.GetReasonCode(),
		InputContext:           inputContext,
		TrajectoryRiskScore:    p.GetTrajectoryRiskScore(),
		SessionCentroidHash:    p.GetSessionCentroidHash(),
		RiskAccumulationWindow: int(p.GetRiskAccumulationWindow()),
		RequirementSetHash:     p.GetRequirementSetHash(),
		Signature:              signature,
		SignatureSchema:        p.GetSignatureSchema(),
		SignatureType:          p.GetSignatureType(),
		Timestamp:              decisionTimestamp,
	}
	if p.GetIntervention() != nil {
		d.Intervention = &contracts.InterventionMetadata{
			Type:         contracts.InterventionType(p.GetIntervention().GetType()),
			ReasonCode:   p.GetIntervention().GetReasonCode(),
			WaitDuration: time.Duration(p.GetIntervention().GetWaitDurationNanos()),
			TokensSaved:  p.GetIntervention().GetTokensSaved(),
		}
	}
	return d, nil
}

func riskAccumulationWindowToProto(value int) (int32, error) {
	const maxInt32 = int(^uint32(0) >> 1)
	const minInt32 = -maxInt32 - 1
	if value < minInt32 || value > maxInt32 {
		return 0, fmt.Errorf("risk accumulation window %d exceeds protobuf int32 range", value)
	}
	return int32(value), nil
}

func decisionVerdictToProto(verdict string) interlockapi.Verdict {
	switch verdict {
	case string(contracts.VerdictAllow):
		return interlockapi.Verdict_VERDICT_ALLOW
	case string(contracts.VerdictDeny):
		return interlockapi.Verdict_VERDICT_DENY
	case string(contracts.VerdictEscalate):
		return interlockapi.Verdict_VERDICT_ESCALATE
	default:
		return interlockapi.Verdict_VERDICT_UNSPECIFIED
	}
}

func decisionVerdictFromProto(verdict interlockapi.Verdict) string {
	switch verdict {
	case interlockapi.Verdict_VERDICT_ALLOW:
		return string(contracts.VerdictAllow)
	case interlockapi.Verdict_VERDICT_DENY:
		return string(contracts.VerdictDeny)
	case interlockapi.Verdict_VERDICT_ESCALATE:
		return string(contracts.VerdictEscalate)
	default:
		return ""
	}
}
