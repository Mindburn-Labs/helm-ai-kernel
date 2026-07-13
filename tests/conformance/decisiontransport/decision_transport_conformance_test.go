package decisiontransport

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	sdkclient "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/client"
	kernelv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/kernel/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestKernelV1DecisionRecordV2RoundTripVerifies(t *testing.T) {
	t.Parallel()

	decision, verifier := signedTransportDecision(t)
	before := canonicalDecisionPayload(t, decision)

	wireRecord, err := kernelV1DecisionFromContracts(decision)
	if err != nil {
		t.Fatalf("kernelV1DecisionFromContracts: %v", err)
	}
	wire, err := proto.Marshal(wireRecord)
	if err != nil {
		t.Fatalf("marshal kernel v1 decision: %v", err)
	}
	var decodedWire kernelv1.DecisionRecord
	if err := proto.Unmarshal(wire, &decodedWire); err != nil {
		t.Fatalf("unmarshal kernel v1 decision: %v", err)
	}
	recovered, err := contractsDecisionFromKernelV1(&decodedWire)
	if err != nil {
		t.Fatalf("contractsDecisionFromKernelV1: %v", err)
	}

	assertVerifiedV2RoundTrip(t, "kernel v1 protobuf", decision, recovered, verifier, before)
}

func TestRESTSDKGoDecisionRecordV2RoundTripVerifies(t *testing.T) {
	t.Parallel()

	decision, verifier := signedTransportDecision(t)
	before := canonicalDecisionPayload(t, decision)

	serverJSON, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("marshal served DecisionRecord: %v", err)
	}
	var sdkDecision sdkclient.DecisionRecord
	if err := json.Unmarshal(serverJSON, &sdkDecision); err != nil {
		t.Fatalf("unmarshal served DecisionRecord into generated SDK model: %v", err)
	}
	clientJSON, err := json.Marshal(sdkDecision)
	if err != nil {
		t.Fatalf("marshal generated SDK DecisionRecord: %v", err)
	}
	var recovered contracts.DecisionRecord
	if err := json.Unmarshal(clientJSON, &recovered); err != nil {
		t.Fatalf("unmarshal generated SDK DecisionRecord into core contract: %v", err)
	}

	assertVerifiedV2RoundTrip(t, "generated REST Go SDK", decision, &recovered, verifier, before)
}

func signedTransportDecision(t *testing.T) (*contracts.DecisionRecord, *crypto.Ed25519Verifier) {
	t.Helper()

	signer, err := crypto.NewEd25519Signer("transport-v2")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	verifier, err := crypto.NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}

	zone := time.FixedZone("EEST", 3*60*60)
	decision := &contracts.DecisionRecord{
		ID:                     "decision-transport-v2",
		ProposalID:             "proposal-001",
		StepID:                 "step-001",
		PhenotypeHash:          "sha256:phenotype",
		PolicyVersion:          "policy-v42",
		SubjectID:              "principal:alice",
		Action:                 "EXECUTE_TOOL",
		Resource:               "files.write",
		TenantID:               "tenant-acme",
		WorkspaceID:            "workspace-prod",
		SessionID:              "session-001",
		EffectDigest:           "sha256:effect",
		PolicyBackend:          "helm",
		PolicyContentHash:      "sha256:policy-content",
		PolicyEpoch:            "42",
		PolicyDecisionHash:     "sha256:policy-decision",
		StateCursor:            "cursor-001",
		Snapshot:               "sha256:snapshot",
		EnvFingerprint:         "sha256:environment",
		Verdict:                string(contracts.VerdictEscalate),
		Reason:                 "human ceremony required",
		ReasonCode:             string(contracts.ReasonApprovalRequired),
		InputContext:           map[string]any{"approved": false, "request_id": "req-001", "risk": 0.125},
		TrajectoryRiskScore:    0.125,
		SessionCentroidHash:    "sha256:centroid",
		RiskAccumulationWindow: 3,
		RequirementSetHash:     "sha256:requirements",
		Timestamp:              time.Date(2026, time.July, 13, 15, 0, 0, 123456789, zone),
		Intervention: &contracts.InterventionMetadata{
			Type:         contracts.InterventionThrottle,
			ReasonCode:   "RATE_LIMITED",
			WaitDuration: 250 * time.Millisecond,
			TokensSaved:  11,
		},
	}
	if err := signer.SignDecision(decision); err != nil {
		t.Fatalf("SignDecision: %v", err)
	}
	if decision.SignatureSchema != crypto.DecisionSignatureSchemaV2 {
		t.Fatalf("SignatureSchema = %q, want %q", decision.SignatureSchema, crypto.DecisionSignatureSchemaV2)
	}
	return decision, verifier
}

func canonicalDecisionPayload(t *testing.T, decision *contracts.DecisionRecord) []byte {
	t.Helper()
	payload, err := crypto.CanonicalDecisionPayload(decision)
	if err != nil {
		t.Fatalf("CanonicalDecisionPayload: %v", err)
	}
	return payload
}

func assertVerifiedV2RoundTrip(t *testing.T, transport string, original, recovered *contracts.DecisionRecord, verifier *crypto.Ed25519Verifier, before []byte) {
	t.Helper()
	after := canonicalDecisionPayload(t, recovered)
	if string(after) != string(before) {
		t.Fatalf("v2 signing payload changed across %s\nbefore: %s\nafter:  %s", transport, before, after)
	}
	valid, err := verifier.VerifyDecision(recovered)
	if err != nil || !valid {
		t.Fatalf("VerifyDecision after %s = %v, %v; want true, nil", transport, valid, err)
	}
	if !recovered.Timestamp.Equal(original.Timestamp) {
		t.Fatalf("%s changed timestamp instant: got %s want %s", transport, recovered.Timestamp, original.Timestamp)
	}
	if !reflect.DeepEqual(recovered.InputContext, original.InputContext) {
		t.Fatalf("%s changed input context: got %#v want %#v", transport, recovered.InputContext, original.InputContext)
	}
	if !reflect.DeepEqual(recovered.Intervention, original.Intervention) {
		t.Fatalf("%s changed intervention: got %#v want %#v", transport, recovered.Intervention, original.Intervention)
	}
}

func kernelV1DecisionFromContracts(d *contracts.DecisionRecord) (*kernelv1.DecisionRecord, error) {
	if d == nil {
		return nil, fmt.Errorf("decision record is required")
	}
	inputContext, err := json.Marshal(d.InputContext)
	if err != nil {
		return nil, fmt.Errorf("marshal input context: %w", err)
	}

	p := &kernelv1.DecisionRecord{
		Id:                     d.ID,
		Verdict:                kernelV1VerdictFromContracts(d.Verdict),
		Reason:                 d.Reason,
		EffectDigest:           d.EffectDigest,
		RequirementSetHash:     d.RequirementSetHash,
		Signature:              d.Signature,
		PolicyDecisionHash:     d.PolicyDecisionHash,
		InputContext:           inputContext,
		SubjectId:              d.SubjectID,
		Action:                 d.Action,
		Resource:               d.Resource,
		TenantId:               d.TenantID,
		WorkspaceId:            d.WorkspaceID,
		SessionId:              d.SessionID,
		SignatureSchema:        d.SignatureSchema,
		SignatureType:          d.SignatureType,
		ProposalId:             d.ProposalID,
		StepId:                 d.StepID,
		PhenotypeHash:          d.PhenotypeHash,
		PolicyVersion:          d.PolicyVersion,
		PolicyBackend:          d.PolicyBackend,
		PolicyContentHash:      d.PolicyContentHash,
		PolicyEpoch:            d.PolicyEpoch,
		StateCursor:            d.StateCursor,
		Snapshot:               d.Snapshot,
		EnvFingerprint:         d.EnvFingerprint,
		ReasonCodeText:         d.ReasonCode,
		TrajectoryRiskScore:    d.TrajectoryRiskScore,
		SessionCentroidHash:    d.SessionCentroidHash,
		RiskAccumulationWindow: int32(d.RiskAccumulationWindow),
	}
	if !d.Timestamp.IsZero() {
		p.Timestamp = timestamppb.New(d.Timestamp.UTC())
		if err := p.Timestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("decision timestamp: %w", err)
		}
	}
	if d.Intervention != nil {
		p.Intervention = &kernelv1.DecisionInterventionMetadata{
			Type:              string(d.Intervention.Type),
			ReasonCode:        d.Intervention.ReasonCode,
			WaitDurationNanos: int64(d.Intervention.WaitDuration),
			TokensSaved:       d.Intervention.TokensSaved,
		}
	}
	return p, nil
}

func contractsDecisionFromKernelV1(p *kernelv1.DecisionRecord) (*contracts.DecisionRecord, error) {
	if p == nil {
		return nil, fmt.Errorf("kernel v1 decision record is required")
	}
	var timestamp time.Time
	if wireTimestamp := p.GetTimestamp(); wireTimestamp != nil {
		if err := wireTimestamp.CheckValid(); err != nil {
			return nil, fmt.Errorf("decision timestamp: %w", err)
		}
		timestamp = wireTimestamp.AsTime().UTC()
	}
	var inputContext map[string]any
	if len(p.GetInputContext()) > 0 {
		if err := json.Unmarshal(p.GetInputContext(), &inputContext); err != nil {
			return nil, fmt.Errorf("unmarshal input context: %w", err)
		}
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
		PolicyDecisionHash:     p.GetPolicyDecisionHash(),
		StateCursor:            p.GetStateCursor(),
		Snapshot:               p.GetSnapshot(),
		EnvFingerprint:         p.GetEnvFingerprint(),
		Verdict:                kernelV1VerdictToContracts(p.GetVerdict()),
		Reason:                 p.GetReason(),
		ReasonCode:             p.GetReasonCodeText(),
		InputContext:           inputContext,
		TrajectoryRiskScore:    p.GetTrajectoryRiskScore(),
		SessionCentroidHash:    p.GetSessionCentroidHash(),
		RiskAccumulationWindow: int(p.GetRiskAccumulationWindow()),
		RequirementSetHash:     p.GetRequirementSetHash(),
		Signature:              p.GetSignature(),
		SignatureSchema:        p.GetSignatureSchema(),
		SignatureType:          p.GetSignatureType(),
		Timestamp:              timestamp,
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

func kernelV1VerdictFromContracts(verdict string) kernelv1.Verdict {
	switch verdict {
	case string(contracts.VerdictAllow):
		return kernelv1.Verdict_VERDICT_ALLOW
	case string(contracts.VerdictDeny):
		return kernelv1.Verdict_VERDICT_DENY
	case string(contracts.VerdictEscalate):
		return kernelv1.Verdict_VERDICT_ESCALATE
	default:
		return kernelv1.Verdict_VERDICT_UNSPECIFIED
	}
}

func kernelV1VerdictToContracts(verdict kernelv1.Verdict) string {
	switch verdict {
	case kernelv1.Verdict_VERDICT_ALLOW:
		return string(contracts.VerdictAllow)
	case kernelv1.Verdict_VERDICT_DENY:
		return string(contracts.VerdictDeny)
	case kernelv1.Verdict_VERDICT_ESCALATE:
		return string(contracts.VerdictEscalate)
	default:
		return ""
	}
}
