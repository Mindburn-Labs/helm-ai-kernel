package interlock_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interlock"
	interlockapi "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/interlock/api"
	"google.golang.org/protobuf/proto"
)

func TestEffectInterlockDecisionRecordV2RoundTripVerifies(t *testing.T) {
	t.Parallel()

	signer, err := crypto.NewEd25519Signer("effect-interlock-v2")
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	verifier, err := crypto.NewEd25519Verifier(signer.PublicKeyBytes())
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}

	zone := time.FixedZone("EEST", 3*60*60)
	decision := &contracts.DecisionRecord{
		ID:                     "decision-effect-interlock-v2",
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

	before, err := crypto.CanonicalDecisionPayload(decision)
	if err != nil {
		t.Fatalf("CanonicalDecisionPayload before transport: %v", err)
	}
	protoDecision, err := interlock.DecisionRecordToProto(decision)
	if err != nil {
		t.Fatalf("DecisionRecordToProto: %v", err)
	}
	wire, err := proto.Marshal(&interlockapi.EffectRequest{
		ProposalId:     decision.ProposalID,
		StepId:         decision.StepID,
		ActionClass:    "tool",
		ToolName:       "filesystem",
		DecisionRecord: protoDecision,
	})
	if err != nil {
		t.Fatalf("marshal EffectRequest: %v", err)
	}

	var decoded interlockapi.EffectRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal EffectRequest: %v", err)
	}
	recovered, err := interlock.DecisionRecordFromProto(decoded.GetDecisionRecord())
	if err != nil {
		t.Fatalf("DecisionRecordFromProto: %v", err)
	}

	after, err := crypto.CanonicalDecisionPayload(recovered)
	if err != nil {
		t.Fatalf("CanonicalDecisionPayload after transport: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("v2 signing payload changed across EffectInterlock protobuf transport\nbefore: %s\nafter:  %s", before, after)
	}
	valid, err := verifier.VerifyDecision(recovered)
	if err != nil || !valid {
		t.Fatalf("VerifyDecision after EffectInterlock protobuf round trip = %v, %v; want true, nil", valid, err)
	}
	if !recovered.Timestamp.Equal(decision.Timestamp) {
		t.Fatalf("timestamp instant changed: got %s want %s", recovered.Timestamp, decision.Timestamp)
	}
	if !reflect.DeepEqual(recovered.InputContext, decision.InputContext) {
		t.Fatalf("input context changed: got %#v want %#v", recovered.InputContext, decision.InputContext)
	}
	if !reflect.DeepEqual(recovered.Intervention, decision.Intervention) {
		t.Fatalf("intervention changed: got %#v want %#v", recovered.Intervention, decision.Intervention)
	}
}
