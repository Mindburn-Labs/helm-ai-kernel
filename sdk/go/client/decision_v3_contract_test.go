// quantum_posture: SDK contract coverage preserves signature fields but does not implement or claim a cryptographic control.
package client

import (
	"testing"

	kernelv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/kernel/v1"
	"google.golang.org/protobuf/proto"
)

func TestDecisionRecordRoundTripPreservesV3Bindings(t *testing.T) {
	original := &kernelv1.DecisionRecord{
		Id:                "decision-v3-wire",
		Verdict:           kernelv1.Verdict_VERDICT_ALLOW,
		ReasonCode:        kernelv1.ReasonCode_REASON_CODE_POLICY_VIOLATION,
		ReasonCodeText:    "POLICY_MATCHED",
		EffectDigest:      "sha256:effect",
		SignatureVersion:  "decision_record.v3",
		PhenotypeHash:     "sha256:phenotype",
		PolicyContentHash: "sha256:policy",
		SubjectId:         "agent:alice",
		Action:            "EXECUTE_TOOL",
		Resource:          "github.create_issue",
		SignatureType:     "ed25519:key-1",
		Signature:         "signature-bytes",
	}
	wire, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal DecisionRecord: %v", err)
	}
	var decoded kernelv1.DecisionRecord
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal DecisionRecord: %v", err)
	}
	if decoded.Id != original.Id ||
		decoded.Verdict != original.Verdict ||
		decoded.ReasonCode != original.ReasonCode ||
		decoded.ReasonCodeText != original.ReasonCodeText ||
		decoded.EffectDigest != original.EffectDigest ||
		decoded.Signature != original.Signature ||
		decoded.SubjectId != original.SubjectId ||
		decoded.Action != original.Action ||
		decoded.Resource != original.Resource ||
		decoded.SignatureType != original.SignatureType ||
		decoded.SignatureVersion != original.SignatureVersion ||
		decoded.PhenotypeHash != original.PhenotypeHash ||
		decoded.PolicyContentHash != original.PolicyContentHash {
		t.Fatalf("protobuf roundtrip dropped V3 decision binding: got %+v", &decoded)
	}
}
