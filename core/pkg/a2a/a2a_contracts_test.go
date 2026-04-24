package a2a

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_SchemaVersionString(t *testing.T) {
	v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
	if v.String() != "1.2.3" {
		t.Fatalf("want 1.2.3, got %s", v.String())
	}
}

func TestFinal_CurrentVersionNotZero(t *testing.T) {
	if CurrentVersion.Major == 0 && CurrentVersion.Minor == 0 && CurrentVersion.Patch == 0 {
		t.Fatal("CurrentVersion should not be 0.0.0")
	}
}

func TestFinal_FeatureConstants(t *testing.T) {
	features := []Feature{FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync, FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments, FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation}
	seen := make(map[Feature]bool)
	for _, f := range features {
		if f == "" {
			t.Fatal("feature must not be empty")
		}
		if seen[f] {
			t.Fatalf("duplicate: %s", f)
		}
		seen[f] = true
	}
}

func TestFinal_DenyReasonConstants(t *testing.T) {
	reasons := []DenyReason{DenyVersionIncompatible, DenyFeatureMissing, DenyPolicyViolation, DenySignatureInvalid, DenyAgentNotTrusted, DenyChallengeFailure, DenyVouchRevoked}
	if len(reasons) != 7 {
		t.Fatal("want 7 deny reasons")
	}
}

func TestFinal_PolicyActionConstants(t *testing.T) {
	if PolicyAllow == PolicyDeny {
		t.Fatal("ALLOW and DENY must be distinct")
	}
}

func TestFinal_EnvelopeJSON(t *testing.T) {
	e := Envelope{EnvelopeID: "e1", OriginAgentID: "a1", TargetAgentID: "a2"}
	data, _ := json.Marshal(e)
	var e2 Envelope
	json.Unmarshal(data, &e2)
	if e2.EnvelopeID != "e1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SignatureJSON(t *testing.T) {
	s := Signature{KeyID: "k1", Algorithm: "ed25519", Value: "abc", AgentID: "a1"}
	data, _ := json.Marshal(s)
	var s2 Signature
	json.Unmarshal(data, &s2)
	if s2.KeyID != "k1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_NegotiationResultJSON(t *testing.T) {
	nr := NegotiationResult{Accepted: true, AgreedFeatures: []Feature{FeatureMeteringReceipts}}
	data, _ := json.Marshal(nr)
	var nr2 NegotiationResult
	json.Unmarshal(data, &nr2)
	if !nr2.Accepted {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ComputeEnvelopeHashDeterminism(t *testing.T) {
	e := &Envelope{EnvelopeID: "e1", SchemaVersion: CurrentVersion, OriginAgentID: "a1", TargetAgentID: "a2", PayloadHash: "ph1"}
	h1 := ComputeEnvelopeHash(e)
	h2 := ComputeEnvelopeHash(e)
	if h1 != h2 {
		t.Fatal("hash should be deterministic")
	}
}

func TestFinal_ComputeEnvelopeHashNonEmpty(t *testing.T) {
	e := &Envelope{EnvelopeID: "e1"}
	h := ComputeEnvelopeHash(e)
	if h == "" {
		t.Fatal("hash should not be empty")
	}
}

func TestFinal_SignEnvelope(t *testing.T) {
	e := &Envelope{EnvelopeID: "e1"}
	SignEnvelope(e, "k1", "ed25519", "a1")
	if e.Signature.KeyID != "k1" || e.Signature.Value == "" {
		t.Fatal("envelope should be signed")
	}
}

func TestFinal_TaskStatusIsTerminal(t *testing.T) {
	if !TaskStatusCompleted.IsTerminal() || !TaskStatusFailed.IsTerminal() || !TaskStatusCanceled.IsTerminal() {
		t.Fatal("COMPLETED, FAILED, CANCELED are terminal")
	}
	if TaskStatusSubmitted.IsTerminal() || TaskStatusWorking.IsTerminal() {
		t.Fatal("SUBMITTED, WORKING are not terminal")
	}
}

func TestFinal_TaskStatusConstants(t *testing.T) {
	statuses := []TaskStatus{TaskStatusSubmitted, TaskStatusWorking, TaskStatusInputRequired, TaskStatusCompleted, TaskStatusFailed, TaskStatusCanceled}
	if len(statuses) != 6 {
		t.Fatal("want 6 task statuses")
	}
}

func TestFinal_TaskJSON(t *testing.T) {
	task := Task{TaskID: "t1", Status: TaskStatusSubmitted, OriginAgent: "a1", TargetAgent: "a2", CreatedAt: time.Now()}
	data, _ := json.Marshal(task)
	var task2 Task
	json.Unmarshal(data, &task2)
	if task2.TaskID != "t1" || task2.Status != TaskStatusSubmitted {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TrustedKeyJSON(t *testing.T) {
	tk := TrustedKey{KeyID: "k1", AgentID: "a1", Algorithm: "ed25519", Active: true}
	data, _ := json.Marshal(tk)
	var tk2 TrustedKey
	json.Unmarshal(data, &tk2)
	if !tk2.Active {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PolicyRuleJSON(t *testing.T) {
	pr := PolicyRule{RuleID: "r1", OriginAgent: "*", TargetAgent: "a2", Action: PolicyAllow}
	data, _ := json.Marshal(pr)
	var pr2 PolicyRule
	json.Unmarshal(data, &pr2)
	if pr2.Action != PolicyAllow {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AgentCardJSON(t *testing.T) {
	ac := AgentCard{AgentID: "a1", Name: "test-agent", Description: "a test agent"}
	data, _ := json.Marshal(ac)
	var ac2 AgentCard
	json.Unmarshal(data, &ac2)
	if ac2.AgentID != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentEnvelopeHash(t *testing.T) {
	e := &Envelope{EnvelopeID: "e1", PayloadHash: "ph1"}
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ComputeEnvelopeHash(e)
		}()
	}
	wg.Wait()
}

func TestFinal_SchemaVersionJSON(t *testing.T) {
	v := SchemaVersion{Major: 2, Minor: 1, Patch: 0}
	data, _ := json.Marshal(v)
	var v2 SchemaVersion
	json.Unmarshal(data, &v2)
	if v2.Major != 2 || v2.Minor != 1 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DefaultVerifierInterface(t *testing.T) {
	var _ Verifier = (*DefaultVerifier)(nil)
}

func TestFinal_PropagationConfigJSON(t *testing.T) {
	pc := PropagationConfig{MaxHops: 3, DecayPerHop: 0.8}
	data, _ := json.Marshal(pc)
	var pc2 PropagationConfig
	json.Unmarshal(data, &pc2)
	if pc2.MaxHops != 3 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TrustPathJSON(t *testing.T) {
	tp := TrustPath{Hops: []string{"a1", "a2"}, FinalScore: 750}
	data, _ := json.Marshal(tp)
	var tp2 TrustPath
	json.Unmarshal(data, &tp2)
	if tp2.FinalScore != 750 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_VouchRecordJSON(t *testing.T) {
	vr := VouchRecord{VouchID: "v1", Voucher: "a1", Vouchee: "a2", Stake: 100}
	data, _ := json.Marshal(vr)
	var vr2 VouchRecord
	json.Unmarshal(data, &vr2)
	if vr2.Stake != 100 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_IATPSessionStatusConstants(t *testing.T) {
	statuses := []IATPSessionStatus{IATPPending, IATPAuthenticated, IATPFailed}
	for _, s := range statuses {
		if s == "" {
			t.Fatal("IATP status must not be empty")
		}
	}
}
