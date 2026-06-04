package governance

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestPolicyEngineAgentSafetyBaselineLoaded(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	if !engine.AgentSafetyBaselineLoaded() {
		t.Fatal("agent safety baseline should be loaded by default")
	}
}

func TestEvaluateAgentSafetyBaselineAllow(t *testing.T) {
	engine, _ := NewPolicyEngine()
	decision, err := engine.EvaluateAgentSafetyBaseline(context.Background(), safeAgentSafetyContext())
	if err != nil {
		t.Fatalf("EvaluateAgentSafetyBaseline: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("verdict = %s, want ALLOW: %#v", decision.Verdict, decision)
	}
	if decision.PolicyContentHash == "" {
		t.Fatal("policy content hash should be bound to decision")
	}
}

func TestEvaluateAgentSafetyBaselineDenyTaintedHighRisk(t *testing.T) {
	engine, _ := NewPolicyEngine()
	input := safeAgentSafetyContext()
	input.EffectClass = "E4"
	input.Taint = []string{"prompt_injection"}

	decision, _ := engine.EvaluateAgentSafetyBaseline(context.Background(), input)
	if decision.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("verdict = %s, want DENY", decision.Verdict)
	}
	if decision.ReasonCode != string(contracts.ReasonTaintedInputDeny) {
		t.Fatalf("reason = %s, want %s", decision.ReasonCode, contracts.ReasonTaintedInputDeny)
	}
}

func TestEvaluateAgentSafetyBaselineEscalatesHighImpact(t *testing.T) {
	engine, _ := NewPolicyEngine()
	input := safeAgentSafetyContext()
	input.EffectType = contracts.EffectTypeSoftwarePublish
	input.EffectClass = "E4"

	decision, _ := engine.EvaluateAgentSafetyBaseline(context.Background(), input)
	if decision.Verdict != string(contracts.VerdictEscalate) {
		t.Fatalf("verdict = %s, want ESCALATE", decision.Verdict)
	}
	if decision.ReasonCode != string(contracts.ReasonApprovalRequired) {
		t.Fatalf("reason = %s, want %s", decision.ReasonCode, contracts.ReasonApprovalRequired)
	}
}

func TestEvaluateAgentSafetyBaselineMissingContextFailsClosed(t *testing.T) {
	engine, _ := NewPolicyEngine()
	decision, _ := engine.EvaluateAgentSafetyBaseline(context.Background(), AgentSafetyContext{})
	if decision.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("verdict = %s, want DENY", decision.Verdict)
	}
	if decision.ReasonCode != string(contracts.ReasonNoPolicy) {
		t.Fatalf("reason = %s, want %s", decision.ReasonCode, contracts.ReasonNoPolicy)
	}
}

func TestEvaluateAgentSafetyBaselineLogsBenchmarkEvidence(t *testing.T) {
	engine, _ := NewPolicyEngine()
	input := safeAgentSafetyContext()
	input.SourceChannel = "benchmark"

	decision, _ := engine.EvaluateAgentSafetyBaseline(context.Background(), input)
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("verdict = %s, want ALLOW", decision.Verdict)
	}
	if decision.ReasonCode != "" {
		t.Fatalf("reason code = %s, want empty", decision.ReasonCode)
	}
}

func TestGuardianAuthorizeAgentSafetySignsDecision(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("guardian-agent-safety-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	engine, _ := NewPolicyEngine()
	guardian := NewGuardian(signer, engine)

	input := safeAgentSafetyContext()
	input.EffectClass = "E4"
	input.Taint = []string{"tool_output_instruction"}
	decision, err := guardian.AuthorizeAgentSafety(context.Background(), input)
	if err != nil {
		t.Fatalf("AuthorizeAgentSafety: %v", err)
	}
	if decision.Signature == "" {
		t.Fatal("expected signed decision")
	}
	valid, err := signer.VerifyDecision(decision)
	if err != nil {
		t.Fatalf("VerifyDecision: %v", err)
	}
	if !valid {
		t.Fatal("signed agent safety decision did not verify")
	}
}

func safeAgentSafetyContext() AgentSafetyContext {
	return AgentSafetyContext{
		EffectType:             contracts.EffectTypeUpdateDoc,
		EffectClass:            "E1",
		ToolName:               "doc_writer",
		ConnectorID:            "connector-docs",
		Action:                 "read",
		Taint:                  []string{},
		SourceTrust:            "trusted",
		SourceChannel:          "user",
		MemoryTier:             "none",
		MemoryReviewState:      "approved",
		MemoryTrustScore:       100,
		ProvenanceScore:        2,
		DelegationSessionValid: true,
		CredentialScope:        "task_bound",
		A2ASignatureValid:      true,
		ManifestDigestValid:    true,
		OutputContractValid:    true,
		ApprovedArgsValid:      true,
		SafeDepState:           "normal",
		BudgetRemaining:        100,
		FanoutCount:            1,
		RetryCount:             0,
		PrincipalID:            "agent-safe",
		ResourceID:             "doc-1",
	}
}
