package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func contractCoverageTime() time.Time {
	return time.Date(2026, 5, 21, 10, 30, 0, 0, time.UTC)
}

func TestCoverageBoundarySurfacesSealAndHelpers(t *testing.T) {
	now := contractCoverageTime()
	checkpoint := BoundaryCheckpoint{
		CheckpointID:    "checkpoint-1",
		Sequence:        7,
		RecordCount:     2,
		ReceiptCount:    1,
		RecordRootHash:  "sha256:record-root",
		ReceiptRootHash: "sha256:receipt-root",
		PreviousHash:    "sha256:previous",
		RecordHashes:    []string{"sha256:record-a", "sha256:record-b"},
		CreatedAt:       now,
	}

	for name, mutate := range map[string]func(*BoundaryCheckpoint){
		"missing id":      func(c *BoundaryCheckpoint) { c.CheckpointID = "" },
		"negative seq":    func(c *BoundaryCheckpoint) { c.Sequence = -1 },
		"missing roots":   func(c *BoundaryCheckpoint) { c.RecordRootHash = "" },
		"missing created": func(c *BoundaryCheckpoint) { c.CreatedAt = time.Time{} },
	} {
		t.Run("checkpoint "+name, func(t *testing.T) {
			candidate := checkpoint
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	sealed, err := checkpoint.Seal()
	if err != nil {
		t.Fatalf("seal checkpoint: %v", err)
	}
	checkpoint.CheckpointHash = "sha256:stale"
	resealed, err := checkpoint.Seal()
	if err != nil {
		t.Fatalf("reseal checkpoint: %v", err)
	}
	if sealed.CheckpointHash == "" || sealed.CheckpointHash != resealed.CheckpointHash {
		t.Fatalf("checkpoint hash was not stable: %q vs %q", sealed.CheckpointHash, resealed.CheckpointHash)
	}

	ceremony := ApprovalCeremony{
		ApprovalID:       "approval-1",
		Subject:          "effect:publish",
		Action:           "approve",
		State:            ApprovalCeremonyPending,
		RequestedBy:      "user:requester",
		Approvers:        []string{"user:approver"},
		Quorum:           1,
		ExpiresAt:        now.Add(time.Hour),
		AuthMethod:       "webauthn",
		ChallengeID:      "challenge-1",
		ChallengeHash:    "sha256:challenge",
		AssertionHash:    "sha256:assertion",
		Reason:           "high-risk action",
		ReceiptID:        "receipt-1",
		BoundaryRecordID: "record-1",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	for name, mutate := range map[string]func(*ApprovalCeremony){
		"missing id":        func(a *ApprovalCeremony) { a.ApprovalID = "" },
		"missing subject":   func(a *ApprovalCeremony) { a.Subject = "" },
		"missing state":     func(a *ApprovalCeremony) { a.State = "" },
		"missing requester": func(a *ApprovalCeremony) { a.RequestedBy = "" },
		"missing created":   func(a *ApprovalCeremony) { a.CreatedAt = time.Time{} },
		"missing updated":   func(a *ApprovalCeremony) { a.UpdatedAt = time.Time{} },
	} {
		t.Run("approval "+name, func(t *testing.T) {
			candidate := ceremony
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	sealedCeremony, err := ceremony.Seal()
	if err != nil {
		t.Fatalf("seal ceremony: %v", err)
	}
	ceremony.CeremonyHash = "sha256:stale"
	resealedCeremony, err := ceremony.Seal()
	if err != nil {
		t.Fatalf("reseal ceremony: %v", err)
	}
	if sealedCeremony.CeremonyHash == "" || sealedCeremony.CeremonyHash != resealedCeremony.CeremonyHash {
		t.Fatalf("ceremony hash was not stable: %q vs %q", sealedCeremony.CeremonyHash, resealedCeremony.CeremonyHash)
	}

	if NormalizeSurfaceLimit(-1) != 50 || NormalizeSurfaceLimit(0) != 50 {
		t.Fatal("non-positive surface limits should use default")
	}
	if NormalizeSurfaceLimit(1001) != 1000 {
		t.Fatal("large surface limits should be capped")
	}
	if NormalizeSurfaceLimit(25) != 25 {
		t.Fatal("valid surface limit should pass through")
	}
	if got := SurfaceID("surface", " Foo:Bar/Baz qux "); got != "surface-foo-bar-baz-qux" {
		t.Fatalf("unexpected surface id: %s", got)
	}
	if got := SurfaceID("surface", " "); got != "surface-default" {
		t.Fatalf("unexpected default surface id: %s", got)
	}
}

func TestCoverageDelegationProofChainVerification(t *testing.T) {
	now := contractCoverageTime()
	root := DelegationProof{
		ProofID:     "proof-root",
		DelegatorID: "owner",
		DelegateeID: "operator",
		Scope: DelegationProofScope{
			Actions:      []string{"approve"},
			Resources:    []string{"effect:*"},
			MaxBudget:    1000,
			MaxDepth:     2,
			AllowRedeleg: true,
		},
		ChainDepth: 0,
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	root.ContentHash = root.ComputeHash()
	child := DelegationProof{
		ProofID:       "proof-child",
		DelegatorID:   "operator",
		DelegateeID:   "agent",
		ParentProofID: root.ProofID,
		Scope: DelegationProofScope{
			Actions:   []string{"approve"},
			Resources: []string{"effect:publish"},
			MaxBudget: 500,
			MaxDepth:  1,
		},
		ChainDepth: 1,
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	child.ContentHash = child.ComputeHash()

	if err := (&DelegationChain{ChainID: "chain-1", Proofs: []DelegationProof{root, child}}).Verify(); err != nil {
		t.Fatalf("verify valid chain: %v", err)
	}
	if err := (&DelegationChain{ChainID: "empty"}).Verify(); err == nil {
		t.Fatal("expected empty chain to fail")
	}

	for name, mutate := range map[string]func([]DelegationProof){
		"hash mismatch": func(proofs []DelegationProof) {
			proofs[0].ContentHash = "sha256:wrong"
		},
		"parent mismatch": func(proofs []DelegationProof) {
			proofs[1].ParentProofID = "proof-other"
		},
		"depth mismatch": func(proofs []DelegationProof) {
			proofs[1].ChainDepth = 2
			proofs[1].ContentHash = ""
		},
		"revoked": func(proofs []DelegationProof) {
			proofs[0].Revoked = true
		},
		"scope escalation": func(proofs []DelegationProof) {
			proofs[1].Scope.MaxDepth = 3
			proofs[1].ContentHash = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			proofs := []DelegationProof{root, child}
			mutate(proofs)
			if err := (&DelegationChain{ChainID: "chain-1", Proofs: proofs}).Verify(); err == nil {
				t.Fatal("expected chain verification error")
			}
		})
	}
}

func TestCoveragePhenotypeRoleAndGovernanceConstructors(t *testing.T) {
	phenotype := PhenotypeContract{
		PhenotypeID:  "phenotype-1",
		Name:         "Boundary Operator",
		Version:      "1.0.0",
		AllowedTools: []string{"receipt.verify"},
		EffectBudget: PhenotypeEffectBudget{MaxTotalEffects: 3},
	}
	for name, mutate := range map[string]func(*PhenotypeContract){
		"missing id":      func(p *PhenotypeContract) { p.PhenotypeID = "" },
		"missing name":    func(p *PhenotypeContract) { p.Name = "" },
		"missing version": func(p *PhenotypeContract) { p.Version = "" },
		"missing tools": func(p *PhenotypeContract) {
			p.AllowedTools = nil
			p.BlockedTools = nil
		},
		"missing budget": func(p *PhenotypeContract) { p.EffectBudget.MaxTotalEffects = 0 },
	} {
		t.Run("phenotype "+name, func(t *testing.T) {
			candidate := phenotype
			mutate(&candidate)
			if err := ValidatePhenotype(candidate); err == nil {
				t.Fatal("expected phenotype validation error")
			}
		})
	}
	if err := ValidatePhenotype(phenotype); err != nil {
		t.Fatalf("valid phenotype rejected: %v", err)
	}
	blockedOnly := phenotype
	blockedOnly.AllowedTools = nil
	blockedOnly.BlockedTools = []string{"shell.exec"}
	if err := ValidatePhenotype(blockedOnly); err != nil {
		t.Fatalf("blocked-only phenotype rejected: %v", err)
	}

	role := NewRole("role-1", "tenant-1", "Operator", RoleOperator, RoleNSExecution, []PermissionScope{
		{Resource: "effect", Action: "approve"},
		{Resource: "receipt", Action: "*"},
		{Resource: "*", Action: "read"},
	})
	if err := role.Validate(); err != nil {
		t.Fatalf("valid role rejected: %v", err)
	}
	if !strings.HasPrefix(role.ContentHash, "sha256:") {
		t.Fatalf("role content hash missing sha256 prefix: %s", role.ContentHash)
	}
	for _, check := range []struct {
		resource string
		action   string
		want     bool
	}{
		{"effect", "approve", true},
		{"receipt", "delete", true},
		{"ledger", "read", true},
		{"ledger", "write", false},
	} {
		if got := role.HasPermission(check.resource, check.action); got != check.want {
			t.Fatalf("HasPermission(%q, %q) = %v, want %v", check.resource, check.action, got, check.want)
		}
	}
	for name, mutate := range map[string]func(*Role){
		"missing id":       func(r *Role) { r.ID = "" },
		"missing tenant":   func(r *Role) { r.TenantID = "" },
		"missing name":     func(r *Role) { r.Name = "" },
		"missing taxonomy": func(r *Role) { r.Taxonomy = "" },
	} {
		t.Run("role "+name, func(t *testing.T) {
			candidate := *role
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected role validation error")
			}
		})
	}

	binding := NewPhenotypeBinding("phenotype-1", "AGENT", "worker-1", []string{"verify"})
	if binding.PhenotypeID != "phenotype-1" || !strings.HasPrefix(binding.ContentHash, "sha256:") {
		t.Fatalf("phenotype binding was not initialized: %+v", binding)
	}
	dispute := NewDispute("dispute-1", "tenant-1", "run-1", "user:alice", "receipt mismatch", []string{"evidence-1"})
	if dispute.Status != DisputeStatusOpen || dispute.CreatedAt.IsZero() || !strings.HasPrefix(dispute.ContentHash, "sha256:") {
		t.Fatalf("dispute was not initialized: %+v", dispute)
	}
}

func TestCoverageHarnessValidatorsAndSealers(t *testing.T) {
	now := contractCoverageTime()
	scope := VerificationScope{
		VerificationScopeID: "scope-1",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T3",
		ChecksPerformed:     []string{"unit", "replay"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
		CreatedAt:           now,
	}
	for name, mutate := range map[string]func(*VerificationScope){
		"missing id":      func(s *VerificationScope) { s.VerificationScopeID = "" },
		"bad subject":     func(s *VerificationScope) { s.SubjectHash = "subject" },
		"bad risk":        func(s *VerificationScope) { s.RiskClass = "T4" },
		"missing checks":  func(s *VerificationScope) { s.ChecksPerformed = []string{" "} },
		"bad verifier":    func(s *VerificationScope) { s.VerifierHash = "verifier" },
		"bad policy":      func(s *VerificationScope) { s.PolicyHash = "policy" },
		"missing created": func(s *VerificationScope) { s.CreatedAt = time.Time{} },
	} {
		t.Run("scope "+name, func(t *testing.T) {
			candidate := scope
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected scope validation error")
			}
		})
	}
	sealedScope, err := scope.Seal()
	if err != nil {
		t.Fatalf("seal scope: %v", err)
	}
	if sealedScope.ScopeHash == "" {
		t.Fatal("scope hash was not set")
	}

	transaction := PlanTransaction{
		PlanTransactionID:       "transaction-1",
		PlanHash:                "sha256:plan",
		ReadSet:                 []string{"input:a"},
		WriteSet:                []string{"output:b"},
		AssumptionSet:           []string{"clock fixed"},
		VerificationObligations: []string{"scope-1"},
		ConflictPolicy:          "escalate",
		RollbackPolicy:          json.RawMessage(`{"mode":"compensate"}`),
		ApprovalState:           "approved",
	}
	for name, mutate := range map[string]func(*PlanTransaction){
		"missing id":          func(p *PlanTransaction) { p.PlanTransactionID = "" },
		"bad plan hash":       func(p *PlanTransaction) { p.PlanHash = "plan" },
		"missing read set":    func(p *PlanTransaction) { p.ReadSet = []string{" "} },
		"missing write set":   func(p *PlanTransaction) { p.WriteSet = nil },
		"missing assumptions": func(p *PlanTransaction) { p.AssumptionSet = nil },
		"missing obligations": func(p *PlanTransaction) { p.VerificationObligations = nil },
		"bad conflict":        func(p *PlanTransaction) { p.ConflictPolicy = "merge" },
		"bad approval":        func(p *PlanTransaction) { p.ApprovalState = "waiting" },
		"bad rollback":        func(p *PlanTransaction) { p.RollbackPolicy = json.RawMessage(`{`) },
	} {
		t.Run("transaction "+name, func(t *testing.T) {
			candidate := transaction
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected transaction validation error")
			}
		})
	}
	sealedTransaction, err := transaction.Seal()
	if err != nil {
		t.Fatalf("seal transaction: %v", err)
	}
	if sealedTransaction.TransactionHash == "" {
		t.Fatal("transaction hash was not set")
	}

	trace := HarnessTrace{
		TraceID:               "trace-1",
		PlanHash:              "sha256:plan",
		ToolSchemaHashes:      []string{"sha256:tool-schema"},
		SandboxGrantHash:      "sha256:grant",
		ConnectorContractHash: "sha256:connector",
		PolicyHash:            "sha256:policy",
		CPIOutputHash:         "sha256:cpi",
		ReceiptRefs:           []string{"receipt-1"},
		CreatedAt:             now,
	}
	for name, mutate := range map[string]func(*HarnessTrace){
		"missing id":       func(h *HarnessTrace) { h.TraceID = "" },
		"bad plan":         func(h *HarnessTrace) { h.PlanHash = "plan" },
		"bad policy":       func(h *HarnessTrace) { h.PolicyHash = "policy" },
		"missing receipts": func(h *HarnessTrace) { h.ReceiptRefs = nil },
		"missing created":  func(h *HarnessTrace) { h.CreatedAt = time.Time{} },
		"bad optional":     func(h *HarnessTrace) { h.ToolSchemaHashes = []string{"tool-schema"} },
	} {
		t.Run("trace "+name, func(t *testing.T) {
			candidate := trace
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected trace validation error")
			}
		})
	}
	sealedTrace, err := trace.Seal()
	if err != nil {
		t.Fatalf("seal trace: %v", err)
	}
	if sealedTrace.TraceHash == "" {
		t.Fatal("trace hash was not set")
	}

	change := HarnessChangeContract{
		ChangeContractID:       "change-1",
		ComponentModified:      "connector_contract",
		FailureModeTargeted:    "schema drift",
		PredictedImprovement:   "deny drifted schema",
		InvariantsPreserved:    []string{"fail closed"},
		SafetyProperties:       []string{"no direct dispatch"},
		RegressionSuiteRefs:    []string{"suite-1"},
		SimulationEvidenceRefs: []string{"evidence-1"},
		CanaryScope:            json.RawMessage(`{"tenant":"canary"}`),
		RollbackPlan:           json.RawMessage(`{"mode":"revert"}`),
		ApprovalRequired:       true,
		CreatedAt:              now,
	}
	for name, mutate := range map[string]func(*HarnessChangeContract){
		"missing id":          func(c *HarnessChangeContract) { c.ChangeContractID = "" },
		"bad component":       func(c *HarnessChangeContract) { c.ComponentModified = "database" },
		"missing target":      func(c *HarnessChangeContract) { c.FailureModeTargeted = "" },
		"missing invariants":  func(c *HarnessChangeContract) { c.InvariantsPreserved = nil },
		"missing regression":  func(c *HarnessChangeContract) { c.RegressionSuiteRefs = nil },
		"missing activation":  func(c *HarnessChangeContract) { c.ApprovalRequired = false },
		"bad canary":          func(c *HarnessChangeContract) { c.CanaryScope = json.RawMessage(`{`) },
		"bad rollback":        func(c *HarnessChangeContract) { c.RollbackPlan = json.RawMessage(`{`) },
		"missing created":     func(c *HarnessChangeContract) { c.CreatedAt = time.Time{} },
		"missing improvement": func(c *HarnessChangeContract) { c.PredictedImprovement = "" },
		"missing safety":      func(c *HarnessChangeContract) { c.SafetyProperties = nil },
	} {
		t.Run("change "+name, func(t *testing.T) {
			candidate := change
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected change contract validation error")
			}
		})
	}
	sealedChange, err := change.Seal()
	if err != nil {
		t.Fatalf("seal change: %v", err)
	}
	if sealedChange.ContractHash == "" {
		t.Fatal("change contract hash was not set")
	}
	activationChange := change
	activationChange.ApprovalRequired = false
	activationChange.ActivationReceiptRef = "receipt-activation"
	if err := activationChange.Validate(); err != nil {
		t.Fatalf("activation-backed change rejected: %v", err)
	}

	action := GroundedActionRef{
		GroundedActionID:     "grounded-1",
		ScreenshotHash:       "sha256:screenshot",
		DOMOrAXSnapshotHash:  "sha256:dom",
		TargetRef:            "button#submit",
		BBoxOrElementID:      "button#submit",
		ActionType:           "click",
		Precondition:         "form is valid",
		Postcondition:        "submission toast appears",
		PostconditionRef:     "proof:postcondition:submit-toast",
		ProofGraphNodeRef:    "proofgraph:gui-action:submit",
		VerificationScopeRef: "scope-1",
		PolicyHash:           "sha256:policy",
		SandboxGrantHash:     "sha256:grant",
		CreatedAt:            now,
	}
	for name, mutate := range map[string]func(*GroundedActionRef){
		"missing id":      func(a *GroundedActionRef) { a.GroundedActionID = "" },
		"bad hash":        func(a *GroundedActionRef) { a.ScreenshotHash = "screenshot" },
		"missing target":  func(a *GroundedActionRef) { a.TargetRef = "" },
		"bad action":      func(a *GroundedActionRef) { a.ActionType = "drag" },
		"missing pre":     func(a *GroundedActionRef) { a.Precondition = "" },
		"missing scope":   func(a *GroundedActionRef) { a.VerificationScopeRef = "" },
		"bad grant":       func(a *GroundedActionRef) { a.SandboxGrantHash = "grant" },
		"missing created": func(a *GroundedActionRef) { a.CreatedAt = time.Time{} },
		"missing bbox":    func(a *GroundedActionRef) { a.BBoxOrElementID = "" },
		"missing post":    func(a *GroundedActionRef) { a.Postcondition = "" },
		"missing post ref": func(a *GroundedActionRef) {
			a.PostconditionRef = ""
		},
		"missing proofgraph node": func(a *GroundedActionRef) {
			a.ProofGraphNodeRef = ""
		},
		"bad policy hash": func(a *GroundedActionRef) { a.PolicyHash = "policy" },
		"bad snapshot hash": func(a *GroundedActionRef) {
			a.DOMOrAXSnapshotHash = "dom"
		},
	} {
		t.Run("action "+name, func(t *testing.T) {
			candidate := action
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected grounded action validation error")
			}
		})
	}
	for _, actionType := range []string{"click", "type", "select", "submit", "navigate"} {
		candidate := action
		candidate.ActionType = actionType
		if err := candidate.Validate(); err != nil {
			t.Fatalf("valid GUI action type %q rejected: %v", actionType, err)
		}
	}
	sealedAction, err := action.Seal()
	if err != nil {
		t.Fatalf("seal grounded action: %v", err)
	}
	if sealedAction.GroundingHash == "" {
		t.Fatal("grounding hash was not set")
	}

	receipt := GUIActionReceipt{
		ReceiptID:             "receipt-1",
		GroundedActionRef:     action.GroundedActionID,
		ScreenshotHash:        action.ScreenshotHash,
		DOMOrAXSnapshotHash:   action.DOMOrAXSnapshotHash,
		TargetRef:             action.TargetRef,
		BBoxOrElementID:       action.BBoxOrElementID,
		ActionType:            action.ActionType,
		Precondition:          action.Precondition,
		Postcondition:         action.Postcondition,
		PostconditionRef:      action.PostconditionRef,
		PostconditionVerified: true,
		ProofGraphNodeRef:     action.ProofGraphNodeRef,
		VerificationScopeRef:  action.VerificationScopeRef,
		PolicyHash:            action.PolicyHash,
		SandboxGrantHash:      action.SandboxGrantHash,
		CreatedAt:             action.CreatedAt,
	}
	for name, mutate := range map[string]func(*GUIActionReceipt){
		"missing id":   func(r *GUIActionReceipt) { r.ReceiptID = "" },
		"missing ref":  func(r *GUIActionReceipt) { r.GroundedActionRef = "" },
		"bad ref data": func(r *GUIActionReceipt) { r.TargetRef = "" },
		"unverified":   func(r *GUIActionReceipt) { r.PostconditionVerified = false },
		"missing postcondition ref": func(r *GUIActionReceipt) {
			r.PostconditionRef = ""
		},
		"missing proofgraph node": func(r *GUIActionReceipt) {
			r.ProofGraphNodeRef = ""
		},
	} {
		t.Run("receipt "+name, func(t *testing.T) {
			candidate := receipt
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected GUI receipt validation error")
			}
		})
	}
	sealedReceipt, err := receipt.Seal()
	if err != nil {
		t.Fatalf("seal GUI receipt: %v", err)
	}
	if sealedReceipt.ReceiptHash == "" {
		t.Fatal("receipt hash was not set")
	}
}

func TestCoverageExecutionBoundaryAndTaintBranches(t *testing.T) {
	now := contractCoverageTime()
	grant := SandboxGrant{
		GrantID:    "grant-1",
		Runtime:    "docker",
		Profile:    "locked",
		Env:        EnvExposurePolicy{Mode: "allowlist", NamesHash: "sha256:env-names"},
		Network:    NetworkGrant{Mode: "allowlist", Destinations: []string{"api.example.test"}},
		DeclaredAt: now,
	}
	for name, mutate := range map[string]func(*SandboxGrant){
		"missing id":       func(g *SandboxGrant) { g.GrantID = "" },
		"missing runtime":  func(g *SandboxGrant) { g.Runtime = "" },
		"missing profile":  func(g *SandboxGrant) { g.Profile = "" },
		"missing declared": func(g *SandboxGrant) { g.DeclaredAt = time.Time{} },
		"empty preopen":    func(g *SandboxGrant) { g.FilesystemPreopens = []FilesystemPreopen{{Mode: "ro"}} },
		"bad preopen mode": func(g *SandboxGrant) { g.FilesystemPreopens = []FilesystemPreopen{{Path: "/workspace", Mode: "write"}} },
		"bad env":          func(g *SandboxGrant) { g.Env = EnvExposurePolicy{Mode: "open"} },
		"empty env list":   func(g *SandboxGrant) { g.Env = EnvExposurePolicy{Mode: "allowlist"} },
		"bad redacted env": func(g *SandboxGrant) { g.Env = EnvExposurePolicy{Mode: "redacted"} },
		"bad network":      func(g *SandboxGrant) { g.Network = NetworkGrant{Mode: "open"} },
		"empty network":    func(g *SandboxGrant) { g.Network = NetworkGrant{Mode: "allowlist"} },
	} {
		t.Run("grant "+name, func(t *testing.T) {
			candidate := grant
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected sandbox grant validation error")
			}
		})
	}
	sealedGrant, err := grant.Seal()
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}
	if sealedGrant.GrantHash == "" {
		t.Fatal("grant hash was not set")
	}
	redactedGrant := grant
	redactedGrant.Env = EnvExposurePolicy{Mode: "redacted", Redacted: true}
	redactedGrant.Network = NetworkGrant{Mode: "deny-all"}
	if err := redactedGrant.Validate(); err != nil {
		t.Fatalf("redacted grant rejected: %v", err)
	}

	snapshot := AuthzSnapshot{
		SnapshotID:       "snapshot-1",
		Resolver:         "openfga",
		ModelID:          "model-1",
		RelationshipHash: "sha256:relationships",
		Subject:          "user:alice",
		Object:           "tool:deploy",
		Relation:         "can_call",
		CheckedAt:        now,
	}
	for name, mutate := range map[string]func(*AuthzSnapshot){
		"missing id":           func(s *AuthzSnapshot) { s.SnapshotID = "" },
		"missing resolver":     func(s *AuthzSnapshot) { s.Resolver = "" },
		"missing model":        func(s *AuthzSnapshot) { s.ModelID = "" },
		"missing relationship": func(s *AuthzSnapshot) { s.RelationshipHash = "" },
		"missing subject":      func(s *AuthzSnapshot) { s.Subject = "" },
		"missing checked":      func(s *AuthzSnapshot) { s.CheckedAt = time.Time{} },
	} {
		t.Run("snapshot "+name, func(t *testing.T) {
			candidate := snapshot
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected authz snapshot validation error")
			}
		})
	}
	sealedSnapshot, err := snapshot.Seal()
	if err != nil {
		t.Fatalf("seal snapshot: %v", err)
	}
	if sealedSnapshot.SnapshotHash == "" {
		t.Fatal("snapshot hash was not set")
	}

	profile := MCPAuthorizationProfile{
		ProfileID:       "profile-1",
		Resource:        "mcp://server",
		ScopesSupported: []string{"tool:call"},
		RequiredScopes:  []string{"tool:call"},
	}
	for name, mutate := range map[string]func(*MCPAuthorizationProfile){
		"missing id":       func(p *MCPAuthorizationProfile) { p.ProfileID = "" },
		"missing resource": func(p *MCPAuthorizationProfile) { p.Resource = "" },
		"required only": func(p *MCPAuthorizationProfile) {
			p.ScopesSupported = nil
			p.RequiredScopes = []string{"tool:call"}
		},
	} {
		t.Run("profile "+name, func(t *testing.T) {
			candidate := profile
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected MCP profile validation error")
			}
		})
	}
	sealedProfile, err := profile.Seal()
	if err != nil {
		t.Fatalf("seal profile: %v", err)
	}
	if sealedProfile.ProfileHash == "" {
		t.Fatal("profile hash was not set")
	}

	record := ExecutionBoundaryRecord{
		RecordID:    "record-1",
		Verdict:     VerdictAllow,
		PolicyEpoch: "epoch-1",
		CreatedAt:   now,
	}
	for name, mutate := range map[string]func(*ExecutionBoundaryRecord){
		"missing id":      func(r *ExecutionBoundaryRecord) { r.RecordID = "" },
		"bad verdict":     func(r *ExecutionBoundaryRecord) { r.Verdict = Verdict("MAYBE") },
		"missing epoch":   func(r *ExecutionBoundaryRecord) { r.PolicyEpoch = "" },
		"missing created": func(r *ExecutionBoundaryRecord) { r.CreatedAt = time.Time{} },
		"missing reason":  func(r *ExecutionBoundaryRecord) { r.Verdict = VerdictEscalate },
		"bad reason": func(r *ExecutionBoundaryRecord) {
			r.Verdict = VerdictDeny
			r.ReasonCode = ReasonCode("NOT_CANONICAL")
		},
	} {
		t.Run("record "+name, func(t *testing.T) {
			candidate := record
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected boundary record validation error")
			}
		})
	}
	sealedRecord, err := record.Seal()
	if err != nil {
		t.Fatalf("seal record: %v", err)
	}
	if sealedRecord.RecordHash == "" {
		t.Fatal("record hash was not set")
	}

	manifest := EvidenceEnvelopeManifest{
		ManifestID:         "manifest-1",
		Envelope:           "cose",
		NativeEvidenceHash: "sha256:evidence",
		NativeAuthority:    true,
		CreatedAt:          now,
	}
	for name, mutate := range map[string]func(*EvidenceEnvelopeManifest){
		"missing id":       func(m *EvidenceEnvelopeManifest) { m.ManifestID = "" },
		"missing envelope": func(m *EvidenceEnvelopeManifest) { m.Envelope = "" },
		"missing native":   func(m *EvidenceEnvelopeManifest) { m.NativeEvidenceHash = "" },
		"not authority":    func(m *EvidenceEnvelopeManifest) { m.NativeAuthority = false },
		"missing created":  func(m *EvidenceEnvelopeManifest) { m.CreatedAt = time.Time{} },
		"bad envelope":     func(m *EvidenceEnvelopeManifest) { m.Envelope = "zip" },
	} {
		t.Run("manifest "+name, func(t *testing.T) {
			candidate := manifest
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected manifest validation error")
			}
		})
	}
	sealedManifest, err := manifest.Seal()
	if err != nil {
		t.Fatalf("seal manifest: %v", err)
	}
	if sealedManifest.ManifestHash == "" {
		t.Fatal("manifest hash was not set")
	}

	labels := TaintLabelsFromContext(map[string]interface{}{"taint": []interface{}{"PII", 12, "external"}})
	if !TaintContainsAny(labels, "credential", "external") {
		t.Fatalf("expected external taint in %v", labels)
	}
	if TaintContainsAny(labels, "secret", "credential") {
		t.Fatalf("unexpected taint match in %v", labels)
	}
	if got := TaintLabelsFromContext(map[string]interface{}{"taint": nil, "taint_labels": []string{"User_Input", " pii "}}); len(got) != 2 {
		t.Fatalf("expected fallback taint labels, got %v", got)
	}
	if got := TaintLabelsFromContext(map[string]interface{}{"taint": 42}); got != nil {
		t.Fatalf("unexpected labels for unsupported context value: %v", got)
	}
	if got := NormalizeTaintLabels(nil); got != nil {
		t.Fatalf("nil labels should normalize to nil, got %v", got)
	}
}
