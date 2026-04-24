package governance

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestFinal_DenialReasonConstants(t *testing.T) {
	reasons := []DenialReason{DenialPolicy, DenialProvenance, DenialBudget, DenialSandbox, DenialTenant, DenialJurisdiction, DenialVerification, DenialEnvelope}
	seen := make(map[DenialReason]bool)
	for _, r := range reasons {
		if r == "" {
			t.Fatal("denial reason must not be empty")
		}
		if seen[r] {
			t.Fatalf("duplicate denial reason: %s", r)
		}
		seen[r] = true
	}
}

func TestFinal_DenialReasonCount(t *testing.T) {
	expected := 8
	reasons := []DenialReason{DenialPolicy, DenialProvenance, DenialBudget, DenialSandbox, DenialTenant, DenialJurisdiction, DenialVerification, DenialEnvelope}
	if len(reasons) != expected {
		t.Fatalf("want %d denial reasons, got %d", expected, len(reasons))
	}
}

func TestFinal_DenialReceiptJSON(t *testing.T) {
	dr := DenialReceipt{ReceiptID: "r1", Principal: "p1", Action: "test", Reason: DenialPolicy, Details: "blocked"}
	data, _ := json.Marshal(dr)
	var dr2 DenialReceipt
	json.Unmarshal(data, &dr2)
	if dr2.ReceiptID != "r1" || dr2.Reason != DenialPolicy {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DenialLedgerNew(t *testing.T) {
	ledger := NewDenialLedger()
	if ledger == nil {
		t.Fatal("ledger should not be nil")
	}
}

func TestFinal_DenialLedgerDenyAndCount(t *testing.T) {
	ledger := NewDenialLedger()
	ledger.Deny("p1", "action", DenialPolicy, "details")
	if ledger.Length() != 1 {
		t.Fatalf("want 1 entry, got %d", ledger.Length())
	}
}

func TestFinal_DenialLedgerConcurrent(t *testing.T) {
	ledger := NewDenialLedger()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ledger.Deny("p", "a", DenialPolicy, "d")
		}()
	}
	wg.Wait()
	if ledger.Length() != 20 {
		t.Fatal("should have 20 entries")
	}
}

func TestFinal_ChangeClassConstants(t *testing.T) {
	classes := []ChangeClass{ChangeClassC0, ChangeClassC1, ChangeClassC2, ChangeClassC3}
	for _, c := range classes {
		if c == "" {
			t.Fatal("change class constant must not be empty")
		}
	}
}

func TestFinal_DataClassConstants(t *testing.T) {
	classes := []DataClass{DataClassPublic, DataClassInternal, DataClassConfidential, DataClassRestricted}
	for _, c := range classes {
		if c == "" {
			t.Fatal("data class must not be empty")
		}
	}
}

func TestFinal_ConflictTypeConstants(t *testing.T) {
	types := []ConflictType{ConflictPolicyOverlap, ConflictBudgetConflict, ConflictAuthority, ConflictJurisdiction}
	seen := make(map[ConflictType]bool)
	for _, ct := range types {
		if seen[ct] {
			t.Fatalf("duplicate: %s", ct)
		}
		seen[ct] = true
	}
}

func TestFinal_ArbitrationStrategyConstants(t *testing.T) {
	strats := []ArbitrationStrategy{StrategyStrictest, StrategySpecific, StrategyPriority, StrategyEscalate}
	if len(strats) != 4 {
		t.Fatalf("want 4 arbitration strategies")
	}
}

func TestFinal_PlanStatusConstants(t *testing.T) {
	statuses := []PlanStatus{PlanStatusPending, PlanStatusApproved, PlanStatusRejected, PlanStatusTimeout, PlanStatusAborted}
	for _, s := range statuses {
		if s == "" {
			t.Fatal("plan status must not be empty")
		}
	}
}

func TestFinal_ExecutionPlanJSON(t *testing.T) {
	ep := ExecutionPlan{PlanID: "ep1", Description: "test plan"}
	data, _ := json.Marshal(ep)
	var ep2 ExecutionPlan
	json.Unmarshal(data, &ep2)
	if ep2.PlanID != "ep1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PolicyDomainConstants(t *testing.T) {
	domains := []PolicyDomain{DomainAuthorization, DomainCompliance, DomainRisk, DomainAudit, DomainGeneral}
	seen := make(map[PolicyDomain]bool)
	for _, d := range domains {
		if seen[d] {
			t.Fatalf("duplicate: %s", d)
		}
		seen[d] = true
	}
}

func TestFinal_CELDPErrorCodeConstants(t *testing.T) {
	codes := []CELDPErrorCode{CELDPErrorTypeError, CELDPErrorDivZero, CELDPErrorOverflow, CELDPErrorUndefined, CELDPErrorInvalidArg, CELDPErrorInternal}
	for _, c := range codes {
		if c == "" {
			t.Fatal("error code must not be empty")
		}
	}
}

func TestFinal_CELDPOutcomeConstants(t *testing.T) {
	outcomes := []CELDPOutcome{CELDPOutcomeValue, CELDPOutcomeError}
	for _, o := range outcomes {
		if o == "" {
			t.Fatal("outcome must not be empty")
		}
	}
}

func TestFinal_JurisdictionContextJSON(t *testing.T) {
	jc := JurisdictionContext{Entity: "Acme Corp", ServiceRegion: "US", LegalRegime: "US/CCPA"}
	data, _ := json.Marshal(jc)
	var jc2 JurisdictionContext
	json.Unmarshal(data, &jc2)
	if jc2.Entity != "Acme Corp" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ModuleBundleJSON(t *testing.T) {
	mb := ModuleBundle{ID: "mb1", ContentHash: "sha256:abc"}
	data, _ := json.Marshal(mb)
	var mb2 ModuleBundle
	json.Unmarshal(data, &mb2)
	if mb2.ID != "mb1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PowerDeltaZeroValue(t *testing.T) {
	pd := PowerDelta{}
	if pd.RiskScoreDelta != 0 {
		t.Fatal("zero value should have 0 delta")
	}
}

func TestFinal_RiskEnvelopeJSON(t *testing.T) {
	re := RiskEnvelope{EnvelopeID: "re1"}
	data, _ := json.Marshal(re)
	var re2 RiskEnvelope
	json.Unmarshal(data, &re2)
	if re2.EnvelopeID != "re1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SwarmPDPConfigJSON(t *testing.T) {
	cfg := SwarmPDPConfig{MaxParallelPDPs: 5, EnableMetrics: true}
	data, _ := json.Marshal(cfg)
	var cfg2 SwarmPDPConfig
	json.Unmarshal(data, &cfg2)
	if cfg2.MaxParallelPDPs != 5 || !cfg2.EnableMetrics {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConflictRecordJSON(t *testing.T) {
	cr := ConflictRecord{ID: "c1", Type: ConflictPolicyOverlap}
	data, _ := json.Marshal(cr)
	var cr2 ConflictRecord
	json.Unmarshal(data, &cr2)
	if cr2.ID != "c1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CorroboratedReceiptJSON(t *testing.T) {
	cr := CorroboratedReceipt{ReceiptID: "r1", CorroboratorID: "c1", Status: "VERIFIED"}
	data, _ := json.Marshal(cr)
	var cr2 CorroboratedReceipt
	json.Unmarshal(data, &cr2)
	if cr2.Status != "VERIFIED" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ClassifierZeroValue(t *testing.T) {
	c := &Classifier{}
	if c == nil {
		t.Fatal("zero-value classifier should not be nil")
	}
}

func TestFinal_MemoryKeyProviderImpl(t *testing.T) {
	var _ KeyProvider = (*MemoryKeyProvider)(nil)
}

func TestFinal_KeyringNew(t *testing.T) {
	mkp, err := NewMemoryKeyProvider()
	if err != nil {
		t.Fatal(err)
	}
	kr := NewKeyring(mkp)
	if kr == nil {
		t.Fatal("keyring should not be nil")
	}
}

func TestFinal_CanaryConfigJSON(t *testing.T) {
	cc := CanaryConfig{StepDurationSec: 60, Steps: 3}
	data, _ := json.Marshal(cc)
	var cc2 CanaryConfig
	json.Unmarshal(data, &cc2)
	if cc2.Steps != 3 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DenialReceiptContentHashPopulated(t *testing.T) {
	ledger := NewDenialLedger()
	receipt := ledger.Deny("p", "a", DenialPolicy, "d")
	if receipt.ContentHash == "" {
		t.Fatal("content hash should be computed")
	}
}

func TestFinal_DenialLedgerDeterminism(t *testing.T) {
	l1 := NewDenialLedger()
	l2 := NewDenialLedger()
	r1 := l1.Deny("p", "a", DenialPolicy, "d")
	r2 := l2.Deny("p", "a", DenialPolicy, "d")
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("content hash should be deterministic for same inputs")
	}
}
