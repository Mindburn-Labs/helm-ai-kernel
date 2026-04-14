package contracts

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_VerdictAllowString(t *testing.T) {
	if string(VerdictAllow) != "ALLOW" {
		t.Fatalf("want ALLOW, got %s", VerdictAllow)
	}
}

func TestFinal_VerdictDenyString(t *testing.T) {
	if string(VerdictDeny) != "DENY" {
		t.Fatalf("want DENY, got %s", VerdictDeny)
	}
}

func TestFinal_VerdictEscalateString(t *testing.T) {
	if string(VerdictEscalate) != "ESCALATE" {
		t.Fatalf("want ESCALATE, got %s", VerdictEscalate)
	}
}

func TestFinal_CanonicalVerdictsCount(t *testing.T) {
	if len(CanonicalVerdicts()) != 3 {
		t.Fatalf("want 3 canonical verdicts, got %d", len(CanonicalVerdicts()))
	}
}

func TestFinal_CoreReasonCodesNonEmpty(t *testing.T) {
	codes := CoreReasonCodes()
	if len(codes) == 0 {
		t.Fatal("CoreReasonCodes must not be empty")
	}
}

func TestFinal_CoreReasonCodesUnique(t *testing.T) {
	seen := make(map[ReasonCode]bool)
	for _, c := range CoreReasonCodes() {
		if seen[c] {
			t.Fatalf("duplicate reason code: %s", c)
		}
		seen[c] = true
	}
}

func TestFinal_IsCanonicalVerdictTrue(t *testing.T) {
	if !IsCanonicalVerdict("ALLOW") {
		t.Fatal("ALLOW should be canonical")
	}
}

func TestFinal_IsCanonicalVerdictFalse(t *testing.T) {
	if IsCanonicalVerdict("BOGUS") {
		t.Fatal("BOGUS should not be canonical")
	}
}

func TestFinal_IsTerminalAllowDeny(t *testing.T) {
	if !VerdictAllow.IsTerminal() || !VerdictDeny.IsTerminal() {
		t.Fatal("ALLOW and DENY are terminal")
	}
}

func TestFinal_EscalateNotTerminal(t *testing.T) {
	if VerdictEscalate.IsTerminal() {
		t.Fatal("ESCALATE is not terminal")
	}
}

func TestFinal_DecisionRecordJSON(t *testing.T) {
	d := DecisionRecord{ID: "d1", Verdict: "ALLOW", Reason: "ok"}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var d2 DecisionRecord
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatal(err)
	}
	if d2.ID != d.ID || d2.Verdict != d.Verdict {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AccessRequestJSON(t *testing.T) {
	a := AccessRequest{PrincipalID: "p1", Action: "read", ResourceID: "r1"}
	data, _ := json.Marshal(a)
	var a2 AccessRequest
	json.Unmarshal(data, &a2)
	if a2.PrincipalID != "p1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_EventEnvelopeJSON(t *testing.T) {
	e := EventEnvelope{EventID: "e1", ProposalID: "p1", EventType: "test"}
	data, _ := json.Marshal(e)
	var e2 EventEnvelope
	json.Unmarshal(data, &e2)
	if e2.ProposalID != "p1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PostureAllCount(t *testing.T) {
	if len(AllPostures()) != 4 {
		t.Fatalf("want 4 postures, got %d", len(AllPostures()))
	}
}

func TestFinal_PostureEscalation(t *testing.T) {
	if !PostureObserve.CanEscalateTo(PostureSovereign) {
		t.Fatal("OBSERVE should escalate to SOVEREIGN")
	}
	if PostureSovereign.CanEscalateTo(PostureObserve) {
		t.Fatal("SOVEREIGN cannot escalate to OBSERVE")
	}
}

func TestFinal_BudgetExhausted(t *testing.T) {
	b := Budget{MaxTokens: 100, ConsumedTokens: 100}
	if !b.Exhausted() {
		t.Fatal("budget should be exhausted")
	}
}

func TestFinal_BudgetRemainingTokens(t *testing.T) {
	b := Budget{MaxTokens: 100, ConsumedTokens: 30}
	if b.RemainingTokens() != 70 {
		t.Fatalf("want 70, got %d", b.RemainingTokens())
	}
}

func TestFinal_BudgetZeroMax(t *testing.T) {
	b := Budget{}
	if b.Exhausted() {
		t.Fatal("zero-max budget should not be exhausted")
	}
}

func TestFinal_EffectRiskClassE4(t *testing.T) {
	if EffectRiskClass(EffectTypeInfraDestroy) != "E4" {
		t.Fatal("INFRA_DESTROY should be E4")
	}
}

func TestFinal_EffectRiskClassUnknownDefault(t *testing.T) {
	if EffectRiskClass("UNKNOWN_TYPE_XYZ") != "E3" {
		t.Fatal("unknown effect types should default to E3")
	}
}

func TestFinal_DefaultEffectCatalogNonEmpty(t *testing.T) {
	cat := DefaultEffectCatalog()
	if len(cat.EffectTypes) == 0 {
		t.Fatal("default catalog must not be empty")
	}
}

func TestFinal_LookupEffectTypeFound(t *testing.T) {
	et := LookupEffectType(EffectTypeSendEmail)
	if et == nil || et.TypeID != EffectTypeSendEmail {
		t.Fatal("should find SEND_EMAIL in catalog")
	}
}

func TestFinal_LookupEffectTypeNotFound(t *testing.T) {
	if LookupEffectType("NONEXISTENT") != nil {
		t.Fatal("should return nil for unknown type")
	}
}

func TestFinal_DiffCategoriesNonEmpty(t *testing.T) {
	cats := []DiffCategory{DiffCategoryCapability, DiffCategoryControl, DiffCategoryWorkflow, DiffCategoryData, DiffCategoryBudget, DiffCategoryPosture}
	for _, c := range cats {
		if c == "" {
			t.Fatal("category must not be empty")
		}
	}
}

func TestFinal_OpMappingIndexKeys(t *testing.T) {
	idx := OpMappingIndex()
	if len(idx) == 0 {
		t.Fatal("mapping index must not be empty")
	}
	if _, ok := idx["posture.change"]; !ok {
		t.Fatal("missing posture.change mapping")
	}
}

func TestFinal_DecisionRequestValidate(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "r1",
		Title:     "Pick one",
		Kind:      DecisionKindApproval,
		Options: []DecisionOption{
			{ID: "a", Label: "A"},
			{ID: "b", Label: "B"},
		},
	}
	if err := dr.Validate(); err != nil {
		t.Fatalf("valid request should pass: %v", err)
	}
}

func TestFinal_DecisionRequestValidateTooFewOptions(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Title: "Pick", Kind: DecisionKindApproval,
		Options: []DecisionOption{{ID: "a", Label: "A"}}}
	if dr.Validate() == nil {
		t.Fatal("should fail with too few options")
	}
}

func TestFinal_DecisionRequestResolve(t *testing.T) {
	dr := &DecisionRequest{
		RequestID: "r1", Title: "Pick", Kind: DecisionKindApproval,
		Status: DecisionStatusPending,
		Options: []DecisionOption{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}},
	}
	if err := dr.Resolve("a", "user1"); err != nil {
		t.Fatal(err)
	}
	if dr.Status != DecisionStatusResolved {
		t.Fatal("should be resolved")
	}
}

func TestFinal_DecisionRequestSkipNotAllowed(t *testing.T) {
	dr := &DecisionRequest{RequestID: "r1", Status: DecisionStatusPending, SkipAllowed: false}
	if dr.Skip("user") == nil {
		t.Fatal("skip should fail when not allowed")
	}
}

func TestFinal_InterventionTypeConstants(t *testing.T) {
	types := []InterventionType{InterventionNone, InterventionThrottle, InterventionInterrupt, InterventionQuarantine}
	seen := make(map[InterventionType]bool)
	for _, it := range types {
		if it == "" {
			t.Fatal("intervention type must not be empty")
		}
		if seen[it] {
			t.Fatalf("duplicate intervention type: %s", it)
		}
		seen[it] = true
	}
}

func TestFinal_BuildInfoJSON(t *testing.T) {
	b := BuildInfo{Commit: "abc123", Builder: "ci"}
	data, _ := json.Marshal(b)
	var b2 BuildInfo
	json.Unmarshal(data, &b2)
	if b2.Commit != "abc123" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ReceiptJSON(t *testing.T) {
	r := Receipt{ReceiptID: "r1", DecisionID: "d1", Status: "OK", Timestamp: time.Now()}
	data, _ := json.Marshal(r)
	var r2 Receipt
	json.Unmarshal(data, &r2)
	if r2.ReceiptID != "r1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentVerdictAccess(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = CanonicalVerdicts()
			_ = CoreReasonCodes()
			_ = IsCanonicalVerdict("ALLOW")
		}()
	}
	wg.Wait()
}

func TestFinal_EffectCatalogDeterminism(t *testing.T) {
	a := DefaultEffectCatalog()
	b := DefaultEffectCatalog()
	if len(a.EffectTypes) != len(b.EffectTypes) {
		t.Fatal("catalog should be deterministic")
	}
}

func TestFinal_DecisionKindConstants(t *testing.T) {
	kinds := []DecisionRequestKind{
		DecisionKindApproval, DecisionKindPolicyChoice, DecisionKindClarification,
		DecisionKindSpending, DecisionKindIrreversible, DecisionKindSensitivePolicy, DecisionKindNaming,
	}
	if len(kinds) != 7 {
		t.Fatalf("want 7 kinds, got %d", len(kinds))
	}
}
