package guardian

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/trust"
)

func TestFinal_ResponseLevelStringObserve(t *testing.T) {
	if ResponseObserve.String() != "OBSERVE" {
		t.Fatalf("want OBSERVE, got %s", ResponseObserve.String())
	}
}

func TestFinal_ResponseLevelStringThrottle(t *testing.T) {
	if ResponseThrottle.String() != "THROTTLE" {
		t.Fatalf("want THROTTLE, got %s", ResponseThrottle.String())
	}
}

func TestFinal_ResponseLevelStringInterrupt(t *testing.T) {
	if ResponseInterrupt.String() != "INTERRUPT" {
		t.Fatalf("want INTERRUPT, got %s", ResponseInterrupt.String())
	}
}

func TestFinal_ResponseLevelStringQuarantine(t *testing.T) {
	if ResponseQuarantine.String() != "QUARANTINE" {
		t.Fatalf("want QUARANTINE, got %s", ResponseQuarantine.String())
	}
}

func TestFinal_ResponseLevelStringFailClosed(t *testing.T) {
	if ResponseFailClosed.String() != "FAIL_CLOSED" {
		t.Fatalf("want FAIL_CLOSED, got %s", ResponseFailClosed.String())
	}
}

func TestFinal_ResponseLevelStringUnknown(t *testing.T) {
	got := ResponseLevel(99).String()
	if got != "UNKNOWN(99)" {
		t.Fatalf("want UNKNOWN(99), got %s", got)
	}
}

func TestFinal_PrivilegeTierStringRestricted(t *testing.T) {
	if TierRestricted.String() != "RESTRICTED" {
		t.Fatalf("want RESTRICTED, got %s", TierRestricted.String())
	}
}

func TestFinal_PrivilegeTierStringStandard(t *testing.T) {
	if TierStandard.String() != "STANDARD" {
		t.Fatalf("want STANDARD, got %s", TierStandard.String())
	}
}

func TestFinal_PrivilegeTierStringElevated(t *testing.T) {
	if TierElevated.String() != "ELEVATED" {
		t.Fatalf("want ELEVATED, got %s", TierElevated.String())
	}
}

func TestFinal_PrivilegeTierStringSystem(t *testing.T) {
	if TierSystem.String() != "SYSTEM" {
		t.Fatalf("want SYSTEM, got %s", TierSystem.String())
	}
}

func TestFinal_PrivilegeTierStringUnknown(t *testing.T) {
	got := PrivilegeTier(42).String()
	expected := fmt.Sprintf("UNKNOWN(%d)", 42)
	if got != expected {
		t.Fatalf("want %s, got %s", expected, got)
	}
}

func TestFinal_RequiredTierForInfraDestroy(t *testing.T) {
	if RequiredTierForEffect("INFRA_DESTROY") != TierSystem {
		t.Fatal("INFRA_DESTROY requires TierSystem")
	}
}

func TestFinal_RequiredTierForSendEmail(t *testing.T) {
	if RequiredTierForEffect("SEND_EMAIL") != TierStandard {
		t.Fatal("SEND_EMAIL requires TierStandard")
	}
}

func TestFinal_RequiredTierUnknownDefault(t *testing.T) {
	if RequiredTierForEffect("UNKNOWN_EFFECT") != TierStandard {
		t.Fatal("unknown effects default to TierStandard")
	}
}

func TestFinal_EffectiveTierHostile(t *testing.T) {
	if EffectiveTier(TierSystem, trust.TierHostile) != TierRestricted {
		t.Fatal("hostile trust should force TierRestricted")
	}
}

func TestFinal_EffectiveTierSuspectCap(t *testing.T) {
	if EffectiveTier(TierSystem, trust.TierSuspect) != TierStandard {
		t.Fatal("suspect trust should cap at TierStandard")
	}
}

func TestFinal_EffectiveTierNeutralNoChange(t *testing.T) {
	if EffectiveTier(TierElevated, trust.TierNeutral) != TierElevated {
		t.Fatal("neutral trust should not change tier")
	}
}

func TestFinal_StaticPrivilegeResolverDefault(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	tier, err := r.ResolveTier(nil, "unknown-agent")
	if err != nil || tier != TierStandard {
		t.Fatal("should return default tier")
	}
}

func TestFinal_StaticPrivilegeResolverSetGet(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierRestricted)
	r.SetTier("agent-1", TierSystem)
	tier, _ := r.ResolveTier(nil, "agent-1")
	if tier != TierSystem {
		t.Fatal("should return set tier")
	}
}

func TestFinal_EffectTierMapNonEmpty(t *testing.T) {
	if len(EffectTierMap) == 0 {
		t.Fatal("EffectTierMap must not be empty")
	}
}

func TestFinal_EffectTierMapUniqueValues(t *testing.T) {
	for k, v := range EffectTierMap {
		if k == "" {
			t.Fatal("empty key in EffectTierMap")
		}
		if v < TierRestricted || v > TierSystem {
			t.Fatalf("tier out of range for %s: %d", k, v)
		}
	}
}

func TestFinal_GradedResponseJSON(t *testing.T) {
	gr := GradedResponse{Level: ResponseThrottle, Reason: "rate limit", Duration: time.Second, AllowEffect: false, WindowRate: 5.5}
	data, err := json.Marshal(gr)
	if err != nil {
		t.Fatal(err)
	}
	var gr2 GradedResponse
	if err := json.Unmarshal(data, &gr2); err != nil {
		t.Fatal(err)
	}
	if gr2.Level != ResponseThrottle {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_BudgetCostJSON(t *testing.T) {
	bc := BudgetCost{Requests: 42}
	data, _ := json.Marshal(bc)
	var bc2 BudgetCost
	json.Unmarshal(data, &bc2)
	if bc2.Requests != 42 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AuditEntryJSON(t *testing.T) {
	ae := AuditEntry{ID: "e1", Actor: "a1", Action: "test", Target: "t1", Timestamp: time.Now()}
	data, _ := json.Marshal(ae)
	var ae2 AuditEntry
	json.Unmarshal(data, &ae2)
	if ae2.Actor != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AuditLogAppendAndVerify(t *testing.T) {
	al := NewAuditLog()
	al.Append("actor1", "test", "target1", "details")
	if len(al.Entries) != 1 {
		t.Fatal("should have 1 entry")
	}
	ok, err := al.VerifyChain()
	if err != nil || !ok {
		t.Fatal("chain should verify")
	}
}

func TestFinal_ConcurrentTierResolution(t *testing.T) {
	r := NewStaticPrivilegeResolver(TierStandard)
	r.SetTier("a", TierElevated)
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.ResolveTier(nil, "a")
		}()
	}
	wg.Wait()
}

func TestFinal_ResponseLevelOrder(t *testing.T) {
	if ResponseObserve >= ResponseThrottle {
		t.Fatal("observe should be < throttle")
	}
	if ResponseThrottle >= ResponseInterrupt {
		t.Fatal("throttle should be < interrupt")
	}
	if ResponseInterrupt >= ResponseQuarantine {
		t.Fatal("interrupt should be < quarantine")
	}
	if ResponseQuarantine >= ResponseFailClosed {
		t.Fatal("quarantine should be < fail_closed")
	}
}

func TestFinal_AllResponseLevelsStringNonempty(t *testing.T) {
	levels := []ResponseLevel{ResponseObserve, ResponseThrottle, ResponseInterrupt, ResponseQuarantine, ResponseFailClosed}
	for _, l := range levels {
		if l.String() == "" {
			t.Fatalf("level %d has empty string", l)
		}
	}
}

func TestFinal_PrivilegeTierValues(t *testing.T) {
	if TierRestricted != 0 || TierStandard != 1 || TierElevated != 2 || TierSystem != 3 {
		t.Fatal("tier values must be 0,1,2,3")
	}
}

func TestFinal_DecisionRequestZeroValue(t *testing.T) {
	var dr DecisionRequest
	if dr.Principal != "" {
		t.Fatal("zero-value request should have empty principal")
	}
}
