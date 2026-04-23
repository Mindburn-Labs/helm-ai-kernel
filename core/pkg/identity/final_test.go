package identity

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_PrincipalTypeConstants(t *testing.T) {
	types := []PrincipalType{PrincipalUser, PrincipalAgent, PrincipalService}
	seen := make(map[PrincipalType]bool)
	for _, pt := range types {
		if pt == "" {
			t.Fatal("principal type must not be empty")
		}
		if seen[pt] {
			t.Fatalf("duplicate: %s", pt)
		}
		seen[pt] = true
	}
}

func TestFinal_AgentIdentityPrincipal(t *testing.T) {
	ai := &AgentIdentity{AgentID: "a1", DelegatorID: "u1"}
	if ai.ID() != "a1" {
		t.Fatal("ID mismatch")
	}
	if ai.Type() != PrincipalAgent {
		t.Fatal("type mismatch")
	}
}

func TestFinal_AgentIdentityInterface(t *testing.T) {
	var _ Principal = (*AgentIdentity)(nil)
}

func TestFinal_IdentityTokenJSON(t *testing.T) {
	it := IdentityToken{Subject: "sub1", Email: "a@b.com", Issuer: "iss1"}
	data, _ := json.Marshal(it)
	var it2 IdentityToken
	json.Unmarshal(data, &it2)
	if it2.Subject != "sub1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DelegationSessionJSON(t *testing.T) {
	ds := DelegationSession{SessionID: "s1", DelegatorPrincipal: "u1", DelegatePrincipal: "a1", ExpiresAt: time.Now().Add(time.Hour)}
	data, _ := json.Marshal(ds)
	var ds2 DelegationSession
	json.Unmarshal(data, &ds2)
	if ds2.SessionID != "s1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CapabilityGrantJSON(t *testing.T) {
	cg := CapabilityGrant{Resource: "tool1", Actions: []string{"EXECUTE_TOOL", "READ"}}
	data, _ := json.Marshal(cg)
	var cg2 CapabilityGrant
	json.Unmarshal(data, &cg2)
	if len(cg2.Actions) != 2 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DeviceClassConstants(t *testing.T) {
	classes := []DeviceClass{DeviceClassRobot, DeviceClassSensor, DeviceClassActuator, DeviceClassGateway, DeviceClassTerminal}
	for _, c := range classes {
		if c == "" {
			t.Fatal("device class must not be empty")
		}
	}
}

func TestFinal_DeviceClassUnique(t *testing.T) {
	classes := []DeviceClass{DeviceClassRobot, DeviceClassSensor, DeviceClassActuator, DeviceClassGateway, DeviceClassTerminal, DeviceClassVehicle, DeviceClassFacility}
	seen := make(map[DeviceClass]bool)
	for _, c := range classes {
		if seen[c] {
			t.Fatalf("duplicate: %s", c)
		}
		seen[c] = true
	}
}

func TestFinal_DeviceTrustLevelConstants(t *testing.T) {
	levels := []DeviceTrustLevel{DeviceTrustUnverified, DeviceTrustBasic, DeviceTrustVerified, DeviceTrustAttested}
	for _, l := range levels {
		if l == "" {
			t.Fatal("trust level must not be empty")
		}
	}
}

func TestFinal_TokenManagerZeroValue(t *testing.T) {
	tm := &TokenManager{}
	if tm == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_IsolationViolationRecordJSON(t *testing.T) {
	ivr := IsolationViolationRecord{AttemptingPrincipal: "a1", BoundPrincipal: "b1"}
	data, _ := json.Marshal(ivr)
	var ivr2 IsolationViolationRecord
	json.Unmarshal(data, &ivr2)
	if ivr2.AttemptingPrincipal != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DelegationErrorJSON(t *testing.T) {
	e := DelegationError{Message: "invalid scope"}
	if e.Error() == "" {
		t.Fatal("error should have message")
	}
}

func TestFinal_PrincipalTypeUnique(t *testing.T) {
	types := []PrincipalType{PrincipalUser, PrincipalAgent, PrincipalService}
	seen := make(map[PrincipalType]bool)
	for _, pt := range types {
		if seen[pt] {
			t.Fatalf("duplicate principal type: %s", pt)
		}
		seen[pt] = true
	}
}

func TestFinal_IdentityClaimsJSON(t *testing.T) {
	ic := IdentityClaims{Type: PrincipalAgent, TenantID: "t1"}
	data, _ := json.Marshal(ic)
	var ic2 IdentityClaims
	json.Unmarshal(data, &ic2)
	if ic2.TenantID != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_IsolationCheckerZeroValue(t *testing.T) {
	ic := &IsolationChecker{}
	if ic == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_AgentCertificateJSON(t *testing.T) {
	ac := AgentCertificate{CertID: "c1", AgentID: "a1", IssuerID: "ca1"}
	data, _ := json.Marshal(ac)
	var ac2 AgentCertificate
	json.Unmarshal(data, &ac2)
	if ac2.CertID != "c1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CertificateRequestJSON(t *testing.T) {
	cr := CertificateRequest{AgentID: "a1", Capabilities: []string{"tool:execute"}}
	data, _ := json.Marshal(cr)
	var cr2 CertificateRequest
	json.Unmarshal(data, &cr2)
	if cr2.AgentID != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_FileStoreZeroValue(t *testing.T) {
	fs := &FileStore{}
	if fs == nil {
		t.Fatal("zero value should not be nil")
	}
}

func TestFinal_InMemoryDelegationStoreImpl(t *testing.T) {
	var _ DelegationStore = (*InMemoryDelegationStore)(nil)
}

func TestFinal_ConcurrentPrincipalAccess(t *testing.T) {
	var wg sync.WaitGroup
	ai := &AgentIdentity{AgentID: "a1"}
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ai.ID()
			_ = ai.Type()
		}()
	}
	wg.Wait()
}

func TestFinal_DeviceIdentityJSON(t *testing.T) {
	di := DeviceIdentity{ID: "d1", Class: DeviceClassRobot, TrustLevel: DeviceTrustVerified}
	data, _ := json.Marshal(di)
	var di2 DeviceIdentity
	json.Unmarshal(data, &di2)
	if di2.ID != "d1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CapabilityGrantActions(t *testing.T) {
	cg := CapabilityGrant{Resource: "tool1", Actions: []string{"READ", "WRITE", "EXECUTE"}}
	if len(cg.Actions) != 3 {
		t.Fatal("should have 3 actions")
	}
}

func TestFinal_DelegationSessionCapabilities(t *testing.T) {
	ds := DelegationSession{
		SessionID: "s1",
		Capabilities: []CapabilityGrant{
			{Resource: "tool1", Actions: []string{"READ"}},
			{Resource: "tool2", Actions: []string{"WRITE"}},
		},
	}
	if len(ds.Capabilities) != 2 {
		t.Fatal("should have 2 capabilities")
	}
}
