package contracts

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ── Verdict Tests ────────────────────────────────────────────────

func TestDeepVerdictIsTerminal(t *testing.T) {
	if !VerdictAllow.IsTerminal() {
		t.Fatal("ALLOW should be terminal")
	}
	if !VerdictDeny.IsTerminal() {
		t.Fatal("DENY should be terminal")
	}
	if VerdictEscalate.IsTerminal() {
		t.Fatal("ESCALATE should not be terminal")
	}
}

func TestDeepIsCanonicalVerdictAllValues(t *testing.T) {
	for _, v := range CanonicalVerdicts() {
		if !IsCanonicalVerdict(string(v)) {
			t.Fatalf("expected %q to be canonical", v)
		}
	}
}

func TestDeepIsCanonicalVerdictRejectsInvalid(t *testing.T) {
	invalids := []string{"", "allow", "PENDING", "BLOCK", "PERMIT", " ALLOW", "ALLOW "}
	for _, v := range invalids {
		if IsCanonicalVerdict(v) {
			t.Fatalf("expected %q to be rejected", v)
		}
	}
}

func TestDeepIsCanonicalReasonCodeAllValues(t *testing.T) {
	for _, rc := range CoreReasonCodes() {
		if !IsCanonicalReasonCode(string(rc)) {
			t.Fatalf("expected %q to be canonical", rc)
		}
	}
}

func TestDeepIsCanonicalReasonCodeRejectsInvalid(t *testing.T) {
	invalids := []string{"", "policy_violation", "UNKNOWN", "CUSTOM_REASON"}
	for _, rc := range invalids {
		if IsCanonicalReasonCode(rc) {
			t.Fatalf("expected %q to be rejected", rc)
		}
	}
}

func TestDeepCoreReasonCodesCount(t *testing.T) {
	codes := CoreReasonCodes()
	if len(codes) < 30 {
		t.Fatalf("expected at least 30 reason codes, got %d", len(codes))
	}
}

// ── DecisionRecord Tests ─────────────────────────────────────────

func TestDeepDecisionRecordJSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	d := DecisionRecord{
		ID: "dec-1", ProposalID: "prop-1", StepID: "step-1",
		PhenotypeHash: "ph-hash", PolicyVersion: "v1",
		SubjectID: "agent-1", Action: "read", Resource: "res-1",
		Verdict: "ALLOW", Reason: "policy match", Timestamp: now,
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var d2 DecisionRecord
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatal(err)
	}
	if d2.ID != d.ID || d2.Verdict != d.Verdict || !d2.Timestamp.Equal(d.Timestamp) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDeepDecisionRecordDeterministicHash(t *testing.T) {
	d := DecisionRecord{ID: "x", Verdict: "DENY", Reason: "test"}
	b1, _ := json.Marshal(d)
	b2, _ := json.Marshal(d)
	if string(b1) != string(b2) {
		t.Fatal("same struct should produce identical JSON")
	}
}

func TestDeepDecisionRecordEmptyFields(t *testing.T) {
	var d DecisionRecord
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"verdict":""`) {
		t.Fatal("empty verdict should marshal as empty string")
	}
}

func TestDeepDecisionRecordWithIntervention(t *testing.T) {
	d := DecisionRecord{
		ID: "dec-int", Verdict: "DENY",
		Intervention: &InterventionMetadata{
			Type: InterventionThrottle, ReasonCode: "VELOCITY_LIMIT_EXCEEDED",
			WaitDuration: 5 * time.Second, TokensSaved: 100,
		},
	}
	data, _ := json.Marshal(d)
	var d2 DecisionRecord
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatal(err)
	}
	if d2.Intervention == nil || d2.Intervention.Type != InterventionThrottle {
		t.Fatal("intervention lost in round-trip")
	}
}

// ── Receipt Tests ────────────────────────────────────────────────

func TestDeepReceiptJSONRoundTrip(t *testing.T) {
	r := Receipt{
		ReceiptID: "rcpt-1", DecisionID: "dec-1", EffectID: "eff-1",
		Status: "success", LamportClock: 42, PrevHash: "prev-hash",
	}
	data, _ := json.Marshal(r)
	var r2 Receipt
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.ReceiptID != r.ReceiptID || r2.LamportClock != 42 {
		t.Fatal("round-trip mismatch")
	}
}

func TestDeepReceiptDeterministicHash(t *testing.T) {
	r := Receipt{ReceiptID: "r1", Status: "ok"}
	b1, _ := json.Marshal(r)
	b2, _ := json.Marshal(r)
	if string(b1) != string(b2) {
		t.Fatal("same receipt should produce identical JSON")
	}
}

func TestDeepReceiptWithPortExposures(t *testing.T) {
	r := Receipt{
		ReceiptID: "rcpt-pe",
		PortExposures: []PortExposureEvent{
			{Port: 8080, Protocol: "tcp", Direction: "inbound"},
			{Port: 443, Protocol: "tcp", Direction: "outbound"},
		},
	}
	data, _ := json.Marshal(r)
	var r2 Receipt
	json.Unmarshal(data, &r2)
	if len(r2.PortExposures) != 2 {
		t.Fatalf("expected 2 port exposures, got %d", len(r2.PortExposures))
	}
}

// ── Codec Tests ──────────────────────────────────────────────────

func TestDeepDecodeDecisionRecordJSON(t *testing.T) {
	token := `{"id":"d1","verdict":"ALLOW","reason":"ok"}`
	d, err := DecodeDecisionRecord(token)
	if err != nil || d.ID != "d1" || d.Verdict != "ALLOW" {
		t.Fatal("plain JSON decode failed")
	}
}

func TestDeepDecodeDecisionRecordInvalid(t *testing.T) {
	_, err := DecodeDecisionRecord("not-json-or-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestDeepEncodeDecisionRecord(t *testing.T) {
	d := &DecisionRecord{ID: "enc-1", Verdict: "DENY"}
	s, err := EncodeDecisionRecord(d)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DecodeDecisionRecord(s)
	if err != nil || d2.ID != "enc-1" {
		t.Fatal("encode-decode round-trip failed")
	}
}

func TestDeepEncodeDecisionRecordNil(t *testing.T) {
	_, err := EncodeDecisionRecord(nil)
	if err != nil {
		t.Fatal("encoding nil should produce null JSON, not error")
	}
}

// ── EffectRiskClass Tests ────────────────────────────────────────

func TestDeepEffectRiskClassE4(t *testing.T) {
	e4 := []string{EffectTypeInfraDestroy, EffectTypeCICredentialAccess, EffectTypeSoftwarePublish, EffectTypeDataEgress, EffectTypeExecutePayment, EffectTypeRequestPurchase}
	for _, e := range e4 {
		if EffectRiskClass(e) != "E4" {
			t.Fatalf("expected E4 for %s, got %s", e, EffectRiskClass(e))
		}
	}
}

func TestDeepEffectRiskClassUnknownDefaultsE3(t *testing.T) {
	if EffectRiskClass("TOTALLY_UNKNOWN_EFFECT") != "E3" {
		t.Fatal("unknown effects should default to E3 (fail-closed)")
	}
}

func TestDeepEffectRiskClassE1(t *testing.T) {
	e1 := []string{EffectTypeAgentIdentityIsolation, EffectTypeSendChatMessage, EffectTypeCreateTask, EffectTypeRunSandboxedCode}
	for _, e := range e1 {
		if EffectRiskClass(e) != "E1" {
			t.Fatalf("expected E1 for %s, got %s", e, EffectRiskClass(e))
		}
	}
}

// ── LookupEffectType Tests ───────────────────────────────────────

func TestDeepLookupEffectTypeFound(t *testing.T) {
	et := LookupEffectType(EffectTypeInfraDestroy)
	if et == nil || et.TypeID != EffectTypeInfraDestroy {
		t.Fatal("should find INFRA_DESTROY in default catalog")
	}
}

func TestDeepLookupEffectTypeNotFound(t *testing.T) {
	if LookupEffectType("NONEXISTENT") != nil {
		t.Fatal("should return nil for unknown effect type")
	}
}

func TestDeepDefaultEffectCatalogNonEmpty(t *testing.T) {
	cat := DefaultEffectCatalog()
	if len(cat.EffectTypes) < 10 {
		t.Fatalf("expected at least 10 effect types, got %d", len(cat.EffectTypes))
	}
}

// ── ThreatSignal Tests ───────────────────────────────────────────

func TestDeepSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast(ThreatSeverityCritical, ThreatSeverityInfo) {
		t.Fatal("CRITICAL should be >= INFO")
	}
	if SeverityAtLeast(ThreatSeverityLow, ThreatSeverityHigh) {
		t.Fatal("LOW should not be >= HIGH")
	}
	if !SeverityAtLeast(ThreatSeverityMedium, ThreatSeverityMedium) {
		t.Fatal("MEDIUM should be >= MEDIUM")
	}
}

func TestDeepMaxSeverityOfEmpty(t *testing.T) {
	result := MaxSeverityOf(nil)
	if result != ThreatSeverityInfo {
		t.Fatalf("empty findings should yield INFO, got %s", result)
	}
}

func TestDeepMaxSeverityOfMixed(t *testing.T) {
	findings := []ThreatFinding{
		{Severity: ThreatSeverityLow},
		{Severity: ThreatSeverityCritical},
		{Severity: ThreatSeverityMedium},
	}
	if MaxSeverityOf(findings) != ThreatSeverityCritical {
		t.Fatal("should return CRITICAL")
	}
}

func TestDeepInputTrustLevelIsTainted(t *testing.T) {
	if !InputTrustTainted.IsTainted() {
		t.Fatal("TAINTED should be tainted")
	}
	if !InputTrustExternalUntrusted.IsTainted() {
		t.Fatal("EXTERNAL_UNTRUSTED should be tainted")
	}
	if InputTrustTrusted.IsTainted() {
		t.Fatal("TRUSTED should not be tainted")
	}
}

func TestDeepThreatScanResultRef(t *testing.T) {
	r := &ThreatScanResult{
		ScanID: "scan-1", MaxSeverity: ThreatSeverityHigh,
		FindingCount: 3, TrustLevel: InputTrustTainted, RawInputHash: "abc",
	}
	ref := r.Ref()
	if ref.ScanID != "scan-1" || ref.MaxSeverity != ThreatSeverityHigh || ref.FindingCount != 3 {
		t.Fatal("ref should copy fields from result")
	}
}

// ── EventEnvelope Tests ──────────────────────────────────────────

func TestDeepEventEnvelopeJSONRoundTrip(t *testing.T) {
	e := EventEnvelope{
		EventID: "ev-1", ProposalID: "prop-1", EventType: "test",
		OracleTick: 12345, IdempotencyKey: "key-1",
	}
	data, _ := json.Marshal(e)
	var e2 EventEnvelope
	json.Unmarshal(data, &e2)
	if e2.EventID != "ev-1" || e2.OracleTick != 12345 {
		t.Fatal("round-trip mismatch")
	}
}

func TestDeepInterventionTypeConstants(t *testing.T) {
	types := []InterventionType{InterventionNone, InterventionThrottle, InterventionInterrupt, InterventionQuarantine}
	seen := map[InterventionType]bool{}
	for _, it := range types {
		if seen[it] {
			t.Fatalf("duplicate intervention type: %s", it)
		}
		seen[it] = true
	}
	if len(seen) != 4 {
		t.Fatal("expected exactly 4 intervention types")
	}
}

// ── EvidencePack Tests ───────────────────────────────────────────

func TestDeepEvidencePackJSONRoundTrip(t *testing.T) {
	ep := EvidencePack{
		PackID: "pack-1", FormatVersion: "1.0",
		Identity: EvidencePackIdentity{ActorID: "a1", ActorType: "agent"},
		Policy:   EvidencePackPolicy{DecisionID: "d1", PolicyVersion: "v1"},
		Effect:   EvidencePackEffect{EffectID: "e1", EffectType: "SEND_EMAIL"},
	}
	data, _ := json.Marshal(ep)
	var ep2 EvidencePack
	json.Unmarshal(data, &ep2)
	if ep2.PackID != "pack-1" || ep2.Identity.ActorID != "a1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestDeepEvidencePackEmptyFields(t *testing.T) {
	var ep EvidencePack
	data, _ := json.Marshal(ep)
	if len(data) == 0 {
		t.Fatal("empty evidence pack should still serialize")
	}
}
