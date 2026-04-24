package tooling

import (
	"encoding/json"
	"testing"
)

func TestFinal_ToolDescriptorJSONRoundTrip(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "http://localhost", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	data, _ := json.Marshal(td)
	var got ToolDescriptor
	json.Unmarshal(data, &got)
	if got.ToolID != "t1" || got.Version != "1.0" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CostEnvelopeJSONRoundTrip(t *testing.T) {
	ce := CostEnvelope{MaxLatencyMs: 100, MaxCostUnits: 1.5, MaxTokens: 4096}
	data, _ := json.Marshal(ce)
	var got CostEnvelope
	json.Unmarshal(data, &got)
	if got.MaxLatencyMs != 100 || got.MaxTokens != 4096 {
		t.Fatal("cost envelope round-trip")
	}
}

func TestFinal_FingerprintDeterministic(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "http://localhost", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	f1 := td.Fingerprint()
	f2 := td.Fingerprint()
	if f1 != f2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_FingerprintChangesOnVersion(t *testing.T) {
	td1 := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	td2 := ToolDescriptor{ToolID: "t1", Version: "2.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if td1.Fingerprint() == td2.Fingerprint() {
		t.Fatal("different versions should have different fingerprints")
	}
}

func TestFinal_FingerprintLength(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	f := td.Fingerprint()
	if len(f) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(f))
	}
}

func TestFinal_ValidateSuccess(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "http://x", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if err := td.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFinal_ValidateMissingToolID(t *testing.T) {
	td := ToolDescriptor{Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if td.Validate() == nil {
		t.Fatal("should error")
	}
}

func TestFinal_ValidateMissingVersion(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if td.Validate() == nil {
		t.Fatal("should error")
	}
}

func TestFinal_ValidateMissingEndpoint(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if td.Validate() == nil {
		t.Fatal("should error")
	}
}

func TestFinal_ValidateMissingInputSchema(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", OutputSchemaHash: "h2"}
	if td.Validate() == nil {
		t.Fatal("should error")
	}
}

func TestFinal_ValidateMissingOutputSchema(t *testing.T) {
	td := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1"}
	if td.Validate() == nil {
		t.Fatal("should error")
	}
}

func TestFinal_HasChangedTrue(t *testing.T) {
	td1 := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	td2 := ToolDescriptor{ToolID: "t1", Version: "2.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if !td1.HasChanged(&td2) {
		t.Fatal("should detect change")
	}
}

func TestFinal_HasChangedFalse(t *testing.T) {
	td1 := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	td2 := ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	if td1.HasChanged(&td2) {
		t.Fatal("same should not detect change")
	}
}

func TestFinal_DeterministicFlagsSorted(t *testing.T) {
	td := ToolDescriptor{DeterministicFlags: []string{"c", "a", "b"}}
	sorted := td.deterministicFlagsSorted()
	if sorted[0] != "a" || sorted[1] != "b" || sorted[2] != "c" {
		t.Fatal("not sorted")
	}
}

func TestFinal_DeterministicFlagsNil(t *testing.T) {
	td := ToolDescriptor{}
	sorted := td.deterministicFlagsSorted()
	if len(sorted) != 0 {
		t.Fatal("nil should return empty")
	}
}

func TestFinal_NewToolRegistry(t *testing.T) {
	r := NewToolRegistry()
	if r == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_ToolRegistryRegister(t *testing.T) {
	r := NewToolRegistry()
	td := &ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	err := r.Register(td)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_ToolRegistryRegisterInvalid(t *testing.T) {
	r := NewToolRegistry()
	err := r.Register(&ToolDescriptor{})
	if err == nil {
		t.Fatal("should error on invalid")
	}
}

func TestFinal_ToolRegistryGet(t *testing.T) {
	r := NewToolRegistry()
	r.Register(&ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"})
	td, ok := r.Get("t1")
	if !ok || td.Version != "1.0" {
		t.Fatal("get failed")
	}
}

func TestFinal_ToolRegistryGetMissing(t *testing.T) {
	r := NewToolRegistry()
	_, ok := r.Get("nope")
	if ok {
		t.Fatal("should not find")
	}
}

func TestFinal_ToolRegistryGetFingerprint(t *testing.T) {
	r := NewToolRegistry()
	r.Register(&ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"})
	fp, ok := r.GetFingerprint("t1")
	if !ok || fp == "" {
		t.Fatal("fingerprint failed")
	}
}

func TestFinal_ToolRegistryList(t *testing.T) {
	r := NewToolRegistry()
	r.Register(&ToolDescriptor{ToolID: "b", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"})
	r.Register(&ToolDescriptor{ToolID: "a", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"})
	ids := r.List()
	if ids[0] != "a" || ids[1] != "b" {
		t.Fatal("should be sorted")
	}
}

func TestFinal_NewToolChangeDetector(t *testing.T) {
	d := NewToolChangeDetector()
	if d == nil {
		t.Fatal("nil detector")
	}
}

func TestFinal_ToolChangeDetectorBaseline(t *testing.T) {
	d := NewToolChangeDetector()
	td := &ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.RegisterBaseline(td)
	if d.RequiresReevaluation("t1") {
		t.Fatal("should not need reevaluation after baseline")
	}
}

func TestFinal_ToolChangeDetectorChange(t *testing.T) {
	d := NewToolChangeDetector()
	td1 := &ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.RegisterBaseline(td1)
	td2 := &ToolDescriptor{ToolID: "t1", Version: "2.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	changed, _ := d.CheckForChange(td2)
	if !changed {
		t.Fatal("should detect change")
	}
}

func TestFinal_ToolChangeDetectorNoChange(t *testing.T) {
	d := NewToolChangeDetector()
	td := &ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.RegisterBaseline(td)
	changed, _ := d.CheckForChange(td)
	if changed {
		t.Fatal("same tool should not be flagged")
	}
}

func TestFinal_GateExecutionBlocked(t *testing.T) {
	d := NewToolChangeDetector()
	td1 := &ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.RegisterBaseline(td1)
	td2 := &ToolDescriptor{ToolID: "t1", Version: "2.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.CheckForChange(td2)
	err := d.GateExecution(td2)
	if err == nil {
		t.Fatal("should block execution")
	}
}

func TestFinal_MarkReevaluated(t *testing.T) {
	d := NewToolChangeDetector()
	td1 := &ToolDescriptor{ToolID: "t1", Version: "1.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.RegisterBaseline(td1)
	td2 := &ToolDescriptor{ToolID: "t1", Version: "2.0", Endpoint: "e", InputSchemaHash: "h1", OutputSchemaHash: "h2"}
	d.CheckForChange(td2)
	d.MarkReevaluated(td2)
	if d.RequiresReevaluation("t1") {
		t.Fatal("should be cleared")
	}
}

func TestFinal_ToolChangeErrorString(t *testing.T) {
	e := &ToolChangeError{ToolID: "t1", Message: "changed"}
	if e.Error() == "" {
		t.Fatal("error string should not be empty")
	}
}

func TestFinal_PolicyInputBundleJSONRoundTrip(t *testing.T) {
	b := PolicyInputBundle{RequestID: "r1", EffectType: "DATA_WRITE", Principal: "agent-1"}
	data, _ := json.Marshal(b)
	var got PolicyInputBundle
	json.Unmarshal(data, &got)
	if got.RequestID != "r1" {
		t.Fatal("bundle round-trip")
	}
}

func TestFinal_NormalizeBundleNil(t *testing.T) {
	_, err := NormalizeBundle(nil)
	if err == nil {
		t.Fatal("should error on nil")
	}
}

func TestFinal_NormalizeBundleDeterministic(t *testing.T) {
	b := &PolicyInputBundle{RequestID: "r1", Payload: map[string]interface{}{"z": 1, "a": 2}}
	d1, _ := NormalizeBundle(b)
	d2, _ := NormalizeBundle(b)
	if string(d1) != string(d2) {
		t.Fatal("not deterministic")
	}
}

func TestFinal_BundleHashDeterministic(t *testing.T) {
	b := &PolicyInputBundle{RequestID: "r1", Payload: map[string]interface{}{"k": "v"}}
	h1, _ := BundleHash(b)
	h2, _ := BundleHash(b)
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_NormalizationEquivalent(t *testing.T) {
	a := &PolicyInputBundle{RequestID: "r1", Payload: map[string]interface{}{"k": "v"}}
	b := &PolicyInputBundle{RequestID: "r1", Payload: map[string]interface{}{"k": "v"}}
	eq, _ := NormalizationEquivalent(a, b)
	if !eq {
		t.Fatal("should be equivalent")
	}
}

func TestFinal_NormalizationNotEquivalent(t *testing.T) {
	a := &PolicyInputBundle{RequestID: "r1"}
	b := &PolicyInputBundle{RequestID: "r2"}
	eq, _ := NormalizationEquivalent(a, b)
	if eq {
		t.Fatal("should not be equivalent")
	}
}
