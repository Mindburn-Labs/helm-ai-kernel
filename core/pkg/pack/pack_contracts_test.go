package pack

import (
	"encoding/json"
	"testing"
)

func TestFinal_PackTypeConstants(t *testing.T) {
	types := []PackType{PackTypeFactory, PackTypeConnector, PackTypePolicy, PackTypeEvidence}
	if len(types) != 4 {
		t.Fatal("expected 4 pack types")
	}
}

func TestFinal_PackGradeConstants(t *testing.T) {
	grades := []PackGrade{GradeBronze, GradeSilver, GradeGold}
	if len(grades) != 3 {
		t.Fatal("expected 3 grades")
	}
}

func TestFinal_PackManifestJSONRoundTrip(t *testing.T) {
	m := PackManifest{PackID: "p1", Name: "test", Version: "1.0.0", Type: PackTypePolicy}
	data, _ := json.Marshal(m)
	var got PackManifest
	json.Unmarshal(data, &got)
	if got.PackID != "p1" || got.Type != PackTypePolicy {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_PackJSONRoundTrip(t *testing.T) {
	p := Pack{PackID: "p1", ContentHash: "h1", Manifest: PackManifest{Name: "test"}}
	data, _ := json.Marshal(p)
	var got Pack
	json.Unmarshal(data, &got)
	if got.PackID != "p1" || got.ContentHash != "h1" {
		t.Fatal("pack round-trip")
	}
}

func TestFinal_PackDependencyJSONRoundTrip(t *testing.T) {
	pd := PackDependency{PackName: "dep1", VersionSpec: ">=1.0.0", Optional: true}
	data, _ := json.Marshal(pd)
	var got PackDependency
	json.Unmarshal(data, &got)
	if got.PackName != "dep1" || !got.Optional {
		t.Fatal("dependency round-trip")
	}
}

func TestFinal_PackVersionJSONRoundTrip(t *testing.T) {
	pv := PackVersion{PackName: "p1", Version: "1.0.0", ContentHash: "h1", Deprecated: false}
	data, _ := json.Marshal(pv)
	var got PackVersion
	json.Unmarshal(data, &got)
	if got.Version != "1.0.0" {
		t.Fatal("version round-trip")
	}
}

func TestFinal_GradingReportJSONRoundTrip(t *testing.T) {
	gr := GradingReport{PackID: "p1", Grade: GradeGold, Evidence: []string{"e1"}}
	data, _ := json.Marshal(gr)
	var got GradingReport
	json.Unmarshal(data, &got)
	if got.Grade != GradeGold || len(got.Evidence) != 1 {
		t.Fatal("grading round-trip")
	}
}

func TestFinal_NewPackBuilder(t *testing.T) {
	b := NewPackBuilder(PackManifest{Name: "test", Version: "1.0"})
	if b == nil {
		t.Fatal("nil builder")
	}
}

func TestFinal_BuildSuccess(t *testing.T) {
	b := NewPackBuilder(PackManifest{Name: "test", Version: "1.0"})
	p, err := b.Build()
	if err != nil || p == nil {
		t.Fatal("build failed")
	}
}

func TestFinal_BuildMissingName(t *testing.T) {
	b := NewPackBuilder(PackManifest{Version: "1.0"})
	_, err := b.Build()
	if err == nil {
		t.Fatal("should error on missing name")
	}
}

func TestFinal_BuildMissingVersion(t *testing.T) {
	b := NewPackBuilder(PackManifest{Name: "test"})
	_, err := b.Build()
	if err == nil {
		t.Fatal("should error on missing version")
	}
}

func TestFinal_BuildSetsContentHash(t *testing.T) {
	b := NewPackBuilder(PackManifest{Name: "test", Version: "1.0"})
	p, _ := b.Build()
	if p.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFinal_BuildSetsPackID(t *testing.T) {
	b := NewPackBuilder(PackManifest{Name: "test", Version: "1.0"})
	p, _ := b.Build()
	if p.PackID == "" {
		t.Fatal("pack ID should be set")
	}
}

func TestFinal_ValidateManifestValid(t *testing.T) {
	err := ValidateManifest(PackManifest{Capabilities: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinal_ValidateManifestEmptyCap(t *testing.T) {
	err := ValidateManifest(PackManifest{Capabilities: []string{"read", ""}})
	if err == nil {
		t.Fatal("should error on empty capability")
	}
}

func TestFinal_ValidateManifestNoCaps(t *testing.T) {
	err := ValidateManifest(PackManifest{})
	if err != nil {
		t.Fatal("no caps should be valid")
	}
}

func TestFinal_EvidenceContractJSONRoundTrip(t *testing.T) {
	ec := EvidenceContract{
		Produces: []EvidenceProduce{{Class: "SOC2", Format: "json"}},
		Requires: []EvidenceRequire{{Class: "audit", Source: "internal"}},
	}
	data, _ := json.Marshal(ec)
	var got EvidenceContract
	json.Unmarshal(data, &got)
	if len(got.Produces) != 1 || len(got.Requires) != 1 {
		t.Fatal("evidence contract round-trip")
	}
}

func TestFinal_ToolBindingJSONRoundTrip(t *testing.T) {
	tb := ToolBinding{ToolID: "tool1", Required: true}
	data, _ := json.Marshal(tb)
	var got ToolBinding
	json.Unmarshal(data, &got)
	if got.ToolID != "tool1" || !got.Required {
		t.Fatal("tool binding round-trip")
	}
}

func TestFinal_PDPHookJSONRoundTrip(t *testing.T) {
	h := PDPHook{HookType: "pre", EffectTypes: []string{"DATA_WRITE"}}
	data, _ := json.Marshal(h)
	var got PDPHook
	json.Unmarshal(data, &got)
	if got.HookType != "pre" {
		t.Fatal("pdp hook round-trip")
	}
}

func TestFinal_SignatureJSONRoundTrip(t *testing.T) {
	s := Signature{SignerID: "s1", Signature: "sig", Algorithm: "ed25519"}
	data, _ := json.Marshal(s)
	var got Signature
	json.Unmarshal(data, &got)
	if got.SignerID != "s1" {
		t.Fatal("signature round-trip")
	}
}

func TestFinal_ProvenanceJSONRoundTrip(t *testing.T) {
	p := Provenance{SLSALevel: 3, Source: &SourceInfo{Repo: "github.com/test"}}
	data, _ := json.Marshal(p)
	var got Provenance
	json.Unmarshal(data, &got)
	if got.SLSALevel != 3 {
		t.Fatal("provenance round-trip")
	}
}

func TestFinal_SBOMInfoJSONRoundTrip(t *testing.T) {
	s := SBOMInfo{Format: "cyclonedx", Hash: "h1"}
	data, _ := json.Marshal(s)
	var got SBOMInfo
	json.Unmarshal(data, &got)
	if got.Format != "cyclonedx" {
		t.Fatal("sbom round-trip")
	}
}

func TestFinal_LifecycleJSONRoundTrip(t *testing.T) {
	l := Lifecycle{Status: "active", SuccessorID: "p2"}
	data, _ := json.Marshal(l)
	var got Lifecycle
	json.Unmarshal(data, &got)
	if got.Status != "active" {
		t.Fatal("lifecycle round-trip")
	}
}

func TestFinal_SLOsJSONRoundTrip(t *testing.T) {
	s := ServiceLevelObjectives{MaxFailureRate: 0.001, MinEvidenceRate: 0.99}
	data, _ := json.Marshal(s)
	var got ServiceLevelObjectives
	json.Unmarshal(data, &got)
	if got.MaxFailureRate != 0.001 {
		t.Fatal("slo round-trip")
	}
}

func TestFinal_ApplicabilityConstraintsJSONRoundTrip(t *testing.T) {
	ac := ApplicabilityConstraints{MinAutonomy: "L2", KernelVersion: ">=1.0.0"}
	data, _ := json.Marshal(ac)
	var got ApplicabilityConstraints
	json.Unmarshal(data, &got)
	if got.MinAutonomy != "L2" {
		t.Fatal("applicability round-trip")
	}
}

func TestFinal_TestSpecsJSONRoundTrip(t *testing.T) {
	ts := TestSpecs{Unit: &TestMetric{Count: 100, Coverage: 85.5}}
	data, _ := json.Marshal(ts)
	var got TestSpecs
	json.Unmarshal(data, &got)
	if got.Unit == nil || got.Unit.Count != 100 {
		t.Fatal("test specs round-trip")
	}
}

func TestFinal_BuildInfoJSONRoundTrip(t *testing.T) {
	bi := BuildInfo{BuilderID: "b1", Hermetic: true}
	data, _ := json.Marshal(bi)
	var got BuildInfo
	json.Unmarshal(data, &got)
	if got.BuilderID != "b1" || !got.Hermetic {
		t.Fatal("build info round-trip")
	}
}

func TestFinal_SourceInfoJSONRoundTrip(t *testing.T) {
	si := SourceInfo{Repo: "github.com/test", Commit: "abc123", Tag: "v1.0"}
	data, _ := json.Marshal(si)
	var got SourceInfo
	json.Unmarshal(data, &got)
	if got.Tag != "v1.0" {
		t.Fatal("source info round-trip")
	}
}
