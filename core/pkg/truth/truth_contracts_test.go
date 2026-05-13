package truth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestFinal_TruthTypeConstants(t *testing.T) {
	types := []TruthType{TruthTypePolicy, TruthTypeSchema, TruthTypeRegulation, TruthTypeOrgGenome, TruthTypePackABI, TruthTypeAttestation}
	if len(types) != 6 {
		t.Fatal("expected 6 truth types")
	}
}

func TestFinal_VersionScopeString(t *testing.T) {
	v := VersionScope{Major: 1, Minor: 2, Patch: 3}
	if v.String() != "1.2.3" {
		t.Fatalf("unexpected: %s", v.String())
	}
}

func TestFinal_VersionScopeStringWithEpoch(t *testing.T) {
	v := VersionScope{Epoch: "2026Q1", Major: 1, Minor: 0, Patch: 0}
	s := v.String()
	if s != "2026Q1:1.0.0" {
		t.Fatalf("unexpected: %s", s)
	}
}

func TestFinal_VersionScopeStringWithLabel(t *testing.T) {
	v := VersionScope{Major: 2, Minor: 0, Patch: 0, Label: "rc"}
	if v.String() != "2.0.0-rc" {
		t.Fatalf("unexpected: %s", v.String())
	}
}

func TestFinal_TruthObjectJSONRoundTrip(t *testing.T) {
	obj := TruthObject{ObjectID: "o1", Type: TruthTypePolicy, Name: "base-policy"}
	data, _ := json.Marshal(obj)
	var got TruthObject
	json.Unmarshal(data, &got)
	if got.ObjectID != "o1" || got.Type != TruthTypePolicy {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_FreshnessInfoJSONRoundTrip(t *testing.T) {
	fi := FreshnessInfo{Stale: true, LastValidated: time.Now()}
	data, _ := json.Marshal(fi)
	var got FreshnessInfo
	json.Unmarshal(data, &got)
	if !got.Stale {
		t.Fatal("freshness round-trip")
	}
}

func TestFinal_CompatibilityInfoJSONRoundTrip(t *testing.T) {
	ci := CompatibilityInfo{BreakingChange: true, ReplacedBy: "v2"}
	data, _ := json.Marshal(ci)
	var got CompatibilityInfo
	json.Unmarshal(data, &got)
	if !got.BreakingChange || got.ReplacedBy != "v2" {
		t.Fatal("compat round-trip")
	}
}

func TestFinal_NewInMemoryRegistry(t *testing.T) {
	r := NewInMemoryRegistry()
	if r == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_RegisterAndGet(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&TruthObject{ObjectID: "o1", Type: TruthTypePolicy, Name: "p1"})
	obj, _ := r.Get("o1")
	if obj == nil || obj.Name != "p1" {
		t.Fatal("get failed")
	}
}

func TestFinal_RegisterDuplicate(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&TruthObject{ObjectID: "o1"})
	err := r.Register(&TruthObject{ObjectID: "o1"})
	if err == nil {
		t.Fatal("should error on duplicate")
	}
}

func TestFinal_GetNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	obj, _ := r.Get("nope")
	if obj != nil {
		t.Fatal("should return nil")
	}
}

func TestFinal_GetLatest(t *testing.T) {
	r := NewInMemoryRegistry()
	now := time.Now()
	r.Register(&TruthObject{ObjectID: "o1", Type: TruthTypePolicy, Name: "p1", RegisteredAt: now.Add(-time.Hour)})
	r.Register(&TruthObject{ObjectID: "o2", Type: TruthTypePolicy, Name: "p1", RegisteredAt: now})
	latest, _ := r.GetLatest(TruthTypePolicy, "p1")
	if latest == nil || latest.ObjectID != "o2" {
		t.Fatal("should return latest")
	}
}

func TestFinal_List(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&TruthObject{ObjectID: "o1", Type: TruthTypePolicy})
	r.Register(&TruthObject{ObjectID: "o2", Type: TruthTypeSchema})
	list, _ := r.List(TruthTypePolicy)
	if len(list) != 1 {
		t.Fatal("list should filter by type")
	}
}

func TestFinal_GetAtEpoch(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Register(&TruthObject{ObjectID: "o1", Type: TruthTypePolicy, Name: "p1", Version: VersionScope{Epoch: "2026Q1"}})
	obj, _ := r.GetAtEpoch(TruthTypePolicy, "p1", "2026Q1")
	if obj == nil {
		t.Fatal("should find by epoch")
	}
}

func TestFinal_GetAtEpochNotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	obj, _ := r.GetAtEpoch(TruthTypePolicy, "p1", "nope")
	if obj != nil {
		t.Fatal("should not find")
	}
}

func TestFinal_DuplicateObjectErrorString(t *testing.T) {
	e := &DuplicateObjectError{ObjectID: "o1"}
	if e.Error() == "" {
		t.Fatal("error should have message")
	}
}

func TestFinal_ClaimStatusConstants(t *testing.T) {
	statuses := []ClaimStatus{ClaimStatusPending, ClaimStatusVerified, ClaimStatusRefuted, ClaimStatusExpired}
	if len(statuses) != 4 {
		t.Fatal("expected 4 claim statuses")
	}
}

func TestFinal_ClaimRecordJSONRoundTrip(t *testing.T) {
	cr := ClaimRecord{ClaimID: "c1", Statement: "X is true", Confidence: 0.9, Status: ClaimStatusPending}
	data, _ := json.Marshal(cr)
	var got ClaimRecord
	json.Unmarshal(data, &got)
	if got.ClaimID != "c1" || got.Confidence != 0.9 {
		t.Fatal("claim round-trip")
	}
}

func TestFinal_NewInMemoryClaimRegistry(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	if r == nil {
		t.Fatal("nil registry")
	}
}

func TestFinal_ClaimRegisterAndGet(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1", Statement: "test"})
	got, _ := r.Get("c1")
	if got == nil || got.Status != ClaimStatusPending {
		t.Fatal("should be pending")
	}
}

func TestFinal_ClaimRegisterDuplicate(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1"})
	err := r.Register(&ClaimRecord{ClaimID: "c1"})
	if err == nil {
		t.Fatal("should error on duplicate")
	}
}

func TestFinal_ClaimVerify(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1"})
	r.Verify("c1", []string{"ev1"})
	got, _ := r.Get("c1")
	if got.Status != ClaimStatusVerified {
		t.Fatal("should be verified")
	}
}

func TestFinal_ClaimRefute(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1"})
	r.Refute("c1", "proven false")
	got, _ := r.Get("c1")
	if got.Status != ClaimStatusRefuted {
		t.Fatal("should be refuted")
	}
}

func TestFinal_ClaimVerifyRefutedFails(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1"})
	r.Refute("c1", "reason")
	err := r.Verify("c1", nil)
	if err == nil {
		t.Fatal("should not verify refuted")
	}
}

func TestFinal_ClaimListByStatus(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1"})
	r.Register(&ClaimRecord{ClaimID: "c2"})
	r.Verify("c1", nil)
	list, _ := r.ListByStatus(ClaimStatusPending)
	if len(list) != 1 {
		t.Fatal("should have 1 pending")
	}
}

func TestFinal_ClaimListAll(t *testing.T) {
	r := NewInMemoryClaimRegistry()
	r.Register(&ClaimRecord{ClaimID: "c1"})
	r.Register(&ClaimRecord{ClaimID: "c2"})
	list, _ := r.ListAll()
	if len(list) != 2 {
		t.Fatal("should list all")
	}
}

func TestFinal_NewInMemoryUnknownRegistry(t *testing.T) {
	r := NewInMemoryUnknownRegistry()
	if r == nil {
		t.Fatal("nil")
	}
}

func TestFinal_UnknownRegisterAndGet(t *testing.T) {
	r := NewInMemoryUnknownRegistry()
	r.Register(&contracts.Unknown{ID: "u1", Description: "test"})
	got, _ := r.Get("u1")
	if got == nil || got.Resolved {
		t.Fatal("should be unresolved")
	}
}

func TestFinal_UnknownResolve(t *testing.T) {
	r := NewInMemoryUnknownRegistry()
	r.Register(&contracts.Unknown{ID: "u1"})
	r.Resolve("u1", "fixed it")
	got, _ := r.Get("u1")
	if !got.Resolved || got.Resolution != "fixed it" {
		t.Fatal("should be resolved")
	}
}

func TestFinal_UnknownListUnresolved(t *testing.T) {
	r := NewInMemoryUnknownRegistry()
	r.Register(&contracts.Unknown{ID: "u1"})
	r.Register(&contracts.Unknown{ID: "u2"})
	r.Resolve("u1", "done")
	list, _ := r.ListUnresolved()
	if len(list) != 1 {
		t.Fatal("should have 1 unresolved")
	}
}

func TestFinal_LineageEntryJSONRoundTrip(t *testing.T) {
	le := LineageEntry{EntryID: "le1", ObjectID: "o1", Relation: "DERIVED_FROM"}
	data, _ := json.Marshal(le)
	var got LineageEntry
	json.Unmarshal(data, &got)
	if got.Relation != "DERIVED_FROM" {
		t.Fatal("lineage round-trip")
	}
}

func TestFinal_TrackedUnknownJSONRoundTrip(t *testing.T) {
	tu := TrackedUnknown{Unknown: contracts.Unknown{ID: "u1"}, Resolved: true, Resolution: "done"}
	data, _ := json.Marshal(tu)
	var got TrackedUnknown
	json.Unmarshal(data, &got)
	if !got.Resolved {
		t.Fatal("tracked unknown round-trip")
	}
}
