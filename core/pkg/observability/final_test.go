package observability

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_SLISourceConstants(t *testing.T) {
	sources := []SLISource{SLISourceMetric, SLISourceLog, SLISourceTrace, SLISourceProbe}
	seen := make(map[SLISource]bool)
	for _, s := range sources {
		if s == "" {
			t.Fatal("SLI source must not be empty")
		}
		if seen[s] {
			t.Fatalf("duplicate: %s", s)
		}
		seen[s] = true
	}
}

func TestFinal_TimelineEntryTypeConstants(t *testing.T) {
	types := []TimelineEntryType{EntryTypeAction, EntryTypeToolCall, EntryTypeDecision, EntryTypeProof, EntryTypeReconciliation, EntryTypeEscalation, EntryTypeEvidence}
	if len(types) != 7 {
		t.Fatalf("want 7 timeline entry types, got %d", len(types))
	}
}

func TestFinal_SLIRegistryNew(t *testing.T) {
	r := NewSLIRegistry()
	if r == nil {
		t.Fatal("registry should not be nil")
	}
	if r.Count() != 0 {
		t.Fatal("new registry should be empty")
	}
}

func TestFinal_SLIRegistryRegisterAndGet(t *testing.T) {
	r := NewSLIRegistry()
	sli := &SLI{SLIID: "sli-1", Name: "latency", Operation: "execute"}
	if err := r.Register(sli); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get("sli-1")
	if err != nil || got.Name != "latency" {
		t.Fatal("should retrieve registered SLI")
	}
}

func TestFinal_SLIRegistryGetMissing(t *testing.T) {
	r := NewSLIRegistry()
	_, err := r.Get("missing")
	if err == nil {
		t.Fatal("should error on missing SLI")
	}
}

func TestFinal_SLIRegistryRegisterInvalid(t *testing.T) {
	r := NewSLIRegistry()
	if err := r.Register(&SLI{}); err == nil {
		t.Fatal("should error on empty SLI")
	}
}

func TestFinal_SLIRegistryByOperation(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "n1", Operation: "execute"})
	r.Register(&SLI{SLIID: "s2", Name: "n2", Operation: "execute"})
	r.Register(&SLI{SLIID: "s3", Name: "n3", Operation: "compile"})
	results := r.ByOperation("execute")
	if len(results) != 2 {
		t.Fatalf("want 2 SLIs for execute, got %d", len(results))
	}
}

func TestFinal_SLIRegistryLinkToSLO(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "n1", Operation: "op"})
	if err := r.LinkToSLO("s1", "slo-1"); err != nil {
		t.Fatal(err)
	}
	sli, _ := r.Get("s1")
	if sli.LinkedSLOID != "slo-1" {
		t.Fatal("SLO link mismatch")
	}
}

func TestFinal_SLIRegistryLinkToSLOMissing(t *testing.T) {
	r := NewSLIRegistry()
	if err := r.LinkToSLO("missing", "slo-1"); err == nil {
		t.Fatal("should error on missing SLI")
	}
}

func TestFinal_SLIJSON(t *testing.T) {
	sli := SLI{SLIID: "s1", Name: "latency", Operation: "execute", Source: SLISourceMetric, Unit: "ms"}
	data, _ := json.Marshal(sli)
	var sli2 SLI
	json.Unmarshal(data, &sli2)
	if sli2.SLIID != "s1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SLOTargetJSON(t *testing.T) {
	st := SLOTarget{SLOID: "slo1", Name: "p99 latency", SuccessRate: 0.999}
	data, _ := json.Marshal(st)
	var st2 SLOTarget
	json.Unmarshal(data, &st2)
	if st2.SuccessRate != 0.999 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TimelineEntryJSON(t *testing.T) {
	te := TimelineEntry{EntryID: "e1", EntryType: EntryTypeDecision, RunID: "r1", Summary: "allowed"}
	data, _ := json.Marshal(te)
	var te2 TimelineEntry
	json.Unmarshal(data, &te2)
	if te2.EntryType != EntryTypeDecision {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TimelineQueryJSON(t *testing.T) {
	tq := TimelineQuery{RunID: "r1", Limit: 100}
	data, _ := json.Marshal(tq)
	var tq2 TimelineQuery
	json.Unmarshal(data, &tq2)
	if tq2.Limit != 100 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_AuditTimelineNew(t *testing.T) {
	at := NewAuditTimeline()
	if at == nil {
		t.Fatal("audit timeline should not be nil")
	}
}

func TestFinal_AuditTimelineAppendAndQuery(t *testing.T) {
	at := NewAuditTimeline()
	at.Record(TimelineEntry{EntryID: "e1", EntryType: EntryTypeAction, RunID: "r1", Summary: "test", Timestamp: time.Now()})
	results := at.Query(TimelineQuery{RunID: "r1"})
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
}

func TestFinal_AuditTimelineContentHash(t *testing.T) {
	at := NewAuditTimeline()
	at.Record(TimelineEntry{EntryID: "e1", EntryType: EntryTypeAction, RunID: "r1", Summary: "test", Timestamp: time.Now()})
	results := at.Query(TimelineQuery{RunID: "r1"})
	if results[0].ContentHash == "" {
		t.Fatal("content hash should be computed")
	}
}

func TestFinal_ConcurrentSLIRegistry(t *testing.T) {
	r := NewSLIRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Register(&SLI{SLIID: "s" + string(rune('a'+i)), Name: "n", Operation: "op"})
		}(i)
	}
	wg.Wait()
}

func TestFinal_ConfigJSON(t *testing.T) {
	c := Config{ServiceName: "helm", Environment: "prod"}
	data, _ := json.Marshal(c)
	var c2 Config
	json.Unmarshal(data, &c2)
	if c2.ServiceName != "helm" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SLOObservationJSON(t *testing.T) {
	so := SLOObservation{Operation: "execute", Success: true}
	data, _ := json.Marshal(so)
	var so2 SLOObservation
	json.Unmarshal(data, &so2)
	if !so2.Success {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_SLOStatusJSON(t *testing.T) {
	ss := SLOStatus{SLOID: "slo1", Operation: "execute", CurrentP99: 99.5}
	data, _ := json.Marshal(ss)
	var ss2 SLOStatus
	json.Unmarshal(data, &ss2)
	if ss2.CurrentP99 != 99.5 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TimelineEntryTypesUnique(t *testing.T) {
	types := []TimelineEntryType{EntryTypeAction, EntryTypeToolCall, EntryTypeDecision, EntryTypeProof, EntryTypeReconciliation, EntryTypeEscalation, EntryTypeEvidence}
	seen := make(map[TimelineEntryType]bool)
	for _, et := range types {
		if seen[et] {
			t.Fatalf("duplicate: %s", et)
		}
		seen[et] = true
	}
}

func TestFinal_SLIRegistryCount(t *testing.T) {
	r := NewSLIRegistry()
	r.Register(&SLI{SLIID: "s1", Name: "n", Operation: "op"})
	r.Register(&SLI{SLIID: "s2", Name: "n", Operation: "op"})
	if r.Count() != 2 {
		t.Fatalf("want 2, got %d", r.Count())
	}
}
