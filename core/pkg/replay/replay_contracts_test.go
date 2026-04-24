package replay

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinal_ReceiptJSONRoundTrip(t *testing.T) {
	r := Receipt{ID: "r-1", ToolName: "exec", ArgsHash: "abc", Status: "ALLOW", LamportClock: 7}
	data, _ := json.Marshal(r)
	var got Receipt
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != r.ID || got.LamportClock != 7 {
		t.Fatalf("round-trip mismatch")
	}
}

func TestFinal_ReplayResultJSONRoundTrip(t *testing.T) {
	rr := ReplayResult{TotalReceipts: 5, ValidChain: true, Summary: map[string]int{"ok": 3}}
	data, _ := json.Marshal(rr)
	var got ReplayResult
	json.Unmarshal(data, &got)
	if got.TotalReceipts != 5 || got.Summary["ok"] != 3 {
		t.Fatal("mismatch")
	}
}

func TestFinal_ReplayEmptyReceipts(t *testing.T) {
	res, err := Replay(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalReceipts != 0 || !res.ValidChain {
		t.Fatal("empty should be valid")
	}
}

func TestFinal_ReplaySingleReceipt(t *testing.T) {
	res, _ := Replay([]Receipt{{ID: "r1", Status: "ALLOW", LamportClock: 1, ReasonCode: "ok"}})
	if res.TotalReceipts != 1 || res.Summary["ok"] != 1 {
		t.Fatal("single receipt mismatch")
	}
}

func TestFinal_ReplayDetectsDuplicateIDs(t *testing.T) {
	res, _ := Replay([]Receipt{
		{ID: "dup", LamportClock: 1},
		{ID: "dup", LamportClock: 2, PrevHash: "x"},
	})
	if len(res.DuplicateIDs) == 0 {
		t.Fatal("should detect duplicate")
	}
}

func TestFinal_ReplayLamportMonotonicity(t *testing.T) {
	res, _ := Replay([]Receipt{
		{ID: "a", LamportClock: 5},
		{ID: "b", LamportClock: 3, PrevHash: "x"},
	})
	if res.LamportValid {
		t.Fatal("should detect non-monotonic Lamport")
	}
}

func TestFinal_ReplayFromReaderValid(t *testing.T) {
	r := strings.NewReader(`{"receipt_id":"r1","lamport_clock":1,"status":"ok"}` + "\n")
	res, err := ReplayFromReader(r)
	if err != nil || res.TotalReceipts != 1 {
		t.Fatal("reader replay failed")
	}
}

func TestFinal_WithSignatureVerifierOption(t *testing.T) {
	verifier := func(data []byte, sig string) error { return nil }
	opt := WithSignatureVerifier(verifier)
	cfg := &replayConfig{}
	opt(cfg)
	if cfg.verifier == nil {
		t.Fatal("verifier not set")
	}
}

func TestFinal_SessionStatusConstants(t *testing.T) {
	statuses := []SessionStatus{SessionStatusRunning, SessionStatusComplete, SessionStatusDiverged, SessionStatusFailed}
	for _, s := range statuses {
		if s == "" {
			t.Fatal("empty status constant")
		}
	}
}

func TestFinal_StepJSONRoundTrip(t *testing.T) {
	s := Step{SequenceNumber: 1, EventID: "e1", EventType: "COMPUTE", Duration: time.Millisecond}
	data, _ := json.Marshal(s)
	var got Step
	json.Unmarshal(data, &got)
	if got.SequenceNumber != 1 || got.EventID != "e1" {
		t.Fatal("step round-trip")
	}
}

func TestFinal_SessionJSONRoundTrip(t *testing.T) {
	sess := Session{SessionID: "s1", RunID: "run-1", Status: SessionStatusComplete, TotalSteps: 3}
	data, _ := json.Marshal(sess)
	var got Session
	json.Unmarshal(data, &got)
	if got.SessionID != "s1" || got.TotalSteps != 3 {
		t.Fatal("session round-trip")
	}
}

func TestFinal_RunEventJSONRoundTrip(t *testing.T) {
	re := RunEvent{EventID: "ev-1", EventType: "COMPUTE", PayloadHash: "hash1"}
	data, _ := json.Marshal(re)
	var got RunEvent
	json.Unmarshal(data, &got)
	if got.EventID != "ev-1" {
		t.Fatal("RunEvent round-trip")
	}
}

func TestFinal_ReplayModeConstants(t *testing.T) {
	modes := []ReplayMode{ReplayModeDry, ReplayModeBounded, ReplayModeFull}
	seen := map[ReplayMode]bool{}
	for _, m := range modes {
		if seen[m] {
			t.Fatalf("duplicate mode: %s", m)
		}
		seen[m] = true
	}
}

func TestFinal_ReplayManifestJSONRoundTrip(t *testing.T) {
	m := ReplayManifest{ManifestID: "m1", RunID: "r1", Mode: ReplayModeDry, Backend: "sandbox"}
	data, _ := json.Marshal(m)
	var got ReplayManifest
	json.Unmarshal(data, &got)
	if got.ManifestID != "m1" || got.Mode != ReplayModeDry {
		t.Fatal("manifest round-trip")
	}
}

func TestFinal_VerifyReplayIntegrityComplete(t *testing.T) {
	sess := &Session{Status: SessionStatusComplete, TotalSteps: 2, ReplayedSteps: 2}
	receipt := VerifyReplayIntegrity(sess)
	if !receipt.Success {
		t.Fatal("complete session should succeed")
	}
}

func TestFinal_VerifyReplayIntegrityFailed(t *testing.T) {
	sess := &Session{Status: SessionStatusFailed, TotalSteps: 2, ReplayedSteps: 1, DivergenceInfo: "boom"}
	receipt := VerifyReplayIntegrity(sess)
	if receipt.Success {
		t.Fatal("failed session should not succeed")
	}
	if receipt.Error != "boom" {
		t.Fatal("error not propagated")
	}
}

func TestFinal_VerifyReplayIntegrityDiverged(t *testing.T) {
	sess := &Session{Status: SessionStatusDiverged, TotalSteps: 5, ReplayedSteps: 3}
	receipt := VerifyReplayIntegrity(sess)
	if receipt.Success {
		t.Fatal("diverged should not succeed")
	}
}

func TestFinal_ReplayHashDeterminism(t *testing.T) {
	steps := []Step{{OutputHash: "a"}, {OutputHash: "b"}}
	h1, _ := computeReplayHash(steps)
	h2, _ := computeReplayHash(steps)
	if h1 != h2 {
		t.Fatal("replay hash not deterministic")
	}
}

func TestFinal_RunHashDeterminism(t *testing.T) {
	events := []RunEvent{{PayloadHash: "x"}, {PayloadHash: "y"}}
	h1, _ := computeRunHash(events)
	h2, _ := computeRunHash(events)
	if h1 != h2 {
		t.Fatal("run hash not deterministic")
	}
}

func TestFinal_RunHashPrefix(t *testing.T) {
	h, _ := computeRunHash([]RunEvent{{PayloadHash: "test"}})
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_TimelineEventTypeConstants(t *testing.T) {
	types := []TimelineEventType{EventTypeDecision, EventTypeDelegation, EventTypeEffect, EventTypeApproval, EventTypeEscalation, EventTypeCheckpoint, EventTypeError}
	if len(types) != 7 {
		t.Fatal("expected 7 event types")
	}
}

func TestFinal_TimelineViewJSONRoundTrip(t *testing.T) {
	tv := TimelineView{ViewID: "v1", Summary: TimelineSummary{TotalEvents: 3, ReasonCodes: map[string]int{}}}
	data, _ := json.Marshal(tv)
	var got TimelineView
	json.Unmarshal(data, &got)
	if got.ViewID != "v1" || got.Summary.TotalEvents != 3 {
		t.Fatal("timeline round-trip")
	}
}

func TestFinal_BuildTimelineEmpty(t *testing.T) {
	_, err := BuildTimeline("v1", nil)
	if err == nil {
		t.Fatal("should error on empty")
	}
}

func TestFinal_BuildTimelineSingle(t *testing.T) {
	tv, err := BuildTimeline("v1", []Receipt{{ID: "r1", Status: "ALLOW", Timestamp: time.Now().Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	if tv.Summary.TotalEvents != 1 {
		t.Fatal("expected 1 event")
	}
}

func TestFinal_ClassifyEventDeny(t *testing.T) {
	et := classifyEvent(Receipt{Status: "DENY"})
	if et != EventTypeDecision {
		t.Fatal("DENY should be DECISION")
	}
}

func TestFinal_ClassifyEventAllow(t *testing.T) {
	et := classifyEvent(Receipt{Status: "ALLOW"})
	if et != EventTypeDecision {
		t.Fatal("ALLOW should be DECISION")
	}
}

func TestFinal_ClassifyEventError(t *testing.T) {
	et := classifyEvent(Receipt{Status: "ERROR"})
	if et != EventTypeError {
		t.Fatal("ERROR should be ERROR type")
	}
}

func TestFinal_ClassifyEventDefault(t *testing.T) {
	et := classifyEvent(Receipt{Status: "UNKNOWN"})
	if et != EventTypeEffect {
		t.Fatal("unknown should be EFFECT")
	}
}

func TestFinal_TraceLineageNotFound(t *testing.T) {
	_, err := TraceLineage("l1", nil, "nonexistent")
	if err == nil {
		t.Fatal("should error on missing leaf")
	}
}

func TestFinal_TraceLineageSingleNode(t *testing.T) {
	events := []TimelineEvent{{EventID: "e1", Verdict: "ALLOW"}}
	lin, err := TraceLineage("l1", events, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if lin.TotalDepth != 1 {
		t.Fatal("single node depth should be 1")
	}
}

func TestFinal_DecisionLineageJSONRoundTrip(t *testing.T) {
	dl := DecisionLineage{LineageID: "l1", RootEvent: "r", LeafEvent: "l", TotalDepth: 2}
	data, _ := json.Marshal(dl)
	var got DecisionLineage
	json.Unmarshal(data, &got)
	if got.LineageID != "l1" || got.TotalDepth != 2 {
		t.Fatal("lineage round-trip")
	}
}

func TestFinal_ReplayHarnessRegister(t *testing.T) {
	h := NewReplayHarness()
	if h == nil {
		t.Fatal("nil harness")
	}
	if len(h.engines) != 0 {
		t.Fatal("should start empty")
	}
}

func TestFinal_ReplayResultSummaryInit(t *testing.T) {
	res, _ := Replay([]Receipt{})
	if res.Summary == nil {
		t.Fatal("summary should be initialized")
	}
}

func TestFinal_ReceiptOmitEmptySignature(t *testing.T) {
	r := Receipt{ID: "r1"}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "signature") {
		t.Fatal("empty signature should be omitted")
	}
}
