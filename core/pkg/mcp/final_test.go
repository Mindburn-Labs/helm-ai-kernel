package mcp

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestFinal_TrustTierConstants(t *testing.T) {
	tiers := []TrustTier{TrustTierUntrusted, TrustTierProbationary, TrustTierStandard, TrustTierTrusted, TrustTierVerified}
	seen := make(map[TrustTier]bool)
	for _, tier := range tiers {
		if tier == "" {
			t.Fatal("trust tier must not be empty")
		}
		if seen[tier] {
			t.Fatalf("duplicate: %s", tier)
		}
		seen[tier] = true
	}
}

func TestFinal_RugPullSeverityConstants(t *testing.T) {
	sevs := []RugPullSeverity{RugPullSeverityLow, RugPullSeverityMedium, RugPullSeverityHigh, RugPullSeverityCritical}
	for _, s := range sevs {
		if s == "" {
			t.Fatal("severity must not be empty")
		}
	}
}

func TestFinal_RugPullChangeConstants(t *testing.T) {
	changes := []RugPullChange{RugPullChangeDescription, RugPullChangeSchema, RugPullChangeBoth, RugPullChangeNew, RugPullChangeRemoved}
	if len(changes) != 5 {
		t.Fatal("want 5 rug pull change types")
	}
}

func TestFinal_SessionStoreCreateGet(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	id, err := store.Create("2025-11-25", "test-client")
	if err != nil {
		t.Fatal(err)
	}
	s := store.Get(id)
	if s == nil || s.ClientName != "test-client" {
		t.Fatal("should retrieve created session")
	}
}

func TestFinal_SessionStoreGetMissing(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	if store.Get("nonexistent") != nil {
		t.Fatal("should return nil for missing session")
	}
}

func TestFinal_SessionStoreDelete(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	id, _ := store.Create("2025-11-25", "c")
	store.Delete(id)
	if store.Get(id) != nil {
		t.Fatal("deleted session should not exist")
	}
}

func TestFinal_SessionStoreLen(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	store.Create("v1", "c1")
	store.Create("v1", "c2")
	if store.Len() != 2 {
		t.Fatalf("want 2, got %d", store.Len())
	}
}

func TestFinal_SessionJSON(t *testing.T) {
	s := Session{ID: "s1", ProtocolVersion: "2025-11-25", ClientName: "test"}
	data, _ := json.Marshal(s)
	var s2 Session
	json.Unmarshal(data, &s2)
	if s2.ProtocolVersion != "2025-11-25" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ToolRefJSON(t *testing.T) {
	tr := ToolRef{ServerID: "srv1", Name: "tool1", Description: "a tool"}
	data, _ := json.Marshal(tr)
	var tr2 ToolRef
	json.Unmarshal(data, &tr2)
	if tr2.Name != "tool1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ToolFingerprintJSON(t *testing.T) {
	tf := ToolFingerprint{ServerID: "s1", ToolName: "t1", CombinedHash: "abc", Version: 1}
	data, _ := json.Marshal(tf)
	var tf2 ToolFingerprint
	json.Unmarshal(data, &tf2)
	if tf2.Version != 1 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TrustScoreJSON(t *testing.T) {
	ts := TrustScore{ToolName: "t1", Score: 750, Tier: TrustTierTrusted}
	data, _ := json.Marshal(ts)
	var ts2 TrustScore
	json.Unmarshal(data, &ts2)
	if ts2.Score != 750 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ToolExecutionRequestJSON(t *testing.T) {
	ter := ToolExecutionRequest{ToolName: "t1", SessionID: "s1"}
	data, _ := json.Marshal(ter)
	var ter2 ToolExecutionRequest
	json.Unmarshal(data, &ter2)
	if ter2.ToolName != "t1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ToolExecutionResponseJSON(t *testing.T) {
	resp := ToolExecutionResponse{Content: "result", Evaluated: true}
	data, _ := json.Marshal(resp)
	var resp2 ToolExecutionResponse
	json.Unmarshal(data, &resp2)
	if !resp2.Evaluated {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_GatewayConfigJSON(t *testing.T) {
	gc := GatewayConfig{ListenAddr: ":8080"}
	data, _ := json.Marshal(gc)
	var gc2 GatewayConfig
	json.Unmarshal(data, &gc2)
	if gc2.ListenAddr != ":8080" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ToolAnnotationsJSON(t *testing.T) {
	ta := ToolAnnotations{ReadOnlyHint: true, DestructiveHint: false}
	data, _ := json.Marshal(ta)
	var ta2 ToolAnnotations
	json.Unmarshal(data, &ta2)
	if !ta2.ReadOnlyHint {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ElicitationRequestJSON(t *testing.T) {
	er := ElicitationRequest{Message: "confirm?", Action: "approve"}
	data, _ := json.Marshal(er)
	var er2 ElicitationRequest
	json.Unmarshal(data, &er2)
	if er2.Message != "confirm?" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_TyposquatFindingJSON(t *testing.T) {
	f := TyposquatFinding{ToolName: "g1thub-mcp", SimilarTool: "github-mcp"}
	data, _ := json.Marshal(f)
	var f2 TyposquatFinding
	json.Unmarshal(data, &f2)
	if f2.SimilarTool != "github-mcp" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_ConcurrentSessionStore(t *testing.T) {
	store := NewSessionStore(time.Minute)
	defer store.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _ := store.Create("v1", "c")
			store.Get(id)
		}()
	}
	wg.Wait()
}

func TestFinal_DefaultSessionTTL(t *testing.T) {
	if DefaultSessionTTL != 30*time.Minute {
		t.Fatal("default TTL should be 30 minutes")
	}
}

func TestFinal_ToolCatalogInterface(t *testing.T) {
	var _ Catalog = (*ToolCatalog)(nil)
}

func TestFinal_ToolCallReceiptJSON(t *testing.T) {
	r := ToolCallReceipt{ID: "r1", ToolName: "t1"}
	data, _ := json.Marshal(r)
	var r2 ToolCallReceipt
	json.Unmarshal(data, &r2)
	if r2.ID != "r1" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_MCPToolCallRequestJSON(t *testing.T) {
	req := MCPToolCallRequest{Method: "tools/call"}
	data, _ := json.Marshal(req)
	var req2 MCPToolCallRequest
	json.Unmarshal(data, &req2)
	if req2.Method != "tools/call" {
		t.Fatal("round-trip mismatch")
	}
}
