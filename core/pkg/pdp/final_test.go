package pdp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFinal_BackendHELMConstant(t *testing.T) {
	if BackendHELM != "helm" {
		t.Fatalf("unexpected backend: %s", BackendHELM)
	}
}

func TestFinal_DecisionRequestJSONRoundTrip(t *testing.T) {
	req := DecisionRequest{Principal: "agent-1", Action: "read", Resource: "db", Timestamp: time.Now()}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.Principal != "agent-1" || got.Action != "read" {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_DecisionResponseJSONRoundTrip(t *testing.T) {
	resp := DecisionResponse{Allow: true, ReasonCode: "policy_match", PolicyRef: "p1"}
	data, _ := json.Marshal(resp)
	var got DecisionResponse
	json.Unmarshal(data, &got)
	if !got.Allow || got.PolicyRef != "p1" {
		t.Fatal("response round-trip")
	}
}

func TestFinal_ComputeDecisionHashDeterministic(t *testing.T) {
	resp := &DecisionResponse{Allow: true, ReasonCode: "ok", PolicyRef: "p1"}
	h1, err := ComputeDecisionHash(resp)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := ComputeDecisionHash(resp)
	if h1 != h2 {
		t.Fatal("not deterministic")
	}
}

func TestFinal_ComputeDecisionHashPrefix(t *testing.T) {
	resp := &DecisionResponse{Allow: true, PolicyRef: "p1"}
	h, _ := ComputeDecisionHash(resp)
	if !strings.HasPrefix(h, "sha256:") {
		t.Fatal("missing sha256 prefix")
	}
}

func TestFinal_ComputeDecisionHashDifferentInputs(t *testing.T) {
	r1 := &DecisionResponse{Allow: true, PolicyRef: "p1"}
	r2 := &DecisionResponse{Allow: false, PolicyRef: "p1"}
	h1, _ := ComputeDecisionHash(r1)
	h2, _ := ComputeDecisionHash(r2)
	if h1 == h2 {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestFinal_ComputeDecisionHashExcludesHash(t *testing.T) {
	r1 := &DecisionResponse{Allow: true, PolicyRef: "p1", DecisionHash: "old-hash"}
	r2 := &DecisionResponse{Allow: true, PolicyRef: "p1", DecisionHash: "different"}
	h1, _ := ComputeDecisionHash(r1)
	h2, _ := ComputeDecisionHash(r2)
	if h1 != h2 {
		t.Fatal("hash field should be excluded")
	}
}

func TestFinal_NormalizeDecisionReasonCodeAllow(t *testing.T) {
	code := normalizeDecisionReasonCode(true, "anything")
	if code != "" {
		t.Fatal("allow should have empty reason code")
	}
}

func TestFinal_NormalizeDecisionReasonCodeDenyCanonical(t *testing.T) {
	code := normalizeDecisionReasonCode(false, "POLICY_VIOLATION")
	if code != "POLICY_VIOLATION" {
		t.Fatalf("canonical code should pass through: %s", code)
	}
}

func TestFinal_DecisionRequestWithContext(t *testing.T) {
	req := DecisionRequest{
		Principal: "agent-1",
		Action:    "write",
		Resource:  "db",
		Context:   map[string]any{"env": "prod"},
	}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.Context["env"] != "prod" {
		t.Fatal("context lost")
	}
}

func TestFinal_DecisionRequestWithEnvironment(t *testing.T) {
	req := DecisionRequest{
		Principal:   "a1",
		Action:      "read",
		Resource:    "table",
		Environment: map[string]string{"region": "us-east"},
	}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.Environment["region"] != "us-east" {
		t.Fatal("environment lost")
	}
}

func TestFinal_DecisionRequestSchemaHash(t *testing.T) {
	req := DecisionRequest{SchemaHash: "sha256:abc"}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.SchemaHash != "sha256:abc" {
		t.Fatal("schema hash lost")
	}
}

func TestFinal_DecisionResponseDecisionHash(t *testing.T) {
	resp := DecisionResponse{DecisionHash: "sha256:xyz"}
	data, _ := json.Marshal(resp)
	var got DecisionResponse
	json.Unmarshal(data, &got)
	if got.DecisionHash != "sha256:xyz" {
		t.Fatal("decision hash lost")
	}
}

func TestFinal_BackendTypeString(t *testing.T) {
	b := BackendHELM
	data, _ := json.Marshal(b)
	if string(data) != `"helm"` {
		t.Fatalf("unexpected: %s", data)
	}
}

func TestFinal_DecisionRequestTimestamp(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	req := DecisionRequest{Timestamp: now}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if !got.Timestamp.Equal(now) {
		t.Fatal("timestamp lost")
	}
}

func TestFinal_DecisionResponseReasonCode(t *testing.T) {
	resp := DecisionResponse{Allow: false, ReasonCode: "EGRESS_BLOCKED"}
	if resp.ReasonCode != "EGRESS_BLOCKED" {
		t.Fatal("reason code mismatch")
	}
}

func TestFinal_DecisionHashChangesOnPolicy(t *testing.T) {
	r1 := &DecisionResponse{Allow: true, PolicyRef: "p1"}
	r2 := &DecisionResponse{Allow: true, PolicyRef: "p2"}
	h1, _ := ComputeDecisionHash(r1)
	h2, _ := ComputeDecisionHash(r2)
	if h1 == h2 {
		t.Fatal("different policy should produce different hash")
	}
}

func TestFinal_DecisionHashChangesOnReason(t *testing.T) {
	r1 := &DecisionResponse{Allow: false, ReasonCode: "A", PolicyRef: "p1"}
	r2 := &DecisionResponse{Allow: false, ReasonCode: "B", PolicyRef: "p1"}
	h1, _ := ComputeDecisionHash(r1)
	h2, _ := ComputeDecisionHash(r2)
	if h1 == h2 {
		t.Fatal("different reason should produce different hash")
	}
}

func TestFinal_EmptyDecisionRequest(t *testing.T) {
	req := DecisionRequest{}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.Principal != "" {
		t.Fatal("empty fields should be empty")
	}
}

func TestFinal_EmptyDecisionResponse(t *testing.T) {
	resp := DecisionResponse{}
	data, _ := json.Marshal(resp)
	var got DecisionResponse
	json.Unmarshal(data, &got)
	if got.Allow {
		t.Fatal("default allow should be false")
	}
}

func TestFinal_DecisionRequestAllFields(t *testing.T) {
	req := DecisionRequest{
		Principal:   "p",
		Action:      "a",
		Resource:    "r",
		Context:     map[string]any{"k": "v"},
		SchemaHash:  "h",
		Environment: map[string]string{"e": "v"},
		Timestamp:   time.Now(),
	}
	data, _ := json.Marshal(req)
	if len(data) == 0 {
		t.Fatal("should serialize")
	}
}

func TestFinal_DecisionResponseAllFields(t *testing.T) {
	resp := DecisionResponse{
		Allow:        true,
		ReasonCode:   "POLICY_MATCH",
		PolicyRef:    "pol-1",
		DecisionHash: "sha256:abc",
	}
	data, _ := json.Marshal(resp)
	if len(data) == 0 {
		t.Fatal("should serialize")
	}
}

func TestFinal_ComputeDecisionHashEmptyResponse(t *testing.T) {
	h, err := ComputeDecisionHash(&DecisionResponse{})
	if err != nil || h == "" {
		t.Fatal("empty response should still hash")
	}
}

func TestFinal_ComputeDecisionHashLength(t *testing.T) {
	h, _ := ComputeDecisionHash(&DecisionResponse{Allow: true})
	// "sha256:" + 64 hex chars
	if len(h) != 7+64 {
		t.Fatalf("unexpected hash length: %d", len(h))
	}
}

func TestFinal_NormalizeReasonCodeNonCanonical(t *testing.T) {
	code := normalizeDecisionReasonCode(false, "some_random_thing")
	if code == "some_random_thing" {
		t.Fatal("non-canonical should be normalized")
	}
}

func TestFinal_DecisionRequestContextNil(t *testing.T) {
	req := DecisionRequest{Principal: "a", Context: nil}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.Context != nil {
		t.Fatal("nil context should round-trip")
	}
}

func TestFinal_DecisionRequestEnvironmentNil(t *testing.T) {
	req := DecisionRequest{Principal: "a", Environment: nil}
	data, _ := json.Marshal(req)
	var got DecisionRequest
	json.Unmarshal(data, &got)
	if got.Environment != nil {
		t.Fatal("nil env should round-trip")
	}
}
