package a2a

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDIDAgentIdentifierHelpers(t *testing.T) {
	validDID := "did:web:example.com:agents:alice"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if !IsDID(validDID) {
		t.Fatalf("IsDID(%q) = false, want true", validDID)
	}
	if IsDID("legacy-agent") {
		t.Fatalf("legacy opaque id classified as DID")
	}
	if err := parseDID(validDID); err != nil {
		t.Fatalf("parseDID(%q): %v", validDID, err)
	}
	if err := parseDID("not-a-did"); err == nil {
		t.Fatalf("parseDID accepted malformed identifier")
	}
	if err := ValidateAgentIdentifier("origin_agent_id", "", logger); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty identifier error = %v, want empty error", err)
	}
	if err := ValidateAgentIdentifier("origin_agent_id", "did:web:", logger); err == nil || !strings.Contains(err.Error(), "malformed DID") {
		t.Fatalf("malformed DID error = %v, want malformed DID error", err)
	}
	if err := ValidateAgentIdentifier("origin_agent_id", "legacy-agent", logger); err != nil {
		t.Fatalf("legacy identifier rejected: %v", err)
	}

	if err := CanonicalizeDIDFields(nil, logger); err == nil || !strings.Contains(err.Error(), "nil envelope") {
		t.Fatalf("nil envelope error = %v, want nil envelope error", err)
	}
	if err := CanonicalizeDIDFields(&Envelope{OriginAgentID: "did:web:", TargetAgentID: validDID}, logger); err == nil {
		t.Fatalf("canonicalization accepted malformed origin DID")
	}
	if err := CanonicalizeDIDFields(&Envelope{OriginAgentID: validDID, TargetAgentID: ""}, logger); err == nil {
		t.Fatalf("canonicalization accepted missing target")
	}
	if err := CanonicalizeDIDFields(&Envelope{OriginAgentID: validDID, TargetAgentID: "legacy-target"}, logger); err != nil {
		t.Fatalf("canonicalization rejected valid/legacy envelope: %v", err)
	}

	origin, target := EnvelopeIdentifierKind(&Envelope{OriginAgentID: validDID, TargetAgentID: ""})
	if origin != "did" || target != "missing" {
		t.Fatalf("identifier kind = (%q,%q), want (did,missing)", origin, target)
	}
	origin, target = EnvelopeIdentifierKind(&Envelope{OriginAgentID: "legacy-origin", TargetAgentID: "legacy-target"})
	if origin != "legacy" || target != "legacy" {
		t.Fatalf("legacy identifier kind = (%q,%q), want (legacy,legacy)", origin, target)
	}
}

func TestTaskManagerLifecycleAndErrors(t *testing.T) {
	now := time.Date(2026, 6, 2, 10, 0, 0, 0, time.UTC)
	manager := NewTaskManager().WithClock(func() time.Time { return now })

	if _, err := manager.CreateTask("", "target"); err == nil {
		t.Fatalf("CreateTask accepted missing origin")
	}
	if _, err := manager.CreateTask("origin", ""); err == nil {
		t.Fatalf("CreateTask accepted missing target")
	}

	task, err := manager.CreateTask("origin", "target")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if task.Status != TaskStatusSubmitted || !strings.HasPrefix(task.TaskID, "task:") || task.CreatedAt != now {
		t.Fatalf("created task = %+v, want submitted task with fixed timestamp", task)
	}
	if got, ok := manager.GetTask(task.TaskID); !ok || got.TaskID != task.TaskID {
		t.Fatalf("GetTask returned (%+v,%v), want created task", got, ok)
	}
	if _, ok := manager.GetTask("missing"); ok {
		t.Fatalf("GetTask found missing task")
	}
	if ids := manager.ListTasks(); len(ids) != 1 || ids[0] != task.TaskID {
		t.Fatalf("ListTasks = %#v, want created task id", ids)
	}

	if IsValidTransition("UNKNOWN", TaskStatusWorking) {
		t.Fatalf("unknown transition reported valid")
	}
	if IsValidTransition(TaskStatusCompleted, TaskStatusWorking) {
		t.Fatalf("terminal transition reported valid")
	}
	if err := manager.TransitionTask("missing", TaskStatusWorking, "start"); err == nil {
		t.Fatalf("TransitionTask accepted missing task")
	}
	if err := manager.TransitionTask(task.TaskID, TaskStatusCompleted, "skip working"); err == nil {
		t.Fatalf("TransitionTask accepted invalid submitted->completed transition")
	}

	now = now.Add(time.Minute)
	if err := manager.TransitionTask(task.TaskID, TaskStatusWorking, "start"); err != nil {
		t.Fatalf("TransitionTask submitted->working: %v", err)
	}
	message, err := manager.AddMessage(task.TaskID, MessageRoleUser, []Part{{Type: PartTypeText, Text: "hello"}})
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	if message.Role != MessageRoleUser || !strings.HasPrefix(message.MessageID, "msg:") {
		t.Fatalf("message = %+v, want user message with generated id", message)
	}
	if _, err := manager.AddMessage("missing", MessageRoleAgent, nil); err == nil {
		t.Fatalf("AddMessage accepted missing task")
	}

	if err := manager.TransitionTask(task.TaskID, TaskStatusInputRequired, "need input"); err != nil {
		t.Fatalf("TransitionTask working->input_required: %v", err)
	}
	if err := manager.TransitionTask(task.TaskID, TaskStatusWorking, "input received"); err != nil {
		t.Fatalf("TransitionTask input_required->working: %v", err)
	}
	if err := manager.TransitionTask(task.TaskID, TaskStatusCompleted, "done"); err != nil {
		t.Fatalf("TransitionTask working->completed: %v", err)
	}
	if _, err := manager.AddMessage(task.TaskID, MessageRoleAgent, nil); err == nil {
		t.Fatalf("AddMessage accepted terminal task")
	}
	if err := manager.TransitionTask(task.TaskID, TaskStatusWorking, "reopen"); err == nil {
		t.Fatalf("TransitionTask accepted terminal transition")
	}
	if _, err := manager.AddArtifact("missing", "result", "text/plain", nil); err == nil {
		t.Fatalf("AddArtifact accepted missing task")
	}

	artifact, err := manager.AddArtifact(task.TaskID, "result", "text/plain", []Part{{Type: PartTypeText, Text: "output"}})
	if err != nil {
		t.Fatalf("AddArtifact: %v", err)
	}
	if !strings.HasPrefix(artifact.ArtifactID, "art:") || !strings.HasPrefix(artifact.ContentHash, "sha256:") {
		t.Fatalf("artifact = %+v, want generated id and content hash", artifact)
	}
	if ComputeArtifactHash(artifact) != artifact.ContentHash {
		t.Fatalf("ComputeArtifactHash is not deterministic for artifact")
	}
	changed := *artifact
	changed.Parts = []Part{{Type: PartTypeText, Text: "different"}}
	if ComputeArtifactHash(&changed) == artifact.ContentHash {
		t.Fatalf("ComputeArtifactHash did not change when content changed")
	}
}

func TestSSEStreamSnapshotsAndFiltering(t *testing.T) {
	now := time.Date(2026, 6, 2, 11, 0, 0, 0, time.UTC)
	stream := NewSSEStream("task-1").WithClock(func() time.Time { return now })

	first := stream.Emit(SSEEventTaskStatus, json.RawMessage(`{"status":"WORKING"}`))
	if first.Sequence != 1 || first.TaskID != "task-1" || first.EventType != SSEEventTaskStatus || first.Timestamp != now {
		t.Fatalf("first event = %+v, want sequence 1 task status event", first)
	}
	now = now.Add(time.Second)
	second := stream.Emit(SSEEventTaskMessage, json.RawMessage(`{"message":"ok"}`))
	if second.Sequence != 2 || second.Timestamp != now {
		t.Fatalf("second event = %+v, want sequence 2 with advanced clock", second)
	}

	events := stream.Events()
	if len(events) != 2 {
		t.Fatalf("Events length = %d, want 2", len(events))
	}
	events[0].TaskID = "mutated"
	if got := stream.Events()[0].TaskID; got != "task-1" {
		t.Fatalf("Events returned aliased slice, first task id now %q", got)
	}
	if got := stream.EventsSince(1); len(got) != 1 || got[0].Sequence != 2 {
		t.Fatalf("EventsSince(1) = %#v, want only sequence 2", got)
	}
	if got := stream.EventsSince(2); len(got) != 0 {
		t.Fatalf("EventsSince(2) = %#v, want empty", got)
	}
}

func TestWellKnownRouteRegistrationAndProviderRefresh(t *testing.T) {
	if err := ValidateAgentCard(&AgentCard{
		AgentID:  "agent",
		Endpoint: "https://example.test/a2a",
		Skills: []AgentSkill{{
			ID:   "skill",
			Name: "Skill",
		}},
	}); err == nil || !strings.Contains(err.Error(), "supported_version") {
		t.Fatalf("ValidateAgentCard missing supported versions error = %v", err)
	}

	t.Setenv("HELM_PUBLIC_URL", "")
	defaults := NewKernelCardProvider(KernelCardConfig{}).GetCard()
	if defaults.AgentID != "helm-governance" || defaults.Name != "HELM Governance Verifier" || defaults.Endpoint != "http://localhost:9100" {
		t.Fatalf("default card identity = %+v, want built-in defaults", defaults)
	}
	if defaults.Provider != nil || defaults.AuthMethods[0] != AuthMethodAPIKey || len(defaults.Features) != 4 {
		t.Fatalf("default provider/auth/features = provider:%+v auth:%#v features:%#v", defaults.Provider, defaults.AuthMethods, defaults.Features)
	}

	provider := NewKernelCardProvider(KernelCardConfig{
		AgentID:      "agent-old",
		Name:         "Old name",
		EndpointURL:  "https://old.example/a2a",
		Organization: "Mindburn",
		OrgURL:       "https://example.test",
		AuthMethods:  []AuthMethod{AuthMethodIATP},
		Features:     []Feature{FeatureIATPAuth},
		MCPToolSkills: []AgentSkill{{
			ID:          "mcp.tool",
			Name:        "MCP tool",
			InputModes:  []string{"structured"},
			OutputModes: []string{"structured"},
		}},
	})
	if card := provider.GetCard(); card.Name != "Old name" || card.Provider == nil || len(card.Skills) != 3 {
		t.Fatalf("initial card = %+v, want custom name/provider and MCP skill appended", card)
	}

	provider.Refresh(KernelCardConfig{
		AgentID:     "agent-new",
		Name:        "New name",
		EndpointURL: "https://new.example/a2a",
		AuthMethods: []AuthMethod{AuthMethodMTLS},
		Features:    []Feature{FeatureTrustPropagation},
	})
	refreshed := provider.GetCard()
	if refreshed.AgentID != "agent-new" || refreshed.Name != "New name" || refreshed.Endpoint != "https://new.example/a2a" {
		t.Fatalf("refreshed card = %+v, want new identity and endpoint", refreshed)
	}
	if refreshed.Provider != nil || refreshed.AuthMethods[0] != AuthMethodMTLS || refreshed.Features[0] != FeatureTrustPropagation {
		t.Fatalf("refreshed provider/auth/features = provider:%+v auth:%#v features:%#v", refreshed.Provider, refreshed.AuthMethods, refreshed.Features)
	}

	mux := http.NewServeMux()
	RegisterWellKnownRoute(mux, provider)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("well-known status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	if !strings.Contains(rec.Body.String(), `"agent_id":"agent-new"`) {
		t.Fatalf("well-known body = %s, want refreshed card", rec.Body.String())
	}
}
