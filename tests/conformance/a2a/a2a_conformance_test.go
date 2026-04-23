// Package a2a_conformance provides protocol conformance tests for the A2A
// (Agent-to-Agent) subsystem. These tests verify the full A2A protocol surface:
//
//   - Agent Card discovery (.well-known/agent.json semantics)
//   - Task lifecycle (create, get, cancel, state machine invariants)
//   - Message exchange format (roles, parts, ordering)
//   - Streaming support (SSE event emission and ordering)
//   - Error handling (invalid requests, timeouts, fail-closed semantics)
//   - Authentication/authorization (IATP challenge-response, header verification)
//
// The tests are deterministic — all use fixed clocks and pre-constructed state.
// They follow the same patterns as other conformance suites in tests/conformance/.
package a2a_conformance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/a2a"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters"
	a2aadapter "github.com/Mindburn-Labs/helm-oss/core/pkg/runtimeadapters/a2a"
)

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

var fixedTime = time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

// validAgentCard returns a fully valid AgentCard for conformance tests.
func validAgentCard() *a2a.AgentCard {
	return &a2a.AgentCard{
		AgentID:  "agent-conformance-001",
		Name:     "Conformance Test Agent",
		Endpoint: "https://agents.example.com/conformance",
		SupportedVersions: []a2a.SchemaVersion{
			{Major: 1, Minor: 0, Patch: 0},
		},
		Skills: []a2a.AgentSkill{
			{
				ID:          "skill-research",
				Name:        "Research",
				Description: "Conducts research on a given topic",
				InputModes:  []string{"text", "structured"},
				OutputModes: []string{"text", "artifact"},
			},
		},
		AuthMethods: []a2a.AuthMethod{a2a.AuthMethodIATP, a2a.AuthMethodAPIKey},
		Features:    []a2a.Feature{a2a.FeatureEvidenceExport, a2a.FeatureMeteringReceipts},
		CreatedAt:   fixedTime,
		UpdatedAt:   fixedTime,
	}
}

// validEnvelope creates a well-formed A2A envelope.
func validEnvelope() *a2a.Envelope {
	env := &a2a.Envelope{
		EnvelopeID:       "a2a-conform-proto-001",
		SchemaVersion:    a2a.SchemaVersion{Major: 1, Minor: 0, Patch: 0},
		OriginAgentID:    "agent-origin",
		TargetAgentID:    "agent-target",
		RequiredFeatures: []a2a.Feature{a2a.FeatureEvidenceExport},
		OfferedFeatures:  []a2a.Feature{a2a.FeatureEvidenceExport, a2a.FeatureMeteringReceipts},
		PayloadHash:      "sha256:deadbeef01",
		CreatedAt:        fixedTime.Add(-5 * time.Minute),
		ExpiresAt:        fixedTime.Add(1 * time.Hour),
	}
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")
	return env
}

// baseVerifier creates a verifier with a trusted key for agent-origin.
func baseVerifier() *a2a.DefaultVerifier {
	v := a2a.NewDefaultVerifier()
	v.WithClock(func() time.Time { return fixedTime })
	v.RegisterKey(a2a.TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-origin",
		Algorithm: "ed25519",
		PublicKey: "base64-pubkey-origin",
		Active:    true,
	})
	return v
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. Agent Card Discovery (.well-known/agent.json)
// ══════════════════════════════════════════════════════════════════════════════

func TestA2AConformance_AgentCard_ValidCardPassesValidation(t *testing.T) {
	card := validAgentCard()
	err := a2a.ValidateAgentCard(card)
	assert.NoError(t, err, "a valid agent card must pass validation")
}

func TestA2AConformance_AgentCard_NilCardFails(t *testing.T) {
	err := a2a.ValidateAgentCard(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil card")
}

func TestA2AConformance_AgentCard_MissingAgentIDFails(t *testing.T) {
	card := validAgentCard()
	card.AgentID = ""
	err := a2a.ValidateAgentCard(card)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "agent_id")
}

func TestA2AConformance_AgentCard_MissingEndpointFails(t *testing.T) {
	card := validAgentCard()
	card.Endpoint = ""
	err := a2a.ValidateAgentCard(card)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint")
}

func TestA2AConformance_AgentCard_MissingSupportedVersionsFails(t *testing.T) {
	card := validAgentCard()
	card.SupportedVersions = nil
	err := a2a.ValidateAgentCard(card)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supported_version")
}

func TestA2AConformance_AgentCard_MissingSkillsFails(t *testing.T) {
	card := validAgentCard()
	card.Skills = nil
	err := a2a.ValidateAgentCard(card)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skill")
}

func TestA2AConformance_AgentCard_SkillMissingIDFails(t *testing.T) {
	card := validAgentCard()
	card.Skills = []a2a.AgentSkill{{ID: "", Name: "BadSkill"}}
	err := a2a.ValidateAgentCard(card)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skill[0].id")
}

func TestA2AConformance_AgentCard_SkillMissingNameFails(t *testing.T) {
	card := validAgentCard()
	card.Skills = []a2a.AgentSkill{{ID: "s1", Name: ""}}
	err := a2a.ValidateAgentCard(card)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skill[0].name")
}

func TestA2AConformance_AgentCard_ContentHashIsDeterministic(t *testing.T) {
	card := validAgentCard()
	hash1 := a2a.ComputeCardHash(card)
	hash2 := a2a.ComputeCardHash(card)
	assert.Equal(t, hash1, hash2, "card hash must be deterministic across calls")
	assert.True(t, strings.HasPrefix(hash1, "sha256:"), "card hash must start with sha256:")
}

func TestA2AConformance_AgentCard_ContentHashChangesOnMutation(t *testing.T) {
	card := validAgentCard()
	hash1 := a2a.ComputeCardHash(card)

	card.Name = "Mutated Agent Name"
	hash2 := a2a.ComputeCardHash(card)
	assert.NotEqual(t, hash1, hash2, "card hash must change when content changes")
}

func TestA2AConformance_AgentCard_JSONRoundTrip(t *testing.T) {
	card := validAgentCard()
	card.ContentHash = a2a.ComputeCardHash(card)

	data, err := json.Marshal(card)
	require.NoError(t, err)

	var restored a2a.AgentCard
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, card.AgentID, restored.AgentID)
	assert.Equal(t, card.Endpoint, restored.Endpoint)
	assert.Equal(t, card.ContentHash, restored.ContentHash)
	assert.Len(t, restored.Skills, len(card.Skills))
	assert.Len(t, restored.SupportedVersions, len(card.SupportedVersions))
}

// ── Registry Discovery ──────────────────────────────────────────────

func TestA2AConformance_AgentCard_RegistryRegisterAndLookup(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	card := validAgentCard()

	err := reg.Register(card)
	require.NoError(t, err)

	found, ok := reg.Lookup("agent-conformance-001")
	require.True(t, ok, "registered agent must be discoverable")
	assert.Equal(t, card.AgentID, found.AgentID)
	assert.NotEmpty(t, found.ContentHash, "registry must compute content hash on register")
}

func TestA2AConformance_AgentCard_RegistryRejectsInvalidCard(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	badCard := &a2a.AgentCard{AgentID: ""} // missing required fields
	err := reg.Register(badCard)
	require.Error(t, err, "registry must reject invalid cards")
}

func TestA2AConformance_AgentCard_RegistryDeregister(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	card := validAgentCard()
	require.NoError(t, reg.Register(card))

	existed := reg.Deregister("agent-conformance-001")
	assert.True(t, existed, "deregister must return true for existing agent")

	_, ok := reg.Lookup("agent-conformance-001")
	assert.False(t, ok, "deregistered agent must not be discoverable")
}

func TestA2AConformance_AgentCard_RegistryDeregisterNonexistent(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	existed := reg.Deregister("nonexistent-agent")
	assert.False(t, existed, "deregister must return false for nonexistent agent")
}

func TestA2AConformance_AgentCard_RegistryFindBySkill(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	card := validAgentCard()
	require.NoError(t, reg.Register(card))

	found := reg.FindBySkill("skill-research")
	assert.Len(t, found, 1)
	assert.Equal(t, "agent-conformance-001", found[0].AgentID)

	notFound := reg.FindBySkill("skill-nonexistent")
	assert.Empty(t, notFound)
}

func TestA2AConformance_AgentCard_RegistryFindByFeature(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	card := validAgentCard()
	require.NoError(t, reg.Register(card))

	found := reg.FindByFeature(a2a.FeatureEvidenceExport)
	assert.Len(t, found, 1)

	notFound := reg.FindByFeature(a2a.FeatureTrustPropagation)
	assert.Empty(t, notFound)
}

func TestA2AConformance_AgentCard_RegistryListAgents(t *testing.T) {
	reg := a2a.NewAgentRegistry()
	card1 := validAgentCard()
	card2 := validAgentCard()
	card2.AgentID = "agent-conformance-002"
	card2.Name = "Second Agent"
	card2.Endpoint = "https://agents.example.com/second"

	require.NoError(t, reg.Register(card1))
	require.NoError(t, reg.Register(card2))

	agents := reg.ListAgents()
	assert.Len(t, agents, 2)
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. Task Lifecycle (create, get, cancel)
// ══════════════════════════════════════════════════════════════════════════════

func TestA2AConformance_Task_CreateSetsSubmittedStatus(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-origin", "agent-target")
	require.NoError(t, err)
	require.NotNil(t, task)

	assert.Equal(t, a2a.TaskStatusSubmitted, task.Status)
	assert.NotEmpty(t, task.TaskID, "task ID must be generated")
	assert.True(t, strings.HasPrefix(task.TaskID, "task:"), "task ID must have task: prefix")
	assert.Equal(t, "agent-origin", task.OriginAgent)
	assert.Equal(t, "agent-target", task.TargetAgent)
}

func TestA2AConformance_Task_CreateRecordsHistory(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)

	require.Len(t, task.History, 1)
	assert.Equal(t, a2a.TaskStatusSubmitted, task.History[0].To)
	assert.Equal(t, "task created", task.History[0].Reason)
}

func TestA2AConformance_Task_CreateFailsWithEmptyAgents(t *testing.T) {
	tm := a2a.NewTaskManager()

	t.Run("empty_origin_agent", func(t *testing.T) {
		_, err := tm.CreateTask("", "agent-target")
		require.Error(t, err)
	})

	t.Run("empty_target_agent", func(t *testing.T) {
		_, err := tm.CreateTask("agent-origin", "")
		require.Error(t, err)
	})

	t.Run("both_agents_empty", func(t *testing.T) {
		_, err := tm.CreateTask("", "")
		require.Error(t, err)
	})
}

func TestA2AConformance_Task_GetReturnsCreatedTask(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)

	fetched, ok := tm.GetTask(task.TaskID)
	require.True(t, ok, "created task must be retrievable")
	assert.Equal(t, task.TaskID, fetched.TaskID)
	assert.Equal(t, task.Status, fetched.Status)
}

func TestA2AConformance_Task_GetNonexistentReturnsFalse(t *testing.T) {
	tm := a2a.NewTaskManager()
	_, ok := tm.GetTask("task:nonexistent")
	assert.False(t, ok, "nonexistent task must return false")
}

func TestA2AConformance_Task_ListTracksAllTasks(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	_, err := tm.CreateTask("a1", "a2")
	require.NoError(t, err)
	_, err = tm.CreateTask("a3", "a4")
	require.NoError(t, err)

	tasks := tm.ListTasks()
	assert.Len(t, tasks, 2)
}

func TestA2AConformance_Task_CancelFromSubmitted(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)

	err = tm.TransitionTask(task.TaskID, a2a.TaskStatusCanceled, "user requested cancel")
	require.NoError(t, err)

	fetched, ok := tm.GetTask(task.TaskID)
	require.True(t, ok)
	assert.Equal(t, a2a.TaskStatusCanceled, fetched.Status)
	assert.True(t, fetched.Status.IsTerminal(), "CANCELED must be a terminal state")
}

func TestA2AConformance_Task_CancelFromWorking(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)

	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "processing"))
	err = tm.TransitionTask(task.TaskID, a2a.TaskStatusCanceled, "user abort")
	require.NoError(t, err)

	fetched, _ := tm.GetTask(task.TaskID)
	assert.Equal(t, a2a.TaskStatusCanceled, fetched.Status)
}

func TestA2AConformance_Task_FullLifecycleSubmittedToCompleted(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("orchestrator", "worker")
	require.NoError(t, err)

	// SUBMITTED -> WORKING
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "started"))
	// WORKING -> COMPLETED
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusCompleted, "done"))

	fetched, _ := tm.GetTask(task.TaskID)
	assert.Equal(t, a2a.TaskStatusCompleted, fetched.Status)
	assert.True(t, fetched.Status.IsTerminal())

	// History must have 3 entries: creation + 2 transitions
	assert.Len(t, fetched.History, 3)
	assert.Equal(t, a2a.TaskStatusSubmitted, fetched.History[0].To)
	assert.Equal(t, a2a.TaskStatusWorking, fetched.History[1].To)
	assert.Equal(t, a2a.TaskStatusCompleted, fetched.History[2].To)
}

func TestA2AConformance_Task_FullLifecycleSubmittedToFailed(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("orchestrator", "worker")
	require.NoError(t, err)

	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "started"))
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusFailed, "internal error"))

	fetched, _ := tm.GetTask(task.TaskID)
	assert.Equal(t, a2a.TaskStatusFailed, fetched.Status)
	assert.True(t, fetched.Status.IsTerminal())
}

func TestA2AConformance_Task_InputRequiredLoop(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("orchestrator", "worker")
	require.NoError(t, err)

	// SUBMITTED -> WORKING -> INPUT_REQUIRED -> WORKING -> COMPLETED
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "started"))
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusInputRequired, "need clarification"))
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "input received"))
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusCompleted, "done"))

	fetched, _ := tm.GetTask(task.TaskID)
	assert.Equal(t, a2a.TaskStatusCompleted, fetched.Status)
	// 5 entries: creation + 4 transitions
	assert.Len(t, fetched.History, 5)
}

// ── State Machine Invariants ────────────────────────────────────────

func TestA2AConformance_Task_InvalidTransitionFromTerminal(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)

	for _, terminal := range []a2a.TaskStatus{a2a.TaskStatusCompleted, a2a.TaskStatusFailed, a2a.TaskStatusCanceled} {
		t.Run(string(terminal)+"_to_WORKING", func(t *testing.T) {
			task, err := tm.CreateTask("a", "b")
			require.NoError(t, err)
			require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))

			// Drive to terminal state
			if terminal == a2a.TaskStatusCanceled {
				require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusCanceled, "cancel"))
			} else if terminal == a2a.TaskStatusCompleted {
				require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusCompleted, "done"))
			} else {
				require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusFailed, "err"))
			}

			// Attempt invalid transition from terminal
			err = tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "illegal resume")
			assert.Error(t, err, "transition from %s to WORKING must fail", terminal)
			assert.Contains(t, err.Error(), "invalid transition")
		})
	}
}

func TestA2AConformance_Task_InvalidTransitionSubmittedToCompleted(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("a", "b")
	require.NoError(t, err)

	// Cannot skip WORKING to jump to COMPLETED
	err = tm.TransitionTask(task.TaskID, a2a.TaskStatusCompleted, "skip working")
	assert.Error(t, err, "SUBMITTED -> COMPLETED must fail (must go through WORKING)")
}

func TestA2AConformance_Task_InvalidTransitionSubmittedToFailed(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("a", "b")
	require.NoError(t, err)

	err = tm.TransitionTask(task.TaskID, a2a.TaskStatusFailed, "skip working")
	assert.Error(t, err, "SUBMITTED -> FAILED must fail")
}

func TestA2AConformance_Task_TransitionNonexistentTaskFails(t *testing.T) {
	tm := a2a.NewTaskManager()
	err := tm.TransitionTask("task:nonexistent", a2a.TaskStatusWorking, "go")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestA2AConformance_Task_ValidTransitionTable(t *testing.T) {
	// Exhaustive check of the documented state machine
	testCases := []struct {
		from  a2a.TaskStatus
		to    a2a.TaskStatus
		valid bool
	}{
		{a2a.TaskStatusSubmitted, a2a.TaskStatusWorking, true},
		{a2a.TaskStatusSubmitted, a2a.TaskStatusCanceled, true},
		{a2a.TaskStatusSubmitted, a2a.TaskStatusCompleted, false},
		{a2a.TaskStatusSubmitted, a2a.TaskStatusFailed, false},
		{a2a.TaskStatusSubmitted, a2a.TaskStatusInputRequired, false},
		{a2a.TaskStatusWorking, a2a.TaskStatusCompleted, true},
		{a2a.TaskStatusWorking, a2a.TaskStatusFailed, true},
		{a2a.TaskStatusWorking, a2a.TaskStatusCanceled, true},
		{a2a.TaskStatusWorking, a2a.TaskStatusInputRequired, true},
		{a2a.TaskStatusWorking, a2a.TaskStatusSubmitted, false},
		{a2a.TaskStatusInputRequired, a2a.TaskStatusWorking, true},
		{a2a.TaskStatusInputRequired, a2a.TaskStatusCanceled, true},
		{a2a.TaskStatusInputRequired, a2a.TaskStatusCompleted, false},
		{a2a.TaskStatusInputRequired, a2a.TaskStatusFailed, false},
		{a2a.TaskStatusCompleted, a2a.TaskStatusWorking, false},
		{a2a.TaskStatusCompleted, a2a.TaskStatusFailed, false},
		{a2a.TaskStatusCompleted, a2a.TaskStatusCanceled, false},
		{a2a.TaskStatusFailed, a2a.TaskStatusWorking, false},
		{a2a.TaskStatusFailed, a2a.TaskStatusCompleted, false},
		{a2a.TaskStatusCanceled, a2a.TaskStatusWorking, false},
		{a2a.TaskStatusCanceled, a2a.TaskStatusCompleted, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.from)+"_to_"+string(tc.to), func(t *testing.T) {
			result := a2a.IsValidTransition(tc.from, tc.to)
			assert.Equal(t, tc.valid, result,
				"IsValidTransition(%s, %s) = %v, want %v", tc.from, tc.to, result, tc.valid)
		})
	}
}

func TestA2AConformance_Task_TerminalStates(t *testing.T) {
	terminals := []a2a.TaskStatus{a2a.TaskStatusCompleted, a2a.TaskStatusFailed, a2a.TaskStatusCanceled}
	nonTerminals := []a2a.TaskStatus{a2a.TaskStatusSubmitted, a2a.TaskStatusWorking, a2a.TaskStatusInputRequired}

	for _, s := range terminals {
		assert.True(t, s.IsTerminal(), "%s must be terminal", s)
	}
	for _, s := range nonTerminals {
		assert.False(t, s.IsTerminal(), "%s must not be terminal", s)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. Message Exchange Format
// ══════════════════════════════════════════════════════════════════════════════

func TestA2AConformance_Message_AddToActiveTask(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))

	msg, err := tm.AddMessage(task.TaskID, a2a.MessageRoleUser, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "Please research quantum computing"},
	})
	require.NoError(t, err)
	require.NotNil(t, msg)

	assert.NotEmpty(t, msg.MessageID, "message must have generated ID")
	assert.True(t, strings.HasPrefix(msg.MessageID, "msg:"), "message ID must have msg: prefix")
	assert.Equal(t, a2a.MessageRoleUser, msg.Role)
	require.Len(t, msg.Parts, 1)
	assert.Equal(t, a2a.PartTypeText, msg.Parts[0].Type)
	assert.Equal(t, "Please research quantum computing", msg.Parts[0].Text)
}

func TestA2AConformance_Message_AddAgentResponse(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))

	msg, err := tm.AddMessage(task.TaskID, a2a.MessageRoleAgent, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "Analysis complete."},
		{Type: a2a.PartTypeStructured, Data: json.RawMessage(`{"findings":["result1","result2"]}`)},
	})
	require.NoError(t, err)
	assert.Equal(t, a2a.MessageRoleAgent, msg.Role)
	assert.Len(t, msg.Parts, 2)
	assert.Equal(t, a2a.PartTypeStructured, msg.Parts[1].Type)
	assert.NotEmpty(t, msg.Parts[1].Data)
}

func TestA2AConformance_Message_AddToTerminalTaskFails(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusCompleted, "done"))

	_, err = tm.AddMessage(task.TaskID, a2a.MessageRoleUser, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "This should fail"},
	})
	require.Error(t, err, "adding message to terminal task must fail")
	assert.Contains(t, err.Error(), "terminal")
}

func TestA2AConformance_Message_AddToNonexistentTaskFails(t *testing.T) {
	tm := a2a.NewTaskManager()
	_, err := tm.AddMessage("task:nonexistent", a2a.MessageRoleUser, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "no task"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestA2AConformance_Message_MultipleMessagesPreserveOrder(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("agent-a", "agent-b")
	require.NoError(t, err)
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))

	_, err = tm.AddMessage(task.TaskID, a2a.MessageRoleUser, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "first"},
	})
	require.NoError(t, err)

	_, err = tm.AddMessage(task.TaskID, a2a.MessageRoleAgent, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "second"},
	})
	require.NoError(t, err)

	_, err = tm.AddMessage(task.TaskID, a2a.MessageRoleUser, []a2a.Part{
		{Type: a2a.PartTypeText, Text: "third"},
	})
	require.NoError(t, err)

	fetched, _ := tm.GetTask(task.TaskID)
	require.Len(t, fetched.Messages, 3)
	assert.Equal(t, "first", fetched.Messages[0].Parts[0].Text)
	assert.Equal(t, "second", fetched.Messages[1].Parts[0].Text)
	assert.Equal(t, "third", fetched.Messages[2].Parts[0].Text)
}

func TestA2AConformance_Message_PartTypes(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("a", "b")
	require.NoError(t, err)
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))

	t.Run("text_part", func(t *testing.T) {
		msg, err := tm.AddMessage(task.TaskID, a2a.MessageRoleUser, []a2a.Part{
			{Type: a2a.PartTypeText, Text: "hello"},
		})
		require.NoError(t, err)
		assert.Equal(t, a2a.PartTypeText, msg.Parts[0].Type)
	})

	t.Run("file_part", func(t *testing.T) {
		msg, err := tm.AddMessage(task.TaskID, a2a.MessageRoleAgent, []a2a.Part{
			{Type: a2a.PartTypeFile, FileURI: "helm://artifacts/report.pdf"},
		})
		require.NoError(t, err)
		assert.Equal(t, a2a.PartTypeFile, msg.Parts[0].Type)
		assert.Equal(t, "helm://artifacts/report.pdf", msg.Parts[0].FileURI)
	})

	t.Run("structured_part", func(t *testing.T) {
		msg, err := tm.AddMessage(task.TaskID, a2a.MessageRoleAgent, []a2a.Part{
			{Type: a2a.PartTypeStructured, Data: json.RawMessage(`{"key":"value"}`)},
		})
		require.NoError(t, err)
		assert.Equal(t, a2a.PartTypeStructured, msg.Parts[0].Type)
	})
}

// ── Artifact Conformance ────────────────────────────────────────────

func TestA2AConformance_Artifact_AddToTask(t *testing.T) {
	tm := a2a.NewTaskManager().WithClock(fixedClock)
	task, err := tm.CreateTask("a", "b")
	require.NoError(t, err)
	require.NoError(t, tm.TransitionTask(task.TaskID, a2a.TaskStatusWorking, "go"))

	art, err := tm.AddArtifact(task.TaskID, "research-report", "application/pdf", []a2a.Part{
		{Type: a2a.PartTypeFile, FileURI: "helm://outputs/report.pdf"},
	})
	require.NoError(t, err)
	require.NotNil(t, art)

	assert.NotEmpty(t, art.ArtifactID)
	assert.True(t, strings.HasPrefix(art.ArtifactID, "art:"))
	assert.Equal(t, "research-report", art.Name)
	assert.Equal(t, "application/pdf", art.ContentType)
	assert.NotEmpty(t, art.ContentHash, "artifact must have a computed content hash")
	assert.True(t, strings.HasPrefix(art.ContentHash, "sha256:"))
}

func TestA2AConformance_Artifact_ContentHashDeterministic(t *testing.T) {
	a1 := &a2a.Artifact{
		Name:        "test",
		ContentType: "text/plain",
		Parts:       []a2a.Part{{Type: a2a.PartTypeText, Text: "hello"}},
	}
	h1 := a2a.ComputeArtifactHash(a1)
	h2 := a2a.ComputeArtifactHash(a1)
	assert.Equal(t, h1, h2, "artifact hash must be deterministic")
}

func TestA2AConformance_Artifact_AddToNonexistentTaskFails(t *testing.T) {
	tm := a2a.NewTaskManager()
	_, err := tm.AddArtifact("task:nonexistent", "name", "type", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ══════════════════════════════════════════════════════════════════════════════
// 4. Streaming Support (SSE)
// ══════════════════════════════════════════════════════════════════════════════

func TestA2AConformance_SSE_EmitProducesSequencedEvents(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-001").WithClock(fixedClock)

	e1 := stream.Emit(a2a.SSEEventTaskStatus, json.RawMessage(`{"status":"WORKING"}`))
	e2 := stream.Emit(a2a.SSEEventTaskMessage, json.RawMessage(`{"text":"progress"}`))
	e3 := stream.Emit(a2a.SSEEventTaskArtifact, json.RawMessage(`{"name":"report"}`))

	assert.Equal(t, int64(1), e1.Sequence)
	assert.Equal(t, int64(2), e2.Sequence)
	assert.Equal(t, int64(3), e3.Sequence)
}

func TestA2AConformance_SSE_EventsPreserveOrder(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-002").WithClock(fixedClock)

	stream.Emit(a2a.SSEEventTaskStatus, json.RawMessage(`{"s":1}`))
	stream.Emit(a2a.SSEEventTaskMessage, json.RawMessage(`{"s":2}`))
	stream.Emit(a2a.SSEEventTaskStatus, json.RawMessage(`{"s":3}`))

	events := stream.Events()
	require.Len(t, events, 3)

	// Verify ordering and monotonic sequences
	for i := 0; i < len(events)-1; i++ {
		assert.Less(t, events[i].Sequence, events[i+1].Sequence,
			"events must have strictly increasing sequences")
	}
}

func TestA2AConformance_SSE_EventsSince(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-003").WithClock(fixedClock)

	stream.Emit(a2a.SSEEventTaskStatus, json.RawMessage(`{"s":"a"}`))
	stream.Emit(a2a.SSEEventTaskMessage, json.RawMessage(`{"s":"b"}`))
	stream.Emit(a2a.SSEEventTaskArtifact, json.RawMessage(`{"s":"c"}`))

	// EventsSince(0) returns all events
	all := stream.EventsSince(0)
	assert.Len(t, all, 3)

	// EventsSince(2) returns only the third event
	after2 := stream.EventsSince(2)
	require.Len(t, after2, 1)
	assert.Equal(t, int64(3), after2[0].Sequence)

	// EventsSince(3) returns nothing
	after3 := stream.EventsSince(3)
	assert.Empty(t, after3)
}

func TestA2AConformance_SSE_EventTypes(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-004").WithClock(fixedClock)

	types := []a2a.SSEEventType{
		a2a.SSEEventTaskStatus,
		a2a.SSEEventTaskMessage,
		a2a.SSEEventTaskArtifact,
		a2a.SSEEventTaskError,
	}

	for _, et := range types {
		e := stream.Emit(et, json.RawMessage(`{}`))
		assert.Equal(t, et, e.EventType, "emitted event type must match")
		assert.Equal(t, "task-sse-004", e.TaskID, "task ID must be preserved")
	}

	events := stream.Events()
	assert.Len(t, events, len(types))
}

func TestA2AConformance_SSE_EventContainsTimestamp(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-005").WithClock(fixedClock)
	e := stream.Emit(a2a.SSEEventTaskStatus, json.RawMessage(`{"status":"COMPLETED"}`))
	assert.Equal(t, fixedTime, e.Timestamp, "event timestamp must come from clock")
}

func TestA2AConformance_SSE_EmptyStreamReturnsNoEvents(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-006")
	events := stream.Events()
	assert.Empty(t, events)

	since := stream.EventsSince(0)
	assert.Empty(t, since)
}

func TestA2AConformance_SSE_EventJSONRoundTrip(t *testing.T) {
	stream := a2a.NewSSEStream("task-sse-007").WithClock(fixedClock)
	original := stream.Emit(a2a.SSEEventTaskMessage, json.RawMessage(`{"text":"hello"}`))

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored a2a.SSEEvent
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, original.EventType, restored.EventType)
	assert.Equal(t, original.TaskID, restored.TaskID)
	assert.Equal(t, original.Sequence, restored.Sequence)
	assert.JSONEq(t, string(original.Data), string(restored.Data))
}

// ══════════════════════════════════════════════════════════════════════════════
// 5. Error Handling (invalid requests, timeouts, fail-closed semantics)
// ══════════════════════════════════════════════════════════════════════════════

func TestA2AConformance_Error_ExpiredEnvelopeDenied(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()
	env.ExpiresAt = fixedTime.Add(-1 * time.Hour) // already expired
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureEvidenceExport})
	require.NoError(t, err)
	assert.False(t, result.Accepted, "expired envelope must be denied")
	assert.Equal(t, a2a.DenyVersionIncompatible, result.DenyReason)
	assert.Contains(t, result.DenyDetails, "expired")
}

func TestA2AConformance_Error_IncompatibleVersionDenied(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()
	env.SchemaVersion = a2a.SchemaVersion{Major: 99, Minor: 0, Patch: 0}
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureEvidenceExport})
	require.NoError(t, err)
	assert.False(t, result.Accepted)
	assert.Equal(t, a2a.DenyVersionIncompatible, result.DenyReason)
}

func TestA2AConformance_Error_MissingFeatureDenied(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()
	env.RequiredFeatures = []a2a.Feature{a2a.FeatureDisputeReplay}
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	// Local agent does not support DISPUTE_REPLAY
	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureEvidenceExport})
	require.NoError(t, err)
	assert.False(t, result.Accepted)
	assert.Equal(t, a2a.DenyFeatureMissing, result.DenyReason)
	assert.Contains(t, result.DenyDetails, string(a2a.FeatureDisputeReplay))
}

func TestA2AConformance_Error_PolicyViolationDenied(t *testing.T) {
	v := baseVerifier()
	v.AddPolicyRule(a2a.PolicyRule{
		RuleID:         "block-payments",
		OriginAgent:    "*",
		TargetAgent:    "*",
		DeniedFeatures: []a2a.Feature{a2a.FeatureAgentPayments},
		Action:         a2a.PolicyDeny,
	})

	env := validEnvelope()
	env.RequiredFeatures = []a2a.Feature{a2a.FeatureAgentPayments}
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "agent-origin")

	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureAgentPayments})
	require.NoError(t, err)
	assert.False(t, result.Accepted)
	assert.Equal(t, a2a.DenyPolicyViolation, result.DenyReason)
	assert.Contains(t, result.DenyDetails, "block-payments")
}

func TestA2AConformance_Error_PolicyWithWildcardAgent(t *testing.T) {
	v := baseVerifier()
	v.AddPolicyRule(a2a.PolicyRule{
		RuleID:         "deny-all-payments",
		OriginAgent:    "*",
		TargetAgent:    "*",
		DeniedFeatures: []a2a.Feature{a2a.FeatureAgentPayments},
		Action:         a2a.PolicyDeny,
	})

	env := validEnvelope()
	env.RequiredFeatures = []a2a.Feature{a2a.FeatureAgentPayments}
	env.OriginAgentID = "random-agent-x"
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "random-agent-x")

	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureAgentPayments})
	require.NoError(t, err)
	assert.False(t, result.Accepted, "wildcard policy must match all agents")
}

func TestA2AConformance_Error_PolicyWithSpecificAgent(t *testing.T) {
	v := baseVerifier()
	v.AddPolicyRule(a2a.PolicyRule{
		RuleID:         "block-untrusted",
		OriginAgent:    "agent-untrusted",
		TargetAgent:    "*",
		DeniedFeatures: []a2a.Feature{a2a.FeatureEvidenceExport},
		Action:         a2a.PolicyDeny,
	})

	// Envelope from blocked agent
	env := validEnvelope()
	env.OriginAgentID = "agent-untrusted"
	env.RequiredFeatures = []a2a.Feature{a2a.FeatureEvidenceExport}
	a2a.SignEnvelope(env, "key-origin-001", "ed25519", "agent-untrusted")

	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureEvidenceExport})
	require.NoError(t, err)
	assert.False(t, result.Accepted)

	// Envelope from allowed agent should pass
	env2 := validEnvelope()
	env2.RequiredFeatures = []a2a.Feature{a2a.FeatureEvidenceExport}
	a2a.SignEnvelope(env2, "key-origin-001", "ed25519", "agent-origin")

	result2, err := v.Negotiate(context.Background(), env2, []a2a.Feature{a2a.FeatureEvidenceExport})
	require.NoError(t, err)
	assert.True(t, result2.Accepted, "non-blocked agent should be accepted")
}

func TestA2AConformance_Error_SignatureWithEmptyKeyID(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()
	env.Signature.KeyID = ""

	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "empty key ID must fail signature verification")
}

func TestA2AConformance_Error_SignatureWithEmptyValue(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()
	env.Signature.Value = ""

	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "empty signature value must fail verification")
}

func TestA2AConformance_Error_TamperedEnvelopeFailsSignature(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()

	// Tamper with the payload hash after signing
	env.PayloadHash = "sha256:tampered"

	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "tampered envelope must fail signature verification")
}

func TestA2AConformance_Error_NegotiationResultAlwaysHasReceiptID(t *testing.T) {
	v := baseVerifier()

	// Test accepted case
	env := validEnvelope()
	result, err := v.Negotiate(context.Background(), env, []a2a.Feature{a2a.FeatureEvidenceExport})
	require.NoError(t, err)
	assert.NotEmpty(t, result.ReceiptID, "accepted negotiation must have receipt ID")

	// Test denied case
	env2 := validEnvelope()
	env2.SchemaVersion = a2a.SchemaVersion{Major: 99, Minor: 0, Patch: 0}
	a2a.SignEnvelope(env2, "key-origin-001", "ed25519", "agent-origin")
	result2, err := v.Negotiate(context.Background(), env2, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, result2.ReceiptID, "denied negotiation must have receipt ID")
}

func TestA2AConformance_Error_EnvelopeHashDeterministic(t *testing.T) {
	env := validEnvelope()
	h1 := a2a.ComputeEnvelopeHash(env)
	h2 := a2a.ComputeEnvelopeHash(env)
	assert.Equal(t, h1, h2, "envelope hash must be deterministic")
	assert.True(t, strings.HasPrefix(h1, "sha256:"))
}

func TestA2AConformance_Error_EnvelopeHashChangesOnMutation(t *testing.T) {
	env := validEnvelope()
	h1 := a2a.ComputeEnvelopeHash(env)

	env.PayloadHash = "sha256:different"
	h2 := a2a.ComputeEnvelopeHash(env)
	assert.NotEqual(t, h1, h2, "envelope hash must change when content changes")
}

// ── Adapter Error Handling ──────────────────────────────────────────

func TestA2AConformance_Error_AdapterRejectsNilRequest(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := a2aadapter.NewA2AAdapter(a2aadapter.Config{Graph: graph})
	require.NoError(t, err)

	_, err = adapter.Intercept(context.Background(), nil)
	require.Error(t, err, "nil request must produce an error")
}

func TestA2AConformance_Error_AdapterRequiresProofGraph(t *testing.T) {
	_, err := a2aadapter.NewA2AAdapter(a2aadapter.Config{})
	require.Error(t, err, "missing ProofGraph must fail adapter creation")
}

func TestA2AConformance_Error_AdapterCreatesProofNode(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := a2aadapter.NewA2AAdapter(a2aadapter.Config{Graph: graph})
	require.NoError(t, err)

	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "a2a",
		ToolName:    "tasks/send",
		Arguments:   map[string]any{"message": "test"},
		PrincipalID: "agent-test",
		Metadata: map[string]string{
			"a2a.from_agent": "agent-test",
			"a2a.to_agent":   "agent-worker",
			"a2a.task_id":    "task-001",
		},
	}

	resp, err := adapter.Intercept(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ProofGraphNode, "adapter must create a proof graph node")
	assert.NotEmpty(t, resp.ReceiptID, "adapter must return a receipt ID")

	node, ok := graph.Get(resp.ProofGraphNode)
	require.True(t, ok, "proof node must be findable in graph")
	assert.Equal(t, proofgraph.NodeTypeIntent, node.Kind)
	assert.Equal(t, "agent-test", node.Principal)
}

func TestA2AConformance_Error_AdapterHandlesMissingMetadata(t *testing.T) {
	graph := proofgraph.NewGraph()
	adapter, err := a2aadapter.NewA2AAdapter(a2aadapter.Config{Graph: graph})
	require.NoError(t, err)

	// Request with no metadata — adapter must still work (fail-open for metadata)
	req := &runtimeadapters.AdaptedRequest{
		RuntimeType: "a2a",
		ToolName:    "tasks/get",
		Arguments:   map[string]any{"task_id": "t1"},
		PrincipalID: "agent-minimal",
	}

	resp, err := adapter.Intercept(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ProofGraphNode)
}

func TestA2AConformance_Error_AdapterAllMethodsCreateProofNodes(t *testing.T) {
	methods := []string{"tasks/send", "tasks/get", "tasks/cancel", "tasks/sendSubscribe"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			graph := proofgraph.NewGraph()
			adapter, err := a2aadapter.NewA2AAdapter(a2aadapter.Config{Graph: graph})
			require.NoError(t, err)

			req := &runtimeadapters.AdaptedRequest{
				RuntimeType: "a2a",
				ToolName:    method,
				Arguments:   map[string]any{},
				PrincipalID: "agent-test",
			}

			resp, err := adapter.Intercept(context.Background(), req)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.ProofGraphNode,
				"method %s must produce a proof graph node", method)
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// 6. Authentication / Authorization (IATP + Headers)
// ══════════════════════════════════════════════════════════════════════════════

func TestA2AConformance_Auth_IATPChallengeResponseMutualAuth(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-conform")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-conform")
	require.NoError(t, err)

	clock := func() time.Time { return fixedTime }

	authA := a2a.NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := a2a.NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	verifyFn := func(pubKey, data, sig string) bool {
		dataBytes, err := hex.DecodeString(data)
		if err != nil {
			return false
		}
		ok, err := crypto.Verify(pubKey, sig, dataBytes)
		return err == nil && ok
	}

	// Step 1: A challenges B
	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)
	assert.NotEmpty(t, challenge.ChallengeID)
	assert.Equal(t, "agent-alpha", challenge.ChallengerAgent)
	assert.Len(t, challenge.Nonce, 64, "nonce must be 32 bytes = 64 hex chars")

	// Step 2: B responds to challenge
	response, err := authB.RespondToChallenge(challenge)
	require.NoError(t, err)
	assert.Equal(t, challenge.ChallengeID, response.ChallengeID)
	assert.Equal(t, "agent-beta", response.ResponderAgent)
	assert.NotEmpty(t, response.SignedNonce)
	assert.NotEmpty(t, response.PublicKey)

	// Step 3: A verifies response and creates session
	session, err := authA.VerifyResponse(challenge, response, verifyFn)
	require.NoError(t, err)
	assert.Equal(t, a2a.IATPAuthenticated, session.Status)
	assert.Equal(t, "agent-alpha", session.LocalAgent)
	assert.Equal(t, "agent-beta", session.RemoteAgent)
}

func TestA2AConformance_Auth_IATPSessionLookup(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-lookup")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-lookup")
	require.NoError(t, err)

	clock := func() time.Time { return fixedTime }

	authA := a2a.NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := a2a.NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	verifyFn := func(pubKey, data, sig string) bool {
		dataBytes, _ := hex.DecodeString(data)
		ok, _ := crypto.Verify(pubKey, sig, dataBytes)
		return ok
	}

	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)
	response, err := authB.RespondToChallenge(challenge)
	require.NoError(t, err)
	session, err := authA.VerifyResponse(challenge, response, verifyFn)
	require.NoError(t, err)

	// Session lookup should succeed
	found, ok := authA.GetSession(session.SessionID)
	require.True(t, ok, "authenticated session must be retrievable")
	assert.Equal(t, session.SessionID, found.SessionID)
	assert.Equal(t, a2a.IATPAuthenticated, found.Status)
}

func TestA2AConformance_Auth_IATPSessionExpires(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-exp")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-exp")
	require.NoError(t, err)

	now := fixedTime
	authA := a2a.NewIATPAuthenticator(signerA).
		WithAgentID("agent-alpha").
		WithClock(func() time.Time { return now }).
		WithSessionTTL(1 * time.Second) // very short TTL

	authB := a2a.NewIATPAuthenticator(signerB).
		WithAgentID("agent-beta").
		WithClock(func() time.Time { return now })

	verifyFn := func(pubKey, data, sig string) bool {
		dataBytes, _ := hex.DecodeString(data)
		ok, _ := crypto.Verify(pubKey, sig, dataBytes)
		return ok
	}

	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)
	response, err := authB.RespondToChallenge(challenge)
	require.NoError(t, err)
	session, err := authA.VerifyResponse(challenge, response, verifyFn)
	require.NoError(t, err)

	// Advance clock past session TTL
	now = fixedTime.Add(2 * time.Second)

	_, ok := authA.GetSession(session.SessionID)
	assert.False(t, ok, "expired session must not be returned")
}

func TestA2AConformance_Auth_IATPReplayProtection(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-replay")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-replay")
	require.NoError(t, err)

	clock := func() time.Time { return fixedTime }

	authA := a2a.NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := a2a.NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	verifyFn := func(pubKey, data, sig string) bool {
		dataBytes, _ := hex.DecodeString(data)
		ok, _ := crypto.Verify(pubKey, sig, dataBytes)
		return ok
	}

	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)
	response, err := authB.RespondToChallenge(challenge)
	require.NoError(t, err)

	// First verification succeeds
	_, err = authA.VerifyResponse(challenge, response, verifyFn)
	require.NoError(t, err)

	// Second verification with same nonce must fail (replay)
	_, err = authA.VerifyResponse(challenge, response, verifyFn)
	require.Error(t, err, "replay of same nonce must be rejected")
	assert.Contains(t, err.Error(), "replay")
}

func TestA2AConformance_Auth_IATPExpiredChallengeFails(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-ttl")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-ttl")
	require.NoError(t, err)

	now := fixedTime
	authA := a2a.NewIATPAuthenticator(signerA).
		WithAgentID("agent-alpha").
		WithClock(func() time.Time { return now })
	authB := a2a.NewIATPAuthenticator(signerB).
		WithAgentID("agent-beta").
		WithClock(func() time.Time { return now })

	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)

	// Advance clock past challenge TTL (200ms)
	now = fixedTime.Add(1 * time.Second)

	_, err = authB.RespondToChallenge(challenge)
	require.Error(t, err, "responding to expired challenge must fail")
	assert.Contains(t, err.Error(), "expired")
}

func TestA2AConformance_Auth_IATPNilChallengeFails(t *testing.T) {
	signer, err := crypto.NewEd25519Signer("key-nil")
	require.NoError(t, err)
	auth := a2a.NewIATPAuthenticator(signer)

	_, err = auth.RespondToChallenge(nil)
	require.Error(t, err, "nil challenge must be rejected")
}

func TestA2AConformance_Auth_IATPInvalidSignatureFails(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-badsig")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-badsig")
	require.NoError(t, err)

	clock := func() time.Time { return fixedTime }

	authA := a2a.NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := a2a.NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)
	response, err := authB.RespondToChallenge(challenge)
	require.NoError(t, err)

	// Tamper with the signed nonce
	response.SignedNonce = "deadbeef0000" + response.SignedNonce[12:]

	// Use a verifier that actually checks crypto
	verifyFn := func(pubKey, data, sig string) bool {
		dataBytes, _ := hex.DecodeString(data)
		ok, _ := crypto.Verify(pubKey, sig, dataBytes)
		return ok
	}

	session, err := authA.VerifyResponse(challenge, response, verifyFn)
	require.Error(t, err, "tampered signature must fail")
	assert.Equal(t, a2a.IATPFailed, session.Status, "failed session status must be FAILED")
}

func TestA2AConformance_Auth_IATPChallengeIDMismatchFails(t *testing.T) {
	signerA, err := crypto.NewEd25519Signer("key-alpha-mismatch")
	require.NoError(t, err)
	signerB, err := crypto.NewEd25519Signer("key-beta-mismatch")
	require.NoError(t, err)

	clock := func() time.Time { return fixedTime }

	authA := a2a.NewIATPAuthenticator(signerA).WithAgentID("agent-alpha").WithClock(clock)
	authB := a2a.NewIATPAuthenticator(signerB).WithAgentID("agent-beta").WithClock(clock)

	challenge, err := authA.CreateChallenge("agent-beta")
	require.NoError(t, err)
	response, err := authB.RespondToChallenge(challenge)
	require.NoError(t, err)

	// Tamper with challenge ID in the response
	response.ChallengeID = "iatp-ch:tampered"

	verifyFn := func(_, _, _ string) bool { return true } // always-pass verifier
	_, err = authA.VerifyResponse(challenge, response, verifyFn)
	require.Error(t, err, "mismatched challenge ID must fail")
	assert.Contains(t, err.Error(), "mismatch")
}

// ── Signature Verification (Authorization Headers) ──────────────────

func TestA2AConformance_Auth_SignatureVerifiesCorrectly(t *testing.T) {
	v := baseVerifier()
	env := validEnvelope()

	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.True(t, valid, "correctly signed envelope must verify")
}

func TestA2AConformance_Auth_UnknownKeyIDRejected(t *testing.T) {
	v := a2a.NewDefaultVerifier() // no keys registered
	env := validEnvelope()

	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "unknown key ID must fail verification")
}

func TestA2AConformance_Auth_InactiveKeyRejected(t *testing.T) {
	v := a2a.NewDefaultVerifier()
	v.RegisterKey(a2a.TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-origin",
		Algorithm: "ed25519",
		PublicKey: "base64-pubkey",
		Active:    false, // revoked
	})

	env := validEnvelope()
	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "inactive/revoked key must fail verification")
}

func TestA2AConformance_Auth_AlgorithmMismatchRejected(t *testing.T) {
	v := a2a.NewDefaultVerifier()
	v.RegisterKey(a2a.TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-origin",
		Algorithm: "rsa-sha256", // mismatched algorithm
		PublicKey: "base64-pubkey",
		Active:    true,
	})

	env := validEnvelope()
	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "algorithm mismatch must fail verification")
}

func TestA2AConformance_Auth_KeyAgentBindingEnforced(t *testing.T) {
	v := a2a.NewDefaultVerifier()
	v.RegisterKey(a2a.TrustedKey{
		KeyID:     "key-origin-001",
		AgentID:   "agent-different", // key belongs to different agent
		Algorithm: "ed25519",
		PublicKey: "base64-pubkey",
		Active:    true,
	})

	env := validEnvelope() // origin is "agent-origin"
	valid, err := v.VerifySignature(context.Background(), env)
	require.NoError(t, err)
	assert.False(t, valid, "key not bound to envelope origin agent must fail")
}

func TestA2AConformance_Auth_AuthMethodConstants(t *testing.T) {
	// Verify all auth method constants are distinct and non-empty
	methods := []a2a.AuthMethod{
		a2a.AuthMethodIATP,
		a2a.AuthMethodAPIKey,
		a2a.AuthMethodOAuth2,
		a2a.AuthMethodMTLS,
	}

	seen := make(map[a2a.AuthMethod]bool)
	for _, m := range methods {
		assert.NotEmpty(t, string(m), "auth method must be non-empty")
		assert.False(t, seen[m], "auth method %s must be unique", m)
		seen[m] = true
	}
}
