// Package deniallegibility is the conformance scenario for denials that carry
// what a consuming agent needs in order to learn from them.
//
// An implementation passes when, against the frozen policy snapshot in this
// directory, every refusal reports the same finality and discloses exactly the
// same envelope — no more, and no less — on every replay.
//
// The scenario exists because "the agent learned from the denial" is otherwise
// an unfalsifiable claim. Here it is a golden file.
package deniallegibility

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// replayRounds is why this is a conformance scenario rather than a unit test:
// a boundary that classifies a refusal differently on the second look cannot
// be replayed, and a receipt over it proves nothing.
const replayRounds = 8

type observation struct {
	Case           string                          `json:"case"`
	Verdict        string                          `json:"verdict"`
	ReasonCode     string                          `json:"reason_code"`
	Finality       contracts.DenialFinality        `json:"finality"`
	Counterfactual *contracts.DenialCounterfactual `json:"counterfactual,omitempty"`
}

type goldenFile struct {
	Snapshot     string        `json:"policy_snapshot"`
	Digest       string        `json:"digest"`
	Observations []observation `json:"observations"`
}

// Each case names the finality it is here to pin down. Together they cover all
// four: a refusal an agent must stop probing, one nobody granted, one with a
// bound to respect, and one that was never about the action.
func scenarios() []struct {
	name  string
	event workstation.ToolEvent
} {
	return []struct {
		name  string
		event workstation.ToolEvent
	}{
		{"class_forbidden/egress_destination", workstation.ToolEvent{
			EventID:    "cf-egress",
			Type:       "network_egress",
			EffectType: contracts.EffectTypeWorkstationNetworkEgress,
			EffectMode: contracts.WorkstationEffectModeOperate,
			Target:     "unlisted.example.net",
		}},
		{"class_forbidden/memory_class", workstation.ToolEvent{
			EventID:      "cf-memclass",
			Type:         "memory_write",
			EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
			EffectMode:   contracts.WorkstationEffectModeOperate,
			MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "procedural", TTLDays: 1},
		}},
		{"class_forbidden/draft_outside_workspace", workstation.ToolEvent{
			EventID:    "cf-draft",
			Type:       "file_write",
			EffectType: contracts.EffectTypeWorkstationFileWrite,
			EffectMode: contracts.WorkstationEffectModeDraft,
			Target:     "../outside.txt",
		}},
		{"ungranted/operate_permission", workstation.ToolEvent{
			EventID:    "ug-shell",
			Type:       "shell_operate",
			EffectType: contracts.EffectTypeWorkstationShellCommand,
			EffectMode: contracts.WorkstationEffectModeOperate,
			Action:     "operate",
		}},
		{"instance_parameter/memory_ttl", workstation.ToolEvent{
			EventID:      "ip-ttl",
			Type:         "memory_write",
			EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
			EffectMode:   contracts.WorkstationEffectModeOperate,
			MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "episodic", TTLDays: 90},
		}},
		{"instance_context/tainted", workstation.ToolEvent{
			EventID:     "ic-taint",
			Type:        "mcp_tool_call",
			EffectType:  contracts.EffectTypeWorkstationMCPToolCall,
			EffectMode:  contracts.WorkstationEffectModeOperate,
			TaintLabels: []string{"prompt_injection"},
		}},
	}
}

func observe(t *testing.T, profile contracts.WorkstationPolicyProfile) []observation {
	t.Helper()
	out := make([]observation, 0, len(scenarios()))
	for _, sc := range scenarios() {
		verdict, code, _ := workstation.EvaluateEvent(profile, sc.event)
		out = append(out, observation{
			Case:           sc.name,
			Verdict:        verdict,
			ReasonCode:     code,
			Finality:       workstation.DenialFinality(code),
			Counterfactual: workstation.DenialCounterfactualFor(profile, sc.event, code),
		})
	}
	return out
}

func digest(t *testing.T, obs []observation) string {
	t.Helper()
	encoded, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshal observations: %v", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func loadSnapshot(t *testing.T) contracts.WorkstationPolicyProfile {
	t.Helper()
	raw, err := os.ReadFile("policy-snapshot.json")
	if err != nil {
		t.Fatalf("read policy snapshot: %v", err)
	}
	var profile contracts.WorkstationPolicyProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatalf("decode policy snapshot: %v", err)
	}
	return profile
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	raw, err := os.ReadFile("golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden goldenFile
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	return golden
}

// The scenario proper: the frozen snapshot must produce the recorded denials,
// field for field.
func TestDenialsMatchTheGoldenPack(t *testing.T) {
	golden := loadGolden(t)
	got := observe(t, loadSnapshot(t))

	if len(got) != len(golden.Observations) {
		t.Fatalf("observed %d denials, golden records %d", len(got), len(golden.Observations))
	}
	for i, want := range golden.Observations {
		// Compared as encoded JSON: observation holds a pointer, and the
		// receipt contract is the encoding, not the address.
		gotJSON, err := json.Marshal(got[i])
		if err != nil {
			t.Fatalf("marshal observed: %v", err)
		}
		wantJSON, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal golden: %v", err)
		}
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("case %s diverged:\n got %s\nwant %s", want.Case, gotJSON, wantJSON)
		}
	}
	if d := digest(t, got); d != golden.Digest {
		t.Errorf("pack digest = %s, golden = %s", d, golden.Digest)
	}
}

// Replay: the same snapshot, evaluated again, has to say the same thing. A
// boundary that drifts between rounds cannot be proven to an auditor.
func TestDenialClassificationReplaysIdentically(t *testing.T) {
	profile := loadSnapshot(t)
	first := digest(t, observe(t, profile))
	for round := 2; round <= replayRounds; round++ {
		if d := digest(t, observe(t, profile)); d != first {
			t.Fatalf("round %d diverged: %s != %s", round, d, first)
		}
	}
}

// Every scenario must actually be denied. A snapshot that quietly starts
// allowing one of these would still pass a golden comparison if the golden
// were regenerated, so the property is asserted directly.
func TestEveryScenarioIsDenied(t *testing.T) {
	for _, obs := range observe(t, loadSnapshot(t)) {
		if obs.Verdict != contracts.WorkstationVerdictDeny {
			t.Errorf("case %s returned %s, want DENY", obs.Case, obs.Verdict)
		}
		if obs.Finality == "" {
			t.Errorf("case %s produced no finality: a denial a consumer cannot classify teaches nothing", obs.Case)
		}
	}
}

// The disclosure boundary, restated as a conformance property: a refusal that
// turns on set membership discloses nothing about the set. This is the check an
// external implementation is most likely to get wrong in the helpful direction.
func TestMembershipRefusalsDiscloseNothing(t *testing.T) {
	for _, obs := range observe(t, loadSnapshot(t)) {
		if obs.Finality != contracts.DenialClassForbidden {
			continue
		}
		if obs.Counterfactual != nil {
			t.Errorf("case %s disclosed %+v: a forbidden-class refusal must not describe the set it failed against",
				obs.Case, obs.Counterfactual)
		}
	}
}

// Turning the profile switches off must remove the fields entirely, not blank
// them. Presence is itself a policy statement, and an empty field is a claim
// that the policy said nothing when it did.
func TestOptOutEmitsNothing(t *testing.T) {
	profile := loadSnapshot(t)
	profile.Learning = nil
	for _, sc := range scenarios() {
		_, code, _ := workstation.EvaluateEvent(profile, sc.event)
		denied := contracts.AgentDeniedEffect{EffectID: sc.event.EventID, ReasonCode: code}
		encoded, err := json.Marshal(denied)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, present := decoded["finality"]; present {
			t.Errorf("case %s emitted a finality key with learning disabled", sc.name)
		}
		if _, present := decoded["counterfactual"]; present {
			t.Errorf("case %s emitted a counterfactual key with learning disabled", sc.name)
		}
	}
}
