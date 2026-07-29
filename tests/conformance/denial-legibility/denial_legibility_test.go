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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// replayRounds re-evaluates the snapshot in-process. It is the weaker half of
// the replay evidence: the strong half is TestDenialsMatchTheGoldenPack, which
// compares against a digest frozen in a different process on a different day.
// An implementation in a language with per-process hash seeding — Python, Java
// — must compare against the golden to prove anything, because unordered
// iteration is stable within one process and varies between them.
const replayRounds = 8

// requiredFinalities is what the pack must always exercise. Without this the
// scenario set could be trimmed and the golden regenerated, and every check
// below would pass vacuously over whatever remained.
var requiredFinalities = []contracts.DenialFinality{
	contracts.DenialClassForbidden,
	contracts.DenialUngranted,
	contracts.DenialInstanceParameter,
	contracts.DenialInstanceContext,
	contracts.DenialInstanceMembership,
}

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

type scenario struct {
	name  string
	event workstation.ToolEvent
}

// Every finality value appears, and both disclosure outcomes appear within the
// values that can disclose: an implementer keying on finality alone will emit a
// counterfactual for every instance_parameter and every ungranted, which is the
// mistake these cases exist to catch.
func denialScenarios() []scenario {
	return []scenario{
		{"instance_membership/egress_destination", workstation.ToolEvent{
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
		{"instance_membership/draft_outside_workspace", workstation.ToolEvent{
			EventID:    "cf-draft",
			Type:       "file_write",
			EffectType: contracts.EffectTypeWorkstationFileWrite,
			EffectMode: contracts.WorkstationEffectModeDraft,
			Target:     "../outside.txt",
		}},
		{"ungranted/operate_permission_discloses_capability", workstation.ToolEvent{
			EventID:    "ug-shell",
			Type:       "shell_operate",
			EffectType: contracts.EffectTypeWorkstationShellCommand,
			EffectMode: contracts.WorkstationEffectModeOperate,
			Action:     "operate",
		}},
		{"instance_parameter/memory_ttl_discloses_bound", workstation.ToolEvent{
			EventID:      "ip-ttl",
			Type:         "memory_write",
			EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
			EffectMode:   contracts.WorkstationEffectModeOperate,
			MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "episodic", TTLDays: 90},
		}},
		// The same finality with nothing to disclose. The missing field is
		// already named by the reason code, so a counterfactual would add
		// nothing — an implementation that emits one here has misread the
		// rule as "instance_parameter always carries a bound".
		{"instance_parameter/recurring_loop_discloses_nothing", workstation.ToolEvent{
			EventID:             "ip-loop",
			Type:                "recurring_loop",
			EffectType:          contracts.EffectTypeWorkstationRecurringLoop,
			EffectMode:          contracts.WorkstationEffectModeOperate,
			RecurringLoopEffect: &contracts.AgentRecurringLoopEffect{},
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

// allowControl is the negative vector. Without it an implementation that denies
// unconditionally — or that hardcodes answers for the six known event ids —
// passes this pack in full.
func allowControl() scenario {
	return scenario{"allow/egress_to_allowlisted_host", workstation.ToolEvent{
		EventID:    "ok-egress",
		Type:       "network_egress",
		EffectType: contracts.EffectTypeWorkstationNetworkEgress,
		EffectMode: contracts.WorkstationEffectModeOperate,
		Target:     "api.example.com",
	}}
}

// observe drives the signed receipt path. That matters here: a counterfactual
// is useful only when it is bound to the event and policy evaluation that made
// it, not when it is a mutable value a caller can change before signing.
func observe(t *testing.T, profile contracts.WorkstationPolicyProfile) []observation {
	t.Helper()
	scenarios := denialScenarios()
	out := make([]observation, 0, len(scenarios))
	for _, sc := range scenarios {
		verdict, _, _ := workstation.EvaluateEvent(profile, sc.event)
		denied := signedDeniedEffect(t, profile, sc.event)
		out = append(out, observation{
			Case:           sc.name,
			Verdict:        verdict,
			ReasonCode:     denied.ReasonCode,
			Finality:       denied.Finality,
			Counterfactual: denied.Counterfactual,
		})
	}
	return out
}

func signedDeniedEffect(t *testing.T, profile contracts.WorkstationPolicyProfile, event workstation.ToolEvent) contracts.AgentDeniedEffect {
	t.Helper()
	result, err := workstation.BuildReceipt(workstation.RunManifest{
		RunID:         "denial-legibility-" + event.EventID,
		Goal:          "denial legibility conformance",
		ActorID:       "conformance.agent",
		WorkspaceID:   "conformance.workspace",
		AgentSurface:  "conformance",
		PolicyProfile: profile.ID,
	}, workstation.DiffSummary{}, workstation.ValidationArtifact{}, []workstation.ToolEvent{event}, profile,
		map[string]string{workstation.ManifestFile: strings.Repeat("a", 64)},
		workstation.ImportOptions{SigningSeed: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("BuildReceipt(%s): %v", event.EventID, err)
	}
	if ok, err := workstation.VerifyReceiptSignature(result.Receipt); err != nil || !ok {
		t.Fatalf("signed receipt verification = %t/%v, want true/nil", ok, err)
	}
	if len(result.Receipt.DeniedEffects) != 1 {
		t.Fatalf("denied effects = %d, want 1", len(result.Receipt.DeniedEffects))
	}
	return result.Receipt.DeniedEffects[0]
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
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

// The snapshot is a published-contract document, not just a test input. A
// fixture that could not be loaded by a real deployment would make every check
// below prove something about a configuration nobody can run.
func TestSnapshotSatisfiesThePublishedProfileSchema(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../../protocols/json-schemas/policy/workstation_policy_profile.v1.schema.json")
	if err != nil {
		t.Fatalf("compile profile schema: %v", err)
	}
	raw, err := os.ReadFile("policy-snapshot.json")
	if err != nil {
		t.Fatalf("read policy snapshot: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode policy snapshot: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("policy-snapshot.json violates workstation_policy_profile.v1: %v", err)
	}
}

// A denied effect carrying these fields must satisfy the published receipt
// schema, or opting the feature on produces receipts every conforming consumer
// rejects as malformed.
func TestDisclosedFieldsSatisfyThePublishedReceiptSchema(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../../protocols/json-schemas/workstation/agent_run_receipt.v1.schema.json#/$defs/denied_effect")
	if err != nil {
		t.Fatalf("compile denied_effect schema: %v", err)
	}
	profile := loadSnapshot(t)
	for _, sc := range denialScenarios() {
		denied := signedDeniedEffect(t, profile, sc.event)
		encoded, err := json.Marshal(denied)
		if err != nil {
			t.Fatalf("marshal %s: %v", sc.name, err)
		}
		var doc any
		if err := json.Unmarshal(encoded, &doc); err != nil {
			t.Fatalf("decode %s: %v", sc.name, err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("case %s produced a denied effect the published schema rejects: %v", sc.name, err)
		}
	}
}

// A counterfactual belongs to the signed receipt that its policy evaluation
// produced. A caller may inspect it, but a replacement before verification
// must invalidate the receipt.
func TestCounterfactualBindsToTheEvaluatedEvent(t *testing.T) {
	profile := loadSnapshot(t)
	event := workstation.ToolEvent{
		EventID:      "spoofed-denial",
		Type:         "memory_write",
		EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
		EffectMode:   contracts.WorkstationEffectModeOperate,
		MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "episodic", TTLDays: 90},
	}
	result, err := workstation.BuildReceipt(workstation.RunManifest{
		RunID:         "denial-legibility-substitution",
		Goal:          "denial legibility substitution test",
		ActorID:       "conformance.agent",
		WorkspaceID:   "conformance.workspace",
		AgentSurface:  "conformance",
		PolicyProfile: profile.ID,
	}, workstation.DiffSummary{}, workstation.ValidationArtifact{}, []workstation.ToolEvent{event}, profile,
		map[string]string{workstation.ManifestFile: strings.Repeat("a", 64)},
		workstation.ImportOptions{SigningSeed: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatalf("BuildReceipt() error = %v", err)
	}
	if len(result.Receipt.DeniedEffects) != 1 || result.Receipt.DeniedEffects[0].Counterfactual == nil {
		t.Fatalf("denied effects = %+v, want one scalar counterfactual", result.Receipt.DeniedEffects)
	}
	denied := result.Receipt.DeniedEffects[0]
	if got := denied.Counterfactual.Requested; got != 90 {
		t.Fatalf("counterfactual requested = %d, want 90", got)
	}

	result.Receipt.DeniedEffects[0].Counterfactual.Requested = 60
	ok, err := workstation.VerifyReceiptSignature(result.Receipt)
	if err != nil {
		t.Fatalf("VerifyReceiptSignature() error = %v", err)
	}
	if ok {
		t.Fatal("receipt verified after substituting a valid counterfactual from another event")
	}
}

func TestPublishedReceiptSchemaRejectsAmbiguousCounterfactuals(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("../../../protocols/json-schemas/workstation/agent_run_receipt.v1.schema.json#/$defs/denied_effect")
	if err != nil {
		t.Fatalf("compile denied_effect schema: %v", err)
	}
	for name, counterfactual := range map[string]any{
		"field_only":  map[string]any{"field": "ttl_days"},
		"zero_scalar": map[string]any{"field": "ttl_days", "requested": 0, "max": 0},
		"mixed_shapes": map[string]any{
			"field": "ttl_days", "requested": 90, "max": 30, "capability": "network.egress",
		},
		"unknown_capability": map[string]any{
			"field": "operate.permissions", "capability": "attacker.chosen",
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := map[string]any{
				"effect_id": "e1", "effect_type": "WORKSTATION_MEMORY_WRITE",
				"reason_code": "MEMORY_TTL_EXCEEDS_POLICY", "occurred_at": "2026-07-29T00:00:00Z",
				"counterfactual": counterfactual,
			}
			if err := schema.Validate(doc); err == nil {
				t.Fatal("published schema accepted an ambiguous counterfactual")
			}
		})
	}
}

func TestPublishedReceiptContractRejectsUnexceededScalarCounterfactual(t *testing.T) {
	var denied contracts.AgentDeniedEffect
	err := json.Unmarshal([]byte(`{
		"effect_id":"e1",
		"effect_type":"WORKSTATION_MEMORY_WRITE",
		"reason_code":"MEMORY_TTL_EXCEEDS_POLICY",
		"occurred_at":"2026-07-29T00:00:00Z",
		"counterfactual":{"field":"ttl_days","requested":1,"max":2}
	}`), &denied)
	if err == nil {
		t.Fatal("receipt contract accepted a scalar counterfactual that did not exceed its bound")
	}
}

// The scenario set itself is pinned. Trimming a case and regenerating the
// golden would otherwise silently drop a whole finality class from coverage
// while every other check still passed.
func TestPackExercisesEveryFinality(t *testing.T) {
	seen := map[contracts.DenialFinality]int{}
	for _, obs := range observe(t, loadSnapshot(t)) {
		seen[obs.Finality]++
	}
	for _, want := range requiredFinalities {
		if seen[want] == 0 {
			t.Errorf("no scenario exercises finality %q", want)
		}
	}
}

// Both disclosure outcomes must appear within the finality values that are
// allowed to disclose, so the pack cannot be read as "this finality always
// carries an envelope".
func TestDisclosingFinalitiesShowBothOutcomes(t *testing.T) {
	withEnvelope, withoutEnvelope := 0, 0
	for _, obs := range observe(t, loadSnapshot(t)) {
		switch obs.Finality {
		case contracts.DenialInstanceParameter, contracts.DenialUngranted:
			if obs.Counterfactual != nil {
				withEnvelope++
			} else {
				withoutEnvelope++
			}
		}
	}
	if withEnvelope == 0 {
		t.Error("no disclosing case carries a counterfactual")
	}
	if withoutEnvelope == 0 {
		t.Error("no disclosing finality appears without a counterfactual: the pack reads as though the envelope is unconditional")
	}
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

// Replay: the same snapshot, evaluated again, has to say the same thing.
func TestDenialClassificationReplaysIdentically(t *testing.T) {
	profile := loadSnapshot(t)
	first := digest(t, observe(t, profile))
	for round := 2; round <= replayRounds; round++ {
		if d := digest(t, observe(t, profile)); d != first {
			t.Fatalf("round %d diverged: %s != %s", round, d, first)
		}
	}
}

// Every denial scenario must actually be denied, and the control must not be.
// A boundary that refuses everything would otherwise pass this pack.
func TestVerdictsSplitAsExpected(t *testing.T) {
	profile := loadSnapshot(t)
	for _, obs := range observe(t, profile) {
		if obs.Verdict != contracts.WorkstationVerdictDeny {
			t.Errorf("case %s returned %s, want DENY", obs.Case, obs.Verdict)
		}
		if obs.Finality == "" {
			t.Errorf("case %s produced no finality: a denial a consumer cannot classify teaches nothing", obs.Case)
		}
	}
	control := allowControl()
	verdict, code, _ := workstation.EvaluateEvent(profile, control.event)
	if verdict != contracts.WorkstationVerdictAllow {
		t.Errorf("control %s returned %s/%s, want ALLOW", control.name, verdict, code)
	}
}

// The disclosure boundary, restated as a conformance property: a refusal that
// turns on set membership discloses nothing about the set, and a forbidden
// category discloses nothing either. This is the check an external
// implementation is most likely to get wrong in the helpful direction.
func TestMembershipRefusalsDiscloseNothing(t *testing.T) {
	for _, obs := range observe(t, loadSnapshot(t)) {
		if obs.Finality != contracts.DenialInstanceMembership && obs.Finality != contracts.DenialClassForbidden {
			continue
		}
		if obs.Counterfactual != nil {
			t.Errorf("case %s disclosed %+v: this refusal must not describe the set or category it failed against",
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
	for _, sc := range denialScenarios() {
		denied := signedDeniedEffect(t, profile, sc.event)
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
