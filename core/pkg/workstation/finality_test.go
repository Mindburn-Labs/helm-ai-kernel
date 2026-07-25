package workstation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

var denyCodeLiteral = regexp.MustCompile(`WorkstationVerdictDeny, "([A-Z_]+)"`)

// The catalog is the thing that makes finality derived rather than assigned, so
// a deny path that HELM cannot classify is a defect in the catalog, not a
// tolerable gap. Scanning the source is the only check that actually catches a
// new deny path added without a classification.
func TestEveryDenyReasonCodeIsClassified(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	seen := 0
	for _, src := range sources {
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		for _, match := range denyCodeLiteral.FindAllStringSubmatch(string(body), -1) {
			code := match[1]
			seen++
			if _, ok := denialCatalog[code]; !ok {
				t.Errorf("%s emits %s with no denialCatalog entry: classify it, or a consumer learns nothing from this denial", src, code)
			}
		}
	}
	if seen == 0 {
		t.Fatal("scanned no deny reason codes — the scan pattern has drifted from the source")
	}
}

// Membership denials are the disclosure boundary: an egress allowlist or a set
// of workspace roots is a map of internal infrastructure. "Not that one, try
// these" would make every denial a free probe.
func TestSetMembershipDenialsDiscloseNothing(t *testing.T) {
	profile := learningProfile()
	cases := []struct {
		code  string
		event ToolEvent
	}{
		{"EGRESS_DESTINATION_NOT_ALLOWED", ToolEvent{
			Type:       "network_egress",
			EffectType: contracts.EffectTypeWorkstationNetworkEgress,
			EffectMode: contracts.WorkstationEffectModeOperate,
			Target:     "exfil.example.com",
		}},
		{"DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE", ToolEvent{
			Type:       "file_write",
			EffectType: contracts.EffectTypeWorkstationFileWrite,
			EffectMode: contracts.WorkstationEffectModeDraft,
			Target:     "../secrets.txt",
		}},
		{"MEMORY_CLASS_DISALLOWED", ToolEvent{
			Type:         "memory_write",
			EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
			EffectMode:   contracts.WorkstationEffectModeOperate,
			MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "procedural", TTLDays: 1},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			verdict, code, _ := EvaluateEvent(profile, tc.event)
			if verdict != contracts.WorkstationVerdictDeny || code != tc.code {
				t.Fatalf("EvaluateEvent() = %s/%s, want DENY/%s", verdict, code, tc.code)
			}
			if got := DenialCounterfactualFor(profile, tc.event, code); got != nil {
				t.Fatalf("%s disclosed a counterfactual %+v: membership denials must disclose nothing", code, got)
			}
			if got := DenialFinality(code); got != contracts.DenialClassForbidden {
				t.Fatalf("DenialFinality(%s) = %q, want class_forbidden", code, got)
			}
		})
	}
}

// A scalar bound is the case the whole design exists for: the agent is told the
// ceiling and can retry under it without probing.
func TestScalarBoundDisclosesTheCeiling(t *testing.T) {
	profile := learningProfile()
	event := ToolEvent{
		Type:         "memory_write",
		EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
		EffectMode:   contracts.WorkstationEffectModeOperate,
		MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "episodic", TTLDays: 90},
	}
	verdict, code, _ := EvaluateEvent(profile, event)
	if verdict != contracts.WorkstationVerdictDeny || code != "MEMORY_TTL_EXCEEDS_POLICY" {
		t.Fatalf("EvaluateEvent() = %s/%s, want DENY/MEMORY_TTL_EXCEEDS_POLICY", verdict, code)
	}
	if got := DenialFinality(code); got != contracts.DenialInstanceParameter {
		t.Fatalf("DenialFinality() = %q, want instance_parameter", got)
	}
	got := DenialCounterfactualFor(profile, event, code)
	want := &contracts.DenialCounterfactual{Field: "ttl_days", Requested: 90, Max: 30}
	if got == nil || *got != *want {
		t.Fatalf("DenialCounterfactualFor() = %+v, want %+v", got, want)
	}
}

// Ungranted names the capability the action needed — a fixed public vocabulary,
// not infrastructure — so the agent can ask for the right thing.
func TestUngrantedNamesTheCapability(t *testing.T) {
	profile := learningProfile()
	profile.Operate.Permissions = []string{contracts.WorkstationPermissionMemoryWrite}
	event := ToolEvent{
		Type:       "shell_operate",
		EffectType: contracts.EffectTypeWorkstationShellCommand,
		EffectMode: contracts.WorkstationEffectModeOperate,
		Action:     "operate",
	}
	verdict, code, _ := EvaluateEvent(profile, event)
	if verdict != contracts.WorkstationVerdictDeny || code != "OPERATE_PERMISSION_NOT_GRANTED" {
		t.Fatalf("EvaluateEvent() = %s/%s, want DENY/OPERATE_PERMISSION_NOT_GRANTED", verdict, code)
	}
	if got := DenialFinality(code); got != contracts.DenialUngranted {
		t.Fatalf("DenialFinality() = %q, want ungranted", got)
	}
	got := DenialCounterfactualFor(profile, event, code)
	if got == nil || got.Capability == "" {
		t.Fatalf("DenialCounterfactualFor() = %+v, want a named capability", got)
	}
}

// Absent, not empty. A profile that never opted in must serialize exactly as it
// did before these fields existed, or every stored receipt hash moves.
func TestDisabledByDefaultLeavesReceiptsByteIdentical(t *testing.T) {
	profile := learningProfile()
	profile.Learning = nil // the default: no opt-in

	event := ToolEvent{
		Type:         "memory_write",
		EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
		EffectMode:   contracts.WorkstationEffectModeOperate,
		MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "episodic", TTLDays: 90},
	}
	_, code, _ := EvaluateEvent(profile, event)

	denied := contracts.AgentDeniedEffect{EffectID: "e1", EffectType: event.EffectType, ReasonCode: code}
	AnnotateDenial(&denied, profile, event, code)

	encoded, err := json.Marshal(denied)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"effect_id":"e1","effect_type":"WORKSTATION_MEMORY_WRITE","reason_code":"MEMORY_TTL_EXCEEDS_POLICY","occurred_at":"0001-01-01T00:00:00Z"}`
	if string(encoded) != want {
		t.Fatalf("denied effect JSON changed with the feature off:\n got %s\nwant %s", encoded, want)
	}
}

// The agent's own event log may declare a reason code, and normalizeEvents
// honours that declaration for the recorded reason_code. Finality must not
// follow it: a producer able to relabel its own refusal as instance_context
// would be telling the consumer "this was not about the action, keep going"
// about a boundary it had just been refused at.
func TestDeclaredReasonCodeCannotSteerFinality(t *testing.T) {
	profile := learningProfile()
	honest := ToolEvent{
		EventID:    "e-egress",
		Type:       "network_egress",
		EffectType: contracts.EffectTypeWorkstationNetworkEgress,
		EffectMode: contracts.WorkstationEffectModeOperate,
		Target:     "exfil.example.net",
	}
	relabelled := honest
	relabelled.ReasonCode = "TAINTED_CONTEXT_REQUIRES_DENY"

	_, _, _, honestDenials := normalizeEvents(profile, []ToolEvent{honest})
	_, _, _, relabelledDenials := normalizeEvents(profile, []ToolEvent{relabelled})

	if len(honestDenials) != 1 || len(relabelledDenials) != 1 {
		t.Fatalf("expected one denial each, got %d and %d", len(honestDenials), len(relabelledDenials))
	}
	if got := honestDenials[0].Finality; got != contracts.DenialClassForbidden {
		t.Fatalf("honest event finality = %q, want class_forbidden", got)
	}
	if got := relabelledDenials[0].Finality; got != contracts.DenialClassForbidden {
		t.Fatalf("declared reason code steered finality to %q: a producer must not be able to relabel its own refusal", got)
	}
}

// An arbitrary effect_type must not reach the capability field.
// workstationPermissionForEffect echoes unrecognised effect types back, and
// effect_type is producer supplied, so without the vocabulary check a crafted
// event lands an attacker-chosen string in a signed receipt field the contract
// describes as an enum.
func TestCapabilityDisclosureRejectsUnknownVocabulary(t *testing.T) {
	profile := learningProfile()
	profile.Operate.Permissions = []string{contracts.WorkstationPermissionMemoryWrite}
	event := ToolEvent{
		EventID:    "e-crafted",
		Type:       "not_a_known_type",
		EffectType: "s3://prod-secrets/customer-pii?sig=AKIA",
		EffectMode: contracts.WorkstationEffectModeOperate,
		Action:     "operate",
	}
	verdict, code, _ := EvaluateEvent(profile, event)
	if verdict != contracts.WorkstationVerdictDeny || code != "OPERATE_PERMISSION_NOT_GRANTED" {
		t.Fatalf("EvaluateEvent() = %s/%s, want DENY/OPERATE_PERMISSION_NOT_GRANTED", verdict, code)
	}
	if got := DenialCounterfactualFor(profile, event, code); got != nil {
		t.Fatalf("disclosed %+v for an unrecognised effect type: capability must come from the fixed vocabulary", got)
	}
}

// A TTL the event never declared must not be reported as the request. The
// effective value would be the profile default, and echoing that back both
// misstates what the agent asked for and publishes a second policy scalar.
func TestUndeclaredTTLDisclosesNothing(t *testing.T) {
	profile := learningProfile()
	profile.Memory.DefaultTTLDays = 400 // above Max, so the event still denies
	event := ToolEvent{
		EventID:      "e-nottl",
		Type:         "memory_write",
		EffectType:   contracts.EffectTypeWorkstationMemoryWrite,
		EffectMode:   contracts.WorkstationEffectModeOperate,
		MemoryEffect: &contracts.AgentMemoryEffect{MemoryClass: "episodic"},
	}
	_, code, _ := EvaluateEvent(profile, event)
	if code != "MEMORY_TTL_EXCEEDS_POLICY" {
		t.Fatalf("EvaluateEvent() reason = %q, want MEMORY_TTL_EXCEEDS_POLICY", code)
	}
	if got := DenialCounterfactualFor(profile, event, code); got != nil {
		t.Fatalf("disclosed %+v for an undeclared TTL: %d is the policy default, not a request", got, profile.Memory.DefaultTTLDays)
	}
}

// The disclosure rule as a property of the catalog, not of the handful of
// cases someone happened to write down. A future entry pairing class_forbidden
// with a disclosing class would otherwise ship silently.
func TestForbiddenClassNeverDiscloses(t *testing.T) {
	for code, class := range denialCatalog {
		if class.finality == contracts.DenialClassForbidden && class.disclosure != discloseNothing {
			t.Errorf("%s is class_forbidden with a disclosing class: a forbidden-class refusal must not describe the set it failed against", code)
		}
	}
}

// Unknown codes fail closed: no finality, no counterfactual, no guessing.
func TestUnknownCodeDisclosesNothing(t *testing.T) {
	profile := learningProfile()
	if got := DenialFinality("SOME_FUTURE_CODE"); got != "" {
		t.Fatalf("DenialFinality(unknown) = %q, want empty", got)
	}
	if got := DenialCounterfactualFor(profile, ToolEvent{}, "SOME_FUTURE_CODE"); got != nil {
		t.Fatalf("DenialCounterfactualFor(unknown) = %+v, want nil", got)
	}
}

func learningProfile() contracts.WorkstationPolicyProfile {
	return contracts.WorkstationPolicyProfile{
		ID:   "test.learning",
		Mode: "operate",
		Draft: contracts.WorkstationDraftPolicy{
			WorkspaceRoots: []string{"/workspace"},
		},
		Operate: contracts.WorkstationOperatePolicy{
			Permissions: []string{
				contracts.WorkstationPermissionMemoryWrite,
				contracts.WorkstationPermissionNetworkEgress,
			},
		},
		Egress: contracts.WorkstationEgressPolicy{
			Allowlist: []contracts.WorkstationEgressDestination{{Host: "api.example.com", Protocol: "https"}},
		},
		Memory: contracts.WorkstationMemoryPolicy{
			DefaultTTLDays: 7,
			MaxTTLDays:     30,
			AllowedClasses: []string{"episodic", "semantic"},
		},
		Learning: &contracts.WorkstationLearningPolicy{
			EmitFinality:       true,
			EmitCounterfactual: true,
		},
	}
}
