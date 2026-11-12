package pdp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const managedTestSourceHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func managedTestBundle(t *testing.T, mutate func(*ManagedPolicyBundle)) []byte {
	t.Helper()
	bundle := ManagedPolicyBundle{
		P0Ceilings:           json.RawMessage(`{"version":"1.0.0"}`),
		P1Bundle:             json.RawMessage(`{"version":"1.0.0"}`),
		P2Overlay:            json.RawMessage(`{"version":"1.0.0"}`),
		ApprovalRoutes:       json.RawMessage(`{"E3_default":{"level":"SINGLE_HUMAN"}}`),
		SourceLanguage:       "cel-dp",
		SourceHash:           managedTestSourceHash,
		CompiledArtifactKind: ManagedPolicyArtifactKind,
		KernelRuntime: ManagedPolicyRuntime{
			SchemaVersion:  ManagedPolicySchemaV1,
			DefaultVerdict: contracts.VerdictDeny,
			Rules: []ManagedPolicyRule{
				{ID: "p0-e4", Layer: ManagedPolicyLayerP0, EffectClass: "E4", Verdict: contracts.VerdictDeny, Reason: "irreversible effects are denied"},
				{ID: "p0-shell", Layer: ManagedPolicyLayerP0, Pattern: "rm -rf", Verdict: contracts.VerdictDeny, Reason: "destructive shell is denied"},
				{ID: "p1-e0", Layer: ManagedPolicyLayerP1, EffectClass: "E0", Verdict: contracts.VerdictAllow, Reason: "read-only effects are allowed"},
				{ID: "p1-e3", Layer: ManagedPolicyLayerP1, EffectClass: "E3", Verdict: contracts.VerdictEscalate, Reason: "external effects require approval"},
				{ID: "p1-publish", Layer: ManagedPolicyLayerP1, Action: "publish_public_artifact", Verdict: contracts.VerdictAllow, Reason: "explicit governed effect"},
				{ID: "p2-network", Layer: ManagedPolicyLayerP2, Resource: "network", Verdict: contracts.VerdictDeny, Reason: "workspace overlay denies network"},
			},
		},
	}
	if mutate != nil {
		mutate(&bundle)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManagedPolicyPDPFailClosedPrecedence(t *testing.T) {
	p, err := NewManagedPolicyPDP(managedTestBundle(t, nil), []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		req    *DecisionRequest
		allow  bool
		reason string
	}{
		{name: "e0 allow", req: &DecisionRequest{Action: "READ", Context: map[string]any{"effect_class": "E0"}}, allow: true},
		{name: "e3 escalate", req: &DecisionRequest{Action: "WRITE", Context: map[string]any{"effect_class": "E3"}}, reason: string(contracts.ReasonApprovalRequired)},
		{name: "e4 deny", req: &DecisionRequest{Action: "DESTROY", Context: map[string]any{"effect_class": "E4"}}, reason: string(contracts.ReasonPDPDeny)},
		{name: "explicit effect allow", req: &DecisionRequest{Action: "publish_public_artifact"}, allow: true},
		{name: "p2 narrows p1", req: &DecisionRequest{Action: "READ", Resource: "network", Context: map[string]any{"effect_class": "E0"}}, reason: string(contracts.ReasonPDPDeny)},
		{name: "pattern deny overrides allow", req: &DecisionRequest{Action: "READ", Context: map[string]any{"effect_class": "E0", "command": "rm -rf /tmp/data"}}, reason: string(contracts.ReasonPDPDeny)},
		{name: "missing classification denies", req: &DecisionRequest{Action: "READ"}, reason: string(contracts.ReasonPDPDeny)},
		{name: "nil request denies", req: nil, reason: string(contracts.ReasonSchemaViolation)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Evaluate(context.Background(), tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Allow != tt.allow || resp.ReasonCode != tt.reason || resp.DecisionHash == "" {
				t.Fatalf("response = %+v, want allow=%v reason=%q", resp, tt.allow, tt.reason)
			}
		})
	}
}

// When the transport bound the kernel catalog's class over a lower or
// non-class declaration, the declaration stays visible to rules that restrict
// and invisible to rules that allow: it can add a restriction, never lift one.
func TestManagedPolicyPDPDeclarationRestrictsButNeverAllows(t *testing.T) {
	bundle := managedTestBundle(t, func(b *ManagedPolicyBundle) {
		b.KernelRuntime.Rules = append(b.KernelRuntime.Rules,
			ManagedPolicyRule{ID: "p0-payment-label", Layer: ManagedPolicyLayerP0, Pattern: `"effect_class":"payment\.`, Verdict: contracts.VerdictDeny, Reason: "payment labels are denied"},
			ManagedPolicyRule{ID: "p1-e2", Layer: ManagedPolicyLayerP1, EffectClass: "E2", Verdict: contracts.VerdictAllow, Reason: "bounded effects are allowed"},
			ManagedPolicyRule{ID: "p2-e1", Layer: ManagedPolicyLayerP2, EffectClass: "E1", Verdict: contracts.VerdictDeny, Reason: "workspace overlay denies E1"},
		)
	})
	p, err := NewManagedPolicyPDP(bundle, []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	bound := func(class, declared string) map[string]any {
		return map[string]any{"effect_class": class, "effect_class_source": "effect_catalog", "effect_class_declared": declared}
	}
	tests := []struct {
		name   string
		req    *DecisionRequest
		allow  bool
		reason string
	}{
		{name: "allow rule for the declared class does not match the bound class", req: &DecisionRequest{Action: "INFRA_DESTROY", Context: bound("E4", "E0")}, reason: string(contracts.ReasonPDPDeny)},
		{name: "bound E3 escalates although E0 was declared", req: &DecisionRequest{Action: "SPEND_AUTHORIZE", Context: bound("E3", "E0")}, reason: string(contracts.ReasonApprovalRequired)},
		{name: "pattern deny on the declared label still applies", req: &DecisionRequest{Action: "SEND_EMAIL", Context: bound("E2", "payment.write")}, reason: string(contracts.ReasonPDPDeny)},
		{name: "class deny on the declared class still applies", req: &DecisionRequest{Action: "SEND_EMAIL", Context: bound("E2", "E1")}, reason: string(contracts.ReasonPDPDeny)},
		{name: "bound class allowed when nothing restricts the declaration", req: &DecisionRequest{Action: "SEND_EMAIL", Context: bound("E2", "ticket.write")}, allow: true},
		{name: "a label bound as it is matches the pattern as before", req: &DecisionRequest{Action: "urn:tool:pay", Context: map[string]any{"effect_class": "payment.write", "effect_class_source": "caller_declared"}}, reason: string(contracts.ReasonPDPDeny)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := p.Evaluate(context.Background(), tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Allow != tt.allow || resp.ReasonCode != tt.reason {
				t.Fatalf("response = %+v, want allow=%v reason=%q", resp, tt.allow, tt.reason)
			}
		})
	}
}

// An allow rule is matched against the bound class only. Here the bound class
// has no allow rule and the declared class has one: were the declared view
// offered to allow rules, a caller would lift the catalog's class by declaring
// a lower one.
func TestManagedPolicyPDPAllowRuleSeesOnlyTheBoundClass(t *testing.T) {
	bundle := managedTestBundle(t, func(b *ManagedPolicyBundle) {
		b.KernelRuntime.Rules = append(b.KernelRuntime.Rules,
			ManagedPolicyRule{ID: "p1-read-label", Layer: ManagedPolicyLayerP1, Pattern: `"effect_class":"ticket\.read"`, Verdict: contracts.VerdictAllow, Reason: "ticket reads are allowed"},
		)
	})
	p, err := NewManagedPolicyPDP(bundle, []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		bound, declared string
	}{
		{"class allow rule for the declared E0, bound E2", "E2", "E0"},
		{"class allow rule for the declared E0, bound E1", "E1", "E0"},
		{"pattern allow rule for the declared label, bound E2", "E2", "ticket.read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := p.Evaluate(context.Background(), &DecisionRequest{Action: "SEND_EMAIL", Context: map[string]any{
				"effect_class": tc.bound, "effect_class_source": "effect_catalog", "effect_class_declared": tc.declared,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Allow || resp.ReasonCode != string(contracts.ReasonPDPDeny) {
				t.Fatalf("response = %+v: the allow rule for the declaration decided", resp)
			}
		})
	}
}

// effect_class_source and effect_class_declared sort directly after
// effect_class in the canonical text a pattern is matched against. A deny or
// escalate pattern written when effect_class was followed by the next context
// member must keep matching, whoever bound the class; an allow pattern reads
// the full text only.
func TestManagedPolicyPDPRestrictingPatternMatchesWithoutTheProvenanceMembers(t *testing.T) {
	bundle := managedTestBundle(t, func(b *ManagedPolicyBundle) {
		b.KernelRuntime.Rules = append(b.KernelRuntime.Rules,
			ManagedPolicyRule{ID: "p0-adjacent", Layer: ManagedPolicyLayerP0, Pattern: `"effect_class":"E1","principal_id":"principal-1"`, Verdict: contracts.VerdictDeny, Reason: "this principal may not run E1"},
			ManagedPolicyRule{ID: "p1-adjacent", Layer: ManagedPolicyLayerP1, Pattern: `"effect_class":"E2","principal_id":"principal-1"`, Verdict: contracts.VerdictEscalate, Reason: "this principal needs approval for E2"},
			ManagedPolicyRule{ID: "p1-e1", Layer: ManagedPolicyLayerP1, EffectClass: "E1", Verdict: contracts.VerdictAllow, Reason: "E1 is allowed"},
			ManagedPolicyRule{ID: "p1-e2", Layer: ManagedPolicyLayerP1, EffectClass: "E2", Verdict: contracts.VerdictAllow, Reason: "E2 is allowed"},
			ManagedPolicyRule{ID: "p1-adjacent-allow", Layer: ManagedPolicyLayerP1, Pattern: `"effect_class":"ticket\.read","principal_id":"principal-1"`, Verdict: contracts.VerdictAllow, Reason: "ticket reads are allowed"},
		)
	})
	p, err := NewManagedPolicyPDP(bundle, []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		context map[string]any
		allow   bool
		reason  string
	}{
		{"no provenance bound, as before", map[string]any{"effect_class": "E1", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
		{"caller_declared", map[string]any{"effect_class": "E1", "effect_class_source": "caller_declared", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
		{"tool_catalog (MCP)", map[string]any{"effect_class": "E1", "effect_class_source": "tool_catalog", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
		{"kernel_route (governed proxy)", map[string]any{"effect_class": "E1", "effect_class_source": "kernel_route", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
		{"effect_catalog with a kept declaration", map[string]any{"effect_class": "E1", "effect_class_source": "effect_catalog", "effect_class_declared": "E0", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
		{"the declared class matches the pattern as well", map[string]any{"effect_class": "E2", "effect_class_source": "effect_catalog", "effect_class_declared": "E1", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
		{"escalate pattern", map[string]any{"effect_class": "E2", "effect_class_source": "caller_declared", "principal_id": "principal-1"}, false, string(contracts.ReasonApprovalRequired)},
		{"another principal is not restricted", map[string]any{"effect_class": "E1", "effect_class_source": "caller_declared", "principal_id": "principal-2"}, true, ""},
		{"an allow pattern is not matched without the members", map[string]any{"effect_class": "ticket.read", "effect_class_source": "caller_declared", "principal_id": "principal-1"}, false, string(contracts.ReasonPDPDeny)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := p.Evaluate(context.Background(), &DecisionRequest{Action: "local.echo", Context: tc.context})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Allow != tc.allow || resp.ReasonCode != tc.reason {
				t.Fatalf("response = %+v, want allow=%v reason=%q", resp, tc.allow, tc.reason)
			}
		})
	}
}

func TestNewManagedPolicyPDPRejectsInvalidContracts(t *testing.T) {
	tests := []struct {
		name   string
		data   func(*testing.T) []byte
		refs   []string
		needle string
	}{
		{name: "unsigned source hash", data: func(t *testing.T) []byte { return managedTestBundle(t, nil) }, needle: "signed source_refs"},
		{name: "wrong artifact kind", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.CompiledArtifactKind = "legacy" })
		}, needle: "compiled_artifact_kind"},
		{name: "default allow", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.DefaultVerdict = contracts.VerdictAllow })
		}, needle: "default_verdict"},
		{name: "p0 allow", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[0].Verdict = contracts.VerdictAllow })
		}, needle: "must DENY"},
		{name: "p2 allow", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[5].Verdict = contracts.VerdictAllow })
		}, needle: "cannot widen"},
		{name: "invalid regex", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[1].Pattern = "[" })
		}, needle: "pattern"},
		{name: "duplicate id", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[1].ID = b.KernelRuntime.Rules[0].ID })
		}, needle: "duplicate"},
		{name: "missing e3 escalation", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[3].EffectClass = "E2" })
		}, needle: "escalate E3"},
		{name: "narrowed e4 denial", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[0].Action = "DELETE" })
		}, needle: "deny E4"},
		{name: "narrowed e3 escalation", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			return managedTestBundle(t, func(b *ManagedPolicyBundle) { b.KernelRuntime.Rules[3].Resource = "production" })
		}, needle: "escalate E3"},
		{name: "unknown top-level field", refs: []string{managedTestSourceHash}, data: func(t *testing.T) []byte {
			data := managedTestBundle(t, nil)
			return []byte(strings.TrimSuffix(string(data), "}") + `,"unknown":true}`)
		}, needle: "unknown field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewManagedPolicyPDP(tt.data(t), tt.refs)
			if err == nil || !strings.Contains(err.Error(), tt.needle) {
				t.Fatalf("error = %v, want %q", err, tt.needle)
			}
		})
	}
}

func TestManagedPolicyLayerHashesAreCanonical(t *testing.T) {
	compact := managedTestBundle(t, nil)
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "  "); err != nil {
		t.Fatal(err)
	}
	first, err := NewManagedPolicyPDP(compact, []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewManagedPolicyPDP([]byte(indented.String()), []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	p0a, p1a, p2a := first.LayerHashes()
	p0b, p1b, p2b := second.LayerHashes()
	if p0a != p0b || p1a != p1b || p2a[0] != p2b[0] {
		t.Fatalf("layer hashes changed with JSON whitespace")
	}
}
