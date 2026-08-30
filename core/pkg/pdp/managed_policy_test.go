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
