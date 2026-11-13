package pdp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// BenchmarkManagedPolicyPDPEvaluate measures one decision over a bundle with
// class rules and one deny pattern, for a request as the evaluate route binds
// it: with no provenance members, with effect_class_source, and with
// effect_class_source and a kept effect_class_declared.
func BenchmarkManagedPolicyPDPEvaluate(b *testing.B) {
	const sourceHash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	data, err := json.Marshal(ManagedPolicyBundle{
		P0Ceilings: json.RawMessage(`{"v":1}`), P1Bundle: json.RawMessage(`{"v":1}`), P2Overlay: json.RawMessage(`{"v":1}`), ApprovalRoutes: json.RawMessage(`{"v":1}`),
		SourceLanguage: "cel-dp", SourceHash: sourceHash, CompiledArtifactKind: ManagedPolicyArtifactKind,
		KernelRuntime: ManagedPolicyRuntime{SchemaVersion: ManagedPolicySchemaV1, DefaultVerdict: contracts.VerdictDeny, Rules: []ManagedPolicyRule{
			{ID: "p0-e4", Layer: ManagedPolicyLayerP0, EffectClass: "E4", Verdict: contracts.VerdictDeny, Reason: "E4 is denied"},
			{ID: "p1-e3", Layer: ManagedPolicyLayerP1, EffectClass: "E3", Verdict: contracts.VerdictEscalate, Reason: "E3 escalates"},
			{ID: "p0-payment-label", Layer: ManagedPolicyLayerP0, Pattern: `"effect_class":"payment\.`, Verdict: contracts.VerdictDeny, Reason: "payment labels are denied"},
			{ID: "p1-e1", Layer: ManagedPolicyLayerP1, EffectClass: "E1", Verdict: contracts.VerdictAllow, Reason: "E1 is allowed"},
			{ID: "p1-e2", Layer: ManagedPolicyLayerP1, EffectClass: "E2", Verdict: contracts.VerdictAllow, Reason: "E2 is allowed"},
		}},
	})
	if err != nil {
		b.Fatal(err)
	}
	p, err := NewManagedPolicyPDP(data, []string{sourceHash})
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{"no_provenance", nil},
		{"source", map[string]any{"effect_class_source": "effect_catalog"}},
		{"source_and_declaration", map[string]any{"effect_class_source": "effect_catalog", "effect_class_declared": "E1"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			requestContext := map[string]any{
				"credential_hash": "sha256:abc", "effect_class": "E2", "principal_id": "principal-1", "security_context_trusted": true,
				"session_id": "s-1", "source_channel": "api_request", "tenant_id": "tenant-1", "trust_level": "external_untrusted",
				"args": map[string]any{"to": "someone@example.com", "subject": "hello"},
			}
			for key, value := range tc.extra {
				requestContext[key] = value
			}
			req := &DecisionRequest{Principal: "principal-1", Action: "SEND_EMAIL", Resource: "E2", Context: requestContext}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				resp, err := p.Evaluate(context.Background(), req)
				if err != nil || !resp.Allow {
					b.Fatalf("Evaluate = %+v, %v; want ALLOW", resp, err)
				}
			}
		})
	}
}
