package pdp

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
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
			ManagedPolicyRule{ID: "p1-wire-label", Layer: ManagedPolicyLayerP1, Pattern: `"effect_class":"wire\.`, Verdict: contracts.VerdictEscalate, Reason: "wire labels need approval"},
			ManagedPolicyRule{ID: "p2-e0-approval", Layer: ManagedPolicyLayerP2, EffectClass: "E0", Action: "SEND_EMAIL", Verdict: contracts.VerdictEscalate, Reason: "workspace overlay wants approval for mail declared E0"},
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
		// An escalate rule restricts, so it reads the declaration as a deny
		// rule does. Were it matched against the bound class only, the allow
		// rule for E2 would decide both of these.
		{name: "pattern escalate on the declared label still applies", req: &DecisionRequest{Action: "SEND_EMAIL", Context: bound("E2", "wire.transfer")}, reason: string(contracts.ReasonApprovalRequired)},
		{name: "class escalate on the declared class still applies", req: &DecisionRequest{Action: "SEND_EMAIL", Context: bound("E2", "E0")}, reason: string(contracts.ReasonApprovalRequired)},
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
// member must keep matching, whoever bound the class. An allow pattern keeps
// matching the bound class too, and never the declaration.
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
		{"an allow pattern written before the members matches the bound class", map[string]any{"effect_class": "ticket.read", "effect_class_source": "caller_declared", "principal_id": "principal-1"}, true, ""},
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

// The readings without the provenance members and as declared are cut from
// the canonical text already built for the request; neither is canonicalized
// again. Here a deny pattern that matches nothing needs both, and the request
// with the members may cost at most a quarter more allocations than the same
// request without them. A second canonicalization of the request costs about
// as much as the first.
func TestManagedPolicyPDPOtherReadingsAreNotCanonicalizedAgain(t *testing.T) {
	bundle := managedTestBundle(t, func(b *ManagedPolicyBundle) {
		b.KernelRuntime.Rules = append(b.KernelRuntime.Rules,
			ManagedPolicyRule{ID: "p1-e2", Layer: ManagedPolicyLayerP1, EffectClass: "E2", Verdict: contracts.VerdictAllow, Reason: "bounded effects are allowed"},
		)
	})
	p, err := NewManagedPolicyPDP(bundle, []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	allocations := func(extra map[string]any) float64 {
		requestContext := map[string]any{
			"credential_hash": "sha256:abc", "effect_class": "E2", "principal_id": "principal-1", "security_context_trusted": true,
			"session_id": "s-1", "source_channel": "api_request", "tenant_id": "tenant-1", "trust_level": "external_untrusted",
			"args": map[string]any{"to": "someone@example.com", "subject": "hello", "lines": []any{"one", "two", 3}},
		}
		for key, value := range extra {
			requestContext[key] = value
		}
		req := &DecisionRequest{Action: "SEND_EMAIL", Resource: "E2", Context: requestContext}
		return testing.AllocsPerRun(50, func() {
			resp, err := p.Evaluate(context.Background(), req)
			if err != nil || !resp.Allow {
				t.Fatalf("Evaluate = %+v, %v; want ALLOW", resp, err)
			}
		})
	}
	without := allocations(nil)
	with := allocations(map[string]any{"effect_class_source": "effect_catalog", "effect_class_declared": "E1"})
	if with > without*5/4 {
		t.Fatalf("a request with the provenance members costs %.0f allocations, without them %.0f: a reading was canonicalized again", with, without)
	}
}

// The readings without the provenance members and as declared are cut from
// the canonical text of the request as bound. Each cut must be byte for byte
// the text canonicalizing that reading writes, or a pattern would match a
// reading that does not exist. Where a cut cannot be exact, the reading is
// canonicalized instead.
func TestManagedPolicyReadingsAreCutAsCanonicalizationWritesThem(t *testing.T) {
	type tricky struct {
		A string `json:"a"`
		B int    `json:"-"`
	}
	bound := func(extra map[string]any) map[string]any {
		requestContext := map[string]any{
			"credential_hash": "sha256:abc", "effect_class": "E2", "effect_class_source": "effect_catalog", "effect_class_declared": "E0",
			"principal_id": "principal-1", "session_id": "s-1", "tenant_id": "tenant-1",
		}
		for key, value := range extra {
			requestContext[key] = value
		}
		return requestContext
	}
	for _, tc := range []struct {
		name             string
		action, resource string
		context          map[string]any
		// cut and cutDeclared: whether each reading can be cut; where it
		// cannot, it must be canonicalized.
		cut, cutDeclared bool
	}{
		{"as the evaluate route binds it", "SEND_EMAIL", "E0", bound(nil), true, true},
		{"the same members nested in args", "SEND_EMAIL", "E0", bound(map[string]any{"args": map[string]any{
			"effect_class": "E9", "effect_class_source": "effect_catalog", "effect_class_declared": "E0", "context": map[string]any{"effect_class": "E4"},
		}}), true, true},
		{"keys that sort among the provenance members", "SEND_EMAIL", "E0", bound(map[string]any{
			"effect_class0": "x", "effect_class_a": 1, "effect_class_declared_x": true, "effect_class_source2": nil, "effect_class_t": []any{},
			"Effect_Class": "E0", "effect_clas": "y", "": "empty key",
		}), true, true},
		{"strings that need escaping", `act"ion\`, "res\u0000\"ource", bound(map[string]any{
			"q": `a"b\c`, "nul": "\x00", "sep": "\u2028\u2029", "emoji": "\U0001F600", "bad": "\xff\xfe", "html": "<a>&</a>",
			`k"ey`: "v", `k\ey`: "v", "é": "accent", "\U0001F600": "emoji key", "\u00e9x": "decomposed",
		}), true, true},
		{"an action that looks like a context", `x","context":{"effect_class_source":"y`, `"},"resource":"`, bound(nil), true, true},
		{"numbers, literals and nesting", "SEND_EMAIL", "", bound(map[string]any{
			"n": 1, "f": 1.5, "big": 1e21, "neg": -0.0, "u": uint64(18446744073709551615), "t": true, "z": nil,
			"deep":   []any{map[string]any{"a": []any{[]any{}, map[string]any{}}}, "]", "}", `\`},
			"struct": tricky{A: "a", B: 2},
		}), true, true},
		{"a declared label", "SEND_EMAIL", "ticket.read", bound(map[string]any{"effect_class_declared": `ticket.read"x`}), true, true},
		{"a class that is not a string", "SEND_EMAIL", "E0", bound(map[string]any{"effect_class": 3}), true, true},
		{"only a source", "local.echo", "E1", map[string]any{"effect_class": "E1", "effect_class_source": "caller_declared"}, true, false},
		{"nothing left without the provenance members", "local.echo", "E1", map[string]any{"effect_class_source": "caller_declared", "effect_class_declared": "E0"}, false, false},
		{"a declaration with no class to replace", "local.echo", "E1", map[string]any{"effect_class_declared": "E0", "x": 1}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireCutReadings(t, &DecisionRequest{Action: tc.action, Resource: tc.resource, Context: tc.context}, tc.cut, tc.cutDeclared)
		})
	}
	// Generated contexts: keys drawn from the provenance names, names that sort
	// beside them and names that need escaping, values nested up to three deep.
	rng := rand.New(rand.NewSource(304))
	keys := []string{"effect_class", "effect_class_source", "effect_class_declared", "effect_class0", "effect_class_a", "effect_class_z",
		"args", "context", "resource", "a", "z", `"`, `\`, "é", "\u2028", "Effect_Class"}
	var value func(depth int) any
	value = func(depth int) any {
		switch n := rng.Intn(8); {
		case n == 0 || depth >= 3:
			return keys[rng.Intn(len(keys))] + `",}]{[\`[:rng.Intn(7)]
		case n == 1:
			return rng.Intn(1000) - 500
		case n == 2:
			return rng.Intn(2) == 0
		case n == 3:
			return nil
		case n == 4:
			list := make([]any, rng.Intn(4))
			for i := range list {
				list[i] = value(depth + 1)
			}
			return list
		default:
			object := make(map[string]any)
			for i := rng.Intn(5); i > 0; i-- {
				object[keys[rng.Intn(len(keys))]] = value(depth + 1)
			}
			return object
		}
	}
	cuts, readings := 0, 0
	for i := 0; i < 2000; i++ {
		requestContext := make(map[string]any)
		for j := rng.Intn(8); j > 0; j-- {
			requestContext[keys[rng.Intn(len(keys))]] = value(1)
		}
		// A transport binds effect_class whenever it binds where it came from.
		if rng.Intn(8) > 0 {
			requestContext["effect_class"] = value(2)
		}
		if rng.Intn(4) > 0 {
			requestContext["effect_class_source"] = "effect_catalog"
		}
		if rng.Intn(2) == 0 {
			requestContext["effect_class_declared"] = keys[rng.Intn(len(keys))]
		}
		req := &DecisionRequest{Action: keys[rng.Intn(len(keys))], Resource: keys[rng.Intn(len(keys))], Context: requestContext}
		made, checked := requireCutReadings(t, req, false, false)
		cuts, readings = cuts+made, readings+checked
	}
	// Most generated readings can be cut; were none, the comparison above
	// would hold nothing.
	if cuts*10 < readings*8 {
		t.Fatalf("only %d of %d generated readings were cut", cuts, readings)
	}
}

// Where a reading cannot be cut from the request's text, it is canonicalized,
// and rules are matched against it all the same. Neither request below comes
// from a transport, which always binds effect_class with its provenance.
func TestManagedPolicyPDPMatchesReadingsThatCannotBeCut(t *testing.T) {
	bundle := managedTestBundle(t, func(b *ManagedPolicyBundle) {
		b.KernelRuntime.Rules = append(b.KernelRuntime.Rules,
			ManagedPolicyRule{ID: "p1-echo", Layer: ManagedPolicyLayerP1, Action: "local.echo", Verdict: contracts.VerdictAllow, Reason: "echo is allowed"},
			ManagedPolicyRule{ID: "p0-bare-echo", Layer: ManagedPolicyLayerP0, Pattern: `^\{"action":"local\.echo","resource":"E1"\}$`, Verdict: contracts.VerdictDeny, Reason: "echo needs a context"},
			ManagedPolicyRule{ID: "p0-payment-label", Layer: ManagedPolicyLayerP0, Pattern: `"effect_class":"payment\.`, Verdict: contracts.VerdictDeny, Reason: "payment labels are denied"},
		)
	})
	p, err := NewManagedPolicyPDP(bundle, []string{managedTestSourceHash})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		context map[string]any
	}{
		// Without the provenance members nothing is left, so that reading has
		// no context at all.
		{"no member left without the provenance members", map[string]any{"effect_class_source": "caller_declared", "effect_class_declared": "E0"}},
		// As declared, effect_class is added.
		{"a declaration with no effect_class", map[string]any{"effect_class_declared": "payment.write", "x": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := p.Evaluate(context.Background(), &DecisionRequest{Action: "local.echo", Resource: "E1", Context: tc.context})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Allow || resp.ReasonCode != string(contracts.ReasonPDPDeny) {
				t.Fatalf("response = %+v, want the deny pattern to match the canonicalized reading", resp)
			}
		})
	}
}

// The scan accepts only the shape managedPolicyCandidate writes; for any other
// text the readings are canonicalized instead of cut.
func TestScanCanonicalContextAcceptsOnlyTheCandidateShape(t *testing.T) {
	if _, _, _, ok := scanCanonicalContext(nil, []byte(`{"action":"a","context":{"x":1,"y":"}"},"resource":"r"}`)); !ok {
		t.Fatal("the scan refused a candidate")
	}
	for _, text := range []string{
		``,
		`{"action":"a","resource":"r"}`,
		`{"action":"a","context":{},"resource":"r"}`,
		`{"action":"a","context":{"x":1}}`,
		`{"action":"a","context":{"x":1},"resource":"r"}x`,
		`{"action":"a","context":{"x":1},"resource":"r"`,
		`{"action":"a","context":{"x":1},"resource":r}`,
		`{"action":"a","context":{"x":1,"resource":"r"}`,
		`{"action":"a","context":{"x":"1},"resource":"r"}`,
		`{"action":"a","context":{"x"1},"resource":"r"}`,
		`{"action":"a","context":{"x":{"y":1},"resource":"r"}`,
		`{"action":a,"context":{"x":1},"resource":"r"}`,
		`{"context":{"x":1},"resource":"r"}`,
	} {
		if _, _, _, ok := scanCanonicalContext(nil, []byte(text)); ok {
			t.Errorf("the scan accepted %q", text)
		}
	}
}

// requireCutReadings checks that each reading of req that cutReading can cut
// equals its canonicalization, and that the cuts named by wantCut and
// wantCutDeclared were made. It returns how many readings were cut and how
// many the request has besides the one as bound.
func requireCutReadings(t *testing.T, req *DecisionRequest, wantCut, wantCutDeclared bool) (cuts, checked int) {
	t.Helper()
	var readings managedPolicyReadings
	if err := readings.bind(req); err != nil {
		t.Fatal(err)
	}
	if !readings.provenance {
		return 0, 0
	}
	for _, reading := range []struct {
		name       string
		asDeclared bool
		class      string
		wantCut    bool
	}{
		{"without the provenance members", false, "", wantCut},
		{"as declared", true, readings.declaredClass, wantCutDeclared},
	} {
		if reading.asDeclared && readings.declaredClass == "" {
			continue
		}
		want, err := canonicalManagedPolicyReading(req, reading.class)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := readings.cutReading(reading.asDeclared)
		checked++
		if ok {
			cuts++
		}
		if reading.wantCut && !ok {
			t.Fatalf("%s: the reading was not cut from %s", reading.name, readings.candidate)
		}
		if ok && !bytes.Equal(got, want) {
			t.Fatalf("%s of %s:\ncut:            %s\ncanonicalized:  %s", reading.name, readings.candidate, got, want)
		}
	}
	return cuts, checked
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
