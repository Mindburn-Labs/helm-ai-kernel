package provision

// quantum_posture: computes SHA-256 plan digests to compare with fixtures;
// signs nothing.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

func examples(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "protocols", "json-schemas", "effects", "authority", "examples")
}

func example(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(examples(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func edit(t *testing.T, raw []byte, fn func(map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wantRefusal(t *testing.T, what string, err error, reason contracts.ReasonCode) {
	t.Helper()
	var r *adapters.Refusal
	if !errors.As(err, &r) || r.Reason != reason {
		t.Fatalf("%s: err = %v, want a refusal with reason %s", what, err, reason)
	}
}

// Every fixture of protocols/json-schemas/effects/authority/examples: the valid
// ones pass Check (the syntax and the store's rules), and every invalid one is
// refused, so this code, the JSON Schemas and their examples agree.
func TestCheckAgreesWithTheSchemaFixtures(t *testing.T) {
	entries, err := os.ReadDir(examples(t))
	if err != nil {
		t.Fatal(err)
	}
	valid, invalid := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		effectType := effectargs.AuthorityProvision
		if strings.HasPrefix(name, "narrow.v1.") {
			effectType = effectargs.AuthorityNarrow
		}
		_, err := Check(effectType, example(t, name))
		if strings.Contains(name, ".valid") {
			valid++
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		invalid++
		var r *adapters.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s: accepted an invalid fixture (err = %v)", name, err)
		}
	}
	if valid < 4 || invalid < 20 {
		t.Fatalf("checked %d valid and %d invalid fixtures", valid, invalid)
	}
}

// Compile refuses what the store would refuse whatever the database holds: a
// child wider than its parent, a limit above the same limit higher up, and a
// condition that does not compile. Each has a passing twin.
func TestCompileRefusesWhatTheStoreWould(t *testing.T) {
	raw := example(t, "provision.v1.valid.json")
	seat := func(doc map[string]any) map[string]any {
		for _, m := range doc["mandates"].([]any) {
			if m := m.(map[string]any); strings.HasPrefix(m["node"].(string), "seat:") {
				return m
			}
		}
		t.Fatal("no seat node")
		return nil
	}
	limit := func(doc map[string]any, node string) map[string]any {
		for _, l := range doc["limits"].([]any) {
			if l := l.(map[string]any); l["node"] == node {
				return l
			}
		}
		t.Fatal("no limit on " + node)
		return nil
	}
	if _, err := Check(effectargs.AuthorityProvision, raw); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		edit   func(map[string]any)
		reason contracts.ReasonCode
	}{
		"a child with any target under a parent with a list": {
			func(d map[string]any) { seat(d)["terms"].(map[string]any)["targets"] = nil }, contracts.ReasonDelegationScopeViolation},
		"a child with a higher per-call limit than its parent": {
			func(d map[string]any) {
				for _, m := range d["mandates"].([]any) {
					m := m.(map[string]any)
					switch {
					case strings.HasPrefix(m["node"].(string), "team:"):
						m["terms"].(map[string]any)["per_call_limit"] = json.Number("10")
					case strings.HasPrefix(m["node"].(string), "seat:"):
						m["terms"].(map[string]any)["per_call_limit"] = json.Number("11")
					}
				}
			}, contracts.ReasonDelegationScopeViolation},
		"a child limit above the same limit of its parent": {
			func(d map[string]any) {
				team := ""
				for _, m := range d["mandates"].([]any) {
					if n := m.(map[string]any)["node"].(string); strings.HasPrefix(n, "team:") {
						team = n
					}
				}
				d["limits"] = append(d["limits"].([]any), map[string]any{"node": seat(d)["node"], "unit": "count", "measure": "count",
					"window": "day", "value": json.Number("51"), "span": json.Number("1")})
				_ = limit(d, team)
			}, contracts.ReasonDelegationScopeViolation},
		"a condition that does not compile": {
			func(d map[string]any) { seat(d)["terms"].(map[string]any)["condition"] = "input.args.head.(" }, contracts.ReasonSchemaViolation},
	}
	for name, c := range cases {
		_, err := Check(effectargs.AuthorityProvision, edit(t, raw, c.edit))
		wantRefusal(t, name, err, c.reason)
	}
	// The same limit at the parent's value passes: the ceiling is inclusive.
	at := edit(t, raw, func(d map[string]any) {
		d["limits"] = append(d["limits"].([]any), map[string]any{"node": seat(d)["node"], "unit": "count", "measure": "count",
			"window": "day", "value": json.Number("50"), "span": json.Number("1")})
	})
	if _, err := Check(effectargs.AuthorityProvision, at); err != nil {
		t.Errorf("a limit equal to its ancestor's: %v", err)
	}
	// The digest of the checked plan is the one ParsePlan computes.
	c, err := Check(effectargs.AuthorityProvision, raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Plan.Digest != "70d6c47ca51186780504038bdadb939319455ee16c14f59d4829fd1a8bdee5af" {
		t.Errorf("digest = %s", c.Plan.Digest)
	}
	if got := c.Nodes[len(c.Nodes)-1].Depth; got != 3 {
		t.Errorf("the seat's depth = %d, want 3", got)
	}
}

// Precheck reads the applied plan: the base, the provisioner and the
// disable rules. Every refusal has a passing twin, and a plan whose digest is
// the applied one passes whatever its base.
func TestPrecheck(t *testing.T) {
	raw := example(t, "provision.v1.valid.json")
	c, err := Check(effectargs.AuthorityProvision, raw)
	if err != nil {
		t.Fatal(err)
	}
	applied := &Applied{
		OrgRef: c.Plan.OrgRef, Digest: "1111111111111111111111111111111111111111111111111111111111111111", Provisioner: "svc:helm-org",
		Principals: []AppliedPrincipal{{ID: "agt:gone", Kind: "agent"}, {ID: "usr_gone", Kind: "human"}},
	}
	for _, n := range c.Nodes {
		applied.Nodes = append(applied.Nodes, AppliedNode{Node: n.Name})
	}
	for _, p := range c.Plan.Principals {
		applied.Principals = append(applied.Principals, AppliedPrincipal{ID: p.ID, Kind: p.Kind})
	}

	// provision: the first plan has an empty base, a later one the applied digest.
	if r := Precheck(c, nil, "svc:helm-org"); r != nil {
		t.Fatalf("the first plan: %v", r)
	}
	if r := Precheck(c, applied, "svc:helm-org"); r == nil || r.Reason != contracts.ReasonPreconditionFailed {
		t.Fatalf("an empty base over an applied plan: %v", r)
	}
	rebased := func(base string) *Compiled {
		p := *c.Plan
		p.BaseDigest = base
		return &Compiled{Plan: &p, Nodes: c.Nodes}
	}
	if r := Precheck(rebased(applied.Digest), applied, "svc:helm-org"); r != nil {
		t.Fatalf("the applied digest as base: %v", r)
	}
	if r := Precheck(rebased("2222222222222222222222222222222222222222222222222222222222222222"), applied, "svc:helm-org"); r == nil {
		t.Fatal("another base passed")
	}
	if r := Precheck(rebased("2222222222222222222222222222222222222222222222222222222222222222"), nil, "svc:helm-org"); r == nil {
		t.Fatal("a base over no applied plan passed")
	}
	same := *applied
	same.Digest = c.Plan.Digest
	if r := Precheck(rebased("2222222222222222222222222222222222222222222222222222222222222222"), &same, "svc:helm-org"); r != nil {
		t.Fatalf("a plan already applied changes nothing, whatever its base: %v", r)
	}
	// a provision plan may come from another service principal.
	if r := Precheck(rebased(applied.Digest), applied, "svc:other"); r != nil {
		t.Fatalf("a provision plan from another requester: %v", r)
	}

	// disable rules.
	disabling := func(ids ...string) *Compiled {
		p := *rebased(applied.Digest).Plan
		p.Disable = ids
		return &Compiled{Plan: &p, Nodes: c.Nodes}
	}
	if r := Precheck(disabling("agt:gone"), applied, "svc:helm-org"); r != nil {
		t.Fatalf("disabling a principal the applied plan lists: %v", r)
	}
	for name, ids := range map[string][]string{
		"a stranger":          {"agt:stranger"},
		"the requester":       {"svc:helm-org"},
		"one of the two":      {"agt:gone", "agt:stranger"},
		"a principal no plan": {"org:elsewhere"},
	} {
		if r := Precheck(disabling(ids...), applied, "svc:helm-org"); r == nil || r.Reason != contracts.ReasonPreconditionFailed {
			t.Errorf("disabling %s: %v", name, r)
		}
	}
	if r := Precheck(disabling("usr_gone"), applied, "svc:helm-org"); r != nil {
		t.Fatalf("a provision plan may disable a human the applied plan lists: %v", r)
	}
}

// A narrowing plan needs no approval, so it is held to more: the provisioner
// only, an applied plan to narrow, nodes and principals the applied plan has,
// and no human disabled.
func TestPrecheckNarrow(t *testing.T) {
	raw := example(t, "narrow.v1.valid.json")
	c, err := Check(effectargs.AuthorityNarrow, raw)
	if err != nil {
		t.Fatal(err)
	}
	applied := &Applied{OrgRef: c.Plan.OrgRef, Digest: c.Plan.BaseDigest, Provisioner: "svc:helm-org"}
	if applied.Digest == "" {
		applied.Digest = strings.Repeat("3", 64)
	}
	for _, n := range c.Nodes {
		applied.Nodes = append(applied.Nodes, AppliedNode{Node: n.Name})
	}
	for _, p := range c.Plan.Principals {
		applied.Principals = append(applied.Principals, AppliedPrincipal{ID: p.ID, Kind: p.Kind})
	}
	withBase := func(mutate func(*effectargs.Plan)) *Compiled {
		p := *c.Plan
		p.BaseDigest = applied.Digest
		p.Digest = strings.Repeat("4", 64)
		mutate(&p)
		return &Compiled{Plan: &p, Nodes: c.Nodes}
	}
	ok := withBase(func(*effectargs.Plan) {})
	if r := Precheck(ok, applied, "svc:helm-org"); r != nil {
		t.Fatalf("the provisioner's narrowing plan: %v", r)
	}
	if r := Precheck(ok, applied, "svc:other"); r == nil || r.Reason != contracts.ReasonInsufficientPrivilege {
		t.Fatalf("another service principal's narrowing plan: %v", r)
	}
	if r := Precheck(ok, applied, "agt:1"); r == nil || r.Reason != contracts.ReasonInsufficientPrivilege {
		t.Fatalf("an agent's narrowing plan: %v", r)
	}
	if r := Precheck(ok, nil, "svc:helm-org"); r == nil || r.Reason != contracts.ReasonPreconditionFailed {
		t.Fatalf("a narrowing plan with nothing applied: %v", r)
	}
	// Even a plan already applied is not accepted from a stranger.
	done := *applied
	done.Digest = ok.Plan.Digest
	if r := Precheck(ok, &done, "svc:other"); r == nil || r.Reason != contracts.ReasonInsufficientPrivilege {
		t.Fatalf("a stranger's narrowing plan that is already applied: %v", r)
	}
	newNode := withBase(func(p *effectargs.Plan) {
		p.Mandates = append(append([]effectargs.PlanMandate(nil), p.Mandates...), effectargs.PlanMandate{Node: "seat:new", Holder: "agt:new", Parent: p.OrgRef})
	})
	if r := Precheck(newNode, applied, "svc:helm-org"); r == nil {
		t.Error("a narrowing plan that adds a node passed")
	}
	newPrincipal := withBase(func(p *effectargs.Plan) {
		p.Principals = append(append([]effectargs.PlanPrincipal(nil), p.Principals...), effectargs.PlanPrincipal{ID: "agt:new", Kind: "agent"})
	})
	if r := Precheck(newPrincipal, applied, "svc:helm-org"); r == nil {
		t.Error("a narrowing plan that registers a principal passed")
	}
	applied.Principals = append(applied.Principals, AppliedPrincipal{ID: "usr_x", Kind: "human"}, AppliedPrincipal{ID: "agt:x", Kind: "agent"})
	human := withBase(func(p *effectargs.Plan) { p.Disable = []string{"usr_x"} })
	if r := Precheck(human, applied, "svc:helm-org"); r == nil {
		t.Error("a narrowing plan that disables a human passed")
	}
	agent := withBase(func(p *effectargs.Plan) { p.Disable = []string{"agt:x"} })
	if r := Precheck(agent, applied, "svc:helm-org"); r != nil {
		t.Errorf("a narrowing plan that disables an agent the applied plan lists: %v", r)
	}
}

func TestDeclarationsAreTheTwoPlanEffects(t *testing.T) {
	a := &Adapter{}
	got := map[string]adapters.RiskClass{}
	for _, d := range a.Declarations() {
		got[d.EffectType] = d.RiskClass
		if d.Mediation != adapters.MediationEnforced || d.Observable != adapters.ObservableYes {
			t.Errorf("%s: declaration %+v", d.EffectType, d)
		}
	}
	if got[effectargs.AuthorityProvision] != adapters.RiskIrreversible || got[effectargs.AuthorityNarrow] != adapters.RiskMedium || len(got) != 2 {
		t.Fatalf("declarations = %v", got)
	}
	// Both are listed in the catalog with their published schema and target
	// form, and neither is one a mandate may grant.
	for _, d := range a.Declarations() {
		published, ok := effectargs.ArgumentSchema(d.EffectType)
		if !ok || !bytes.Equal(d.ArgumentSchema, published) || d.TargetForm != "org:{org_id}" || d.Grantable || d.Description == "" {
			t.Errorf("%s: catalog fields target=%q schema=%d bytes grantable=%v description=%q",
				d.EffectType, d.TargetForm, len(d.ArgumentSchema), d.Grantable, d.Description)
		}
	}
	if r, ok := DeclaredRisk(effectargs.AuthorityNarrow); !ok || r != adapters.RiskMedium {
		t.Errorf("DeclaredRisk(narrow) = %v %v", r, ok)
	}
	if _, ok := DeclaredRisk("github.repository.get"); ok {
		t.Error("DeclaredRisk answers for an effect this adapter does not perform")
	}
}
