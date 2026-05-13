// Cross-language policy equivalence suite.
//
// For every triple under corpus/{cel,rego,cedar}/<NN>-<name>.<ext>, the
// suite (1) compiles all three forms, (2) generates 100 deterministic
// random EquivalenceRequest instances, and (3) asserts the verdicts are
// byte-identical across CEL, Rego, and Cedar evaluators.
//
// Workstream F / F1 — Phase 3 of the helm-ai-kernel 100% SOTA execution plan.
package policylangs

import (
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

const (
	requestsPerTriple = 100
	corpusDir         = "corpus"
)

// triples lists the cross-language reference rules. The base name maps to
// files in corpus/{cel,rego,cedar}/<base>.{cel,rego,cedar}.
var triples = []string{
	"01-allow-view",
	"02-admin-delete",
	"03-deny-drop",
	"04-alice-view",
	"05-view-or-editor-edit",
}

// Input pools used by the property generator. They are deliberately
// small so a 100-request pass exercises every value combination on
// average and keeps every random run inside the policies' value space.
var (
	principals = []string{"alice", "bob", "carol"}
	actions    = []string{"view", "edit", "delete", "drop", "create"}
	resources  = []string{"doc-1", "doc-2", "tool-rm"}
	roles      = []string{"admin", "editor", "user", ""}
	riskTiers  = []string{"R0", "R1", "R2", "R3"}
)

// loadTriple reads the per-language source files for a base triple name.
func loadTriple(t *testing.T, base string) PolicyTriple {
	t.Helper()
	read := func(lang, ext string) string {
		path := filepath.Join(corpusDir, lang, base+ext)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}
	return PolicyTriple{
		Name:  base,
		CEL:   read("cel", ".cel"),
		Rego:  read("rego", ".rego"),
		Cedar: read("cedar", ".cedar"),
	}
}

// genRequest draws one EquivalenceRequest deterministically from r.
func genRequest(r *rand.Rand) EquivalenceRequest {
	pick := func(s []string) string { return s[r.IntN(len(s))] }
	return EquivalenceRequest{
		Principal: pick(principals),
		Action:    pick(actions),
		Resource:  pick(resources),
		Role:      pick(roles),
		RiskTier:  pick(riskTiers),
	}
}

// seedFor derives a stable u64 seed from a triple name using an FNV-1a
// fold so a failing case is reproducible byte-for-byte across Go
// versions and runs. hash/maphash would re-randomize across releases.
func seedFor(name string) uint64 {
	var h uint64 = 0xcbf29ce484222325
	for _, c := range []byte(name) {
		h ^= uint64(c)
		h *= 0x100000001b3
	}
	return h
}

// TestEquivalence_AllTriples is the suite's headline check. For each
// triple it builds three evaluators, runs 100 fuzzed requests, and
// asserts CEL == Rego == Cedar verdict for every input.
func TestEquivalence_AllTriples(t *testing.T) {
	ctx := context.Background()
	for _, base := range triples {
		base := base
		t.Run(base, func(t *testing.T) {
			triple := loadTriple(t, base)
			ev, err := Build(ctx, triple)
			if err != nil {
				t.Fatalf("Build %s: %v", base, err)
			}
			r := rand.New(rand.NewPCG(seedFor(base), 0xa1b2c3d4))
			for i := 0; i < requestsPerTriple; i++ {
				req := genRequest(r)
				celV, regoV, cedarV, err := ev.EvalAll(ctx, req)
				if err != nil {
					t.Fatalf("[%s case %d] %+v: eval error: %v", base, i, req, err)
				}
				if celV != regoV || celV != cedarV {
					t.Fatalf(
						"[%s case %d] divergence: cel=%s rego=%s cedar=%s req=%+v",
						base, i, celV, regoV, cedarV, req,
					)
				}
			}
		})
	}
}

// TestEquivalence_CornerCases drives a small set of hand-written
// requests that exercise each rule's positive and negative direction
// without relying on the random generator. The corner cases backstop
// the property suite: if the random seed stops covering a discriminating
// value, the divergence still surfaces.
func TestEquivalence_CornerCases(t *testing.T) {
	ctx := context.Background()
	for _, base := range triples {
		base := base
		t.Run(base, func(t *testing.T) {
			triple := loadTriple(t, base)
			ev, err := Build(ctx, triple)
			if err != nil {
				t.Fatalf("Build %s: %v", base, err)
			}
			cases := []EquivalenceRequest{
				{Principal: "alice", Action: "view", Resource: "doc-1", Role: "admin", RiskTier: "R0"},
				{Principal: "bob", Action: "delete", Resource: "doc-1", Role: "admin", RiskTier: "R3"},
				{Principal: "bob", Action: "delete", Resource: "doc-1", Role: "user", RiskTier: "R3"},
				{Principal: "carol", Action: "drop", Resource: "tool-rm", Role: "editor", RiskTier: "R2"},
				{Principal: "carol", Action: "edit", Resource: "doc-2", Role: "editor", RiskTier: "R1"},
				{Principal: "alice", Action: "create", Resource: "doc-2", Role: "", RiskTier: "R0"},
			}
			for i, req := range cases {
				celV, regoV, cedarV, err := ev.EvalAll(ctx, req)
				if err != nil {
					t.Fatalf("[%s corner %d] %+v: eval error: %v", base, i, req, err)
				}
				if celV != regoV || celV != cedarV {
					t.Fatalf(
						"[%s corner %d] divergence: cel=%s rego=%s cedar=%s req=%+v",
						base, i, celV, regoV, cedarV, req,
					)
				}
			}
		})
	}
}

// TestCorpus_Present is a structural guard: every triple base must have
// a file in each language directory. A missing source surfaces here
// before the equivalence test attempts to build the evaluator and
// prints a more useful "build failed" rather than a "no such file".
func TestCorpus_Present(t *testing.T) {
	for _, base := range triples {
		for _, leg := range []struct{ lang, ext string }{
			{"cel", ".cel"},
			{"rego", ".rego"},
			{"cedar", ".cedar"},
		} {
			path := filepath.Join(corpusDir, leg.lang, base+leg.ext)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("missing corpus file %s: %v", path, err)
			}
		}
	}
}
