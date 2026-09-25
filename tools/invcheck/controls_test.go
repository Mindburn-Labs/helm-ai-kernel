package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const deadControlSymbol = "core/pkg/example.Unreached"

var fakePlants = plants{deadSymbol: deadControlSymbol, blockingGate: "quality:blocking", advisoryGate: "quality:advisory"}

// fakeEvidence stands in for the go list, deadcode allowlist, test run and gate
// facts, so the rules are tested without building the kernel.
func fakeEvidence() *evidence {
	live, _ := parseRef(liveControlSymbol)
	dead, _ := parseRef(deadControlSymbol)
	return &evidence{
		graph:    map[string]bool{live.importPath(): true, dead.importPath(): true},
		dead:     map[string]bool{dead.key(): true},
		declared: map[string]bool{live.key(): true, dead.key(): true},
		tests:    map[string]string{liveControlTest: "pass"},
		postgres: map[string]bool{"core/pkg/store.TestPostgresOnly": true},
		gates:    map[string]string{"quality:blocking": "", "quality:advisory": "advisory"},
	}
}

func kinds(p problems) map[string]bool {
	out := map[string]bool{}
	for _, is := range p {
		out[is.Kind] = true
	}
	return out
}

func TestRegistryControlsDiscriminate(t *testing.T) {
	if failures := registrySelfTest("../..", fakeEvidence(), fakePlants); len(failures) > 0 {
		t.Fatalf("planted registry entries were not judged as expected:\n%s", strings.Join(failures, "\n"))
	}
}

func TestEntryPointOutsideTheShippedGraphIsUnreachable(t *testing.T) {
	ev := fakeEvidence()
	orphan, _ := parseRef("core/pkg/orphan.Check")
	ev.declared[orphan.key()] = true // declared, but no shipped binary imports the package

	reg := controlRegistry()
	reg.Controls[0].EntryPoints = []string{"core/pkg/orphan.Check"}
	if got := kinds(validate(reg, ev)); !got["unreachable-entry-point"] {
		t.Fatalf("an enforced entry point in an orphan package must be unreachable, got %v", got)
	}

	reg.Controls[0].Status, reg.Controls[0].Reason = statusObservedOnly, "orphan package"
	reg.RemovalProofs = nil
	if got := validate(reg, ev); len(got) > 0 {
		t.Fatalf("an observed-only entry may name an unreachable entry point, got %s", summarize(got))
	}
}

func TestRetiredInvariantMustBeUnmanaged(t *testing.T) {
	reg := controlRegistry()
	reg.Controls[0].Retired = true
	if got := kinds(validate(reg, fakeEvidence())); !got["invalid-status"] {
		t.Fatalf("a retired entry that still claims enforcement must be rejected, got %v", got)
	}
}

func TestInvariantNeedsItsDocumentText(t *testing.T) {
	reg := controlRegistry()
	reg.Controls[0].ID = "INV-001"
	reg.RemovalProofs[0].Control = "INV-001"
	if got := kinds(validate(reg, fakeEvidence())); !got["missing-field"] {
		t.Fatalf("an INV entry without section, body and verify: must be rejected, got %v", got)
	}
}

func TestRemovalProofNeedsAnEnforcedRuntimeEntry(t *testing.T) {
	reg := controlRegistry()
	reg.Controls[0].Status, reg.Controls[0].Reason = statusObservedOnly, "not wired"
	if got := kinds(validate(reg, fakeEvidence())); !got["invalid-proof"] {
		t.Fatalf("a removal proof on an entry that claims nothing must be rejected, got %v", got)
	}
}

func TestRemovalProofsMustCoverEveryRemovalTest(t *testing.T) {
	ev := fakeEvidence()
	ev.tests["core/pkg/canonicalize.TestSecond"] = "pass"
	reg := controlRegistry()
	reg.Controls[0].Tests.Removal = append(reg.Controls[0].Tests.Removal, "core/pkg/canonicalize.TestSecond")
	if got := kinds(validate(reg, ev)); !got["missing-removal-proof"] {
		t.Fatalf("a removal test no proof names must be rejected, got %v", got)
	}

	reg.RemovalProofs[0].Tests = append(reg.RemovalProofs[0].Tests, "core/pkg/canonicalize.TestNotARemovalTest")
	if got := kinds(validate(reg, ev)); !got["invalid-proof"] {
		t.Fatalf("a proof naming a test outside tests.removal must be rejected, got %v", got)
	}
}

func TestPostgresRemovalTestCannotBeProvenHere(t *testing.T) {
	reg := controlRegistry()
	reg.Controls[0].Tests.Removal = []string{"core/pkg/store.TestPostgresOnly"}
	reg.RemovalProofs[0].Tests = []string{"core/pkg/store.TestPostgresOnly"}
	if got := kinds(validate(reg, fakeEvidence())); !got["invalid-proof"] {
		t.Fatalf("a removal test that needs Postgres cannot back a removal proof, got %v", got)
	}
}

// A test listed in postgres-proofs.txt is left to the CI job with Postgres; it
// does not run here and must not be reported as missing.
func TestPostgresListedTestIsAcceptedWithoutARun(t *testing.T) {
	reg := controlRegistry()
	reg.Controls[0].Tests.Bypass = []string{"core/pkg/store.TestPostgresOnly"}
	if got := validate(reg, fakeEvidence()); len(got) > 0 {
		t.Fatalf("a Postgres-listed test must be accepted, got %s", summarize(got))
	}
}

func TestBlockingGatesReadsProfilesAndWorkflows(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(qualityGatesFile, `{"profiles":{"pr":{"gates":["a","c"]}},"gates":[{"id":"a"},{"id":"b"},{"id":"c","advisory":true}]}`)
	write(prWorkflowFile, "on:\n  pull_request:\njobs:\n  quality:\n    steps:\n      - run: make quality-pr\n  soft:\n    continue-on-error: true\n")
	write(".github/workflows/nightly.yml", "on:\n  schedule:\n    - cron: '0 0 * * *'\njobs:\n  night:\n    steps: []\n")

	gates, err := blockingGates(root)
	if err != nil {
		t.Fatal(err)
	}
	for gate, blocking := range map[string]bool{
		"quality:a": true, "quality:b": false, "quality:c": false,
		"workflow:.github/workflows/ci.yml#quality":    true,
		"workflow:.github/workflows/ci.yml#soft":       false,
		"workflow:.github/workflows/nightly.yml#night": false,
	} {
		why, known := gates[gate]
		if !known || (why == "") != blocking {
			t.Errorf("%s: known=%v reason=%q, want blocking=%v", gate, known, why, blocking)
		}
	}
}

func TestLoadRegistryRejectsUnknownFields(t *testing.T) {
	_, err := loadRegistry([]byte("version: 1\ncontrols:\n  - id: CTL-001\n    enforced_by: hope\n"))
	if err == nil || !strings.Contains(err.Error(), "enforced_by") {
		t.Fatalf("a misspelt field must fail to load rather than vanish, got %v", err)
	}
	if _, err := loadRegistry(nil); err == nil {
		t.Fatal("an empty registry must fail to load")
	}
}

func TestParseRef(t *testing.T) {
	for in, want := range map[string]ref{
		"core/pkg/firewall.EgressChecker.CheckEgress": {"core/pkg/firewall", "EgressChecker.CheckEgress"},
		"core/cmd/helm-ai-kernel.main":                {"core/cmd/helm-ai-kernel", "main"},
		"core/pkg/kernel/authority.TestDecideLogic":   {"core/pkg/kernel/authority", "TestDecideLogic"},
		"tools/invcheck.TestRegistryControls":         {"tools/invcheck", "TestRegistryControls"},
	} {
		if got, ok := parseRef(in); !ok || got != want {
			t.Errorf("parseRef(%q) = %+v, %v; want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"CheckEgress", "sdk/go/client.Do", "core/pkg/firewall", "core/pkg/firewall."} {
		if _, ok := parseRef(bad); ok {
			t.Errorf("parseRef(%q) accepted a reference outside <core or tools dir>.<name>", bad)
		}
	}
	if module("tools/invcheck") != "tools/invcheck" || module("core/pkg/x") != "core" {
		t.Error("module() does not map directories to their Go module")
	}
}

// The generated constitution must parse back into the same invariant blocks,
// or verify and concept-gate would judge a different file than the registry.
func TestGeneratedInvariantsParseBack(t *testing.T) {
	reg := &registry{
		Version:  1,
		Document: document{Title: "HELM Invariants", LastReviewed: "2026-09-24", Preamble: "Intro.\n"},
		Sections: []section{{ID: "one", Title: "First"}, {ID: "two", Title: "Second", Intro: "Section intro.\n"}},
		Controls: []entry{
			{ID: "INV-001", Title: "Alpha", Section: "one", Body: "Alpha body.\n\nSecond paragraph.\n",
				Verify: []string{"`Makefile`", "review question"}, Status: statusUnmanaged, Reason: "r"},
			{ID: "CTL-001", Title: "Not an invariant", Status: statusUnmanaged, Reason: "r"},
			{ID: "INV-002", Title: "Beta", Section: "two", Body: "Beta body.\n", Verify: []string{"`Makefile`"},
				Status: statusEnforced, Plane: planeBuild},
		},
	}
	doc := string(generateInvariants(reg))
	invs := parse(doc)
	if len(invs) != 2 || invs[0].ID != "INV-001" || invs[1].ID != "INV-002" {
		t.Fatalf("expected INV-001 and INV-002 blocks, got %+v", invs)
	}
	if len(invs[0].Verify) != 2 || invs[0].Title != "Alpha" {
		t.Fatalf("INV-001 lost its title or verify lines: %+v", invs[0])
	}
	for _, row := range []string{"| CTL-001 | Not an invariant | unmanaged | r |", "| INV-002 | Beta | enforced (build) | — |"} {
		if !strings.Contains(doc, row) {
			t.Fatalf("status table lacks %q:\n%s", row, doc)
		}
	}
	if !strings.HasPrefix(doc, "---\ntitle: HELM Invariants\nlast_reviewed: 2026-09-24\n---\n\n# HELM Invariants\n\nIntro.\n") {
		t.Fatalf("front matter or preamble changed shape:\n%s", doc)
	}
}

// verify's own positive controls, the constitution's half of INV-025.
func TestVerifyControlsDiscriminate(t *testing.T) {
	idx, err := buildIndex("../..")
	if err != nil {
		t.Fatal(err)
	}
	if failures := selfTest(idx); len(failures) > 0 {
		t.Fatalf("verify controls answered wrong:\n%s", strings.Join(failures, "\n"))
	}
}
