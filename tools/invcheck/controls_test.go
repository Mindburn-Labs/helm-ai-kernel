package main

import (
	"strings"
	"testing"
)

const deadControlSymbol = "core/pkg/example.Unreached"

// fakeEvidence stands in for the go list, deadcode allowlist and go test -list
// facts, so the rules are tested without building the kernel.
func fakeEvidence() *evidence {
	live, _ := parseRef(liveControlSymbol)
	dead, _ := parseRef(deadControlSymbol)
	return &evidence{
		graph:    map[string]bool{live.importPath(): true, dead.importPath(): true},
		dead:     map[string]bool{dead.key(): true},
		declared: map[string]bool{live.key(): true, dead.key(): true},
		tests:    map[string]bool{liveControlTest: true},
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
	if failures := registrySelfTest(fakeEvidence(), deadControlSymbol); len(failures) > 0 {
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
	if got := kinds(validate(reg, fakeEvidence())); !got["missing-field"] {
		t.Fatalf("an INV entry without section, body and verify: must be rejected, got %v", got)
	}
}

func TestRemovalMutationNeedsAnEnforcedEntry(t *testing.T) {
	reg := controlRegistry()
	c := &reg.Controls[0]
	c.Status, c.Reason = statusObservedOnly, "not wired"
	c.RemovalMutation = &mutation{File: "core/pkg/x/x.go", Find: "a", Replace: "b"}
	if got := kinds(validate(reg, fakeEvidence())); !got["invalid-field"] {
		t.Fatalf("a removal mutation on an entry that claims nothing must be rejected, got %v", got)
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
	} {
		if got, ok := parseRef(in); !ok || got != want {
			t.Errorf("parseRef(%q) = %+v, %v; want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"CheckEgress", "sdk/go/client.Do", "core/pkg/firewall", "core/pkg/firewall."} {
		if _, ok := parseRef(bad); ok {
			t.Errorf("parseRef(%q) accepted a reference outside <core dir>.<name>", bad)
		}
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
				Status: statusEnforced},
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
	if !strings.Contains(doc, "| CTL-001 | Not an invariant | unmanaged | r |") {
		t.Fatalf("status table does not list the non-invariant control:\n%s", doc)
	}
	if !strings.HasPrefix(doc, "---\ntitle: HELM Invariants\nlast_reviewed: 2026-09-24\n---\n\n# HELM Invariants\n\nIntro.\n") {
		t.Fatalf("front matter or preamble changed shape:\n%s", doc)
	}
}
