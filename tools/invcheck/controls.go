package main

// invcheck controls: the control registry gate (binding rule R1, HELM-746).
//
// controls.yaml names every claimed control: its owner, entry points,
// configuration, protected operations, bypass assumptions and the Go tests for
// the allowed, forbidden, removal and bypass cases. It also holds the text of
// every invariant, so HELM_INVARIANTS.md and coverage-map.json are generated
// from it and never edited by hand.
//
// A runtime entry may say `enforced` only when all of these hold:
//
//   - every entry point is reachable from a shipped binary. Reachable means the
//     symbol is declared in a package that the deadcode gate's roots
//     (scripts/ci/deadcode-roots.txt) import, built for linux/amd64 without
//     cgo, and is absent from scripts/ci/deadcode-allowlist.txt. The deadcode
//     gate fails whenever that allowlist differs from what deadcode measures,
//     so the list is the measured unreachable set and no second analyzer is
//     needed;
//   - its allowed, forbidden and removal tests run and pass;
//   - a removal proof (removal_proofs) deletes the control through
//     `go test -overlay`, and every removal test then fails.
//
// A build-plane entry is a control that CI holds rather than a binary. It names
// gates instead of entry points, and each gate must exist and block pull
// requests.
//
// Every named test is run. A test may skip only when it is listed in
// scripts/ci/postgres-proofs.txt, which CI runs against Postgres with skips
// counted as failures; this gate runs with HELM_TEST_POSTGRES_URL cleared.
//
// Like verify, the gate runs synthetic controls before it reads the real
// registry: planted bad entries must each fail, and a planted good one must
// pass. A checker that stopped discriminating would bless any registry.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	registryFile     = "controls.yaml"
	coverageMapFile  = "coverage-map.json"
	rootsFile        = "scripts/ci/deadcode-roots.txt"
	deadcodeFile     = "scripts/ci/deadcode-allowlist.txt"
	postgresFile     = "scripts/ci/postgres-proofs.txt"
	qualityGatesFile = "scripts/ci/quality-gates.json"
	prWorkflowFile   = ".github/workflows/ci.yml"
	repoModule       = "github.com/Mindburn-Labs/helm-ai-kernel"

	statusEnforced     = "enforced"
	statusObservedOnly = "observed-only"
	statusUnmanaged    = "unmanaged"

	planeRuntime = "runtime"
	planeBuild   = "build"

	mutationTimeout = "3m"

	reachable   = "reachable"
	unreachable = "unreachable"
	missing     = "missing"
)

var (
	controlIDRe = regexp.MustCompile(`^(INV|CTL)-\d{3}$`)
	symbolRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
	goTestRe    = regexp.MustCompile(`^(?:Test|Fuzz)[A-Za-z0-9_]+$`)
)

// ---------------------------------------------------------------------------
// registry model
// ---------------------------------------------------------------------------

type registry struct {
	Version  int       `yaml:"version"`
	Document document  `yaml:"document"`
	Sections []section `yaml:"sections"`
	// RemovalProofs sit apart from the entries: they are anchored to code and
	// change when the code does, while an entry changes when the claim does.
	RemovalProofs []removalProof `yaml:"removal_proofs"`
	Controls      []entry        `yaml:"controls"`
}

// document is the frame of HELM_INVARIANTS.md around the invariant blocks.
type document struct {
	Title        string `yaml:"title"`
	LastReviewed string `yaml:"last_reviewed"`
	Preamble     string `yaml:"preamble"`
}

type section struct {
	ID    string `yaml:"id"`
	Title string `yaml:"title"`
	Intro string `yaml:"intro"`
}

type entry struct {
	ID                  string   `yaml:"id"`
	Title               string   `yaml:"title"`
	Owner               string   `yaml:"owner"`
	Claim               string   `yaml:"claim"`
	Status              string   `yaml:"status"`
	Reason              string   `yaml:"reason"`
	Retired             bool     `yaml:"retired"`
	Plane               string   `yaml:"plane"`
	EntryPoints         []string `yaml:"entry_points"`
	Gates               []string `yaml:"gates"`
	Config              []string `yaml:"config"`
	ProtectedOperations []string `yaml:"protected_operations"`
	BypassAssumptions   []string `yaml:"bypass_assumptions"`
	Tests               testSet  `yaml:"tests"`

	// Invariants (INV-NNN) only: where and how the entry reads in
	// HELM_INVARIANTS.md. verify: lines are still resolved by `invcheck verify`.
	Section string   `yaml:"section"`
	Body    string   `yaml:"body"`
	Verify  []string `yaml:"verify"`
}

func (c entry) plane() string {
	if c.Plane == "" {
		return planeRuntime
	}
	return c.Plane
}

type testSet struct {
	Allowed   []string `yaml:"allowed" json:"allowed"`
	Forbidden []string `yaml:"forbidden" json:"forbidden"`
	Removal   []string `yaml:"removal" json:"removal"`
	Bypass    []string `yaml:"bypass" json:"bypass"`
}

func (t testSet) all() []string {
	out := append([]string{}, t.Allowed...)
	out = append(out, t.Forbidden...)
	out = append(out, t.Removal...)
	return append(out, t.Bypass...)
}

// removalProof deletes one control from one file. Applied through
// `go test -overlay`, every test it names must fail; each of those tests must
// also pass as written, which the full run of named tests checks.
type removalProof struct {
	Control string   `yaml:"control"`
	File    string   `yaml:"file"`
	Find    string   `yaml:"find"`
	Replace string   `yaml:"replace"`
	Tests   []string `yaml:"tests"`
}

func loadRegistry(data []byte) (*registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var reg registry
	if err := dec.Decode(&reg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("registry is empty")
		}
		return nil, err
	}
	return &reg, nil
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

type problems []issue

func (p *problems) add(kind, id, format string, args ...any) {
	*p = append(*p, issue{Kind: kind, ID: id, Msg: fmt.Sprintf(format, args...)})
}

func validate(reg *registry, ev *evidence) problems {
	var p problems
	if reg.Version != 1 {
		p.add("invalid-version", "registry", "version must be 1, got %d", reg.Version)
	}
	if reg.Document.Title == "" || reg.Document.LastReviewed == "" || reg.Document.Preamble == "" {
		p.add("missing-field", "document", "document needs title, last_reviewed and preamble")
	}
	sections := map[string]bool{}
	for _, s := range reg.Sections {
		if s.ID == "" || s.Title == "" {
			p.add("missing-field", "sections", "every section needs an id and a title")
		}
		sections[s.ID] = true
	}
	if len(reg.Controls) == 0 {
		p.add("missing-field", "registry", "the registry declares no controls")
	}

	proofs := map[string][]removalProof{}
	for _, rp := range reg.RemovalProofs {
		proofs[rp.Control] = append(proofs[rp.Control], rp)
	}

	seen := map[string]bool{}
	for _, c := range reg.Controls {
		id := c.ID
		if id == "" {
			id = "(no id)"
		}
		if !controlIDRe.MatchString(c.ID) {
			p.add("invalid-id", id, "id must be INV-NNN or CTL-NNN")
		}
		if seen[c.ID] {
			p.add("duplicate-id", id, "id is already used; ids are never reused")
		}
		seen[c.ID] = true
		for field, value := range map[string]string{"title": c.Title, "owner": c.Owner, "claim": c.Claim} {
			if strings.TrimSpace(value) == "" {
				p.add("missing-field", id, "%s is required", field)
			}
		}

		isInvariant := strings.HasPrefix(c.ID, "INV-")
		switch {
		case isInvariant && (!sections[c.Section] || strings.TrimSpace(c.Body) == "" || len(c.Verify) == 0):
			p.add("missing-field", id, "an invariant needs a known section, a body and a verify: hint")
		case !isInvariant && (c.Section != "" || c.Body != "" || len(c.Verify) > 0):
			p.add("invalid-field", id, "section, body and verify belong to INV-NNN entries only")
		}

		switch c.Status {
		case statusEnforced, statusObservedOnly, statusUnmanaged:
		default:
			p.add("invalid-status", id, "status %q is not one of enforced, observed-only, unmanaged", c.Status)
		}
		if c.Status != statusEnforced && strings.TrimSpace(c.Reason) == "" {
			p.add("missing-reason", id, "a %s entry must say why it is not enforced", c.Status)
		}
		if c.Retired && c.Status != statusUnmanaged {
			p.add("invalid-status", id, "a retired invariant holds no claim, so its status is unmanaged")
		}

		switch c.plane() {
		case planeRuntime:
			if len(c.Gates) > 0 {
				p.add("invalid-field", id, "gates belong to build-plane entries; a runtime entry names entry points")
			}
		case planeBuild:
			if len(c.EntryPoints) > 0 {
				p.add("invalid-field", id, "a build-plane entry names gates, not entry points")
			}
			for _, g := range c.Gates {
				why, known := ev.gates[g]
				switch {
				case !known:
					p.add("unknown-gate", id, "gate %s is not a quality gate (quality:<id>) or workflow job (workflow:<file>#<job>)", g)
				case why != "" && c.Status == statusEnforced:
					p.add("non-blocking-gate", id, "gate %s does not block pull requests: %s", g, why)
				}
			}
		default:
			p.add("invalid-field", id, "plane %q is not runtime or build", c.Plane)
		}

		for _, s := range c.EntryPoints {
			r, ok := parseRef(s)
			if !ok || !strings.HasPrefix(r.Dir, "core/") || !symbolRe.MatchString(r.Name) {
				p.add("invalid-entry-point", id, "entry point %q is not <core dir>.<Func> or <core dir>.<Type>.<Method>", s)
				continue
			}
			switch state := ev.reachability(r); {
			case state == missing:
				p.add("unknown-entry-point", id, "entry point %s is not declared in the linux/amd64 build", s)
			case state == unreachable && c.Status == statusEnforced:
				p.add("unreachable-entry-point", id, "entry point %s is unreachable from %s", s, rootsFile)
			}
		}
		for _, s := range c.Tests.all() {
			r, ok := parseRef(s)
			if !ok || !goTestRe.MatchString(r.Name) {
				p.add("invalid-test", id, "test %q is not <core or tools dir>.<TestName>", s)
				continue
			}
			switch result := ev.tests[s]; {
			case result == "pass", ev.postgres[s]:
			case result == "skip":
				p.add("skipped-test", id, "%s skipped; only a test listed in %s may skip here", s, postgresFile)
			case result == "fail":
				p.add("failing-test", id, "%s fails", s)
			default:
				p.add("unknown-test", id, "%s did not run: it does not exist, or its package does not build", s)
			}
		}

		if c.Status == statusEnforced {
			need := map[string]int{
				"protected_operations": len(c.ProtectedOperations), "bypass_assumptions": len(c.BypassAssumptions),
				"tests.allowed": len(c.Tests.Allowed), "tests.forbidden": len(c.Tests.Forbidden),
				"tests.removal": len(c.Tests.Removal),
			}
			if c.plane() == planeRuntime {
				need["entry_points"] = len(c.EntryPoints)
			} else {
				need["gates"] = len(c.Gates)
			}
			var gaps []string
			for name, n := range need {
				if n == 0 {
					gaps = append(gaps, name)
				}
			}
			if len(gaps) > 0 {
				sort.Strings(gaps)
				p.add("missing-evidence", id, "an enforced entry needs %s", strings.Join(gaps, ", "))
			}
		}
		p = append(p, checkRemovalProofs(c, proofs[c.ID], ev)...)
	}

	for _, rp := range reg.RemovalProofs {
		if !seen[rp.Control] {
			p.add("invalid-proof", rp.Control, "removal proof names a control that is not in the registry")
		}
	}

	// Ids are never removed: an invariant is retired in place and a control
	// keeps its number. A gap means an entry was deleted from the registry.
	for _, prefix := range []string{"INV", "CTL"} {
		highest := 0
		for _, c := range reg.Controls {
			var n int
			if _, err := fmt.Sscanf(c.ID, prefix+"-%03d", &n); err == nil && n > highest {
				highest = n
			}
		}
		for n := 1; n < highest; n++ {
			if want := fmt.Sprintf("%s-%03d", prefix, n); !seen[want] {
				p.add("missing-entry", want, "ids run from %s-001 without gaps; retire an entry instead of deleting it", prefix)
			}
		}
	}
	return p
}

// checkRemovalProofs requires every removal test of an enforced runtime entry
// to be named by one of its removal proofs, and refuses proofs anywhere else.
func checkRemovalProofs(c entry, proofs []removalProof, ev *evidence) problems {
	var p problems
	enforcedRuntime := c.Status == statusEnforced && c.plane() == planeRuntime
	if len(proofs) > 0 && !enforcedRuntime {
		p.add("invalid-proof", c.ID, "removal proofs belong to enforced runtime entries")
		return p
	}
	if !enforcedRuntime {
		return p
	}
	removal := map[string]bool{}
	for _, s := range c.Tests.Removal {
		removal[s] = true
		if ev.postgres[s] {
			p.add("invalid-proof", c.ID, "removal test %s needs Postgres, so no removal proof can run it here", s)
		}
	}
	proven := map[string]bool{}
	for _, rp := range proofs {
		if !strings.HasPrefix(rp.File, "core/") || rp.Find == "" || rp.Find == rp.Replace || len(rp.Tests) == 0 {
			p.add("invalid-proof", c.ID, "a removal proof needs a core/ file, a find that differs from replace, and tests")
		}
		for _, s := range rp.Tests {
			if !removal[s] {
				p.add("invalid-proof", c.ID, "removal proof names %s, which is not one of the entry's removal tests", s)
			}
			proven[s] = true
		}
	}
	for _, s := range c.Tests.Removal {
		if !proven[s] {
			p.add("missing-removal-proof", c.ID, "no removal proof shows that %s fails without the control", s)
		}
	}
	return p
}

// ---------------------------------------------------------------------------
// self-test: planted bad entries must fail, a planted good one must pass
// ---------------------------------------------------------------------------

// Fixed positive references. The control symbol is the shipped binary's own
// main, so it is reachable by definition; the test is the one verify's control
// already depends on. The planted test results are synthetic: the self-test
// checks the rules, while the real run below exercises the runner.
const (
	liveControlSymbol = "core/cmd/helm-ai-kernel.main"
	liveControlTest   = "core/pkg/canonicalize." + controlTest
	plantedFailing    = "core/pkg/canonicalize.TestInvcheckPlantedFailingTest"
	plantedSkipping   = "core/pkg/canonicalize.TestInvcheckPlantedSkippingTest"
)

type registryControl struct {
	name string
	want string // issue kind the check must report; empty means clean
	edit func(*registry)
}

// plants names the real references the controls need: an unreachable function
// from the deadcode allowlist and a blocking and a non-blocking gate from the
// gate registry, so no control depends on one fixed name.
type plants struct {
	deadSymbol, blockingGate, advisoryGate string
}

func registryControls(pl plants) []registryControl {
	first := func(r *registry) *entry { return &r.Controls[0] }
	return []registryControl{
		{"clean enforced entry is accepted", "", func(*registry) {}},
		{"clean build-plane entry is accepted", "", func(r *registry) {
			c := first(r)
			c.Plane, c.EntryPoints, c.Gates = planeBuild, nil, []string{pl.blockingGate}
			r.RemovalProofs = nil
		}},
		{"entry with no owner is rejected", "missing-field", func(r *registry) { first(r).Owner = "" }},
		{"unknown status is rejected", "invalid-status", func(r *registry) { first(r).Status = "partially-enforced" }},
		{"observed-only entry with no reason is rejected", "missing-reason", func(r *registry) {
			first(r).Status = statusObservedOnly
			r.RemovalProofs = nil
		}},
		{"enforced entry with an unreachable entry point is rejected", "unreachable-entry-point",
			func(r *registry) { first(r).EntryPoints = []string{pl.deadSymbol} }},
		{"entry point that does not exist is rejected", "unknown-entry-point",
			func(r *registry) {
				first(r).EntryPoints = []string{"core/cmd/helm-ai-kernel.invcheckControlMustNotExist"}
			}},
		{"test that does not exist is rejected", "unknown-test",
			func(r *registry) {
				first(r).Tests.Forbidden = []string{"core/pkg/canonicalize.TestInvcheckControlMustNotExistAnywhere"}
			}},
		{"failing test is rejected", "failing-test", func(r *registry) { first(r).Tests.Allowed = []string{plantedFailing} }},
		{"skipping test outside postgres-proofs is rejected", "skipped-test",
			func(r *registry) { first(r).Tests.Allowed = []string{plantedSkipping} }},
		{"enforced entry with no forbidden test is rejected", "missing-evidence", func(r *registry) { first(r).Tests.Forbidden = nil }},
		{"enforced entry with no removal proof is rejected", "missing-removal-proof", func(r *registry) { r.RemovalProofs = nil }},
		{"build-plane entry on a non-blocking gate is rejected", "non-blocking-gate", func(r *registry) {
			c := first(r)
			c.Plane, c.EntryPoints, c.Gates = planeBuild, nil, []string{pl.advisoryGate}
			r.RemovalProofs = nil
		}},
		{"duplicate id is rejected", "duplicate-id", func(r *registry) { r.Controls = append(r.Controls, r.Controls[0]) }},
		{"entry removed from the registry is rejected", "missing-entry", func(r *registry) {
			first(r).ID = "CTL-002"
			r.RemovalProofs[0].Control = "CTL-002"
		}},
	}
}

func controlRegistry() *registry {
	return &registry{
		Version:  1,
		Document: document{Title: "Control", LastReviewed: "2026-01-01", Preamble: "Control.\n"},
		RemovalProofs: []removalProof{{
			Control: "CTL-001", File: "core/pkg/canonicalize/jcs.go", Find: "a", Replace: "b", Tests: []string{liveControlTest},
		}},
		Controls: []entry{{
			ID: "CTL-001", Title: "planted control", Owner: "invcheck", Claim: "planted claim",
			Status: statusEnforced, EntryPoints: []string{liveControlSymbol},
			ProtectedOperations: []string{"none"}, BypassAssumptions: []string{"none"},
			Tests: testSet{Allowed: []string{liveControlTest}, Forbidden: []string{liveControlTest}, Removal: []string{liveControlTest}},
		}},
	}
}

func registrySelfTest(root string, real *evidence, pl plants) []string {
	ev := *real
	ev.tests = map[string]string{plantedFailing: "fail", plantedSkipping: "skip"}
	for k, v := range real.tests {
		ev.tests[k] = v
	}
	var failures []string
	for _, rc := range registryControls(pl) {
		reg := controlRegistry()
		rc.edit(reg)
		got := validate(reg, &ev)
		kinds := map[string]bool{}
		for _, is := range got {
			kinds[is.Kind] = true
		}
		switch {
		case rc.want == "" && len(got) > 0:
			failures = append(failures, fmt.Sprintf("control %q: expected a clean result, got %s", rc.name, summarize(got)))
		case rc.want != "" && !kinds[rc.want]:
			failures = append(failures, fmt.Sprintf("control %q: expected %q, got %s", rc.name, rc.want, summarize(got)))
		}
	}
	if driftProblem("control", []byte("a"), []byte("b")) == nil || driftProblem("control", []byte("a"), []byte("a")) != nil {
		failures = append(failures, "control \"stale generated file is rejected\": drift comparison does not discriminate")
	}
	// A removal proof whose anchor matches nothing must fail before any build.
	bad := removalProof{Control: "CTL-001", File: "core/pkg/canonicalize/jcs.go", Find: "invcheck control anchor that matches nothing"}
	if got := proveRemoval(root, bad); len(got) != 1 || got[0].Kind != "mutation-anchor" {
		failures = append(failures, fmt.Sprintf("control \"removal proof with a stale anchor is rejected\": got %s", summarize(got)))
	}
	return failures
}

// firstDeadSymbol picks a function the deadcode allowlist records as
// unreachable, so the unreachable control never depends on one fixed name.
func firstDeadSymbol(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, deadcodeFile))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.HasPrefix(line, "#") || !symbolRe.MatchString(fields[1]) {
			continue
		}
		if dir := strings.TrimPrefix(fields[0], repoModule+"/"); strings.HasPrefix(dir, "core/") {
			return dir + "." + fields[1], nil
		}
	}
	return "", fmt.Errorf("%s records no unreachable function to plant", deadcodeFile)
}

// findPlants picks the self-test's gates from the gate registry.
func findPlants(deadSymbol string, ev *evidence) (plants, error) {
	pl := plants{deadSymbol: deadSymbol}
	var names []string
	for g := range ev.gates {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		if !strings.HasPrefix(g, "quality:") {
			continue
		}
		if ev.gates[g] == "" && pl.blockingGate == "" {
			pl.blockingGate = g
		}
		if ev.gates[g] != "" && pl.advisoryGate == "" {
			pl.advisoryGate = g // any non-blocking gate
		}
	}
	if pl.deadSymbol == "" || pl.blockingGate == "" || pl.advisoryGate == "" {
		return pl, fmt.Errorf("the tree lacks a control reference (unreachable function %q, blocking gate %q, advisory gate %q)",
			pl.deadSymbol, pl.blockingGate, pl.advisoryGate)
	}
	return pl, nil
}

// ---------------------------------------------------------------------------
// controls subcommand
// ---------------------------------------------------------------------------

func runControls(args []string) int {
	flags := flag.NewFlagSet("controls", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	write := flags.Bool("write", false, "regenerate "+constitution+" and "+coverageMapFile+" instead of checking them")
	_ = flags.Parse(args)
	start := time.Now()

	data, err := os.ReadFile(filepath.Join(*root, registryFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: cannot read %s: %v\n", registryFile, err)
		return 2
	}
	reg, err := loadRegistry(data)
	if err != nil {
		fmt.Printf("invcheck controls: FAIL\n  %s: %v\n", registryFile, err)
		return 1
	}

	deadSymbol, err := firstDeadSymbol(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: %v\n", err)
		return 2
	}
	symbols, tests := references(reg)
	dead, _ := parseRef(deadSymbol)
	live, _ := parseRef(liveControlSymbol)
	liveTest, _ := parseRef(liveControlTest)
	ev, err := gatherEvidence(*root, append(symbols, dead, live), append(tests, liveTest))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: cannot gather evidence: %v\n", err)
		return 2
	}
	pl, err := findPlants(deadSymbol, ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: %v\n", err)
		return 2
	}
	fmt.Printf("invcheck controls: evidence in %s — %d shipped packages, %d unreachable functions, %d named tests run, %d gates\n",
		time.Since(start).Round(time.Second), len(ev.graph), len(ev.dead), len(ev.tests), len(ev.gates))

	controls := registryControls(pl)
	fmt.Printf("invcheck controls self-test: %d controls\n", len(controls)+2)
	if failures := registrySelfTest(*root, ev, pl); len(failures) > 0 {
		fmt.Println("SELF-TEST FAILED — the checker no longer discriminates:")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Println("\nRefusing to judge " + registryFile + ".")
		return 2
	}
	for _, rc := range controls {
		want := rc.want
		if want == "" {
			want = "clean"
		}
		fmt.Printf("  ok  %-60s -> %s\n", rc.name, want)
	}
	fmt.Printf("  ok  %-60s -> %s\n", "stale generated file is rejected", "stale-generated")
	fmt.Printf("  ok  %-60s -> %s\n", "removal proof with a stale anchor is rejected", "mutation-anchor")

	doc := generateInvariants(reg)
	cmap := generateCoverageMap(reg, ev)
	if *write {
		for name, content := range map[string][]byte{constitution: doc, coverageMapFile: cmap} {
			if err := os.WriteFile(filepath.Join(*root, name), content, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "invcheck: cannot write %s: %v\n", name, err)
				return 2
			}
			fmt.Printf("wrote %s\n", name)
		}
	}

	found := validate(reg, ev)
	for name, content := range map[string][]byte{constitution: doc, coverageMapFile: cmap} {
		committed, _ := os.ReadFile(filepath.Join(*root, name))
		if is := driftProblem(name, committed, content); is != nil {
			found = append(found, *is)
		}
	}
	proofStart := time.Now()
	proofProblems, proven := proveAll(*root, reg.RemovalProofs)
	found = append(found, proofProblems...)

	s := summarizeStatus(reg)
	fmt.Printf("\n%s: %d controls — %d enforced (%d build-plane), %d observed-only, %d unmanaged (%d retired invariants); %d of %d removal proofs hold (%s); total %s\n",
		registryFile, s.Total, s.Enforced, s.BuildPlane, s.ObservedOnly, s.Unmanaged, s.Retired, proven, len(reg.RemovalProofs),
		time.Since(proofStart).Round(time.Second), time.Since(start).Round(time.Second))
	if len(found) == 0 {
		fmt.Println("\ninvcheck controls: PASS")
		return 0
	}
	fmt.Printf("\ninvcheck controls: FAIL (%d issue(s))\n", len(found))
	sort.SliceStable(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	for _, is := range found {
		fmt.Printf("  [%s] %s: %s\n", is.Kind, is.ID, is.Msg)
	}
	return 1
}
