package main

// invcheck controls: the control registry gate (binding rule R1, HELM-746).
//
// controls.yaml names every claimed control: its owner, entry points,
// configuration, protected operations, bypass assumptions and the Go tests for
// the allowed, forbidden, removal and bypass cases. It also holds the text of
// every invariant, so HELM_INVARIANTS.md and coverage-map.json are generated
// from it and never edited by hand.
//
// An entry may say `enforced` only when every entry point is reachable from a
// shipped binary and its allowed, forbidden and removal tests exist. Reachable
// means the symbol is declared in a package that the deadcode gate's roots
// (scripts/ci/deadcode-roots.txt) import, built for linux/amd64 without cgo,
// and is absent from scripts/ci/deadcode-allowlist.txt. The deadcode gate fails
// whenever that allowlist differs from what deadcode measures, so the list is
// the measured unreachable set and no second analyzer is needed. Tests exist
// when `go test -list` reports them in the named package.
//
// Like verify, the gate runs synthetic controls before it reads the real
// registry: planted bad entries must each fail, and a planted good one must
// pass. A checker that stopped discriminating would bless any registry.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	registryFile    = "controls.yaml"
	coverageMapFile = "coverage-map.json"
	rootsFile       = "scripts/ci/deadcode-roots.txt"
	deadcodeFile    = "scripts/ci/deadcode-allowlist.txt"
	repoModule      = "github.com/Mindburn-Labs/helm-ai-kernel"

	statusEnforced     = "enforced"
	statusObservedOnly = "observed-only"
	statusUnmanaged    = "unmanaged"

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
	Controls []entry   `yaml:"controls"`
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
	ID                  string    `yaml:"id"`
	Title               string    `yaml:"title"`
	Owner               string    `yaml:"owner"`
	Claim               string    `yaml:"claim"`
	Status              string    `yaml:"status"`
	Reason              string    `yaml:"reason"`
	Retired             bool      `yaml:"retired"`
	EntryPoints         []string  `yaml:"entry_points"`
	Config              []string  `yaml:"config"`
	ProtectedOperations []string  `yaml:"protected_operations"`
	BypassAssumptions   []string  `yaml:"bypass_assumptions"`
	Tests               testSet   `yaml:"tests"`
	RemovalMutation     *mutation `yaml:"removal_mutation"`

	// Invariants (INV-NNN) only: where and how the entry reads in
	// HELM_INVARIANTS.md. verify: lines are still resolved by `invcheck verify`.
	Section string   `yaml:"section"`
	Body    string   `yaml:"body"`
	Verify  []string `yaml:"verify"`
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

// mutation removes the control from one file. With it applied through
// `go test -overlay`, every removal test must fail; without it they must pass.
type mutation struct {
	File    string `yaml:"file"`
	Find    string `yaml:"find"`
	Replace string `yaml:"replace"`
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

// ref is a Go symbol or test named "<dir>.<name>", with dir relative to the
// repository root: core/pkg/firewall.EgressChecker.CheckEgress,
// core/pkg/firewall.TestEgressChecker_EmptyPolicyDenyAll.
type ref struct{ Dir, Name string }

func parseRef(s string) (ref, bool) {
	slash := strings.LastIndex(s, "/")
	if slash < 0 {
		return ref{}, false
	}
	dot := strings.Index(s[slash+1:], ".")
	if dot <= 0 {
		return ref{}, false
	}
	dot += slash + 1
	r := ref{Dir: s[:dot], Name: s[dot+1:]}
	if !strings.HasPrefix(r.Dir, "core/") || r.Name == "" {
		return ref{}, false
	}
	return r, true
}

func (r ref) importPath() string { return repoModule + "/" + r.Dir }
func (r ref) key() string        { return r.importPath() + " " + r.Name }

// ---------------------------------------------------------------------------
// evidence: what the tree says about the registry's references
// ---------------------------------------------------------------------------

type evidence struct {
	graph    map[string]bool // import paths the shipped binaries depend on
	dead     map[string]bool // "<import path> <symbol>" that no shipped binary reaches
	declared map[string]bool // "<import path> <symbol>" in the linux/amd64 build
	tests    map[string]bool // "<dir>.<Test>" reported by go test -list
}

func (e *evidence) reachability(r ref) string {
	switch {
	case !e.declared[r.key()]:
		return missing
	case !e.graph[r.importPath()] || e.dead[r.key()]:
		return unreachable
	default:
		return reachable
	}
}

func (e *evidence) testExists(r ref) bool { return e.tests[r.Dir+"."+r.Name] }

func gatherEvidence(root string, symbols, tests []ref) (*evidence, error) {
	ev := &evidence{graph: map[string]bool{}, dead: map[string]bool{}, declared: map[string]bool{}, tests: map[string]bool{}}

	roots, err := readRoots(root)
	if err != nil {
		return nil, err
	}
	out, err := goCmd(root, []string{"GOWORK=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"},
		append([]string{"list", "-deps", "-f", "{{.ImportPath}}"}, roots...)...)
	if err != nil {
		return nil, fmt.Errorf("go list -deps %s: %v\n%s", strings.Join(roots, " "), err, out)
	}
	for _, line := range strings.Fields(out) {
		ev.graph[line] = true
	}

	dead, err := os.ReadFile(filepath.Join(root, deadcodeFile))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(dead), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			ev.dead[line] = true
		}
	}

	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", "amd64", false
	for _, dir := range uniqueDirs(symbols) {
		pkg, err := ctx.ImportDir(filepath.Join(root, filepath.FromSlash(dir)), 0)
		if err != nil {
			continue // no buildable package: every symbol in it reports missing
		}
		for _, name := range pkg.GoFiles {
			for _, sym := range declaredFuncs(filepath.Join(pkg.Dir, name)) {
				ev.declared[repoModule+"/"+dir+" "+sym] = true
			}
		}
	}

	if dirs := uniqueDirs(tests); len(dirs) > 0 {
		pkgs := make([]string, 0, len(dirs))
		for _, dir := range dirs {
			pkgs = append(pkgs, "./"+strings.TrimPrefix(dir, "core/"))
		}
		out, err := goCmd(root, nil, append([]string{"test", "-list", ".", "-json"}, pkgs...)...)
		events, perr := testEvents(out)
		if perr != nil {
			return nil, fmt.Errorf("go test -list: %v", perr)
		}
		for _, ev2 := range events {
			name := strings.TrimSpace(ev2.Output)
			if ev2.Action == "output" && goTestRe.MatchString(name) {
				ev.tests[strings.TrimPrefix(ev2.Package, repoModule+"/")+"."+name] = true
			}
		}
		if err != nil {
			// A package that does not build lists nothing, so its tests surface
			// below as unknown tests. Say why rather than leave it at that.
			fmt.Printf("  note: go test -list exited %v; unbuildable packages list no tests\n", err)
		}
	}
	return ev, nil
}

func readRoots(root string) ([]string, error) {
	f, err := os.Open(filepath.Join(root, rootsFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var roots []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "core/") {
			return nil, fmt.Errorf("%s: root %s is outside the core module", rootsFile, line)
		}
		roots = append(roots, "./"+strings.TrimPrefix(line, "core/"))
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%s lists no roots", rootsFile)
	}
	return roots, sc.Err()
}

// declaredFuncs names every function in a file the way deadcode keys it:
// Func, or Recv.Method with the pointer and type parameters dropped.
func declaredFuncs(path string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			name = receiverName(fn.Recv.List[0].Type) + "." + name
		}
		out = append(out, name)
	}
	return out
}

func receiverName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverName(t.X)
	case *ast.IndexExpr:
		return receiverName(t.X)
	case *ast.IndexListExpr:
		return receiverName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

func testEvents(out string) ([]testEvent, error) {
	var events []testEvent
	dec := json.NewDecoder(strings.NewReader(out))
	for {
		var ev testEvent
		if err := dec.Decode(&ev); err == io.EOF {
			return events, nil
		} else if err != nil {
			return events, fmt.Errorf("%v in output:\n%s", err, out)
		}
		events = append(events, ev)
	}
}

// goCmd runs the go command in the core module and returns stdout, or stdout
// and stderr together when it fails.
func goCmd(root string, env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(root, "core")
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String() + stderr.String(), err
	}
	return stdout.String(), nil
}

func uniqueDirs(refs []ref) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range refs {
		if !seen[r.Dir] {
			seen[r.Dir] = true
			out = append(out, r.Dir)
		}
	}
	sort.Strings(out)
	return out
}

// references returns the parseable symbol and test references of a registry.
// Malformed ones are reported by validate.
func references(reg *registry) (symbols, tests []ref) {
	for _, c := range reg.Controls {
		for _, s := range c.EntryPoints {
			if r, ok := parseRef(s); ok {
				symbols = append(symbols, r)
			}
		}
		for _, s := range c.Tests.all() {
			if r, ok := parseRef(s); ok {
				tests = append(tests, r)
			}
		}
	}
	return symbols, tests
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

		for _, s := range c.EntryPoints {
			r, ok := parseRef(s)
			if !ok || !symbolRe.MatchString(r.Name) {
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
				p.add("invalid-test", id, "test %q is not <core dir>.<TestName>", s)
				continue
			}
			if !ev.testExists(r) {
				p.add("unknown-test", id, "go test -list does not report %s", s)
			}
		}

		if c.Status == statusEnforced {
			var gaps []string
			for name, n := range map[string]int{
				"entry_points": len(c.EntryPoints), "protected_operations": len(c.ProtectedOperations),
				"bypass_assumptions": len(c.BypassAssumptions), "tests.allowed": len(c.Tests.Allowed),
				"tests.forbidden": len(c.Tests.Forbidden), "tests.removal": len(c.Tests.Removal),
			} {
				if n == 0 {
					gaps = append(gaps, name)
				}
			}
			if len(gaps) > 0 {
				sort.Strings(gaps)
				p.add("missing-evidence", id, "an enforced entry needs %s", strings.Join(gaps, ", "))
			}
		}
		if c.RemovalMutation != nil && (c.Status != statusEnforced || len(c.Tests.Removal) == 0) {
			p.add("invalid-field", id, "removal_mutation needs an enforced entry with removal tests")
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

// ---------------------------------------------------------------------------
// removal proofs: the named tests fail when the control is removed
// ---------------------------------------------------------------------------

// proveRemoval runs the removal tests with and without the mutation. They must
// pass as written and fail with the control removed; a mutation that does not
// compile, or an anchor that does not match exactly once, proves nothing.
func proveRemoval(root string, c entry) problems {
	var p problems
	m := c.RemovalMutation
	path := filepath.Join(root, filepath.FromSlash(m.File))
	src, err := os.ReadFile(path)
	if err != nil {
		p.add("mutation-anchor", c.ID, "cannot read %s: %v", m.File, err)
		return p
	}
	if n := strings.Count(string(src), m.Find); n != 1 || m.Find == m.Replace {
		p.add("mutation-anchor", c.ID, "removal_mutation.find must match %s exactly once and differ from replace (matches %d)", m.File, n)
		return p
	}

	tmp, err := os.MkdirTemp("", "invcheck-mutation-")
	if err != nil {
		p.add("mutation-run", c.ID, "%v", err)
		return p
	}
	defer os.RemoveAll(tmp)
	mutated := filepath.Join(tmp, filepath.Base(path))
	overlay := filepath.Join(tmp, "overlay.json")
	absPath, _ := filepath.Abs(path)
	spec, _ := json.Marshal(map[string]map[string]string{"Replace": {absPath: mutated}})
	if err := os.WriteFile(mutated, []byte(strings.Replace(string(src), m.Find, m.Replace, 1)), 0o600); err != nil {
		p.add("mutation-run", c.ID, "%v", err)
		return p
	}
	if err := os.WriteFile(overlay, spec, 0o600); err != nil {
		p.add("mutation-run", c.ID, "%v", err)
		return p
	}

	var names, pkgs []string
	var refs []ref
	for _, s := range c.Tests.Removal {
		r, _ := parseRef(s)
		refs = append(refs, r)
		names = append(names, regexp.QuoteMeta(r.Name))
	}
	for _, dir := range uniqueDirs(refs) {
		pkgs = append(pkgs, "./"+strings.TrimPrefix(dir, "core/"))
	}
	run := "^(" + strings.Join(names, "|") + ")$"

	for _, pass := range []struct {
		label, want string
		extra       []string
	}{
		{"with the control", "pass", nil},
		{"with the control removed", "fail", []string{"-overlay", overlay}},
	} {
		args := append([]string{"test", "-json", "-count=1", "-run", run}, pass.extra...)
		out, _ := goCmd(root, nil, append(args, pkgs...)...)
		events, err := testEvents(out)
		if err != nil {
			p.add("mutation-run", c.ID, "%s: %v", pass.label, err)
			continue
		}
		got := map[string]string{}
		for _, ev := range events {
			if ev.Test != "" && (ev.Action == "pass" || ev.Action == "fail" || ev.Action == "skip") {
				got[strings.TrimPrefix(ev.Package, repoModule+"/")+"."+ev.Test] = ev.Action
			}
		}
		for _, s := range c.Tests.Removal {
			if got[s] != pass.want {
				action := got[s]
				if action == "" {
					action = "did not run (does the mutated package compile?)"
				}
				p.add("removal-not-proven", c.ID, "%s %s: want %s, got %s", s, pass.label, pass.want, action)
			}
		}
	}
	return p
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

type coverageMap struct {
	GeneratedFrom string          `json:"generated_from"`
	Rule          string          `json:"rule"`
	Annotations   []string        `json:"annotations"`
	Summary       coverageSummary `json:"summary"`
	Controls      []coverageEntry `json:"controls"`
}

type coverageSummary struct {
	Total        int `json:"total"`
	Enforced     int `json:"enforced"`
	ObservedOnly int `json:"observed_only"`
	Unmanaged    int `json:"unmanaged"`
	Retired      int `json:"retired_invariants"`
}

type coverageEntry struct {
	ID                  string            `json:"id"`
	Title               string            `json:"title"`
	Owner               string            `json:"owner"`
	Claim               string            `json:"claim"`
	Status              string            `json:"status"`
	Reason              string            `json:"reason,omitempty"`
	Retired             bool              `json:"retired,omitempty"`
	EntryPoints         []entryPointState `json:"entry_points"`
	Config              []string          `json:"config"`
	ProtectedOperations []string          `json:"protected_operations"`
	BypassAssumptions   []string          `json:"bypass_assumptions"`
	Tests               testSet           `json:"tests"`
	RemovalProven       bool              `json:"removal_proven_by_mutation"`
}

type entryPointState struct {
	Symbol       string `json:"symbol"`
	Reachability string `json:"reachability"`
}

func summarizeStatus(reg *registry) coverageSummary {
	var s coverageSummary
	for _, c := range reg.Controls {
		s.Total++
		switch c.Status {
		case statusEnforced:
			s.Enforced++
		case statusObservedOnly:
			s.ObservedOnly++
		case statusUnmanaged:
			s.Unmanaged++
		}
		if c.Retired {
			s.Retired++
		}
	}
	return s
}

func generateCoverageMap(reg *registry, ev *evidence) []byte {
	cm := coverageMap{
		GeneratedFrom: registryFile + " via make controls; do not edit by hand",
		Rule:          "R1: only the tested path reachable from a shipped binary is enforced",
		Annotations: []string{"quantum_posture: this map records which code paths hold existing signing, " +
			"hashing and key-separation properties; it pins no algorithm and makes no post-quantum claim"},
		Summary:  summarizeStatus(reg),
		Controls: []coverageEntry{},
	}
	for _, c := range reg.Controls {
		e := coverageEntry{
			ID: c.ID, Title: c.Title, Owner: c.Owner, Claim: strings.TrimSpace(c.Claim), Status: c.Status,
			Reason: strings.TrimSpace(c.Reason), Retired: c.Retired, EntryPoints: []entryPointState{},
			Config: nonNil(c.Config), ProtectedOperations: nonNil(c.ProtectedOperations),
			BypassAssumptions: nonNil(c.BypassAssumptions), RemovalProven: c.RemovalMutation != nil,
			Tests: testSet{
				Allowed: nonNil(c.Tests.Allowed), Forbidden: nonNil(c.Tests.Forbidden),
				Removal: nonNil(c.Tests.Removal), Bypass: nonNil(c.Tests.Bypass),
			},
		}
		for _, s := range c.EntryPoints {
			state := missing
			if r, ok := parseRef(s); ok {
				state = ev.reachability(r)
			}
			e.EntryPoints = append(e.EntryPoints, entryPointState{Symbol: s, Reachability: state})
		}
		cm.Controls = append(cm.Controls, e)
	}
	out, _ := json.MarshalIndent(cm, "", "  ")
	return append(out, '\n')
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// generateInvariants renders HELM_INVARIANTS.md. The invariant blocks keep the
// exact shape invcheck verify and concept-gate parse.
func generateInvariants(reg *registry) []byte {
	var b strings.Builder
	d := reg.Document
	fmt.Fprintf(&b, "---\ntitle: %s\nlast_reviewed: %s\n---\n\n# %s\n\n", d.Title, d.LastReviewed, d.Title)
	b.WriteString(ensureNewline(d.Preamble))
	b.WriteString("\n---\n\n## Enforcement status\n\n")
	b.WriteString(statusTable(reg))
	for _, s := range reg.Sections {
		fmt.Fprintf(&b, "\n---\n\n## %s\n", s.Title)
		if s.Intro != "" {
			b.WriteString("\n" + ensureNewline(s.Intro))
		}
		for _, c := range reg.Controls {
			if c.Section != s.ID || !strings.HasPrefix(c.ID, "INV-") {
				continue
			}
			fmt.Fprintf(&b, "\n### %s — %s\n\n%s\n", c.ID, c.Title, ensureNewline(c.Body))
			for _, v := range c.Verify {
				fmt.Fprintf(&b, "verify: %s\n", v)
			}
		}
	}
	return []byte(b.String())
}

func statusTable(reg *registry) string {
	s := summarizeStatus(reg)
	var b strings.Builder
	b.WriteString("Generated from [`controls.yaml`](controls.yaml) by `make controls`; do not edit\n")
	b.WriteString("this section or the invariant text below by hand. `make controls-check` fails\n")
	b.WriteString("when this file or `coverage-map.json` differs from the registry. An entry is\n")
	b.WriteString("`enforced` only when every entry point is reachable from a shipped binary\n")
	b.WriteString("(`scripts/ci/deadcode-roots.txt`) and its allowed, forbidden and removal tests\n")
	b.WriteString("exist. Everything else is `observed-only` or `unmanaged`, with the reason.\n\n")
	fmt.Fprintf(&b, "%d controls: %d enforced, %d observed-only, %d unmanaged (%d of them retired invariants).\n\n",
		s.Total, s.Enforced, s.ObservedOnly, s.Unmanaged, s.Retired)
	b.WriteString("| Id | Control | Status | Why it is not enforced |\n| --- | --- | --- | --- |\n")
	for _, c := range reg.Controls {
		status := c.Status
		if c.Retired {
			status = "retired"
		}
		reason := cell(c.Reason)
		if reason == "" {
			reason = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.ID, cell(c.Title), status, reason)
	}
	return b.String()
}

func cell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

func ensureNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func driftProblem(name string, committed, generated []byte) *issue {
	if bytes.Equal(committed, generated) {
		return nil
	}
	return &issue{Kind: "stale-generated", ID: name, Msg: name + " differs from what " + registryFile + " generates; run `make controls`"}
}

// ---------------------------------------------------------------------------
// self-test: planted bad entries must fail, a planted good one must pass
// ---------------------------------------------------------------------------

// Fixed positive references. The control symbol is the shipped binary's own
// main, so it is reachable by definition; the test is the one verify's control
// already depends on.
const (
	liveControlSymbol = "core/cmd/helm-ai-kernel.main"
	liveControlTest   = "core/pkg/canonicalize." + controlTest
)

type registryControl struct {
	name string
	want string // issue kind the check must report; empty means clean
	edit func(*entry)
}

func registryControls(deadSymbol string) []registryControl {
	return []registryControl{
		{"clean enforced entry is accepted", "", func(*entry) {}},
		{"entry with no owner is rejected", "missing-field", func(c *entry) { c.Owner = "" }},
		{"unknown status is rejected", "invalid-status", func(c *entry) { c.Status = "partially-enforced" }},
		{"observed-only entry with no reason is rejected", "missing-reason", func(c *entry) { c.Status = statusObservedOnly }},
		{"enforced entry with an unreachable entry point is rejected", "unreachable-entry-point",
			func(c *entry) { c.EntryPoints = []string{deadSymbol} }},
		{"entry point that does not exist is rejected", "unknown-entry-point",
			func(c *entry) { c.EntryPoints = []string{"core/cmd/helm-ai-kernel.invcheckControlMustNotExist"} }},
		{"test that does not exist is rejected", "unknown-test",
			func(c *entry) {
				c.Tests.Forbidden = []string{"core/pkg/canonicalize.TestInvcheckControlMustNotExistAnywhere"}
			}},
		{"enforced entry with no forbidden test is rejected", "missing-evidence", func(c *entry) { c.Tests.Forbidden = nil }},
		{"duplicate id is rejected", "duplicate-id", nil},
		{"entry removed from the registry is rejected", "missing-entry", func(c *entry) { c.ID = "CTL-002" }},
	}
}

func controlRegistry() *registry {
	return &registry{
		Version:  1,
		Document: document{Title: "Control", LastReviewed: "2026-01-01", Preamble: "Control.\n"},
		Controls: []entry{{
			ID: "CTL-001", Title: "planted control", Owner: "invcheck", Claim: "planted claim",
			Status: statusEnforced, EntryPoints: []string{liveControlSymbol},
			ProtectedOperations: []string{"none"}, BypassAssumptions: []string{"none"},
			Tests: testSet{Allowed: []string{liveControlTest}, Forbidden: []string{liveControlTest}, Removal: []string{liveControlTest}},
		}},
	}
}

func registrySelfTest(ev *evidence, deadSymbol string) []string {
	var failures []string
	for _, rc := range registryControls(deadSymbol) {
		reg := controlRegistry()
		if rc.edit == nil {
			reg.Controls = append(reg.Controls, reg.Controls[0])
		} else {
			rc.edit(&reg.Controls[0])
		}
		got := validate(reg, ev)
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
		dir := strings.TrimPrefix(fields[0], repoModule+"/")
		if strings.HasPrefix(dir, "core/") {
			return dir + "." + fields[1], nil
		}
	}
	return "", fmt.Errorf("%s records no unreachable function to plant", deadcodeFile)
}

// ---------------------------------------------------------------------------
// controls subcommand
// ---------------------------------------------------------------------------

func runControls(args []string) int {
	flags := flag.NewFlagSet("controls", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	write := flags.Bool("write", false, "regenerate "+constitution+" and "+coverageMapFile+" instead of checking them")
	_ = flags.Parse(args)

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

	fmt.Printf("invcheck controls self-test: %d controls against %d shipped packages, %d unreachable functions, %d listed tests\n",
		len(registryControls(deadSymbol))+1, len(ev.graph), len(ev.dead), len(ev.tests))
	if failures := registrySelfTest(ev, deadSymbol); len(failures) > 0 {
		fmt.Println("SELF-TEST FAILED — the checker no longer discriminates:")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Println("\nRefusing to judge " + registryFile + ".")
		return 2
	}
	for _, rc := range registryControls(deadSymbol) {
		want := rc.want
		if want == "" {
			want = "clean"
		}
		fmt.Printf("  ok  %-60s -> %s\n", rc.name, want)
	}
	fmt.Printf("  ok  %-60s -> %s\n", "stale generated file is rejected", "stale-generated")

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
	proven := 0
	for _, c := range reg.Controls {
		if c.RemovalMutation == nil || c.Status != statusEnforced {
			continue
		}
		before := len(found)
		found = append(found, proveRemoval(*root, c)...)
		if len(found) == before {
			proven++
			fmt.Printf("  removal proven: %s — %s fail with the control removed\n", c.ID, strings.Join(c.Tests.Removal, ", "))
		}
	}

	s := summarizeStatus(reg)
	fmt.Printf("\n%s: %d controls — %d enforced, %d observed-only, %d unmanaged (%d retired invariants); %d removal proof(s) by mutation\n",
		registryFile, s.Total, s.Enforced, s.ObservedOnly, s.Unmanaged, s.Retired, proven)
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
