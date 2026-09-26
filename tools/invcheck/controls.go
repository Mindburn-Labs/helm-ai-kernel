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
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
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

// ref is a Go symbol or test named "<dir>.<name>", with dir relative to the
// repository root: core/pkg/firewall.EgressChecker.CheckEgress,
// core/pkg/firewall.TestEgressChecker_EmptyPolicyDenyAll. Symbols live in the
// core module; tests may also live in a tools/ module.
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
	if (!strings.HasPrefix(r.Dir, "core/") && !strings.HasPrefix(r.Dir, "tools/")) || r.Name == "" {
		return ref{}, false
	}
	return r, true
}

func (r ref) importPath() string { return repoModule + "/" + r.Dir }
func (r ref) key() string        { return r.importPath() + " " + r.Name }
func (r ref) String() string     { return r.Dir + "." + r.Name }

// module is the Go module that owns dir: core, or one of the tools/ modules
// that the workspace does not include.
func module(dir string) string {
	if strings.HasPrefix(dir, "core/") {
		return "core"
	}
	parts := strings.Split(dir, "/")
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return dir
}

// ---------------------------------------------------------------------------
// evidence: what the tree says about the registry's references
// ---------------------------------------------------------------------------

type evidence struct {
	graph    map[string]bool   // import paths the shipped binaries depend on
	dead     map[string]bool   // "<import path> <symbol>" that no shipped binary reaches
	declared map[string]bool   // "<import path> <symbol>" in the linux/amd64 build
	tests    map[string]string // "<dir>.<Test>" -> pass, fail or skip, as go test reported it
	postgres map[string]bool   // "<dir>.<Test>" listed in scripts/ci/postgres-proofs.txt
	gates    map[string]string // "quality:<id>" or "workflow:<file>#<job>" -> "" when blocking, else why not
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

func gatherEvidence(root string, symbols, tests []ref) (*evidence, error) {
	ev := &evidence{graph: map[string]bool{}, dead: map[string]bool{}, declared: map[string]bool{}}

	roots, err := readRoots(root)
	if err != nil {
		return nil, err
	}
	out, err := goCmd(root, "core", []string{"GOWORK=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"},
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

	if ev.postgres, err = readPostgresProofs(root); err != nil {
		return nil, err
	}
	if ev.tests, err = runTests(root, tests, ev.postgres); err != nil {
		return nil, err
	}
	if ev.gates, err = blockingGates(root); err != nil {
		return nil, err
	}
	return ev, nil
}

// runTests runs every named test once, grouped by module, and records how each
// ended. Tests listed in postgres-proofs.txt are left to the CI job that runs
// them against Postgres and fails on a skip. Everything else runs here with
// Postgres withheld, so an unlisted Postgres-gated test shows up as a skip.
func runTests(root string, tests []ref, postgres map[string]bool) (map[string]string, error) {
	results := map[string]string{}
	byModule := map[string][]ref{}
	for _, r := range tests {
		if !postgres[r.String()] {
			byModule[module(r.Dir)] = append(byModule[module(r.Dir)], r)
		}
	}
	mods := make([]string, 0, len(byModule))
	for m := range byModule {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	for _, mod := range mods {
		refs := byModule[mod]
		args := append([]string{"test", "-json", "-run", runPattern(refs)}, packageArgs(mod, refs)...)
		out, err := goCmd(root, mod, testEnv(mod), args...)
		events, perr := testEvents(out)
		if perr != nil {
			return nil, fmt.Errorf("go test in %s: %v", mod, perr)
		}
		for key, action := range outcomes(events) {
			results[key] = action
		}
		if err != nil {
			// A failing or unbuildable package is reported per test below,
			// by the tests that did not pass.
			fmt.Printf("  note: go test in %s exited %v\n", mod, err)
		}
	}
	return results, nil
}

func testEnv(mod string) []string {
	env := []string{"HELM_TEST_POSTGRES_URL="}
	if mod != "core" {
		env = append(env, "GOWORK=off")
	}
	return env
}

func runPattern(refs []ref) string {
	seen := map[string]bool{}
	var names []string
	for _, r := range refs {
		if !seen[r.Name] {
			seen[r.Name] = true
			names = append(names, regexp.QuoteMeta(r.Name))
		}
	}
	sort.Strings(names)
	return "^(" + strings.Join(names, "|") + ")$"
}

func packageArgs(mod string, refs []ref) []string {
	var pkgs []string
	for _, dir := range uniqueDirs(refs) {
		rel := strings.TrimPrefix(strings.TrimPrefix(dir, mod), "/")
		if rel == "" {
			pkgs = append(pkgs, ".")
			continue
		}
		pkgs = append(pkgs, "./"+rel)
	}
	return pkgs
}

// outcomes keys every top-level test result as "<dir>.<Test>".
func outcomes(events []testEvent) map[string]string {
	got := map[string]string{}
	for _, ev := range events {
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			got[strings.TrimPrefix(ev.Package, repoModule+"/")+"."+ev.Test] = ev.Action
		}
	}
	return got
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

// readPostgresProofs reads "<package dir under core> <test> <count> <mode>".
func readPostgresProofs(root string) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(root, postgresFile))
	if err != nil {
		return nil, err
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		listed["core/"+fields[0]+"."+fields[1]] = true
	}
	return listed, nil
}

// blockingGates records every gate a build-plane entry could name. Under CI v2
// the PR workflow runs `make check` (directly or through a local reusable
// workflow), and the Makefile's check recipe names the quality profile it runs
// and whether it runs it with --strict. A quality gate blocks when it is in
// that profile and is not advisory, or the profile runs strict (strict turns
// advisory failures into failures). A workflow job blocks when it runs on
// pull_request with no job-level condition or continue-on-error.
func blockingGates(root string) (map[string]string, error) {
	gates := map[string]string{}

	data, err := os.ReadFile(filepath.Join(root, qualityGatesFile))
	if err != nil {
		return nil, err
	}
	var quality struct {
		Profiles map[string]struct {
			Gates []string `json:"gates"`
		} `json:"profiles"`
		Gates []struct {
			ID       string `json:"id"`
			Advisory bool   `json:"advisory"`
		} `json:"gates"`
	}
	if err := json.Unmarshal(data, &quality); err != nil {
		return nil, fmt.Errorf("%s: %v", qualityGatesFile, err)
	}
	profile, strict := checkProfile(root)
	inProfile := map[string]bool{}
	for _, id := range quality.Profiles[profile].Gates {
		inProfile[id] = true
	}
	profileRuns := profile != "" && prWorkflowRunsCheck(root)
	for _, g := range quality.Gates {
		why := ""
		switch {
		case !profileRuns:
			why = prWorkflowFile + " does not run make check"
		case !inProfile[g.ID]:
			why = "not in the " + profile + " profile that make check runs"
		case g.Advisory && !strict:
			why = "advisory"
		}
		gates["quality:"+g.ID] = why
	}

	files, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var wf struct {
			On   any                       `yaml:"on"`
			Jobs map[string]map[string]any `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		onPR := triggers(wf.On)["pull_request"]
		rel, _ := filepath.Rel(root, path)
		for job, spec := range wf.Jobs {
			why := ""
			switch {
			case !onPR:
				why = "the workflow does not run on pull_request"
			case spec["if"] != nil:
				why = "the job has an if: condition"
			case spec["continue-on-error"] == true:
				why = "the job continues on error"
			}
			gates["workflow:"+filepath.ToSlash(rel)+"#"+job] = why
		}
	}
	return gates, nil
}

func triggers(on any) map[string]bool {
	out := map[string]bool{}
	switch v := on.(type) {
	case string:
		out[v] = true
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out[s] = true
			}
		}
	case map[string]any:
		for k := range v {
			out[k] = true
		}
	}
	return out
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

// goCmd runs the go command in a module directory and returns stdout, or
// stdout and stderr together when it fails.
func goCmd(root, mod string, env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(root, filepath.FromSlash(mod))
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
// removal proofs: the named tests fail when the control is removed
// ---------------------------------------------------------------------------

// proveRemoval applies one mutation and requires every test it names to fail.
// A mutation that does not compile, or an anchor that does not match exactly
// once, proves nothing. The tests passing without the mutation is checked by
// the run of all named tests.
func proveRemoval(root string, rp removalProof) problems {
	var p problems
	path := filepath.Join(root, filepath.FromSlash(rp.File))
	src, err := os.ReadFile(path)
	if err != nil {
		p.add("mutation-anchor", rp.Control, "cannot read %s: %v", rp.File, err)
		return p
	}
	if n := strings.Count(string(src), rp.Find); n != 1 {
		p.add("mutation-anchor", rp.Control, "removal proof find must match %s exactly once (matches %d)", rp.File, n)
		return p
	}

	tmp, err := os.MkdirTemp("", "invcheck-mutation-")
	if err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}
	defer os.RemoveAll(tmp)
	mutated := filepath.Join(tmp, filepath.Base(path))
	overlay := filepath.Join(tmp, "overlay.json")
	absPath, _ := filepath.Abs(path)
	spec, _ := json.Marshal(map[string]map[string]string{"Replace": {absPath: mutated}})
	if err := os.WriteFile(mutated, []byte(strings.Replace(string(src), rp.Find, rp.Replace, 1)), 0o600); err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}
	if err := os.WriteFile(overlay, spec, 0o600); err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}

	var refs []ref
	for _, s := range rp.Tests {
		if r, ok := parseRef(s); ok {
			refs = append(refs, r)
		}
	}
	if len(refs) == 0 {
		return p
	}
	mod := module(refs[0].Dir)
	// A deleted control can turn a refusal into a call that blocks (a server
	// that now starts, say). The timeout bounds that; a killed run proves nothing.
	args := append([]string{"test", "-json", "-count=1", "-timeout", mutationTimeout, "-overlay", overlay, "-run", runPattern(refs)}, packageArgs(mod, refs)...)
	out, _ := goCmd(root, mod, testEnv(mod), args...)
	timedOut := strings.Contains(out, "panic: test timed out")
	events, err := testEvents(out)
	if err != nil {
		p.add("mutation-run", rp.Control, "%v", err)
		return p
	}
	got := outcomes(events)
	for _, s := range rp.Tests {
		if got[s] != "fail" {
			action := got[s]
			switch {
			case action == "" && timedOut:
				action = "no result: the run hit the " + mutationTimeout + " timeout, so the test blocks without the control"
			case action == "":
				action = "did not run (does the mutated package compile?)"
			}
			p.add("removal-not-proven", rp.Control, "%s with the control removed (%s): want fail, got %s", s, rp.File, action)
		}
	}
	return p
}

// proveAll runs the removal proofs a few at a time; each is an independent
// build of the mutated package and its tests.
func proveAll(root string, proofs []removalProof) (problems, int) {
	workers := runtime.NumCPU() / 2
	if workers < 2 {
		workers = 2
	}
	results := make([]problems, len(proofs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, rp := range proofs {
		wg.Add(1)
		go func(i int, rp removalProof) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = proveRemoval(root, rp)
		}(i, rp)
	}
	wg.Wait()
	var all problems
	proven := 0
	for i, r := range results {
		if len(r) == 0 {
			proven++
			fmt.Printf("  removal proven: %s — %s fails without the control\n", proofs[i].Control, strings.Join(proofs[i].Tests, ", "))
		}
		all = append(all, r...)
	}
	return all, proven
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
	BuildPlane   int `json:"build_plane"`
}

type coverageEntry struct {
	ID                  string            `json:"id"`
	Title               string            `json:"title"`
	Owner               string            `json:"owner"`
	Claim               string            `json:"claim"`
	Status              string            `json:"status"`
	Plane               string            `json:"plane"`
	Reason              string            `json:"reason,omitempty"`
	Retired             bool              `json:"retired,omitempty"`
	EntryPoints         []entryPointState `json:"entry_points"`
	Gates               []string          `json:"gates"`
	Config              []string          `json:"config"`
	ProtectedOperations []string          `json:"protected_operations"`
	BypassAssumptions   []string          `json:"bypass_assumptions"`
	Tests               testSet           `json:"tests"`
	RemovalProofs       []proofSummary    `json:"removal_proofs"`
}

type entryPointState struct {
	Symbol       string `json:"symbol"`
	Reachability string `json:"reachability"`
}

type proofSummary struct {
	File  string   `json:"file"`
	Tests []string `json:"tests"`
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
		if c.plane() == planeBuild {
			s.BuildPlane++
		}
	}
	return s
}

func generateCoverageMap(reg *registry, ev *evidence) []byte {
	cm := coverageMap{
		GeneratedFrom: registryFile + " via make controls; do not edit by hand",
		Rule: "R1: an entry is enforced only on its tested path: reachable from a shipped binary, " +
			"its tests passing, and its removal tests failing once the control is deleted",
		Annotations: []string{"quantum_posture: this map records which code paths hold existing signing, " +
			"hashing and key-separation properties; it pins no algorithm and makes no post-quantum claim"},
		Summary:  summarizeStatus(reg),
		Controls: []coverageEntry{},
	}
	for _, c := range reg.Controls {
		e := coverageEntry{
			ID: c.ID, Title: c.Title, Owner: c.Owner, Claim: strings.TrimSpace(c.Claim), Status: c.Status,
			Plane: c.plane(), Reason: strings.TrimSpace(c.Reason), Retired: c.Retired,
			EntryPoints: []entryPointState{}, Gates: nonNil(c.Gates), Config: nonNil(c.Config),
			ProtectedOperations: nonNil(c.ProtectedOperations), BypassAssumptions: nonNil(c.BypassAssumptions),
			Tests: testSet{
				Allowed: nonNil(c.Tests.Allowed), Forbidden: nonNil(c.Tests.Forbidden),
				Removal: nonNil(c.Tests.Removal), Bypass: nonNil(c.Tests.Bypass),
			},
			RemovalProofs: []proofSummary{},
		}
		for _, s := range c.EntryPoints {
			state := missing
			if r, ok := parseRef(s); ok {
				state = ev.reachability(r)
			}
			e.EntryPoints = append(e.EntryPoints, entryPointState{Symbol: s, Reachability: state})
		}
		for _, rp := range reg.RemovalProofs {
			if rp.Control == c.ID {
				e.RemovalProofs = append(e.RemovalProofs, proofSummary{File: rp.File, Tests: nonNil(rp.Tests)})
			}
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
	b.WriteString("when this file or `coverage-map.json` differs from the registry. A runtime\n")
	b.WriteString("entry is `enforced` only when every entry point is reachable from a shipped\n")
	b.WriteString("binary (`scripts/ci/deadcode-roots.txt`), its allowed, forbidden and removal\n")
	b.WriteString("tests run and pass, and deleting the control makes its removal tests fail. A\n")
	b.WriteString("`build` entry is held by CI gates that block pull requests. Everything else\n")
	b.WriteString("is `observed-only` or `unmanaged`, with the reason.\n\n")
	fmt.Fprintf(&b, "%d controls: %d enforced (%d of them by CI gates), %d observed-only, %d unmanaged (%d of them retired invariants).\n\n",
		s.Total, s.Enforced, s.BuildPlane, s.ObservedOnly, s.Unmanaged, s.Retired)
	b.WriteString("| Id | Control | Status | Why it is not enforced |\n| --- | --- | --- | --- |\n")
	for _, c := range reg.Controls {
		status := c.Status
		switch {
		case c.Retired:
			status = "retired"
		case c.plane() == planeBuild:
			status += " (build)"
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

// checkProfile reads the Makefile's check recipe and returns the quality
// profile it runs and whether it runs it with --strict. It returns "" when the
// recipe is missing or names no profile.
func checkProfile(root string) (profile string, strict bool) {
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		return "", false
	}
	inCheck := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "check:"):
			inCheck = true
			continue
		case !inCheck:
			continue
		case !strings.HasPrefix(line, "\t"):
			return profile, strict
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "run" && i+1 < len(fields) && profile == "" {
				profile = fields[i+1]
			}
			if f == "--strict" {
				strict = true
			}
		}
	}
	return profile, strict
}

// platformCIWorkflow is the CI v2 reusable workflow; its check job runs
// `make check` by contract.
const platformCIWorkflow = "Mindburn-Labs/platform-actions/.github/workflows/ci.yml@"

// prWorkflowRunsCheck reports whether the PR workflow, a local reusable
// workflow it calls, or the platform-actions CI v2 workflow runs `make check`.
func prWorkflowRunsCheck(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, prWorkflowFile))
	if err != nil {
		return false
	}
	text := string(data)
	for _, line := range strings.Split(text, "\n") {
		ref := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "uses:"))
		if strings.HasPrefix(strings.TrimSpace(line), "uses:") && strings.HasPrefix(ref, platformCIWorkflow) {
			return true
		}
		if strings.HasPrefix(strings.TrimSpace(line), "uses:") && strings.HasPrefix(ref, "./.github/workflows/") {
			if called, err := os.ReadFile(filepath.Join(root, strings.TrimPrefix(ref, "./"))); err == nil {
				text += "\n" + string(called)
			}
		}
	}
	return strings.Contains(text, "make check")
}
