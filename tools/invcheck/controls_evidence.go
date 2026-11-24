package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

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
