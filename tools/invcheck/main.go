// Command invcheck enforces the invariant constitution in HELM_INVARIANTS.md.
//
// Two gates live here:
//
//	invcheck verify         every INV-NNN carries a verify: hint, ids are unique,
//	                        and every machine-checkable reference in a hint
//	                        actually resolves in this tree
//	invcheck concept-gate   a commit that changes an INV-NNN block carries a
//	                        CONCEPT-CHANGE(INV-NNN) marker naming that invariant
//
// verify runs synthetic negative controls BEFORE it reads the real constitution.
// A gate that has silently stopped discriminating is worse than no gate: it
// reports a green constitution it never actually inspected, and everyone
// downstream believes it. So the checker proves on known-bad and known-good
// input that it still answers differently, and if any control comes back the
// wrong way it fails ITSELF and renders no verdict on the real file at all.
//
// A hint may also carry free prose — "review question on any new adapter" is a
// legitimate human-owned obligation that no tool can discharge. invcheck does
// not check those and does not pretend to: it counts them and prints them under
// a heading that says nobody verified them.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const constitution = "HELM_INVARIANTS.md"

var (
	headingRe    = regexp.MustCompile(`^#{1,6}\s`)
	invHeadingRe = regexp.MustCompile(`^#{1,6}\s+(INV-(\d{3}))\b\s*(.*)$`)
	verifyRe     = regexp.MustCompile(`(?i)^\s*(?:[-*]\s*)?verify:\s*(.*)$`)
	backtickRe   = regexp.MustCompile("`([^`]+)`")
	testNameRe   = regexp.MustCompile(`^(?:Test|Fuzz|Benchmark)[A-Za-z0-9_]+$`)
	goTestFuncRe = regexp.MustCompile(`(?m)^func\s+((?:Test|Fuzz|Benchmark)[A-Za-z0-9_]*)\s*\(`)
	makeTargetRe = regexp.MustCompile(`(?m)^([A-Za-z0-9_][A-Za-z0-9_.\-]*):`)
	invRefRe     = regexp.MustCompile(`INV-\d{3}`)
	markerRe     = regexp.MustCompile(`CONCEPT-CHANGE\(([^)]*)\)`)
)

// pathExts are the suffixes that make a bare word a repo path even when it has
// no slash in it (a top-level file such as Makefile is matched by name instead).
var pathExts = []string{
	".go", ".py", ".sh", ".tla", ".cfg", ".lean", ".json", ".yml", ".yaml",
	".md", ".proto", ".toml", ".mod", ".ts", ".rs", ".java",
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "concept-gate":
		os.Exit(runConceptGate(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "invcheck: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `invcheck - enforce the HELM invariant constitution

  invcheck verify [-root DIR]
      Self-test on synthetic controls, then check HELM_INVARIANTS.md.

  invcheck concept-gate [-root DIR] [-range REV..REV] [-strict-any-edit]
      Require a CONCEPT-CHANGE(INV-NNN) commit marker on any commit in the
      range that adds, edits, or retires an invariant.
`)
}

// ---------------------------------------------------------------------------
// constitution model
// ---------------------------------------------------------------------------

type invariant struct {
	ID      string
	Line    int
	Title   string
	Body    []string
	Verify  []string
	Retired bool
}

// parse reads a constitution into invariant blocks. A block runs from its
// INV-NNN heading to the next heading of any level.
func parse(text string) []invariant {
	var out []invariant
	var cur *invariant
	for i, line := range strings.Split(text, "\n") {
		if m := invHeadingRe.FindStringSubmatch(line); m != nil {
			if cur != nil {
				out = append(out, *cur)
			}
			title := strings.TrimLeft(strings.TrimSpace(m[3]), "-—– ")
			cur = &invariant{ID: m[1], Line: i + 1, Title: title}
			cur.Retired = strings.Contains(strings.ToUpper(line), "RETIRED")
			continue
		}
		if headingRe.MatchString(line) {
			if cur != nil {
				out = append(out, *cur)
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		cur.Body = append(cur.Body, line)
		if m := verifyRe.FindStringSubmatch(line); m != nil {
			cur.Verify = append(cur.Verify, strings.TrimSpace(m[1]))
		}
		if strings.Contains(line, "RETIRED") {
			cur.Retired = true
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// ---------------------------------------------------------------------------
// resolution index
// ---------------------------------------------------------------------------

type index struct {
	root        string
	testNames   map[string]string
	makeTargets map[string]bool
}

func buildIndex(root string) (*index, error) {
	idx := &index{
		root:        root,
		testNames:   map[string]string{},
		makeTargets: map[string]bool{},
	}
	skip := map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "dist": true,
		"build": true, "target": true, "bin": true, ".venv": true,
		"__pycache__": true,
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for _, m := range goTestFuncRe.FindAllStringSubmatch(string(data), -1) {
			if _, seen := idx.testNames[m[1]]; !seen {
				idx.testNames[m[1]] = filepath.ToSlash(rel)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data, readErr := os.ReadFile(filepath.Join(root, "Makefile")); readErr == nil {
		for _, m := range makeTargetRe.FindAllStringSubmatch(string(data), -1) {
			idx.makeTargets[m[1]] = true
		}
	}
	return idx, nil
}

func (idx *index) pathExists(p string) bool {
	_, err := os.Stat(filepath.Join(idx.root, filepath.FromSlash(p)))
	return err == nil
}

// ---------------------------------------------------------------------------
// checking
// ---------------------------------------------------------------------------

type issue struct {
	Kind string
	ID   string
	Line int
	Msg  string
}

type result struct {
	issues []issue
	// prose records hint fragments no tool checked, so they are reported as
	// human-owned rather than counted as verified.
	prose   []string
	checked int
}

func (r *result) add(kind, id string, line int, format string, args ...any) {
	r.issues = append(r.issues, issue{Kind: kind, ID: id, Line: line, Msg: fmt.Sprintf(format, args...)})
}

func check(invs []invariant, idx *index) *result {
	res := &result{}

	seen := map[string]int{}
	for _, inv := range invs {
		if first, dup := seen[inv.ID]; dup {
			res.add("duplicate-id", inv.ID, inv.Line,
				"id is already used at line %d; ids are never reused, not even after retirement", first)
			continue
		}
		seen[inv.ID] = inv.Line

		if len(inv.Verify) == 0 {
			res.add("missing-hint", inv.ID, inv.Line,
				"no verify: hint; an invariant nobody can check is a wish, not an invariant")
			continue
		}
		if inv.Retired {
			joined := strings.Join(inv.Body, "\n")
			others := 0
			for _, ref := range invRefRe.FindAllString(joined, -1) {
				if ref != inv.ID {
					others++
				}
			}
			if others == 0 {
				res.add("retired-without-successor", inv.ID, inv.Line,
					"RETIRED but names no superseding INV-NNN")
			}
		}
		for _, hint := range inv.Verify {
			res.checkHint(inv, hint, idx)
		}
	}
	return res
}

// checkHint resolves the machine-checkable references inside one verify: hint.
// Backticked spans are the checkable surface; everything else is prose.
func (r *result) checkHint(inv invariant, hint string, idx *index) {
	spans := backtickRe.FindAllStringSubmatch(hint, -1)
	if len(spans) == 0 {
		r.prose = append(r.prose, fmt.Sprintf("%s: %s", inv.ID, strings.TrimSpace(hint)))
		return
	}
	for _, span := range spans {
		words := strings.Fields(span[1])
		if len(words) == 0 {
			continue
		}
		if words[0] == "make" {
			for _, target := range words[1:] {
				if strings.HasPrefix(target, "-") || strings.Contains(target, "=") {
					continue
				}
				r.checked++
				if !idx.makeTargets[target] {
					r.add("unknown-make-target", inv.ID, inv.Line,
						"verify: hint names make target %q, which the Makefile does not define", target)
				}
			}
			continue
		}
		for _, word := range words {
			switch {
			case testNameRe.MatchString(word):
				r.checked++
				if _, ok := idx.testNames[word]; !ok {
					r.add("unknown-test", inv.ID, inv.Line,
						"verify: hint names Go test %s, which does not exist in this tree", word)
				}
			case looksLikePath(word):
				r.checked++
				if !idx.pathExists(word) {
					r.add("unresolved-path", inv.ID, inv.Line,
						"verify: hint names path %s, which does not exist in this tree", word)
				}
			default:
				r.prose = append(r.prose, fmt.Sprintf("%s: %s", inv.ID, word))
			}
		}
	}
}

func looksLikePath(word string) bool {
	if strings.Contains(word, "/") {
		return true
	}
	for _, ext := range pathExts {
		if strings.HasSuffix(word, ext) {
			return true
		}
	}
	return word == "Makefile"
}

// ---------------------------------------------------------------------------
// self-test: synthetic negative and positive controls
// ---------------------------------------------------------------------------

// The positive control cites references that must exist in this repository. If
// one of them is ever deleted the self-test fails loudly rather than the real
// scan quietly going green on a checker that can no longer resolve anything.
const (
	controlPath = "core/pkg/canonicalize/jcs.go"
	controlTest = "TestCanonicalHash_Stability"
)

type control struct {
	name string
	doc  string
	// want is the issue kind the checker must report. Empty means the control
	// is clean and the checker must report nothing at all.
	want string
}

func controls() []control {
	good := "## INV-001 — a real invariant\n\nBody.\n\nverify: `" + controlPath + "` · test `" + controlTest + "`\n"
	return []control{
		{
			name: "clean input is accepted",
			doc:  good,
			want: "",
		},
		{
			name: "invariant with no verify: hint is rejected",
			doc:  "## INV-001 — no hint anywhere\n\nBody with no way to check it.\n",
			want: "missing-hint",
		},
		{
			name: "duplicate id is rejected",
			doc:  good + "\n## INV-001 — same id again\n\nverify: `" + controlPath + "`\n",
			want: "duplicate-id",
		},
		{
			name: "dangling repo path is rejected",
			doc:  "## INV-002 — cites a file that is not there\n\nverify: `core/pkg/definitely-not-a-package/nope.go`\n",
			want: "unresolved-path",
		},
		{
			name: "unknown Go test name is rejected",
			doc:  "## INV-003 — cites a test that is not there\n\nverify: test `TestInvcheckControlMustNotExistAnywhere`\n",
			want: "unknown-test",
		},
		{
			name: "unknown make target is rejected",
			doc:  "## INV-004 — cites a make target that is not there\n\nverify: `make invcheck-control-not-a-target`\n",
			want: "unknown-make-target",
		},
		{
			name: "retired invariant with no successor is rejected",
			doc:  "## INV-005 — RETIRED\n\nRetired with no pointer.\n\nverify: `" + controlPath + "`\n",
			want: "retired-without-successor",
		},
	}
}

// selfTest proves the checker still discriminates. Any control that comes back
// the wrong way means the gate has stopped working, and a broken gate must fail
// itself rather than green-light the constitution.
func selfTest(idx *index) []string {
	var failures []string
	for _, c := range controls() {
		got := check(parse(c.doc), idx)
		kinds := map[string]bool{}
		for _, is := range got.issues {
			kinds[is.Kind] = true
		}
		switch {
		case c.want == "" && len(got.issues) > 0:
			failures = append(failures, fmt.Sprintf(
				"control %q: expected a clean result, got %d issue(s): %s",
				c.name, len(got.issues), summarize(got.issues)))
		case c.want != "" && !kinds[c.want]:
			failures = append(failures, fmt.Sprintf(
				"control %q: expected issue kind %q, got %s",
				c.name, c.want, summarize(got.issues)))
		}
	}
	return failures
}

func summarize(issues []issue) string {
	if len(issues) == 0 {
		return "none"
	}
	var parts []string
	for _, is := range issues {
		parts = append(parts, is.Kind)
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func runVerify(args []string) int {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	_ = flags.Parse(args)

	idx, err := buildIndex(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: cannot index %s: %v\n", *root, err)
		return 2
	}

	fmt.Printf("invcheck self-test: %d controls against %d Go test names, %d make targets\n",
		len(controls()), len(idx.testNames), len(idx.makeTargets))
	if failures := selfTest(idx); len(failures) > 0 {
		fmt.Println("SELF-TEST FAILED — the checker no longer discriminates:")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Println()
		fmt.Println("Refusing to scan " + constitution + ". A gate that cannot tell good input")
		fmt.Println("from bad would report a green constitution it never really checked.")
		return 2
	}
	for _, c := range controls() {
		want := c.want
		if want == "" {
			want = "clean"
		}
		fmt.Printf("  ok  %-46s -> %s\n", c.name, want)
	}

	docPath := filepath.Join(*root, constitution)
	data, err := os.ReadFile(docPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: cannot read %s: %v\n", constitution, err)
		return 2
	}
	invs := parse(string(data))
	if len(invs) == 0 {
		fmt.Fprintf(os.Stderr, "invcheck: %s declares no INV-NNN blocks\n", constitution)
		return 1
	}

	res := check(invs, idx)
	retired := 0
	withProse := map[string]bool{}
	for _, p := range res.prose {
		withProse[strings.SplitN(p, ":", 2)[0]] = true
	}
	for _, inv := range invs {
		if inv.Retired {
			retired++
		}
	}

	fmt.Printf("\n%s: %d invariants (%d retired)\n", constitution, len(invs), retired)
	unresolved := 0
	for _, is := range res.issues {
		switch is.Kind {
		case "unresolved-path", "unknown-test", "unknown-make-target":
			unresolved++
		}
	}
	fmt.Printf("  %d machine-checkable reference(s) checked, %d resolved, %d unresolved\n",
		res.checked, res.checked-unresolved, unresolved)
	if len(res.prose) > 0 {
		fmt.Printf("  %d hint fragment(s) across %d invariant(s) are free prose — NOT verified by this gate, human-owned:\n",
			len(res.prose), len(withProse))
		for _, p := range res.prose {
			fmt.Printf("      %s\n", p)
		}
	}

	if len(res.issues) == 0 {
		fmt.Println("\ninvcheck verify: PASS")
		return 0
	}
	fmt.Printf("\ninvcheck verify: FAIL (%d issue(s))\n", len(res.issues))
	sort.Slice(res.issues, func(i, j int) bool { return res.issues[i].Line < res.issues[j].Line })
	for _, is := range res.issues {
		fmt.Printf("  %s:%d [%s] %s: %s\n", constitution, is.Line, is.Kind, is.ID, is.Msg)
	}
	return 1
}

// ---------------------------------------------------------------------------
// concept-gate
// ---------------------------------------------------------------------------

func runConceptGate(args []string) int {
	flags := flag.NewFlagSet("concept-gate", flag.ExitOnError)
	root := flags.String("root", ".", "repository root")
	rng := flags.String("range", "", "commit range, e.g. origin/main..HEAD (default: HEAD~1..HEAD)")
	strictAny := flags.Bool("strict-any-edit", false,
		"also require a marker when the file changed but no INV-NNN block did")
	_ = flags.Parse(args)

	commitRange := *rng
	if commitRange == "" {
		commitRange = "HEAD~1..HEAD"
	}

	out, err := git(*root, "rev-list", "--reverse", commitRange)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invcheck: cannot list %s: %v\n", commitRange, err)
		return 2
	}
	shas := strings.Fields(out)
	fmt.Printf("invcheck concept-gate: %d commit(s) in %s\n", len(shas), commitRange)

	var failures []string
	touched := 0
	for _, sha := range shas {
		names, err := git(*root, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
		if err != nil {
			continue
		}
		if !contains(strings.Fields(names), constitution) {
			continue
		}
		touched++

		changed := changedInvariants(*root, sha)
		msg, _ := git(*root, "log", "-1", "--format=%B", sha)
		named := markerIDs(msg)
		short := sha[:min(8, len(sha))]

		if len(changed) == 0 {
			if *strictAny && len(named) == 0 {
				failures = append(failures, fmt.Sprintf(
					"%s changed %s without a CONCEPT-CHANGE marker (-strict-any-edit)", short, constitution))
				continue
			}
			fmt.Printf("  ok  %s  %s edited, no INV-NNN block changed (prose only)\n", short, constitution)
			continue
		}
		if len(named) == 0 {
			failures = append(failures, fmt.Sprintf(
				"%s changed %s without a CONCEPT-CHANGE marker; it must name %s",
				short, strings.Join(changed, ", "), strings.Join(changed, ", ")))
			continue
		}
		var unnamed []string
		for _, id := range changed {
			if !named[id] {
				unnamed = append(unnamed, id)
			}
		}
		if len(unnamed) > 0 {
			failures = append(failures, fmt.Sprintf(
				"%s CONCEPT-CHANGE marker does not name %s", short, strings.Join(unnamed, ", ")))
			continue
		}
		var extra []string
		for id := range named {
			if !contains(changed, id) {
				extra = append(extra, id)
			}
		}
		sort.Strings(extra)
		note := ""
		if len(extra) > 0 {
			note = fmt.Sprintf(" (marker also names unchanged %s)", strings.Join(extra, ", "))
		}
		fmt.Printf("  ok  %s  CONCEPT-CHANGE names %s%s\n", short, strings.Join(changed, ", "), note)
	}

	if touched == 0 {
		fmt.Printf("  %s untouched in this range\n", constitution)
	}
	if len(failures) == 0 {
		fmt.Println("\ninvcheck concept-gate: PASS")
		return 0
	}
	fmt.Printf("\ninvcheck concept-gate: FAIL (%d commit(s))\n", len(failures))
	for _, f := range failures {
		fmt.Printf("  - %s\n", f)
	}
	fmt.Println("\nAmend the commit message to include a marker naming every invariant")
	fmt.Println("added, edited, or retired, e.g. CONCEPT-CHANGE(INV-007, INV-012).")
	return 1
}

// changedInvariants compares the constitution either side of a commit and
// returns the ids that were added, edited, or retired. Comparing parsed blocks
// rather than diff hunks means a change is attributed to the invariant that
// owns it, however the diff happened to be framed.
func changedInvariants(root, sha string) []string {
	before := map[string]string{}
	if text, err := git(root, "show", sha+"^:"+constitution); err == nil {
		before = blocks(text)
	}
	after := map[string]string{}
	if text, err := git(root, "show", sha+":"+constitution); err == nil {
		after = blocks(text)
	}
	changed := map[string]bool{}
	for id, body := range after {
		if before[id] != body {
			changed[id] = true
		}
	}
	for id := range before {
		if _, ok := after[id]; !ok {
			changed[id] = true
		}
	}
	out := make([]string, 0, len(changed))
	for id := range changed {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func blocks(text string) map[string]string {
	out := map[string]string{}
	for _, inv := range parse(text) {
		var trimmed []string
		for _, line := range inv.Body {
			trimmed = append(trimmed, strings.TrimRight(line, " \t"))
		}
		out[inv.ID] = inv.Title + "\n" + strings.Join(trimmed, "\n")
	}
	return out
}

func markerIDs(msg string) map[string]bool {
	ids := map[string]bool{}
	for _, m := range markerRe.FindAllStringSubmatch(msg, -1) {
		for _, id := range invRefRe.FindAllString(m[1], -1) {
			ids[id] = true
		}
	}
	return ids
}

func git(root string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	return string(out), err
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
