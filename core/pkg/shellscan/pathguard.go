package shellscan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"mvdan.cc/sh/v3/syntax"
)

// PathGuard names files and directories that no tool call may touch, such as
// the caller's own signing keys. It answers one question about a path or a
// piece of text: does this refer to that material? Paths are compared after
// expanding the home directory, resolving against the working directory,
// cleaning, and following symbolic links, so another spelling of a protected
// path is still that path. Comparison ignores case: on a case-insensitive
// filesystem two spellings name one file, and elsewhere the cost is only a
// refusal of a file that differs from a protected one by case.
//
// A PathGuard reads the filesystem to follow links. It never grants anything:
// a match can only add a refusal.
type PathGuard struct {
	home       string
	files      []guardedPath // exact files
	trees      []guardedPath // directories whose whole content is protected
	containers []guardedPath // directories protected only when named themselves
	needles    []string      // text that names protected material wherever it appears
	names      []string      // file names protected wherever they are, in lower case

	// resolved caches resolveExisting by path, so a command that names one
	// directory many times looks it up once. targets is protectedTargets,
	// built once, when listed is set.
	mu       sync.Mutex
	resolved map[string]string
	targets  []globTarget
	listed   bool

	// stop is set when the caller has stopped waiting for the guard.
	stop atomic.Bool
}

// stoppedRule is what every decision of a stopped guard reports.
const stoppedRule = "classification stopped at its deadline"

// Stop ends the guard's work: every decision it makes from now on, and every
// one still running, ends at once as a match. A classifier its caller has
// given up on stops instead of running on, and nothing it could not finish
// passes.
func (g *PathGuard) Stop() {
	if g != nil {
		g.stop.Store(true)
	}
}

func (g *PathGuard) stopped() bool {
	return g != nil && g.stop.Load()
}

// guardedPath is one protected location, as written and as it resolves. The
// two forms are in lower case for comparison; dir keeps the resolved path's
// own case so the directory can be listed.
type guardedPath struct {
	lexical  string
	resolved string
	dir      string
}

func (p guardedPath) forms() []string {
	if p.resolved == p.lexical {
		return []string{p.lexical}
	}
	return []string{p.lexical, p.resolved}
}

// NewPathGuard returns a guard that expands "~" and $HOME to home. An empty
// home leaves those spellings to the text match.
func NewPathGuard(home string) *PathGuard {
	guard := &PathGuard{}
	if home != "" {
		guard.home = cleanSlash(home)
	}
	return guard
}

// ProtectFile protects one file.
func (g *PathGuard) ProtectFile(file string) {
	if location, ok := g.locate(file); ok {
		g.files = append(g.files, location)
		g.addNeedles(location)
	}
}

// ProtectTree protects a directory and everything in it.
func (g *PathGuard) ProtectTree(dir string) {
	if location, ok := g.locate(dir); ok {
		g.trees = append(g.trees, location)
		g.addNeedles(location)
	}
}

// ProtectContainer protects a directory when a command names it directly, as
// a recursive copy or archive would, without protecting what else is in it.
func (g *PathGuard) ProtectContainer(dir string) {
	if location, ok := g.locate(dir); ok {
		g.containers = append(g.containers, location)
	}
}

// ProtectName protects a file name wherever it appears as the last part of a
// path, for names specific enough that no unrelated file carries them. A bare
// mention, as in a search for the name, is not a path and is left alone.
func (g *PathGuard) ProtectName(name string) {
	if name = strings.ToLower(name); name != "" {
		g.needles = append(g.needles, "/"+name)
		g.names = append(g.names, name)
	}
}

func (g *PathGuard) locate(location string) (guardedPath, bool) {
	if location == "" {
		return guardedPath{}, false
	}
	absolute := filepath.FromSlash(location)
	if !filepath.IsAbs(absolute) {
		cwd, err := os.Getwd()
		if err != nil {
			return guardedPath{}, false
		}
		// Abs/Join clean parent segments before following symlinks.
		absolute = cwd + string(filepath.Separator) + absolute
	}
	resolved := resolveExisting(absolute)
	return guardedPath{
		lexical:  strings.ToLower(cleanSlash(absolute)),
		resolved: strings.ToLower(resolved),
		dir:      resolved,
	}, true
}

func (g *PathGuard) addNeedles(location guardedPath) {
	for _, form := range location.forms() {
		g.needles = append(g.needles, form)
		home := strings.ToLower(g.home)
		if home == "" || !strings.HasPrefix(form, home+"/") {
			continue
		}
		relative := form[len(home)+1:]
		g.needles = append(g.needles, "~/"+relative, "$home/"+relative, "${home}/"+relative)
		// A dot directory under home is distinctive enough to recognise when a
		// program joins it to the home directory itself.
		if strings.HasPrefix(relative, ".") && strings.Contains(relative, "/") {
			g.needles = append(g.needles, relative)
		}
	}
}

// MatchText reports whether free text, such as a command line or a program
// passed to an interpreter, names protected material.
func (g *PathGuard) MatchText(text string) (string, bool) {
	if g == nil || len(g.needles) == 0 {
		return "", false
	}
	if g.stopped() {
		return stoppedRule, true
	}
	text = strings.ToLower(slashPath(text))
	for strings.Contains(text, "//") {
		text = strings.ReplaceAll(text, "//", "/")
	}
	for strings.Contains(text, "/./") {
		text = strings.ReplaceAll(text, "/./", "/")
	}
	for _, needle := range g.needles {
		for offset := 0; ; {
			index := strings.Index(text[offset:], needle)
			if index < 0 {
				break
			}
			end := offset + index + len(needle)
			// "keys" must not match inside "keys-old": the name ends here.
			if end == len(text) || !pathNameByte(text[end]) {
				return needle, true
			}
			offset += index + 1
		}
	}
	return "", false
}

func pathNameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-'
}

// Match reports whether target, a path as a tool would receive it, refers to
// protected material. Whitespace is part of a filesystem name, so target and
// cwd are never trimmed. A relative target is resolved against cwd; with no cwd
// only the text match applies.
func (g *PathGuard) Match(target, cwd string) (string, bool) {
	native := nativePath(target)
	if rule, ok := g.matchPattern(globEscape(native), -1, cwd, false); ok {
		return rule, true
	}
	// A tool that accepts Windows spellings reads a backslash as a separator,
	// so a location protected under that reading of the target and of the
	// working directory is refused as well.
	if converted := slashPath(target); converted != native || slashPath(cwd) != nativePath(cwd) {
		return g.matchPattern(globEscape(converted), -1, slashPath(cwd), false)
	}
	return "", false
}

// matchPattern takes a path in shell glob syntax (a backslash quotes the next
// byte). dynamicAt, when not negative, is where a part computed at run time
// begins: only the text before it is known. dotGlob lets a wildcard match a
// leading dot.
func (g *PathGuard) matchPattern(pattern string, dynamicAt int, cwd string, dotGlob bool) (string, bool) {
	if g == nil || pattern == "" {
		return "", false
	}
	if g.stopped() {
		return stoppedRule, true
	}
	if dynamicAt < 0 {
		if local, ok := localFileURLPath(unescapeLit(pattern)); ok {
			// URL decoding precedes the same literal-path, symlink and name
			// checks as a filesystem argument. Escaping preserves literal glob
			// characters that were percent-encoded in the URL.
			if rule, protected := g.Match(local, cwd); protected {
				return rule, true
			}
		}
	}
	if needle, ok := g.MatchText(unescapeLit(pattern)); ok {
		return needle, true
	}
	if dynamicAt >= 0 {
		prefix, ok := g.absolute(pattern[:dynamicAt], cwd)
		if !ok {
			return "", false
		}
		return g.reachesInto(unescapeLit(prefix))
	}
	absolute, ok := g.absolute(pattern, cwd)
	if !ok {
		return "", false
	}
	if !hasGlobPattern(absolute) {
		return g.matchConcrete(unescapeLit(absolute))
	}
	return g.matchShellGlob(absolute, dotGlob)
}

// absolute expands the home directory and anchors a relative path at cwd.
// It does not clean the result: a caller matching a prefix needs it as typed.
// target may be in glob syntax, so its backslashes are left alone.
func (g *PathGuard) absolute(target, cwd string) (string, bool) {
	for _, home := range []string{"~", "$HOME", "${HOME}"} {
		if target == home || strings.HasPrefix(target, home+"/") {
			if g.home == "" {
				return "", false
			}
			target = globEscape(g.home) + target[len(home):]
		}
	}
	if path.IsAbs(target) {
		return target, true
	}
	if cwd = nativePath(cwd); cwd == "" || !path.IsAbs(cwd) {
		return "", false
	}
	return globEscape(strings.TrimSuffix(cwd, "/")) + "/" + target, true
}

func (g *PathGuard) matchConcrete(absolute string) (string, bool) {
	candidates := []string{strings.ToLower(path.Clean(absolute)), strings.ToLower(g.resolve(absolute))}
	return g.firstForm(func(kind int, form string) bool {
		for _, candidate := range candidates {
			if candidate == form || kind == protectedTree && strings.HasPrefix(candidate, form+"/") {
				return true
			}
		}
		return false
	})
}

// The kinds of protected location, in the order firstForm visits them.
const (
	protectedFile = iota
	protectedTree
	protectedContainer
)

// firstForm returns the first form of a protected location that accepts.
func (g *PathGuard) firstForm(accepts func(kind int, form string) bool) (string, bool) {
	for kind, set := range [][]guardedPath{g.files, g.trees, g.containers} {
		for _, location := range set {
			for _, form := range location.forms() {
				if accepts(kind, form) {
					return form, true
				}
			}
		}
	}
	return "", false
}

// Globs are read in a small grammar ("/"-separated segments of literal
// characters, "*" and "?", a whole "**", and in a search glob brace groups);
// inside it a glob is matched as any supported tool may anchor it, and a glob
// outside it is not read.

// globTarget is a path a glob may name, in lower-case parts (the first below
// of them the search root's), and the protected location it belongs to. open:
// a directory not all listed. explicitDot: a container, which a wildcard names
// only when the pattern writes its leading dot. anyAbove: leading segments may
// name any directories above it, and the rest must name it from its first
// part, so "*.json" does not name ".docker/config.json".
type globTarget struct {
	parts                       []string
	form                        string
	below                       int
	open, explicitDot, anyAbove bool
}

// maxTreeEntries bounds the entries listed of one protected directory.
const maxTreeEntries = 1024

// protectedTargets lists, once per guard, the protected files, each protected
// directory with what it holds and the protected names, and the containers.
func (g *PathGuard) protectedTargets() []globTarget {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.listed {
		return g.targets
	}
	g.listed = true
	add := func(locations []guardedPath, entries [][]string, open, explicitDot bool) {
		for _, location := range locations {
			for _, form := range location.forms() {
				g.targets = append(g.targets, globTarget{parts: pathParts(form), form: form, open: open, explicitDot: explicitDot})
				for _, entry := range entries {
					g.targets = append(g.targets, globTarget{parts: append(pathParts(form), entry...), form: form})
				}
			}
		}
	}
	add(g.files, nil, false, false)
	add(g.containers, nil, false, true)
	for _, tree := range g.trees {
		listed, complete := listTree(tree.dir, maxTreeEntries, g.stopped)
		var entries [][]string
		for _, entry := range append(listed, g.names...) {
			entries = append(entries, strings.Split(entry, "/"))
		}
		add([]guardedPath{tree}, entries, !complete, false)
	}
	return g.targets
}

// listTree lists up to limit entries below dir, as lower-case slash paths
// relative to it. complete is false when it stopped short, was stopped or dir
// could not be read; a directory below dir that cannot be read is left out.
func listTree(dir string, limit int, stop func() bool) (entries []string, complete bool) {
	dir, complete = filepath.FromSlash(dir), true
	_ = filepath.WalkDir(dir, func(name string, _ fs.DirEntry, err error) error {
		rel, relErr := filepath.Rel(dir, name)
		switch {
		case err != nil:
			complete = complete && (name != dir || errors.Is(err, fs.ErrNotExist))
		case relErr != nil || len(entries) == limit || stop != nil && stop():
			complete = false
			return fs.SkipAll
		case rel != ".":
			entries = append(entries, strings.ToLower(filepath.ToSlash(rel)))
		}
		return nil
	})
	return entries, complete
}

// maxShellGlobSegment is the longest shell glob segment the guard matches
// name by name. No file name is longer than 255 bytes, and a segment that
// names one is not four times as long.
const maxShellGlobSegment = 1024

// matchShellGlob reports whether an absolute shell glob can expand to
// protected material. Links in its literal leading directories are followed.
// A glob with a bracket class is outside the grammar, and a segment longer
// than maxShellGlobSegment is not matched: either matches when the directory
// the glob starts in reaches protected material (searchGate).
func (g *PathGuard) matchShellGlob(pattern string, dotGlob bool) (string, bool) {
	segments := pathParts(strings.ReplaceAll(pattern, `\/`, "/"))
	literal := 0
	for literal < len(segments) && !hasGlobPattern(segments[literal]) {
		literal++
	}
	start := "/" + unescapeLit(strings.Join(segments[:literal], "/"))
	// Preserve the filesystem spelling for link resolution; only comparisons
	// are case-insensitive. Folding first loses aliases on Linux.
	for i := 0; i < literal; i++ {
		segments[i] = strings.ToLower(segments[i])
	}
	// A run of "**" names what one does.
	glob := make([]string, 0, len(segments)-literal)
	for _, segment := range segments[literal:] {
		if len(segment) > maxShellGlobSegment || bracketClass(segment) {
			return g.searchGate(start)
		}
		segment = strings.ToLower(segment)
		if segment != "**" || len(glob) == 0 || glob[len(glob)-1] != "**" {
			glob = append(glob, segment)
		}
	}
	candidates := [][]string{append(segments[:literal:literal], glob...)}
	// Keep lexical coverage for parent segments after a wildcard, while the
	// resolved literal prefix below also checks the actual symlink traversal.
	lexical := "/" + strings.Join(candidates[0], "/")
	if cleaned := path.Clean(lexical); cleaned != lexical {
		candidates = append(candidates, pathParts(cleaned))
	}
	if resolved := strings.ToLower(g.resolve(start)); resolved != strings.ToLower(start) {
		candidates = append(candidates, append(pathParts(globEscape(resolved)), glob...))
	}
	for _, candidate := range candidates {
		for _, target := range g.protectedTargets() {
			if g.stopped() {
				return stoppedRule, true
			}
			if fits(candidate, target, true, dotGlob && !target.explicitDot) {
				return target.form, true
			}
		}
	}
	return "", false
}

// bracketClass reports a "[" that a "]" follows, which the grammar leaves
// out. The last "]" is found once, so a segment of many "[" costs one pass.
func bracketClass(segment string) bool {
	last := strings.LastIndexByte(segment, ']')
	for i := 0; i < last; i++ {
		switch segment[i] {
		case '\\':
			i++
		case '[':
			return true
		}
	}
	return false
}

// fits reports whether pattern can name target. Anchored, it names target in
// full, as a shell word does. A search glob, which a tool anchors where it
// runs, may name target from the root or above it after leading segments that
// can name ".." (a root written relative to the tool), and may name what lies
// at any depth below the root. Without dotGlob a wildcard skips leading dots.
func fits(pattern []string, target globTarget, anchored, dotGlob bool) bool {
	t := target.parts
	if len(t) == 0 && !target.open {
		return false
	}
	dots := 0
	for !anchored && dots < len(pattern) && (target.anyAbove || pattern[dots] == "**" || segmentMatch(pattern[dots], "..", true)) {
		dots++
	}
	// Past the last len(t) segments other than "**", a pattern can only name
	// directories above a target that is not open.
	start, count := 0, 0
	for i := len(pattern) - 1; i >= 0 && !target.open && start == 0; i-- {
		if pattern[i] != "**" {
			if count++; count > len(t) {
				start = i + 1
			}
		}
	}
	if start > 0 && (anchored || start > dots) {
		return false
	}
	p := pattern[start:]
	// next is row i+1 and cur row i of the table "p[i:] names t[j:]".
	next, cur := make([]bool, len(t)+1), make([]bool, len(t)+1)
	next[len(t)] = true
	for i := len(p) - 1; i >= 0; i-- {
		for j := len(t); j >= 0; j-- {
			switch {
			case j == len(t):
				cur[j] = target.open || p[i] == "**" && next[j]
			case p[i] == "**":
				cur[j] = next[j] || (dotGlob || !strings.HasPrefix(t[j], ".")) && cur[j+1]
			default:
				cur[j] = segmentMatch(p[i], t[j], dotGlob) && next[j+1]
			}
		}
		for j := 0; !anchored && start+i <= dots && j < len(cur); j++ {
			// p[i:] names t[j:]. That reaches the target when it starts
			// naming at or above the root, or the whole pattern does at any
			// depth below it; with anyAbove only from the target's first part.
			reaches := j <= target.below || start+i == 0
			if target.anyAbove {
				reaches = j == 0
			}
			if cur[j] && reaches && (j < len(t) || target.open) {
				return true
			}
		}
		next, cur = cur, next
	}
	return anchored && next[0]
}

// segmentMatch matches a segment of literal or backslash-quoted bytes, "*"
// and "?" to a name with path.Match; one it cannot read matches. Without
// dotGlob a wildcard does not match a leading dot.
func segmentMatch(pattern, name string, dotGlob bool) bool {
	if !dotGlob && strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") && !strings.HasPrefix(pattern, `\.`) {
		return false
	}
	matched, err := path.Match(pattern, name)
	return matched || err != nil
}

// ordinaryFileNames are names any source tree holds. A segment that matches
// one selects files in general, as "*" and "*.*" do, rather than aiming at
// one kind of file.
var ordinaryFileNames = []string{"main.go", "readme.md", "index.js", "notes.txt", "makefile", "a"}

func generalSegment(segment string) bool {
	for _, name := range ordinaryFileNames {
		if segment == "**" || segmentMatch(segment, name, true) {
			return true
		}
	}
	return false
}

// searchGate reports the protected location a walk from root passes over:
// one at or below root, or a directory root is inside. An unresolvable root
// ("") is "/", above everything.
func (g *PathGuard) searchGate(root string) (string, bool) {
	roots := g.rootForms(root)
	return g.firstForm(func(kind int, form string) bool {
		for _, r := range roots {
			if r == "/" || form == r || strings.HasPrefix(form, r+"/") || kind != protectedFile && strings.HasPrefix(r, form+"/") {
				return true
			}
		}
		return false
	})
}

func (g *PathGuard) rootForms(root string) []string {
	if root == "" {
		return []string{"/"}
	}
	return []string{strings.ToLower(path.Clean(root)), strings.ToLower(g.resolve(root))}
}

// searchTargets lists what a search from root can select of the protected
// material, and every directory on the way to it from root.
func (g *PathGuard) searchTargets(root string) []globTarget {
	var out []globTarget
	seen := map[string]bool{}
	add := func(parts []string, below int, form string, open bool) {
		if key := fmt.Sprint(open, parts); !seen[key] {
			seen[key] = true
			out = append(out, globTarget{parts: parts, form: form, below: below, open: open})
		}
	}
	for _, r := range g.rootForms(root) {
		base := pathParts(r)
		for _, target := range g.protectedTargets() {
			switch {
			case target.explicitDot:
			case len(target.parts) > len(base) && hasParts(target.parts, base):
				for k := len(base) + 1; k < len(target.parts); k++ {
					add(target.parts[:k], len(base), target.form, false)
				}
				add(target.parts, len(base), target.form, target.open)
			case target.open && hasParts(base, target.parts):
				add(base, len(base), target.form, true)
			}
		}
	}
	return out
}

func hasParts(parts, prefix []string) bool {
	return len(prefix) <= len(parts) && strings.Join(parts[:len(prefix)], "/") == strings.Join(prefix, "/")
}

// pathParts splits an absolute slash path into its components.
func pathParts(absolute string) []string {
	if absolute = strings.Trim(absolute, "/"); absolute == "" {
		return nil
	}
	return strings.Split(absolute, "/")
}

// The budget of the brace expansion of all the search globs of one call, the
// depth braces may nest to, and the walk made of a search root for a glob
// outside the grammar: maxReachEntries entries of at most maxReachWalks roots.
const (
	MaxSearchGlobAlternatives = 256
	MaxSearchGlobBytes        = 64 << 10
	maxGlobBraceDepth         = 4
	maxReachEntries           = 1 << 16
	maxReachWalks             = 4
)

// UnexpandableSearchGlob is the rule MatchSearch reports for a call over the
// budget or a search too large to walk.
const UnexpandableSearchGlob = "search globs too large to expand"

// SearchCall is one file-search call as the guard reads it: where it starts
// and the globs that select what it reads, under one expansion budget. Build
// it once per call; PathGuard.MatchSearch and SecretRead decide on it.
type SearchCall struct {
	home, root          string
	globs               []searchGlob
	alternatives, bytes int
	overBudget          bool
	walks               map[string]*searchReach
	// mayBeRegex is set while a pattern that may be a regular expression is
	// added; stop is the deciding guard's, so a stopped guard ends a walk.
	mayBeRegex bool
	stop       func() bool
}

// searchGlob is one glob: its alternatives in lower-case segments, or the
// construct outside the grammar. A concrete one is a plain path. mayBeRegex:
// outside the grammar it is taken as a regular expression, not walked for.
type searchGlob struct {
	text, root, outside  string
	alts                 [][]string
	concrete, mayBeRegex bool
}

// NewSearchCall starts a search at root, an absolute directory or one under
// home (~, $HOME). Any other root is unresolvable and taken as "/".
func NewSearchCall(root, home string) *SearchCall {
	s := &SearchCall{home: home}
	s.root = s.resolveRoot(root)
	return s
}

func (s *SearchCall) resolveRoot(root string) string {
	if expanded, ok := expandHome(root, s.home); ok {
		root = expanded
	}
	if root = filepath.ToSlash(root); path.IsAbs(root) {
		return root
	}
	return ""
}

// expandHome replaces a leading ~, $HOME or ${HOME}; it gives "" when home
// is not known.
func expandHome(value, home string) (string, bool) {
	for _, spelling := range []string{"~", "$HOME", "${HOME}"} {
		if value == spelling || strings.HasPrefix(value, spelling+"/") {
			if home == "" {
				return "", true
			}
			return home + value[len(spelling):], true
		}
	}
	return "", false
}

// AddFilter adds a glob the search applies to names, as ripgrep's --glob is.
func (s *SearchCall) AddFilter(glob string) {
	s.add(glob, s.root)
}

// AddPathPattern adds a path pattern, as a Glob tool's pattern is. One that
// names its own directory (absolute, under home, through "." or "..") is read
// from the directory its literal leading segments name, "/" when the first
// segment of an absolute one has a wildcard, an absolute one also as anchored
// where the search runs, and each ".." past a wildcard moves its start one
// directory up.
func (s *SearchCall) AddPathPattern(pattern string) {
	if expanded, ok := expandHome(pattern, s.home); expanded != "" {
		pattern = expanded
	} else if ok {
		s.add(pattern, "")
		return
	} else if path.IsAbs(pattern) {
		s.add(pattern[1:], climb(s.root, pattern))
	}
	segments := strings.Split(pattern, "/")
	literal, dotted := 0, false
	for ; literal < len(segments) && !strings.ContainsAny(segments[literal], `*?[]{}\`); literal++ {
		dotted = dotted || segments[literal] == "." || segments[literal] == ".."
	}
	if !path.IsAbs(pattern) && !dotted {
		s.add(pattern, climb(s.root, pattern))
		return
	}
	head, rest := strings.Join(segments[:literal], "/"), strings.Join(segments[literal:], "/")
	switch {
	case head == "" && path.IsAbs(pattern):
		// The first segment already has a wildcard: the pattern starts at
		// "/", whatever root the search was given.
		head = "/"
	case !path.IsAbs(head) && s.root != "":
		head = strings.TrimSuffix(s.root, "/") + "/" + head
	}
	if rest != "" {
		s.add(rest, climb(s.resolveRoot(head), rest))
	} else if s.charge(1, len(head)) {
		s.globs = append(s.globs, searchGlob{text: head, concrete: true})
	}
}

// AddPatternOrRegex adds a pattern that may be a path pattern or a regular
// expression, as an MCP tool's "pattern" may be: in the grammar it is added
// as AddPathPattern adds it; outside it, it is taken as a regular expression,
// which reaches protected material only when the search starts at, inside or
// above it, and the search root is not walked for it.
func (s *SearchCall) AddPatternOrRegex(pattern string) {
	s.mayBeRegex = true
	s.AddPathPattern(pattern)
	s.mayBeRegex = false
}

// climb is the directory as many levels above root as pattern holds "..".
func climb(root, pattern string) string {
	if root != "" && strings.Contains(pattern, "..") {
		root = resolveExisting(root)
	}
	for k := strings.Count(pattern, ".."); k > 0 && root != ""; k-- {
		root = path.Dir(root)
	}
	return root
}

func (s *SearchCall) add(glob, root string) {
	if glob == "" || s.overBudget {
		return
	}
	// Every byte of a glob other than its brace syntax is in at least one of
	// its expansions, so a glob with more of them than the budget has left is
	// over it without being read.
	if len(glob)-strings.Count(glob, "{")-strings.Count(glob, ",")-strings.Count(glob, "}") > MaxSearchGlobBytes-s.bytes {
		s.overBudget = true
		return
	}
	entry := searchGlob{text: glob, root: root, outside: outsideGrammar(glob), mayBeRegex: s.mayBeRegex}
	if entry.outside == "" {
		parser := globParser{text: glob, countLeft: MaxSearchGlobAlternatives - s.alternatives, bytesLeft: MaxSearchGlobBytes - s.bytes}
		texts, size, outside, over := parser.sequence(0)
		if over || outside == "" && !s.charge(len(texts), size) {
			s.overBudget = true
			return
		}
		if entry.outside = outside; outside == "" {
			entry.alts, entry.outside = globAlternatives(texts)
		}
	}
	// A glob the guard does not expand counts as one alternative.
	if entry.alts != nil || s.charge(1, len(glob)) {
		s.globs = append(s.globs, entry)
	}
}

// charge takes count alternatives of size bytes from the budget.
func (s *SearchCall) charge(count, size int) bool {
	s.alternatives, s.bytes = s.alternatives+count, s.bytes+size
	s.overBudget = s.overBudget || s.alternatives > MaxSearchGlobAlternatives || s.bytes > MaxSearchGlobBytes
	return !s.overBudget
}

// outsideGrammar names the first byte of glob that is neither literal
// (letters, digits, "._-+@=%:") nor syntax ("*?/{},"), or a leading "/",
// which a search tool anchors where it runs.
func outsideGrammar(glob string) string {
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("._-+@=%:*?/{},", c) >= 0:
		case c > ' ' && c < 0x7f:
			return fmt.Sprintf("%q", string(c))
		default:
			return "white space, a control character or a character outside ASCII"
		}
	}
	if strings.HasPrefix(glob, "/") {
		return `a leading "/"`
	}
	return ""
}

// globParser expands a glob's braces as it reads them, under what is left of
// the call's budget: nothing past the budget is built, since every partial
// result is no larger than the whole.
type globParser struct {
	text                 string
	pos                  int
	countLeft, bytesLeft int
}

// sequence reads to the "," or "}" that ends an alternative, or at depth 0 to
// the end. It returns the expansions and their size, or what it cannot
// read, or over when the budget does not hold them.
func (p *globParser) sequence(depth int) (out []string, size int, outside string, over bool) {
	out = []string{""}
	start := p.pos
	cross := func(options []string, optionBytes int) bool {
		if len(out) > p.countLeft/len(options) || size*len(options)+optionBytes*len(out) > p.bytesLeft {
			return false
		}
		next := make([]string, 0, len(out)*len(options))
		for _, prefix := range out {
			for _, option := range options {
				next = append(next, prefix+option)
			}
		}
		out, size = next, size*len(options)+optionBytes*len(out)
		return true
	}
	for ; p.pos < len(p.text); p.pos++ {
		switch p.text[p.pos] {
		case '{':
			if depth == maxGlobBraceDepth {
				return nil, 0, fmt.Sprintf("braces nested deeper than %d levels", maxGlobBraceDepth), false
			}
			var options []string
			optionBytes, alternatives := 0, 0
			for closed := !cross([]string{p.text[start:p.pos]}, p.pos-start); !closed; alternatives++ {
				p.pos++
				expanded, expandedBytes, outside, over := p.sequence(depth + 1)
				switch {
				case outside != "" || over:
					return nil, 0, outside, over
				case p.pos == len(p.text):
					return nil, 0, `a "{" that is never closed`, false
				}
				options, optionBytes = append(options, expanded...), optionBytes+expandedBytes
				closed = p.text[p.pos] == '}'
			}
			switch {
			case alternatives == 0 || len(options) > p.countLeft || !cross(options, optionBytes):
				return nil, 0, "", true
			case alternatives < 2:
				return nil, 0, "a brace group of one alternative", false
			}
			start = p.pos + 1
		case ',', '}':
			if depth == 0 {
				return nil, 0, fmt.Sprintf("%q outside braces", p.text[p.pos:p.pos+1]), false
			}
			return out, size, "", !cross([]string{p.text[start:p.pos]}, p.pos-start)
		}
	}
	return out, size, "", !cross([]string{p.text[start:]}, len(p.text)-start)
}

// globAlternatives splits alternatives into lower-case segments, collapsing
// runs of "**", and names the first that is not a path in the grammar.
func globAlternatives(texts []string) ([][]string, string) {
	alternatives := make([][]string, 0, len(texts))
	for _, text := range texts {
		var segments []string
		for _, segment := range strings.Split(strings.ToLower(text), "/") {
			switch {
			case segment == "":
				return nil, "an empty path segment"
			case segment == "." || segment == "..":
				return nil, `a "." or ".." path segment`
			case segment != "**" && strings.Contains(segment, "**"):
				return nil, `"**" inside a path segment`
			case segment != "**" || len(segments) == 0 || segments[len(segments)-1] != "**":
				segments = append(segments, segment)
			}
		}
		alternatives = append(alternatives, segments)
	}
	return alternatives, ""
}

// MatchSearch reports whether a search reaches protected material, and why
// when not plainly. A glob in the grammar does when it can name it from where
// the search starts, or names a protected file name anywhere (a copy is that
// file); one outside it when the search starts at, inside or above it, or can
// reach a file with a protected name. A call over the budget does.
func (g *PathGuard) MatchSearch(s *SearchCall) (rule, reason string, ok bool) {
	if g == nil || s == nil {
		return "", "", false
	}
	s.stop = g.stopped
	if s.overBudget {
		return UnexpandableSearchGlob, fmt.Sprintf("search globs too large to expand (over %d alternatives or %d bytes in one call), taken as reaching HELM signing or trust material", MaxSearchGlobAlternatives, MaxSearchGlobBytes), true
	}
	for _, glob := range s.globs {
		if g.stopped() {
			return stoppedRule, stoppedRule, true
		}
		if glob.concrete {
			if rule, ok := g.Match(glob.text, ""); ok {
				return rule, "", true
			}
			continue
		}
		texts := []string{glob.text}
		for _, alternative := range glob.alts {
			texts = append(texts, strings.Join(alternative, "/"))
			for _, name := range g.names {
				if last := alternative[len(alternative)-1]; !generalSegment(last) && segmentMatch(last, name, true) {
					return name, "", true
				}
			}
		}
		for _, text := range texts {
			if needle, ok := g.MatchText(text); ok {
				return needle, "", true
			}
		}
		location, gated := g.searchGate(glob.root)
		switch {
		case gated && glob.outside != "":
			return location, unreadGlob(glob, "starts at, inside or above HELM signing or trust material"), true
		case gated:
			for _, target := range g.searchTargets(glob.root) {
				if g.stopped() {
					return stoppedRule, stoppedRule, true
				}
				for _, alternative := range glob.alts {
					if fits(alternative, target, false, true) {
						return target.form, "", true
					}
				}
			}
		case glob.outside != "" && !glob.mayBeRegex:
			reach := s.reachable(glob.root)
			for _, name := range g.names {
				if copy, found := reach.names[name]; found {
					return name, unreadGlob(glob, "can reach "+copy+", a copy of HELM signing material"), true
				}
			}
			if !reach.complete {
				return UnexpandableSearchGlob, unreadGlob(glob, reachTooLarge), true
			}
		}
	}
	return "", "", false
}

const reachTooLarge = "the hook could not walk in full"

func unreadGlob(glob searchGlob, search string) string {
	if glob.mayBeRegex {
		return fmt.Sprintf("a search pattern with %s, which the hook does not read as a glob, in a search that %s", glob.outside, search)
	}
	return fmt.Sprintf("a search glob with %s, which the hook does not read, in a search that %s", glob.outside, search)
}

// SecretRead reports whether a search selects credential files by the rules
// of SecretReadPath, and why when not plainly: a glob in the grammar when an
// alternative can name one, unless its last segment selects files in general
// ("*", "*.go"); one outside it when the search can reach one or more than
// the hook walks.
func (s *SearchCall) SecretRead() (glob, reason string, ok bool) {
	if s == nil {
		return "", "", false
	}
	if s.overBudget {
		return UnexpandableSearchGlob, UnexpandableSearchGlob, true
	}
	for _, entry := range s.globs {
		switch {
		case entry.concrete:
			if SecretReadPath(entry.text) {
				return entry.text, "", true
			}
		case entry.outside == "":
			for _, alternative := range entry.alts {
				if secretAlternative(alternative) {
					return entry.text, "", true
				}
			}
		case entry.mayBeRegex:
		case s.reachable(entry.root).secret != "":
			return entry.text, unreadGlob(entry, "can reach the credential file "+s.reachable(entry.root).secret), true
		case !s.reachable(entry.root).complete:
			return entry.text, unreadGlob(entry, reachTooLarge), true
		}
	}
	return "", "", false
}

func secretAlternative(alternative []string) bool {
	if isLocalSecretPath(strings.Join(alternative, "/")) {
		return true
	}
	for _, sample := range secretGlobSamples {
		if !generalSegment(alternative[len(alternative)-1]) && fits(alternative, globTarget{parts: strings.Split(sample, "/"), anyAbove: true}, false, true) {
			return true
		}
	}
	return false
}

// searchReach is what a walk of a search root found, relative to it: the
// first credential file and the entries by lower-case name, and whether it
// walked all of it.
type searchReach struct {
	complete bool
	secret   string
	names    map[string]string
}

// reachable walks root once per call. A directory the walk cannot read is
// one the search, run by the same user, cannot read either.
func (s *SearchCall) reachable(root string) *searchReach {
	if found, ok := s.walks[root]; ok {
		return found
	}
	found := &searchReach{names: map[string]string{}}
	if root == "" || len(s.walks) == maxReachWalks {
		return found
	}
	if s.walks == nil {
		s.walks = map[string]*searchReach{}
	}
	s.walks[root] = found
	entries, complete := listTree(resolveExisting(root), maxReachEntries, s.stop)
	found.complete = complete
	for _, rel := range entries {
		if found.secret == "" && isLocalSecretPath(rel) {
			found.secret = rel
		}
		if base := path.Base(rel); found.names[base] == "" {
			found.names[base] = rel
		}
	}
	return found
}

// reachesInto reports whether a known prefix, followed by text computed at
// run time, can only be completed inside protected ground: the prefix is at
// or below a protected directory, or has begun to spell one's name.
func (g *PathGuard) reachesInto(prefix string) (string, bool) {
	prefixes := []string{strings.ToLower(prefix)}
	directory, rest := path.Split(prefix)
	if resolved := strings.ToLower(strings.TrimSuffix(g.resolve(directory), "/") + "/" + rest); resolved != prefixes[0] {
		prefixes = append(prefixes, resolved)
	}
	return g.firstForm(func(kind int, form string) bool {
		for _, candidate := range prefixes {
			// A container protects itself, not its other content: the
			// unknown part must be able to name it or its direct entry.
			if candidate == form || spellsInto(candidate, form) || kind == protectedContainer && candidate == form+"/" || kind != protectedContainer && strings.HasPrefix(candidate, form+"/") {
				return true
			}
		}
		return false
	})
}

// spellsInto reports whether prefix has begun the last name of target, as
// "/home/u/.hel" has for "/home/u/.helm": whatever follows is taken as
// heading there.
func spellsInto(prefix, target string) bool {
	return strings.HasPrefix(target, prefix) && len(prefix) > len(path.Dir(target))+1
}

func cleanSlash(value string) string {
	return path.Clean(filepath.ToSlash(value))
}

// maxResolvedPaths bounds the cache of resolved paths, and
// maxCachedResolveDepth the depth of a path resolved through its parent.
const (
	maxResolvedPaths      = 1 << 16
	maxCachedResolveDepth = 64
)

// resolve is resolveExisting with the guard's cache, keyed by the original
// spelling so a symlink/.. path cannot collide with its lexical cleanup. A path is resolved
// through its cached parent: one lookup for the last name instead of one for
// every directory above it, which keeps a command that names many files in
// one directory cheap.
func (g *PathGuard) resolve(value string) string {
	clean := filepath.FromSlash(value)
	g.mu.Lock()
	cached, ok := g.resolved[clean]
	g.mu.Unlock()
	if ok {
		return cached
	}
	resolved := ""
	dir, base := filepath.Split(clean)
	switch {
	case base == "" || dir == "" || strings.Count(clean, string(filepath.Separator)) > maxCachedResolveDepth:
		resolved = resolveExisting(clean)
	default:
		joined := filepath.Join(filepath.FromSlash(g.resolve(dir)), base)
		if info, err := os.Lstat(joined); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			resolved = resolveExisting(joined)
		} else {
			resolved = filepath.ToSlash(joined)
		}
	}
	g.mu.Lock()
	if g.resolved == nil {
		g.resolved = map[string]string{}
	}
	if len(g.resolved) < maxResolvedPaths {
		g.resolved[clean] = resolved
	}
	g.mu.Unlock()
	return resolved
}

// resolveExisting follows symbolic links in the part of a path that exists
// and keeps the rest as written, so a file that is about to be created under
// a linked directory resolves to where it will land.
//
// The existing part is found by walking down from the start of the path, one
// lookup per existing name, and the walk stops at the first name that does
// not exist. Trimming one name at a time from the end instead costs the
// square of the path's length, which a caller sending a long path could use
// to hold the hook past its client's timeout.
func resolveExisting(value string) string {
	current := filepath.FromSlash(value)
	// EvalSymlinks walks the original components before resolving "..".
	// Cleaning first changes which parent follows a symlink.
	if resolved, err := filepath.EvalSymlinks(current); err == nil {
		return filepath.ToSlash(resolved)
	}
	separator := string(filepath.Separator)
	existing := filepath.VolumeName(current)
	remaining := current[len(existing):]
	if strings.HasPrefix(remaining, separator) {
		existing += separator
		remaining = strings.TrimLeft(remaining, separator)
	}
	for remaining != "" {
		name, after, _ := strings.Cut(remaining, separator)
		// The prefix is resolved already, so Join may now interpret this
		// component's parent reference. Resolve each link before continuing.
		next := filepath.Join(existing, name)
		info, err := os.Lstat(next)
		if err != nil {
			return filepath.ToSlash(filepath.Join(next, after))
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(next)
			if err != nil {
				return filepath.ToSlash(filepath.Join(next, after))
			}
			next = resolved
		}
		existing, remaining = next, after
	}
	return filepath.ToSlash(existing)
}

// globEscape quotes glob syntax so literal text survives matchPattern.
func globEscape(text string) string {
	if !strings.ContainsAny(text, `*?[\`) {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '*', '?', '[', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(text[i])
	}
	return b.String()
}

// guardWordPattern renders a shell word as matchPattern input: quoted text is
// literal, unquoted text keeps its glob syntax, "~" and $HOME become the home
// directory, and dynamicAt marks where the first part computed at run time
// begins (-1 when the whole word is static).
func guardWordPattern(word *syntax.Word, home string) (pattern string, dynamicAt int) {
	var b strings.Builder
	dynamicAt = -1
	dynamic := func() {
		if dynamicAt < 0 {
			dynamicAt = b.Len()
		}
	}
	homeOrDynamic := func(expansion *syntax.ParamExp) {
		if home != "" && plainHomeExpansion(expansion) {
			b.WriteString(globEscape(home))
			return
		}
		dynamic()
	}
	for index, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			value := p.Value
			if index == 0 && home != "" && (value == "~" || strings.HasPrefix(value, "~/")) {
				b.WriteString(globEscape(home))
				value = value[1:]
			}
			// Brace expansion multiplies the word; what follows is unknown.
			if brace := strings.IndexByte(value, '{'); brace >= 0 && strings.IndexByte(value[brace:], '}') > 0 {
				b.WriteString(value[:brace])
				dynamic()
				continue
			}
			b.WriteString(value)
		case *syntax.SglQuoted:
			value := p.Value
			if p.Dollar {
				value = decodeANSIC(value)
			}
			b.WriteString(globEscape(value))
		case *syntax.DblQuoted:
			if p.Dollar {
				dynamic()
			}
			for _, inner := range p.Parts {
				switch q := inner.(type) {
				case *syntax.Lit:
					b.WriteString(globEscape(q.Value))
				case *syntax.ParamExp:
					homeOrDynamic(q)
				default:
					dynamic()
				}
			}
		case *syntax.ParamExp:
			homeOrDynamic(p)
		default:
			dynamic()
		}
	}
	return b.String(), dynamicAt
}

// plainHomeExpansion reports whether an expansion is exactly $HOME or
// ${HOME}, with no operator that would change the value.
func plainHomeExpansion(expansion *syntax.ParamExp) bool {
	return expansion.Param != nil && expansion.Param.Value == "HOME" &&
		!expansion.Excl && !expansion.Length && !expansion.Width &&
		expansion.Index == nil && expansion.Slice == nil && expansion.Repl == nil &&
		expansion.Names == 0 && expansion.Exp == nil
}
