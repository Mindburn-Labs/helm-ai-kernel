package shellscan

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

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
	// directory many times looks it up once.
	mu       sync.Mutex
	resolved map[string]string
	// listed caches the names each protected directory holds, and globs
	// the result of each glob pattern matched ("" for no match).
	listed map[string][]string
	globs  map[string]string
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
	if strings.TrimSpace(home) != "" {
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
	if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
		g.needles = append(g.needles, "/"+name)
		g.names = append(g.names, name)
	}
}

func (g *PathGuard) locate(location string) (guardedPath, bool) {
	location = strings.TrimSpace(location)
	if location == "" {
		return guardedPath{}, false
	}
	absolute, err := filepath.Abs(location)
	if err != nil {
		return guardedPath{}, false
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

// Match reports whether target, a path or glob pattern as a tool would
// receive it, refers to protected material. A relative target is resolved
// against cwd; with no cwd only the text match applies.
func (g *PathGuard) Match(target, cwd string) (string, bool) {
	return g.matchPattern(globEscape(slashPath(strings.TrimSpace(target))), -1, cwd, false)
}

// MatchPattern is Match for a target in which "*", "?" and "[...]" are glob
// syntax, as in the pattern argument of a file-search tool.
func (g *PathGuard) MatchPattern(pattern, cwd string) (string, bool) {
	return g.matchPattern(slashPath(strings.TrimSpace(pattern)), -1, cwd, true)
}

// matchPattern takes a path in glob syntax (a backslash quotes the next
// byte). dynamicAt, when not negative, is where a part computed at run time
// begins: only the text before it is known. dotGlob lets a wildcard match a
// leading dot.
func (g *PathGuard) matchPattern(pattern string, dynamicAt int, cwd string, dotGlob bool) (string, bool) {
	if g == nil || pattern == "" {
		return "", false
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
	return g.matchGlob(absolute, dotGlob)
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
	if cwd = strings.TrimSpace(cwd); cwd == "" || !path.IsAbs(slashPath(cwd)) {
		return "", false
	}
	return globEscape(strings.TrimSuffix(slashPath(cwd), "/")) + "/" + target, true
}

func (g *PathGuard) matchConcrete(absolute string) (string, bool) {
	candidates := []string{strings.ToLower(path.Clean(absolute)), strings.ToLower(g.resolve(absolute))}
	for _, candidate := range candidates {
		for _, file := range g.files {
			for _, form := range file.forms() {
				if candidate == form {
					return form, true
				}
			}
		}
		for _, tree := range g.trees {
			for _, form := range tree.forms() {
				if candidate == form || strings.HasPrefix(candidate, form+"/") {
					return form, true
				}
			}
		}
		for _, container := range g.containers {
			for _, form := range container.forms() {
				if candidate == form {
					return form, true
				}
			}
		}
	}
	return "", false
}

// matchGlob reports whether an absolute glob pattern can expand to protected
// material: a protected file, a protected directory or anything inside one.
// Results are kept per guard, so a command that repeats a pattern pays once.
func (g *PathGuard) matchGlob(pattern string, dotGlob bool) (string, bool) {
	key := strings.ToLower(pattern)
	if dotGlob {
		key = "1" + key
	} else {
		key = "0" + key
	}
	g.mu.Lock()
	cached, ok := g.globs[key]
	g.mu.Unlock()
	if ok {
		return cached, cached != ""
	}
	rule, matched := g.matchGlobUncached(pattern, dotGlob)
	g.mu.Lock()
	if g.globs == nil {
		g.globs = map[string]string{}
	}
	if len(g.globs) < maxResolvedPaths {
		g.globs[key] = rule
	}
	g.mu.Unlock()
	return rule, matched
}

func (g *PathGuard) matchGlobUncached(pattern string, dotGlob bool) (string, bool) {
	patterns := []string{strings.ToLower(path.Clean(pattern))}
	// Links in the literal directories before the first wildcard are followed,
	// so a pattern under a linked directory is matched where it really points.
	segments := strings.Split(patterns[0], "/")
	for i, segment := range segments {
		if !hasGlobPattern(segment) {
			continue
		}
		literal := "/" + strings.TrimPrefix(unescapeLit(strings.Join(segments[:i], "/")), "/")
		if resolved := strings.ToLower(g.resolve(literal)); resolved != literal {
			patterns = append(patterns, strings.TrimSuffix(globEscape(resolved), "/")+"/"+strings.Join(segments[i:], "/"))
		}
		break
	}
	for _, candidate := range patterns {
		parts := strings.Split(candidate, "/")
		for _, file := range g.files {
			for _, form := range file.forms() {
				if globMatch(parts, strings.Split(form, "/"), dotGlob, nil) {
					return form, true
				}
			}
		}
		for _, tree := range g.trees {
			within := g.treeContentMatcher(tree, dotGlob)
			for _, form := range tree.forms() {
				if globMatch(parts, strings.Split(form, "/"), dotGlob, within) {
					return form, true
				}
			}
		}
		// A container is matched only by a pattern that writes its leading
		// dot: listing a home directory with "*" does not name it.
		for _, container := range g.containers {
			for _, form := range container.forms() {
				if globMatch(parts, strings.Split(form, "/"), false, nil) {
					return form, true
				}
			}
		}
	}
	return "", false
}

// maxGlobSegments bounds the patterns globMatch compares. A longer pattern
// names no real file; it is taken to match, so the bound can only add a
// refusal.
const maxGlobSegments = 4096

// globMatch reports whether a glob pattern, split into path segments, can
// name target, one segment at a time as the shell does: a wildcard never
// crosses a slash and matches a leading dot only when dotGlob is set or the
// pattern writes the dot. A "**" segment matches any number of whole
// segments, as globstar and the search tools' glob syntax read it.
//
// With within set, target is a directory and a pattern that goes on past its
// end also matches when what remains can name something inside it: nothing
// more or only "**" (the directory or all of it), a last segment that within
// accepts, or a path through a subdirectory, which is not looked into and so
// is taken to match.
func globMatch(pattern, target []string, dotGlob bool, within func(segment string) bool) bool {
	if len(pattern) > maxGlobSegments {
		return true
	}
	// A leading run of segments without wildcards, such as the home directory
	// a pattern starts with, is compared as text.
	for len(pattern) > 0 && len(target) > 0 && pattern[0] != "**" && !hasGlobPattern(pattern[0]) {
		if unescapeLit(pattern[0]) != target[0] {
			return false
		}
		pattern, target = pattern[1:], target[1:]
	}
	// literal[i] counts the segments of pattern[i:] that are not "**", and
	// first[i] is the index of the first of them.
	literal := make([]int, len(pattern)+1)
	first := make([]int, len(pattern)+1)
	first[len(pattern)] = len(pattern)
	for i := len(pattern) - 1; i >= 0; i-- {
		literal[i], first[i] = literal[i+1], first[i+1]
		if pattern[i] != "**" {
			literal[i]++
			first[i] = i
		}
	}
	// past(i) decides pattern[i:] once target has run out. It is worked out
	// only for the rows that reach the end of target, since within may read
	// the directory.
	pastMemo := make([]int8, len(pattern)+1)
	past := func(i int) bool {
		if pastMemo[i] == 0 {
			ok := true
			switch {
			case literal[i] == 0:
			case within == nil:
				ok = false
			case literal[i] == 1 && first[i] == len(pattern)-1:
				ok = within(pattern[first[i]])
			}
			pastMemo[i] = -1
			if ok {
				pastMemo[i] = 1
			}
		}
		return pastMemo[i] == 1
	}
	if len(target) == 0 {
		return past(0)
	}
	if literal[0] == len(pattern) {
		// No "**": one segment against one segment, as far as both go.
		for j := range target {
			if j == len(pattern) || !segmentMatches(pattern[j], target[j], dotGlob) {
				return false
			}
		}
		return past(len(target))
	}
	// Dynamic programming over the segments of pattern, last first: next
	// holds row i+1 and cur row i, each indexed by the position in target.
	// The column past the end of target is past(i).
	last := len(target) - 1
	// Row len(pattern) is all false: the pattern ends before target does.
	next := make([]bool, len(target))
	cur := make([]bool, len(target))
	for i := len(pattern) - 1; i >= 0; i-- {
		for j := last; j >= 0; j-- {
			if pattern[i] == "**" {
				deeper := false
				if dotGlob || !strings.HasPrefix(target[j], ".") {
					if j == last {
						deeper = past(i)
					} else {
						deeper = cur[j+1]
					}
				}
				cur[j] = next[j] || deeper
				continue
			}
			if !segmentMatches(pattern[i], target[j], dotGlob) {
				cur[j] = false
				continue
			}
			if j == last {
				cur[j] = past(i + 1)
			} else {
				cur[j] = next[j+1]
			}
		}
		next, cur = cur, next
	}
	return next[0]
}

// segmentMatches matches one pattern segment to one name. A pattern that
// path.Match cannot read is taken to match: the guard can only add a refusal,
// so what it cannot read must not pass.
func segmentMatches(pattern, name string, dotGlob bool) bool {
	ok, err := segmentMatch(pattern, name, dotGlob)
	return ok || err != nil
}

// segmentMatch is segmentMatches with the pattern error reported, for a
// caller to which an unreadable pattern means something else.
func segmentMatch(pattern, name string, dotGlob bool) (bool, error) {
	translated := shellBracket(pattern)
	if _, err := path.Match(translated, ""); err != nil {
		return false, err
	}
	if !dotGlob && strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") && !strings.HasPrefix(pattern, `\.`) {
		return false, nil
	}
	return path.Match(translated, name)
}

// maxTreeEntries bounds how many names treeContentMatcher reads from a
// protected directory.
const maxTreeEntries = 1024

// treeContentMatcher decides whether the last segment of a pattern that runs
// into a protected directory names something there: a protected file name, or
// the name of a file or directory the tree holds. A wildcard that can name
// nothing in it, as "*.go" cannot in a key directory, does not reach it.
func (g *PathGuard) treeContentMatcher(tree guardedPath, dotGlob bool) func(string) bool {
	return func(segment string) bool {
		for _, name := range g.treeNames(tree) {
			if segmentMatches(segment, name, dotGlob) {
				return true
			}
		}
		return false
	}
}

// treeNames lists, once per guard, the protected names and the names a
// protected directory holds, in lower case.
func (g *PathGuard) treeNames(tree guardedPath) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if names, ok := g.listed[tree.dir]; ok {
		return names
	}
	names := append([]string(nil), g.names...)
	_ = filepath.WalkDir(filepath.FromSlash(tree.dir), func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || len(names) >= maxTreeEntries+len(g.names) {
			return fs.SkipAll
		}
		names = append(names, strings.ToLower(entry.Name()))
		return nil
	})
	if g.listed == nil {
		g.listed = map[string][]string{}
	}
	g.listed[tree.dir] = names
	return names
}

// ordinaryFileNames are names any source tree holds. A glob segment that
// matches one of them selects files in general, as "*" and "*.*" do, rather
// than aiming at one kind of file.
var ordinaryFileNames = []string{"main.go", "readme.md", "index.js", "notes.txt", "makefile", "a"}

// generalSegment reports whether a glob segment selects files in general. A
// segment path.Match cannot read is not taken as general: it is compared with
// the protected names, which it is taken to match.
func generalSegment(segment string) bool {
	if segment == "**" {
		return true
	}
	for _, name := range ordinaryFileNames {
		if ok, err := segmentMatch(segment, name, true); err == nil && ok {
			return true
		}
	}
	return false
}

// MatchSearchGlob reports whether the glob a file-search tool is given can
// select protected material. root is the directory the search starts in, or
// "" when it is not known. A filter applies at any depth below root, as
// ripgrep's --glob and the include options of search tools do; otherwise the
// pattern is anchored at root, as a Glob tool's pattern is. Brace
// alternatives are tried one by one. Whatever the root, a last segment aimed
// at a protected name, as "*.seed" is at a seed file and "*" is not, matches:
// a copy of that file is still that file. A glob too large to expand under
// the budget of expandBraces matches as UnexpandableSearchGlob.
func (g *PathGuard) MatchSearchGlob(pattern, root string, filter bool) (string, bool) {
	if g == nil {
		return "", false
	}
	pattern = slashPath(strings.TrimSpace(pattern))
	if pattern == "" {
		return "", false
	}
	alternatives, ok := expandBraces(pattern)
	if !ok {
		return UnexpandableSearchGlob, true
	}
	root = strings.TrimSuffix(slashPath(strings.TrimSpace(root)), "/")
	for _, alternative := range alternatives {
		if needle, ok := g.MatchText(unescapeLit(alternative)); ok {
			return needle, true
		}
		if last := strings.ToLower(path.Base(alternative)); !generalSegment(last) {
			for _, name := range g.names {
				if segmentMatches(last, name, true) {
					return name, true
				}
			}
		}
		anchored := alternative
		if !anchoredPattern(alternative) {
			if root == "" {
				continue
			}
			if filter && !strings.HasPrefix(alternative, "**/") {
				anchored = "**/" + alternative
			}
			anchored = globEscape(root) + "/" + anchored
		}
		if rule, ok := g.matchPattern(anchored, -1, "", true); ok {
			return rule, true
		}
	}
	return "", false
}

// anchoredPattern reports whether a pattern names its own starting point:
// an absolute path or one under the home directory.
func anchoredPattern(pattern string) bool {
	if path.IsAbs(pattern) {
		return true
	}
	for _, home := range []string{"~", "$HOME", "${HOME}"} {
		if pattern == home || strings.HasPrefix(pattern, home+"/") {
			return true
		}
	}
	return false
}

// UnexpandableSearchGlob is the rule MatchSearchGlob reports for a glob too
// large to expand. Such a glob is taken to reach trust material: the guard
// can only add a refusal, so what it cannot read must not pass.
const UnexpandableSearchGlob = "search glob too large to expand"

// The budget of one search glob's brace expansion. Past any of these bounds
// the glob is not expanded at all, and is refused: the work one glob costs is
// linear in its length and never more than these bounds allow.
const (
	// MaxSearchGlobAlternatives bounds how many alternatives a glob expands
	// to.
	MaxSearchGlobAlternatives = 256
	// MaxSearchGlobBytes bounds the glob and the total length of its
	// alternatives. No file name or path a search selects comes near it.
	MaxSearchGlobBytes = 64 << 10
	// maxBraceDepth bounds how deeply brace groups nest.
	maxBraceDepth = 32

	maxBraceAlternatives   = MaxSearchGlobAlternatives
	maxBraceExpansionBytes = MaxSearchGlobBytes
)

// expandBraces expands the "{a,b}" alternatives of a search glob, as ripgrep
// and the other search tools read them: groups nest, a group of one
// alternative is that alternative, a backslash quotes the next byte, and a
// "}" or "," inside a bracket class is a member of the class, not part of a
// group. A "{" that is never closed and a "}" that closes nothing are
// themselves. ok is false when the glob is past the budget above; nothing is
// expanded then, so no fallback can match less than the glob would.
//
// The glob is scanned once to pair its braces and classes, and the
// alternatives are built under the budget, so the work is linear in the
// length of the glob and bounded by the budget.
func expandBraces(pattern string) (alternatives []string, ok bool) {
	if len(pattern) > maxBraceExpansionBytes {
		return nil, false
	}
	if !strings.Contains(pattern, "{") {
		return []string{pattern}, true
	}
	groups, ok := pairBraces(pattern)
	if !ok {
		return nil, false
	}
	if len(groups) == 0 {
		return []string{pattern}, true
	}
	e := braceExpander{pattern: pattern, groups: groups}
	return e.sequence(0, len(pattern))
}

// braceGroup is one "{...}" of a glob: where it closes and where its commas
// are.
type braceGroup struct {
	close  int
	commas []int
}

// pairBraces finds the groups of a glob, keyed by the offset of their "{".
// ok is false when they nest deeper than maxBraceDepth.
func pairBraces(pattern string) (map[int]*braceGroup, bool) {
	classes := newBracketClasses(pattern)
	groups := map[int]*braceGroup{}
	var open []int
	var commas [][]int
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '[':
			if end := classes.end(i); end > 0 {
				i = end
			}
		case '{':
			if len(open) == maxBraceDepth {
				return nil, false
			}
			open = append(open, i)
			commas = append(commas, nil)
		case ',':
			if len(open) > 0 {
				commas[len(commas)-1] = append(commas[len(commas)-1], i)
			}
		case '}':
			if len(open) > 0 {
				last := len(open) - 1
				groups[open[last]] = &braceGroup{close: i, commas: commas[last]}
				open, commas = open[:last], commas[:last]
			}
		}
	}
	return groups, true
}

// braceExpander builds the alternatives of a glob under the budget.
type braceExpander struct {
	pattern string
	groups  map[int]*braceGroup
}

// sequence expands pattern[start:end], which holds whole groups only.
func (e braceExpander) sequence(start, end int) ([]string, bool) {
	out := []string{""}
	literal := start
	for i := start; i < end; i++ {
		switch e.pattern[i] {
		case '\\':
			i++
		case '{':
			group, isGroup := e.groups[i]
			if !isGroup {
				continue
			}
			var ok bool
			if out, ok = appendLiteral(out, e.pattern[literal:i]); !ok {
				return nil, false
			}
			var alternatives []string
			from := i + 1
			for _, to := range append(group.commas, group.close) {
				expanded, ok := e.sequence(from, to)
				if !ok || len(alternatives)+len(expanded) > maxBraceAlternatives {
					return nil, false
				}
				alternatives = append(alternatives, expanded...)
				from = to + 1
			}
			if out, ok = crossAlternatives(out, alternatives); !ok {
				return nil, false
			}
			i = group.close
			literal = i + 1
		}
	}
	return appendLiteral(out, e.pattern[literal:end])
}

// expansionBytes is the total length of a set of alternatives.
func expansionBytes(values []string) int {
	total := 0
	for _, value := range values {
		total += len(value)
	}
	return total
}

func appendLiteral(prefixes []string, literal string) ([]string, bool) {
	if literal == "" {
		return prefixes, true
	}
	if expansionBytes(prefixes)+len(prefixes)*len(literal) > maxBraceExpansionBytes {
		return nil, false
	}
	for i := range prefixes {
		prefixes[i] += literal
	}
	return prefixes, true
}

// crossAlternatives joins every prefix to every alternative, refusing a
// result past the budget before building it.
func crossAlternatives(prefixes, alternatives []string) ([]string, bool) {
	if len(prefixes) > maxBraceAlternatives/max(len(alternatives), 1) {
		return nil, false
	}
	count := len(prefixes) * len(alternatives)
	if count > maxBraceAlternatives || expansionBytes(prefixes)*len(alternatives)+expansionBytes(alternatives)*len(prefixes) > maxBraceExpansionBytes {
		return nil, false
	}
	out := make([]string, 0, count)
	for _, prefix := range prefixes {
		for _, alternative := range alternatives {
			out = append(out, prefix+alternative)
		}
	}
	return out, true
}

// bracketClasses finds the bracket classes of a glob in time linear in its
// length. A class is "[" up to the first unquoted "]" after it, where a "]"
// right after the "[" (or after a leading "!" or "^") is a member; a "[" with
// no such "]" after it is itself.
type bracketClasses struct {
	text string
	// next[i] is the first unquoted "]" at or after i, or -1.
	next []int
}

func newBracketClasses(text string) bracketClasses {
	classes := bracketClasses{text: text}
	if !strings.Contains(text, "[") {
		return classes
	}
	quoted := make([]bool, len(text))
	for i := 1; i < len(text); i++ {
		quoted[i] = text[i-1] == '\\' && !quoted[i-1]
	}
	classes.next = make([]int, len(text)+1)
	classes.next[len(text)] = -1
	for i := len(text) - 1; i >= 0; i-- {
		classes.next[i] = classes.next[i+1]
		if text[i] == ']' && !quoted[i] {
			classes.next[i] = i
		}
	}
	return classes
}

// end returns the offset of the "]" that closes the class opened at open, or
// -1 when the "[" there opens none.
func (c bracketClasses) end(open int) int {
	if c.next == nil || open >= len(c.text) || c.text[open] != '[' {
		return -1
	}
	members := c.membersStart(open)
	if members < len(c.text) && c.text[members] == ']' {
		members++
	}
	if members >= len(c.text) {
		return -1
	}
	return c.next[members]
}

// membersStart is the offset of the first member of the class opened at open,
// past a negation.
func (c bracketClasses) membersStart(open int) int {
	start := open + 1
	if start < len(c.text) && (c.text[start] == '!' || c.text[start] == '^') {
		start++
	}
	return start
}

// shellBracket rewrites one pattern segment from the glob syntax of the shell
// and the search tools into the syntax path.Match reads. They differ in
// bracket classes: the shell and ripgrep negate a class with "[!...]" as well
// as "[^...]", take a "]" right after the "[" as a member and a "-" at either
// end as itself, and read a "[" that is never closed, and a trailing
// backslash, as themselves; path.Match does none of these. A class that holds
// a POSIX class, an equivalence class or a collating symbol ("[[:alpha:]]")
// makes the rest of the segment "*", which matches at least what it would.
func shellBracket(segment string) string {
	if !strings.ContainsAny(segment, `[\`) {
		return segment
	}
	classes := newBracketClasses(segment)
	var out strings.Builder
	for i := 0; i < len(segment); i++ {
		switch c := segment[i]; {
		case c == '\\':
			out.WriteByte('\\')
			if i+1 < len(segment) {
				i++
				out.WriteByte(segment[i])
			} else {
				out.WriteByte('\\')
			}
		case c == '[':
			end := classes.end(i)
			if end < 0 {
				out.WriteString(`\[`)
				continue
			}
			start := classes.membersStart(i)
			members := segment[start:end]
			if strings.Contains(members, "[:") || strings.Contains(members, "[=") || strings.Contains(members, "[.") {
				out.WriteByte('*')
				return out.String()
			}
			out.WriteByte('[')
			if start > i+1 {
				out.WriteByte('^')
			}
			writeClassMembers(&out, members)
			out.WriteByte(']')
			i = end
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

// writeClassMembers writes the members of a class as path.Match reads them:
// a "-" between two members is a range, and every other character path.Match
// treats as syntax is quoted.
func writeClassMembers(out *strings.Builder, members string) {
	for i := 0; i < len(members); i++ {
		c := members[i]
		switch {
		case c == '\\' && i+1 < len(members):
			out.WriteByte('\\')
			i++
			out.WriteByte(members[i])
		case c == '-' && i > 0 && i < len(members)-1:
			out.WriteByte('-')
		case strings.IndexByte(`-]\^[!`, c) >= 0:
			out.WriteByte('\\')
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
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
	for _, candidate := range prefixes {
		for _, location := range append(append([]guardedPath{}, g.files...), g.trees...) {
			for _, form := range location.forms() {
				if candidate == form || strings.HasPrefix(candidate, form+"/") || spellsInto(candidate, form) {
					return form, true
				}
			}
		}
		// A container protects itself, not its other content: the unknown
		// part must be able to name the container or its direct entry.
		for _, container := range g.containers {
			for _, form := range container.forms() {
				if candidate == form || candidate == form+"/" || spellsInto(candidate, form) {
					return form, true
				}
			}
		}
	}
	return "", false
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

// resolve is resolveExisting with the guard's cache. A path is resolved
// through its cached parent: one lookup for the last name instead of one for
// every directory above it, which keeps a command that names many files in
// one directory cheap.
func (g *PathGuard) resolve(value string) string {
	clean := filepath.Clean(filepath.FromSlash(value))
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
	current := filepath.Clean(filepath.FromSlash(value))
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
		next := filepath.Join(existing, name)
		if _, err := os.Lstat(next); err != nil {
			break
		}
		existing, remaining = next, after
	}
	// A link at the end of the existing part may point nowhere; step back
	// over it, which costs at most one step per existing name.
	for {
		if resolved, err := filepath.EvalSymlinks(existing); err == nil {
			return filepath.ToSlash(filepath.Join(resolved, remaining))
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return filepath.ToSlash(filepath.Join(existing, remaining))
		}
		remaining = filepath.Join(filepath.Base(existing), remaining)
		existing = parent
	}
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
