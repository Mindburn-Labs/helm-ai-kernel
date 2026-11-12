package shellscan

import (
	"path"
	"path/filepath"
	"strings"

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
}

// guardedPath is one protected location, as written and as it resolves.
type guardedPath struct {
	lexical  string
	resolved string
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
	return guardedPath{
		lexical:  strings.ToLower(cleanSlash(absolute)),
		resolved: strings.ToLower(resolveExisting(absolute)),
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
	candidates := []string{strings.ToLower(path.Clean(absolute)), strings.ToLower(resolveExisting(absolute))}
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
func (g *PathGuard) matchGlob(pattern string, dotGlob bool) (string, bool) {
	patterns := []string{strings.ToLower(path.Clean(pattern))}
	// Links in the literal directories before the first wildcard are followed,
	// so a pattern under a linked directory is matched where it really points.
	segments := strings.Split(patterns[0], "/")
	for i, segment := range segments {
		if !hasGlobPattern(segment) {
			continue
		}
		literal := "/" + strings.TrimPrefix(unescapeLit(strings.Join(segments[:i], "/")), "/")
		if resolved := strings.ToLower(resolveExisting(literal)); resolved != literal {
			patterns = append(patterns, strings.TrimSuffix(globEscape(resolved), "/")+"/"+strings.Join(segments[i:], "/"))
		}
		break
	}
	for _, candidate := range patterns {
		parts := strings.Split(candidate, "/")
		for _, file := range g.files {
			for _, form := range file.forms() {
				if target := strings.Split(form, "/"); len(target) == len(parts) && segmentsMatch(parts, target, dotGlob) {
					return form, true
				}
			}
		}
		for _, tree := range g.trees {
			for _, form := range tree.forms() {
				if target := strings.Split(form, "/"); len(parts) >= len(target) && segmentsMatch(parts[:len(target)], target, dotGlob) {
					return form, true
				}
			}
		}
		// A container is matched only by a pattern that writes its leading
		// dot: listing a home directory with "*" does not name it.
		for _, container := range g.containers {
			for _, form := range container.forms() {
				if target := strings.Split(form, "/"); len(target) == len(parts) && segmentsMatch(parts, target, false) {
					return form, true
				}
			}
		}
	}
	return "", false
}

// segmentsMatch matches a pattern to a path one segment at a time, as the
// shell does: a wildcard never crosses a slash, and matches a leading dot
// only when dotGlob is set or the pattern writes the dot.
func segmentsMatch(pattern, target []string, dotGlob bool) bool {
	for i := range target {
		if !dotGlob && strings.HasPrefix(target[i], ".") && !strings.HasPrefix(pattern[i], ".") && !strings.HasPrefix(pattern[i], `\.`) {
			return false
		}
		if ok, err := path.Match(pattern[i], target[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// reachesInto reports whether a known prefix, followed by text computed at
// run time, can only be completed inside protected ground: the prefix is at
// or below a protected directory, or has begun to spell one's name.
func (g *PathGuard) reachesInto(prefix string) (string, bool) {
	prefixes := []string{strings.ToLower(prefix)}
	directory, rest := path.Split(prefix)
	if resolved := strings.ToLower(strings.TrimSuffix(resolveExisting(directory), "/") + "/" + rest); resolved != prefixes[0] {
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

// resolveExisting follows symbolic links in the part of a path that exists
// and keeps the rest as written, so a file that is about to be created under
// a linked directory resolves to where it will land.
func resolveExisting(value string) string {
	current := filepath.Clean(filepath.FromSlash(value))
	remainder := ""
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.ToSlash(filepath.Join(resolved, remainder))
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.ToSlash(filepath.Join(current, remainder))
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
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
