package shellscan

import (
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// classifyString parses a shell snippet and walks every command node,
// including those inside pipelines, substitutions and subshells.
func (c *collector) classifyString(src, via string, depth int) {
	if depth > maxWrapperDepth {
		c.decide("wrapper nesting too deep to classify statically")
		return
	}
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil {
		c.signal(SignalParseError)
		c.parseOK = false
		c.decide("unparseable shell command (fail-closed)")
		return
	}
	if len(file.Stmts) > 1 {
		c.signal(SignalChaining)
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			switch n.Op {
			case syntax.Pipe:
				c.signal(SignalChaining)
				if encodedPipeline(n) {
					c.signal(SignalEncodedWrapper)
					c.decide("encoded payload decoded into a shell or eval")
				}
			case syntax.AndStmt, syntax.OrStmt:
				c.signal(SignalChaining)
			}
		case *syntax.CmdSubst:
			c.classifySubstitution(n.Stmts)
		case *syntax.ProcSubst:
			c.classifySubstitution(n.Stmts)
		case *syntax.Assign:
			c.markLiteralWord(n.Value)
			c.recordAssignment(n)
		case *syntax.Stmt:
			c.classifyShellInput(n, via, depth)
		case *syntax.SglQuoted:
			if n.Dollar {
				c.signal(SignalANSICQuoting)
				c.decide("ANSI-C quoting cannot be evaluated statically (fail-closed)")
			}
		case *syntax.DblQuoted:
			if n.Dollar {
				c.signal(SignalANSICQuoting)
				c.decide("locale quoting cannot be evaluated statically (fail-closed)")
			}
		case *syntax.Word:
			c.guardWord(n)
			if !c.literalWords[n] && hasBraceExpansion(n) {
				c.signal(SignalBraceExpansion)
				c.decide("brace expansion cannot be evaluated statically (fail-closed)")
			}
		case *syntax.FuncDecl:
			c.hasIndirection = true
		case *syntax.Redirect:
			c.markLiteralWord(n.Hdoc)
			c.classifyRedirect(n)
		case *syntax.CallExpr:
			c.classifyCall(n, via, depth)
		}
		return true
	})
}

func (c *collector) markLiteralWord(w *syntax.Word) {
	if w == nil {
		return
	}
	if c.literalWords == nil {
		c.literalWords = map[*syntax.Word]bool{}
	}
	c.literalWords[w] = true
}

// recordAssignment keeps an assignment to a variable that network clients
// read. Scope is not modelled: a prefix assignment, an export and a plain
// assignment all count for every network command in the text.
func (c *collector) recordAssignment(assign *syntax.Assign) {
	if assign.Name == nil && assign.Naked && assign.Value != nil {
		// export "NAME=value" and declare -x 'NAME=value' reach the parser as
		// one quoted word, not as a name and a value; the shell still assigns.
		word := resolveWord(assign.Value)
		name, value, isAssignment := strings.Cut(word.text, "=")
		switch {
		case strings.HasPrefix(word.text, "-"):
			// an option of the builtin
		case word.dynamic && (!isAssignment || !assignmentWord(word.text)):
			c.env = append(c.env, envOverride{dynamic: true})
		case isAssignment && tracksVariable(name):
			c.env = append(c.env, envOverride{name: name, value: value, dynamic: word.dynamic})
		}
		return
	}
	if assign.Name == nil || !tracksVariable(assign.Name.Value) {
		return
	}
	override := envOverride{name: assign.Name.Value, dynamic: assign.Append || assign.Array != nil || assign.Index != nil}
	if assign.Value != nil {
		value := resolveWord(assign.Value)
		override.value, override.dynamic = value.text, override.dynamic || value.dynamic
	}
	c.env = append(c.env, override)
}

// classifyShellInput classifies a heredoc or here-string that feeds a shell
// its commands. The shell invocation itself still fails closed as reading
// standard input; this adds what the visible script would do.
func (c *collector) classifyShellInput(stmt *syntax.Stmt, via string, depth int) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	name := resolveCommandWord(call.Args[0])
	if name.dynamic || !shellNames[path.Base(name.text)] {
		return
	}
	for _, redirect := range stmt.Redirs {
		var body *syntax.Word
		switch redirect.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			body = redirect.Hdoc
		case syntax.WordHdoc:
			body = redirect.Word
		}
		if body == nil {
			continue
		}
		if script := resolveWord(body); !script.dynamic {
			c.classifyString(script.text, joinVia(via, path.Base(name.text)+" stdin"), depth+1)
		}
	}
}

// classifySubstitution decides whether a command or process substitution
// needs a decision of its own. Its inner commands are classified by the
// surrounding walk either way. A substitution whose every inner command is on
// the read-only allowlist with literal input yields opaque text, and the word
// holding it stays dynamic: command position, eval, sh -c, source,
// interpreters, redirect targets and destructive operands still fail closed
// on that word. Anything else requires a decision.
func (c *collector) classifySubstitution(stmts []*syntax.Stmt) {
	c.signal(SignalCommandSubstitution)
	c.hasIndirection = true
	if !readOnlySubstitution(stmts) {
		c.decide("command substitution runs a command outside the read-only allowlist (fail-closed)")
	}
}

// readOnlySubstitution reports whether every statement is one allowlisted
// read-only command with literal words and at most heredoc or here-string
// input: no pipelines, lists, assignments, other redirects or nested
// expansion.
func readOnlySubstitution(stmts []*syntax.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	for _, stmt := range stmts {
		if stmt.Negated || stmt.Background || stmt.Coprocess {
			return false
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
			return false
		}
		args := make([]string, 0, len(call.Args))
		for _, word := range call.Args {
			tok := resolveWord(word)
			if tok.dynamic || tok.glob || hasBraceExpansion(word) {
				return false
			}
			args = append(args, tok.text)
		}
		literalInput := false
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.Hdoc, syntax.DashHdoc:
				literalInput = true
			case syntax.WordHdoc:
				if resolveWord(redirect.Word).dynamic {
					return false
				}
				literalInput = true
			default:
				return false
			}
		}
		if !readOnlySubstitutionCommand(args, literalInput) {
			return false
		}
	}
	return true
}

// readOnlySubstitutionCommand is the deliberately small allowlist of commands
// whose output may be captured without a decision.
func readOnlySubstitutionCommand(args []string, literalInput bool) bool {
	rest := args[1:]
	switch args[0] {
	case "cat":
		// Only the heredoc or here-string itself, never a file.
		return literalInput && len(rest) == 0
	case "echo", "printf", "basename", "dirname":
		return true
	case "pwd":
		for _, arg := range rest {
			if arg != "-L" && arg != "-P" {
				return false
			}
		}
		return true
	case "date":
		// Display formats only; an operand or -s/--set would set the clock.
		for _, arg := range rest {
			switch {
			case strings.HasPrefix(arg, "+"), arg == "-u", arg == "--utc", arg == "--universal",
				arg == "-R", arg == "--rfc-email", strings.HasPrefix(arg, "-I"),
				strings.HasPrefix(arg, "--iso-8601"), strings.HasPrefix(arg, "--rfc-3339="):
			default:
				return false
			}
		}
		return true
	case "git":
		// The subcommand must come first: global options such as -c can run
		// configured programs.
		if len(rest) == 0 {
			return false
		}
		switch rest[0] {
		case "rev-parse":
			return true
		case "log":
			for _, arg := range rest[1:] {
				if strings.HasPrefix(arg, "--output") {
					return false
				}
			}
			return true
		}
	}
	return false
}

func encodedPipeline(node *syntax.BinaryCmd) bool {
	decoded := false
	for _, call := range pipelineCalls(node) {
		if len(call.Args) == 0 {
			continue
		}
		args := make([]wordTok, 0, len(call.Args))
		for _, word := range call.Args {
			args = append(args, resolveWord(word))
		}
		if args[0].dynamic {
			continue
		}
		name := path.Base(path.Clean(args[0].text))
		if decoded && (name == "eval" || shellNames[name]) {
			return true
		}
		if isDecoderCall(name, args[1:]) {
			decoded = true
		}
	}
	return false
}

func pipelineCalls(node *syntax.BinaryCmd) []*syntax.CallExpr {
	var calls []*syntax.CallExpr
	var walkStmt func(*syntax.Stmt)
	walkStmt = func(stmt *syntax.Stmt) {
		if stmt == nil {
			return
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && binary.Op == syntax.Pipe {
			walkStmt(binary.X)
			walkStmt(binary.Y)
			return
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			calls = append(calls, call)
		}
	}
	walkStmt(node.X)
	walkStmt(node.Y)
	return calls
}

func isDecoderCall(name string, args []wordTok) bool {
	switch name {
	case "base64":
		for _, arg := range args {
			if !arg.dynamic && (arg.text == "-d" || arg.text == "--decode" || arg.text == "-D") {
				return true
			}
		}
	case "xxd":
		for _, arg := range args {
			if !arg.dynamic && strings.HasPrefix(arg.text, "-r") {
				return true
			}
		}
	case "openssl":
		hasDecode, hasBase64 := false, false
		for _, arg := range args {
			if arg.dynamic {
				continue
			}
			hasDecode = hasDecode || arg.text == "-d"
			hasBase64 = hasBase64 || arg.text == "-base64" || arg.text == "-a" || arg.text == "-A"
		}
		return hasDecode && hasBase64
	}
	return false
}

func (c *collector) classifyRedirect(r *syntax.Redirect) {
	c.signal(SignalRedirect)
	if r.Word == nil {
		return
	}
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrInOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		// write-capable redirect
	case syntax.DplOut:
		// ">&word" duplicates a descriptor when word is a number or "-", and
		// writes stdout and stderr to the file word otherwise.
		if word := resolveWord(r.Word); !word.dynamic && (word.text == "-" || fileDescriptor(word.text)) {
			return
		}
	case syntax.RdrIn:
		target := resolveWord(r.Word)
		if scan, ok := deviceSocketEgress(target); ok {
			c.facts = append(c.facts, scan.facts("a shell socket redirect")...)
		} else if !target.dynamic && isLocalSecretPath(target.text) {
			c.facts = append(c.facts, EffectFact{
				Class:  "secret",
				Action: "secret_read",
				Target: target.text,
				Reason: "secret read via input redirect",
			})
		}
		return
	default:
		return
	}
	target := resolveWord(r.Word)
	if scan, ok := deviceSocketEgress(target); ok {
		// Bash opens a socket for this path; no file is written.
		c.facts = append(c.facts, scan.facts("a shell socket redirect")...)
		return
	}
	c.recordWriteTarget(target, "write redirect")
}

// fileDescriptor reports whether a redirect word names a descriptor ("2",
// "10", or "3-" for a move) rather than a file.
func fileDescriptor(word string) bool {
	word = strings.TrimSuffix(word, "-")
	if word == "" {
		return false
	}
	for i := 0; i < len(word); i++ {
		if word[i] < '0' || word[i] > '9' {
			return false
		}
	}
	return true
}

func (c *collector) recordWriteTarget(tok wordTok, source string) {
	if tok.dynamic || tok.glob {
		c.recordDynamicSensitiveTarget(tok, source)
		c.decide(source + " with an unresolvable target (fail-closed)")
		return
	}
	target := strings.ToLower(tok.text)
	// fd duplication targets ("&1", "&2") are not file writes.
	if strings.HasPrefix(target, "&") {
		return
	}
	if c.writtenPaths == nil {
		c.writtenPaths = map[string]bool{}
	}
	c.writtenPaths[c.normalizedPath(tok.text)] = true
	c.recordSensitiveTarget(tok, "write redirect", SignalSensitiveRedirect)
	if c.cwdUnknown && !path.IsAbs(nativePath(tok.text)) {
		c.decide(source + " relative to an unresolved directory change (fail-closed)")
	}
}

// recordDynamicSensitiveTarget matches the static fragment of an opaque
// target (for example the decoded text of $'...' or the literal tail of
// "$HOME/.bashrc") so a recognizable protected file keeps its file class.
func (c *collector) recordDynamicSensitiveTarget(tok wordTok, operation string) {
	if rule, ok := SensitiveWriteTarget(tok.text, ""); ok {
		c.markSensitiveTarget(rule, operation, SignalSensitiveTarget)
	}
}

func (c *collector) recordSensitiveTarget(tok wordTok, operation, signal string) {
	if _, ok := SensitiveWriteTarget(tok.text, c.cwd); ok {
		c.markSensitiveTarget(tok.text, operation, signal)
	}
}

func (c *collector) markSensitiveTarget(target, operation, signal string) {
	if c.sensitiveTarget == "" {
		c.sensitiveTarget = target
	}
	c.signal(signal)
	c.recordCompoundEffect()
	c.decide(fmt.Sprintf("%s to sensitive target %q", operation, target))
}

// changeDirectory follows cd/pushd inside the command so later relative write
// targets resolve against the new directory. A directory the classifier
// cannot resolve (dynamic, globbed, "-", $HOME, a stack entry) makes later
// relative write targets opaque instead.
func (c *collector) changeDirectory(args []wordTok) {
	endOptions := false
	for _, tok := range args {
		if tok.dynamic || tok.glob {
			c.cwdUnknown = true
			return
		}
		if !endOptions && tok.text == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(tok.text, "-") && tok.text != "-" {
			continue // -L, -P, -e, -@
		}
		if tok.text == "-" || strings.HasPrefix(tok.text, "+") {
			c.cwdUnknown = true
			return
		}
		target := nativePath(tok.text)
		if c.home != "" && (target == "~" || strings.HasPrefix(target, "~/")) {
			target = c.home + target[1:]
		}
		if path.IsAbs(target) {
			c.cwdUnknown = false
		}
		c.cwd = c.normalizedPath(target)
		return
	}
	// No operand: cd changes to $HOME.
	if c.home == "" {
		c.cwdUnknown = true
		return
	}
	c.cwd, c.cwdUnknown = c.home, false
}

// recordDestructiveEffect marks a statically identified effect that needs a
// shell-operate permission when it is combined with a protected file target.
// It deliberately excludes opaque or merely suspicious commands: callers use
// it only after matching a concrete destructive operation.
func (c *collector) recordDestructiveEffect() {
	c.destructiveEffect = true
	c.recordCompoundEffect()
}

func (c *collector) recordCompoundEffect() {
	if !c.destructiveEffect || c.sensitiveTarget == "" {
		return
	}
	c.requiresShellPermission = true
	c.signal(SignalSensitiveDestructive)
}

func (c *collector) recordTeeWrites(args []wordTok) {
	endOptions := false
	targets := make([]wordTok, 0, len(args)-1)
	for _, tok := range args[1:] {
		if tok.dynamic {
			targets = append(targets, tok)
			continue
		}
		if !endOptions && tok.text == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(tok.text, "-") && tok.text != "-" {
			switch {
			case !strings.HasPrefix(tok.text, "--") && strings.Trim(tok.text[1:], "aip") == "",
				tok.text == "--append", tok.text == "--ignore-interrupts",
				tok.text == "--output-error", strings.HasPrefix(tok.text, "--output-error="):
				continue
			case tok.text == "--help", tok.text == "--version":
				return
			default:
				c.decide("tee with unrecognized flag " + tok.text + " (fail-closed)")
				continue
			}
		}
		if tok.text != "-" {
			targets = append(targets, tok)
		}
	}
	for _, target := range targets {
		c.recordWriteTarget(target, "tee write")
	}
}

// classifyCall resolves one command call's words and classifies it,
// unwrapping sudo/env/eval/sh -c/xargs wrappers recursively.
func (c *collector) classifyCall(call *syntax.CallExpr, via string, depth int) {
	args := make([]wordTok, 0, len(call.Args))
	for i, w := range call.Args {
		tok := resolveWord(w)
		if i == 0 && !tok.dynamic {
			tok = resolveCommandWord(w)
		}
		args = append(args, tok)
	}
	c.classifyTokens(args, via, depth)
}

type wordTok struct {
	text    string
	dynamic bool
	// glob is true when an unquoted part holds a pathname-expansion pattern,
	// so the word names whatever files match at run time.
	glob bool
}

// hasGlobPattern reports whether an unquoted literal holds an unescaped "*",
// "?" or bracket expression. A lone "[" (the test builtin) is not a pattern.
func hasGlobPattern(lit string) bool {
	// A "[" is glob syntax when a "]" follows it anywhere; the last "]" is
	// found once, so a word of many "[" costs one pass, not one per "[".
	lastClose := strings.LastIndexByte(lit, ']')
	for i := 0; i < len(lit); i++ {
		switch lit[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		case '[':
			if lastClose > i {
				return true
			}
		}
	}
	return false
}

// hasBraceExpansion reports whether bash would brace-expand the word. It
// splits a copy so the parsed word stays intact for the other resolvers.
func hasBraceExpansion(w *syntax.Word) bool {
	split := *w
	if !syntax.SplitBraces(&split) {
		return false
	}
	for _, part := range split.Parts {
		if _, ok := part.(*syntax.BraceExp); ok {
			return true
		}
	}
	return false
}

// decodeANSIC decodes the escapes of a $'...' body. The result is only used
// to recognize a protected target; the word itself stays opaque.
func decodeANSIC(value string) string {
	decoded, _, err := expand.Format(nil, value, nil)
	if err != nil {
		return value
	}
	return decoded
}

func unescapeLit(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Inside shell double quotes, only these escapes lose their backslash.
// A quoted curl form can itself contain quotes; preserve the argv curl sees.
func unescapeDoubleQuoted(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\n':
				i++
				continue
			case '$', '`', '"', '\\':
				i++
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func resolveCommandWord(w *syntax.Word) wordTok {
	var b strings.Builder
	glob := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			glob = glob || hasGlobPattern(p.Value)
			b.WriteString(unescapeLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				return wordTok{dynamic: true}
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return wordTok{dynamic: true}
			}
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return wordTok{dynamic: true}
				}
				b.WriteString(unescapeDoubleQuoted(lit.Value))
			}
		default:
			return wordTok{dynamic: true}
		}
	}
	return wordTok{text: b.String(), glob: glob}
}

func resolveWord(w *syntax.Word) wordTok {
	var b strings.Builder
	dynamic, glob := false, false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			glob = glob || hasGlobPattern(p.Value)
			b.WriteString(unescapeLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				b.WriteString(decodeANSIC(p.Value))
				dynamic = true
				continue
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			// $"..." is locale-translated at run time.
			dynamic = dynamic || p.Dollar
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					b.WriteString(unescapeDoubleQuoted(lit.Value))
				} else {
					dynamic = true
				}
			}
		default:
			// ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob, ...
			dynamic = true
		}
	}
	return wordTok{text: b.String(), dynamic: dynamic, glob: glob}
}
