package shellscan

import (
	"fmt"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Signal names recorded during classification. Signals are audit metadata for
// the decision receipt; they never grant anything by themselves.
const (
	SignalParseError          = "parse-error"
	SignalCommandSubstitution = "command-substitution"
	SignalChaining            = "command-chaining"
	SignalRedirect            = "redirect"
	SignalEncodedWrapper      = "encoded-wrapper"
	SignalPathObfuscation     = "path-obfuscation"
	SignalPrivilegeWrapper    = "privilege-wrapper"
	SignalEnvWrapper          = "env-wrapper"
	SignalEvalWrapper         = "eval-wrapper"
	SignalShellInvocation     = "shell-invocation"
	SignalSensitiveRedirect   = "sensitive-redirect"
)

// maxWrapperDepth bounds recursive unwrapping of eval / sh -c payloads so
// adversarial nesting cannot exhaust the classifier.
const maxWrapperDepth = 8

// Command is one statically classified command node from the parsed AST.
type Command struct {
	Name    string   // basename of the command word (after wrapper unwrapping)
	Tokens  []string // statically resolved tokens (empty segments mark dynamic words)
	Prefix  string   // arity-aware prefix, e.g. "git checkout"
	Via     string   // wrapper chain this command was reached through ("" = direct)
	Dynamic bool     // true when any token could not be resolved statically
}

// Result is the advisory classification of one raw shell command string.
type Result struct {
	// Decide is true when the command must be routed through the kernel's
	// signed decision path instead of passing through unclassified.
	Decide   bool
	Reason   string
	ParseOK  bool
	Commands []Command
	Signals  []string
}

// legacyNeedles is the pre-AST substring list from hook_cmd.go, kept verbatim
// as a fallback layer so existing classification behavior is strictly
// preserved (the AST layer only ever adds detection).
var legacyNeedles = []string{
	"rm -rf ",
	"rm -fr ",
	"rm -r ",
	"git reset --hard",
	"git clean -fd",
	"git clean -xdf",
	"mkfs",
	"dd if=",
	"kubectl delete",
	"docker rm -f",
	"drop table",
	"truncate table",
}

// sensitiveRedirectTargets mirrors the sensitive-write list in the hook so a
// shell redirect cannot bypass the Write-tool path protection.
var sensitiveRedirectTargets = []string{
	".env",
	".pem",
	".key",
	"id_rsa",
	"id_ed25519",
	".git/",
	`.git\`,
}

// Classify parses and structurally classifies a raw shell command string.
// Fail-closed: anything the classifier cannot statically understand in a
// security-relevant position is decision-worthy, never safe.
func Classify(raw string) Result {
	res := Result{ParseOK: true}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return res
	}

	c := &collector{parseOK: true}
	// Fallback layer: legacy substring needles on the raw text.
	if needle := legacyNeedleHit(trimmed); needle != "" {
		c.decide(fmt.Sprintf("legacy needle %q", needle))
	}
	c.classifyString(trimmed, "", 0)

	res.Decide = c.decideFlag
	res.Reason = strings.Join(c.reasons, "; ")
	res.Commands = c.commands
	res.Signals = c.signalList()
	res.ParseOK = c.parseOK
	return res
}

type collector struct {
	decideFlag bool
	reasons    []string
	commands   []Command
	signals    map[string]bool
	parseOK    bool

	writtenPaths map[string]bool
}

func (c *collector) decide(reason string) {
	c.decideFlag = true
	for _, existing := range c.reasons {
		if existing == reason {
			return
		}
	}
	c.reasons = append(c.reasons, reason)
}

func (c *collector) signal(name string) {
	if c.signals == nil {
		c.signals = map[string]bool{}
	}
	c.signals[name] = true
}

func (c *collector) signalList() []string {
	out := make([]string, 0, len(c.signals))
	for name := range c.signals {
		out = append(out, name)
	}
	// Deterministic order for tests and receipts.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

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
		case *syntax.CmdSubst, *syntax.ProcSubst:
			c.signal(SignalCommandSubstitution)
		case *syntax.Redirect:
			c.classifyRedirect(n)
		case *syntax.CallExpr:
			c.classifyCall(n, via, depth)
		}
		return true
	})
}

func encodedPipeline(node syntax.Node) bool {
	decoded, executed := false, false
	syntax.Walk(node, func(child syntax.Node) bool {
		call, ok := child.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		args := make([]wordTok, 0, len(call.Args))
		for _, word := range call.Args {
			args = append(args, resolveWord(word))
		}
		if args[0].dynamic {
			return true
		}
		name := path.Base(path.Clean(args[0].text))
		executed = executed || name == "eval" || shellNames[name]
		decoded = decoded || isDecoderCall(name, args[1:])
		return true
	})
	return decoded && executed
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
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrInOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		// write-capable redirect
	default:
		return
	}
	if r.Word == nil {
		return
	}
	c.recordWriteTarget(resolveWord(r.Word), "write redirect")
}

func (c *collector) recordWriteTarget(tok wordTok, source string) {
	if tok.dynamic {
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
	c.writtenPaths[path.Clean(tok.text)] = true
	for _, needle := range sensitiveRedirectTargets {
		if strings.Contains(target, needle) {
			c.signal(SignalSensitiveRedirect)
			c.decide(fmt.Sprintf("write redirect to sensitive target %q", tok.text))
			return
		}
	}
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
}

func unescapeCommandLit(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func resolveCommandWord(w *syntax.Word) wordTok {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescapeCommandLit(p.Value))
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return wordTok{dynamic: true}
				}
				b.WriteString(lit.Value)
			}
		default:
			return wordTok{dynamic: true}
		}
	}
	return wordTok{text: b.String()}
}

func resolveWord(w *syntax.Word) wordTok {
	var b strings.Builder
	dynamic := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				} else {
					dynamic = true
				}
			}
		default:
			// ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob, ...
			dynamic = true
		}
	}
	return wordTok{text: b.String(), dynamic: dynamic}
}

// valueFlags lists wrapper flags that consume a value (short and long forms;
// long forms also match their --flag=value attached spelling).
var valueFlags = map[string]map[string]bool{
	"sudo": {
		"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-T": true,
		"-D": true, "-U": true, "-t": true, "-R": true,
		"--user": true, "--group": true, "--host": true, "--prompt": true,
		"--chdir": true, "--role": true, "--type": true, "--close-from": true,
		"--other-user": true, "--command-timeout": true,
	},
	"exec":   {"-a": true},
	"nice":   {"-n": true, "--adjustment": true},
	"stdbuf": {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"time":   {"-f": true, "-o": true, "--format": true, "--output": true},
	"xargs": {
		"-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-d": true, "-E": true, "-a": true,
		"-i": true, "-l": true, // deprecated aliases of -I / -L (take values)
		"--replace": true, "--max-lines": true, "--max-args": true, "--max-procs": true,
		"--max-chars": true, "--delimiter": true, "--eof": true, "--arg-file": true,
	},
}

// noValueShortFlags lists wrapper short flags known to take no value.
// Unknown short flags are NOT assumed valueless: they may consume the next
// token, so they are treated as ambiguous and route to the decision path.
var noValueShortFlags = map[string]map[string]bool{
	"sudo": {
		"-A": true, "-b": true, "-E": true, "-e": true, "-H": true, "-i": true,
		"-k": true, "-K": true, "-l": true, "-n": true, "-P": true, "-S": true,
		"-s": true, "-v": true, "-V": true,
	},
	"xargs":   {"-0": true, "-p": true, "-t": true, "-v": true, "-x": true, "-r": true, "-o": true},
	"setsid":  {"-f": true, "-w": true, "-c": true},
	"time":    {"-p": true, "-a": true, "-v": true, "-q": true},
	"exec":    {"-l": true, "-c": true},
	"command": {"-p": true},
	"builtin": {"-a": true, "-p": true},
}

// noValueLongFlags lists wrapper long flags known to take no value. Unknown
// long flags are treated as ambiguous (they may consume the next token) and
// route to the decision path.
var noValueLongFlags = map[string]map[string]bool{
	"sudo": {
		"--login": true, "--shell": true, "--edit": true, "--background": true,
		"--preserve-env": true, "--non-interactive": true, "--validate": true,
		"--reset-timestamp": true, "--remove-timestamp": true, "--kill": true,
		"--update": true, "--stdin": true, "--help": true, "--version": true,
	},
	"xargs": {
		"--interactive": true, "--verbose": true, "--exit": true, "--null": true,
		"--no-run-if-empty": true, "--open-tty": true, "--show-limits": true,
	},
	"setsid": {"--ctty": true, "--fork": true, "--wait": true},
}

// dropWrapperFlags removes leading flag tokens (and their values) from args.
// It returns nil when the flag sequence cannot be resolved statically —
// dynamic words or unrecognized long flags in flag position are ambiguous
// because they may hide the wrapped command or its flags.
func dropWrapperFlags(cmd string, args []wordTok) []wordTok {
	vals := valueFlags[cmd]
	novals := noValueLongFlags[cmd]
	shortNovals := noValueShortFlags[cmd]
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok.text == "--" {
			i++
			break
		}
		if tok.dynamic {
			return nil
		}
		if !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			break
		}
		if strings.HasPrefix(tok.text, "--") {
			name := tok.text
			attached := false
			if idx := strings.Index(name, "="); idx >= 0 {
				name, attached = name[:idx], true
			}
			if vals[name] {
				if attached {
					i++
				} else {
					i += 2
				}
				continue
			}
			if novals[name] {
				i++
				continue
			}
			return nil // unknown long flag may consume the next token
		}
		// Short-flag cluster: a value-taking flag consumes the rest of the
		// cluster or, when last, the next token. Unknown short flags are NOT
		// assumed valueless (WRAPPER_SHORT_VALUE_BYPASS): they are ambiguous.
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			key := "-" + string(cluster[j])
			if vals[key] {
				if j+1 == len(cluster) {
					i++
				}
				break // value consumes the rest of the cluster
			}
			if shortNovals[key] {
				continue
			}
			return nil
		}
		i++
	}
	if i > len(args) {
		return nil
	}
	return args[i:]
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
	"mksh": true, "yash": true, "tcsh": true, "csh": true, "rc": true,
	"fish": true, "nu": true, "pwsh": true, "powershell": true,
	"elvish": true, "xonsh": true,
}

// strictFlagShells are shells whose single-dash options are not guaranteed
// POSIX-valueless (fish -d takes a value, pwsh uses -Word options). For
// these, unrecognized short-flag characters are ambiguous → decision path.
var strictFlagShells = map[string]bool{
	"fish": true, "nu": true, "pwsh": true, "powershell": true,
	"elvish": true, "xonsh": true,
}

// splitEnvPayload splits an env -S/--split-string payload into words using
// the shell parser (env's splitting is shell-like: quotes are honored).
// The payload must reduce to a single simple command line.
func splitEnvPayload(payload string) ([]wordTok, bool) {
	if strings.TrimSpace(payload) == "" {
		return nil, true
	}
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(payload), "")
	if err != nil || len(file.Stmts) != 1 || file.Stmts[0].Negated || file.Stmts[0].Background {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 {
		return nil, false
	}
	out := make([]wordTok, 0, len(call.Args))
	for _, w := range call.Args {
		out = append(out, resolveWord(w))
	}
	return out, true
}

// executorSpec describes a process-executor wrapper whose leading positional
// operands configure the execution instead of naming the command.
type executorSpec struct {
	valueShort     string   // letters of value-taking short flags
	valueLong      []string // long flags taking a value
	noValueShort   string   // letters of no-value short flags
	noValueLong    []string // long flags taking no value
	commandShort   string   // short flags whose values are command strings
	commandLong    []string // long flags whose values are command strings
	pidFlag        byte     // short flag meaning "operate on a pid; no command executes" (0 = none)
	skip           int      // leading positionals before the command (duration, mask, lockfile, jail dir)
	decideBare     bool     // invocation with operands but no command is opaque (chroot runs a shell)
	requireCommand bool     // no command-string flag means an opaque shell (su)
}

// executorWrappers are process-executor prefixes (UNKNOWN_WRAPPER_BYPASS).
// Unknown flags on these wrappers route to the decision path.
var executorWrappers = map[string]executorSpec{
	"timeout": {
		valueShort: "sk", valueLong: []string{"--signal", "--kill-after"},
		noValueShort: "v", noValueLong: []string{"--preserve-status", "--foreground"},
		skip: 1, // DURATION
	},
	"flock": {
		valueShort: "wEc", valueLong: []string{"--timeout", "--conflict-exit-code", "--command"},
		noValueShort: "sxunoFv", noValueLong: []string{"--shared", "--exclusive", "--unlock", "--nonblock", "--close", "--fork", "--verbose"},
		commandShort: "c", commandLong: []string{"--command"},
		skip: 1, // LOCKFILE
	},
	"su": {
		valueShort: "cCgsGw", valueLong: []string{"--command", "--session-command", "--group", "--supp-group", "--shell", "--whitelist-environment"},
		noValueShort: "flmPp", noValueLong: []string{"--fast", "--login", "--preserve-environment", "--pty", "--help", "--version"},
		commandShort: "cC", commandLong: []string{"--command", "--session-command"},
		requireCommand: true,
	},
	"taskset": {
		valueShort: "c", valueLong: []string{"--cpu-list"},
		pidFlag: 'p',
		skip:    1, // MASK (absent when -c/--cpu-list supplies it)
	},
	"chrt": {
		valueShort:   "pTPD",
		valueLong:    []string{"--sched-runtime", "--sched-period", "--sched-deadline"},
		noValueShort: "frobiamd", noValueLong: []string{"--fifo", "--rr", "--other", "--batch", "--idle", "--deadline", "--all", "--max"},
		pidFlag: 'p',
		skip:    1, // PRIO
	},
	"ionice": {
		valueShort:   "cnp",
		valueLong:    []string{"--class", "--classdata", "--pid"},
		noValueShort: "t", noValueLong: []string{"--ignore"},
		pidFlag: 'p',
	},
	"chroot": {
		valueLong:   []string{"--userspec", "--groups"},
		noValueLong: []string{"--help", "--version"},
		skip:        1, // NEWROOT
		decideBare:  true,
	},
	"strace": {
		valueShort:   "eopusPES",
		valueLong:    []string{"--trace", "--output", "--user", "--env", "--string-limit", "--summary-sort-by", "--filter", "--detach-on"},
		noValueShort: "bfDxXykKcCwtTzZvVrAiqdF",
		noValueLong:  []string{"--follow-forks", "--summary", "--summary-wall-clock", "--timestamps", "--syscall-times", "--instruction-pointer", "--stack-trace", "--decode-fds", "--help", "--version"},
		pidFlag:      'p',
	},
	"ltrace": {
		valueShort:   "eolxsnFp",
		valueLong:    []string{"--output", "--filter", "--library", "--config", "--indent", "--strlen", "--pid"},
		noValueShort: "tifrdSCV",
		noValueLong:  []string{"--timestamp", "--follow-forks", "--demangle", "--help", "--version"},
		pidFlag:      'p',
	},
	"catchsegv": {},
	"valgrind": {
		noValueShort: "qv",
		valueLong: []string{
			"--tool", "--log-file", "--xml-file", "--xml-fd", "--suppressions",
			"--error-exitcode", "--leak-check", "--show-leak-kinds", "--track-origins",
			"--gen-suppressions", "--num-callers", "--max-stackframe", "--main-stacksize",
			"--max-threads", "--fair-sched", "--smc-check", "--read-var-info",
			"--freelist-vol", "--malloc-fill", "--free-fill", "--demangle",
			"--error-limit", "--show-below-main", "--partial-loads-ok",
			"--expensive-definedness-checks", "--keep-stacktraces", "--xml-user-comment",
		},
		noValueLong: []string{"--help", "--version", "--verbose", "--quiet"},
	},
}

// hasSudoShellFlag reports whether sudo/doas arguments contain -s/-i (or
// --shell/--login), honoring value-taking flags so their values are not
// misread as flags (e.g. -ui is -u with value "i", not the -i shell flag).
func hasSudoShellFlag(args []wordTok) bool {
	vals := valueFlags["sudo"]
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic || tok.text == "--" || !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			return false
		}
		if strings.HasPrefix(tok.text, "--") {
			name := tok.text
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			if name == "--shell" || name == "--login" {
				return true
			}
			if vals[name] && !strings.Contains(tok.text, "=") {
				i++ // skip the value token
			}
			continue
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			key := "-" + string(cluster[j])
			if vals[key] {
				if j+1 == len(cluster) {
					i++ // value is the next token
				}
				break // value consumes the rest of the cluster
			}
			if cluster[j] == 's' || cluster[j] == 'i' {
				return true
			}
		}
	}
	return false
}

// xargsUsesReplace reports whether xargs arguments use -I/--replace
// (including the deprecated -i alias), which makes the command template
// data-driven and unclassifiable.
func xargsUsesReplace(args []wordTok) bool {
	vals := valueFlags["xargs"]
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic || tok.text == "--" || !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			return false
		}
		if strings.HasPrefix(tok.text, "--") {
			name := tok.text
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			if name == "--replace" {
				return true
			}
			if vals[name] && !strings.Contains(tok.text, "=") {
				i++ // skip the value token
			}
			continue
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			key := "-" + string(cluster[j])
			if vals[key] {
				if cluster[j] == 'I' || cluster[j] == 'i' {
					return true
				}
				if j+1 == len(cluster) {
					i++ // value is the next token
				}
				break // value consumes the rest of the cluster
			}
		}
	}
	return false
}

// isExecutorWrapper reports whether name is a registered process-executor
// wrapper.
func isExecutorWrapper(name string) bool {
	_, ok := executorWrappers[name]
	return ok
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// shellLongValueFlags are shell long flags that consume the next token.
var shellLongValueFlags = map[string]bool{
	"--init-file": true, "--rcfile": true, "--emulate": true,
}

// scanShellScriptFlag analyzes a shell invocation's arguments. It locates
// the script operand of a -c flag, honoring combined short-flag clusters
// (-lc), attached values (-cCMD), value-taking flags (-o option, bash -O
// shopt, long flags with values), "--" end-of-options, and -s/stdin mode.
//
// Returns: the -c script word (found), whether the shell will read commands
// from stdin because no static script source exists (stdin), whether scanning
// hit an unresolvable word (ambiguous), and whether a positional script file
// was seen (positional).
func scanShellScriptFlag(rest []wordTok, strict bool) (script wordTok, found, stdin, ambiguous bool, positional wordTok) {
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		if tok.dynamic {
			return wordTok{}, false, false, true, wordTok{}
		}
		if tok.text == "--" {
			if i+1 < len(rest) {
				return wordTok{}, false, false, false, rest[i+1] // positional after --
			}
			return wordTok{}, false, true, false, wordTok{}
		}
		if tok.text == "--help" || tok.text == "--version" {
			// Prints and exits; treat like a benign positional.
			return wordTok{}, false, false, false, tok
		}
		if strings.HasPrefix(tok.text, "--") {
			if shellLongValueFlags[tok.text] {
				i++
			}
			continue
		}
		if tok.text == "-" {
			return wordTok{}, false, true, false, wordTok{}
		}
		if !strings.HasPrefix(tok.text, "-") {
			return wordTok{}, false, false, false, tok // script file positional
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'c':
				if j+1 < len(cluster) {
					// Attached payload: bash -cCMD (e.g. -c'rm -rf /').
					return wordTok{text: cluster[j+1:]}, true, false, false, wordTok{}
				}
				if i+1 < len(rest) {
					return rest[i+1], true, false, false, wordTok{}
				}
				return wordTok{}, false, true, false, wordTok{} // -c with no operand: stdin
			case 's':
				// -s reads commands from standard input: opaque.
				return wordTok{}, false, true, false, wordTok{}
			case 'o', 'O':
				// -o option-name / bash -O shopt_option: value is attached
				// or the next token.
				if j+1 == len(cluster) {
					i++
				}
				j = len(cluster) // value consumes the rest of the cluster
			default:
				// POSIX single-letter shell options are valueless, so
				// letters are safe to skip for POSIX shells. For strict
				// shells (fish/pwsh/nu/...) letter options may take values,
				// so any unrecognized option is ambiguous. Non-letter
				// characters (digits, punctuation) are never standard
				// options and are always ambiguous. Both fail closed.
				if strict {
					return wordTok{}, false, false, true, wordTok{}
				}
				if !((cluster[j] >= 'a' && cluster[j] <= 'z') || (cluster[j] >= 'A' && cluster[j] <= 'Z')) {
					return wordTok{}, false, false, true, wordTok{}
				}
			}
		}
	}
	return wordTok{}, false, true, false, wordTok{} // no script source: stdin
}

func (c *collector) classifyTokens(args []wordTok, via string, depth int) {
	for len(args) > 0 {
		head := args[0]
		if head.dynamic {
			c.decide("dynamic command word cannot be classified statically")
			return
		}
		name := head.text
		if strings.Contains(name, "/") {
			cleaned := path.Clean(name)
			if cleaned != name {
				c.signal(SignalPathObfuscation)
			}
			name = path.Base(cleaned)
		}
		switch {
		case name == "sudo" || name == "doas":
			c.signal(SignalPrivilegeWrapper)
			if hasSudoShellFlag(args[1:]) {
				// sudo -s/-i (and long forms) launch a privileged shell —
				// opaque regardless of any trailing command (fail-closed).
				c.decide(name + " launches a privileged shell (fail-closed)")
				return
			}
			args = dropWrapperFlags("sudo", args[1:])
			via = joinVia(via, name)
			if args != nil && len(args) == 0 {
				c.decide(name + " without a command (fail-closed)")
				return
			}
		case name == "env":
			c.signal(SignalEnvWrapper)
			via = joinVia(via, "env")
			rest := args[1:]
			commandIdx := -1
			splits := 0
		envScan:
			for i := 0; i < len(rest); i++ {
				tok := rest[i]
				if tok.dynamic {
					c.decide("env wrapper arguments cannot be resolved statically")
					return
				}
				if tok.text == "--" {
					commandIdx = i + 1
					break
				}
				if strings.HasPrefix(tok.text, "--") {
					switch {
					case tok.text == "--help" || tok.text == "--version":
						c.record(Command{Name: "env", Via: via, Prefix: "env"})
						return
					case tok.text == "--ignore-environment" || tok.text == "--null":
						// flag without a value
					case tok.text == "--unset" || tok.text == "--chdir":
						i++ // value is the next token
					case strings.HasPrefix(tok.text, "--unset=") || strings.HasPrefix(tok.text, "--chdir="):
						// attached value
					case tok.text == "--split-string" || strings.HasPrefix(tok.text, "--split-string="):
						payload := ""
						if tok.text == "--split-string" {
							if i+1 >= len(rest) || rest[i+1].dynamic {
								c.decide("env --split-string with an unresolvable payload")
								return
							}
							payload = rest[i+1].text
							i++
						} else {
							payload = strings.TrimPrefix(tok.text, "--split-string=")
						}
						// env -S splits ONLY the payload into words; trailing
						// arguments are appended to the split words. Combine
						// both and restart the env scan (ENV_SPLIT_SUFFIX_BYPASS).
						words, ok := splitEnvPayload(payload)
						if !ok {
							c.decide("env --split-string payload cannot be parsed statically (fail-closed)")
							return
						}
						splits++
						if splits > 4 {
							c.decide("env --split-string nesting too deep (fail-closed)")
							return
						}
						combined := make([]wordTok, 0, len(words)+len(rest))
						combined = append(combined, words...)
						combined = append(combined, rest[i+1:]...)
						rest = combined
						i = -1
						continue envScan
					default:
						c.decide("env with unrecognized flag " + tok.text + " (fail-closed)")
						return
					}
					continue
				}
				if strings.HasPrefix(tok.text, "-") && tok.text != "-" {
					// Short-flag cluster: -i/-0 take no value; -u/-C take a
					// value (attached or next token); -S payload is a command line.
					cluster := tok.text[1:]
					for j := 0; j < len(cluster); j++ {
						switch cluster[j] {
						case 'i', '0':
						case 'u', 'C':
							if j+1 == len(cluster) {
								i++ // value is the next token
							}
							j = len(cluster) // value consumes the rest of the cluster
						case 'S':
							payload := ""
							if j+1 < len(cluster) {
								payload = cluster[j+1:]
							} else if i+1 < len(rest) && !rest[i+1].dynamic {
								payload = rest[i+1].text
								i++
							} else {
								c.decide("env -S with an unresolvable payload")
								return
							}
							words, ok := splitEnvPayload(payload)
							if !ok {
								c.decide("env -S payload cannot be parsed statically (fail-closed)")
								return
							}
							splits++
							if splits > 4 {
								c.decide("env -S nesting too deep (fail-closed)")
								return
							}
							combined := make([]wordTok, 0, len(words)+len(rest))
							combined = append(combined, words...)
							combined = append(combined, rest[i+1:]...)
							rest = combined
							i = -1
							continue envScan
						default:
							c.decide(fmt.Sprintf("env with unrecognized flag -%c (fail-closed)", cluster[j]))
							return
						}
					}
					continue
				}
				if strings.Contains(tok.text, "=") {
					continue // VAR=value assignment
				}
				commandIdx = i
				break
			}
			if commandIdx < 0 || commandIdx >= len(rest) {
				// Bare env (prints the environment): nothing executes.
				c.record(Command{Name: "env", Via: via, Prefix: "env"})
				return
			}
			args = rest[commandIdx:]
		case name == "command" && len(args) > 1 && !args[1].dynamic && (args[1].text == "-v" || args[1].text == "-V"):
			c.signal(SignalEnvWrapper)
			c.record(Command{Name: name, Tokens: staticTokens(args), Prefix: name, Via: via})
			return
		case name == "nice" || name == "nohup" || name == "time" || name == "command" || name == "builtin" || name == "stdbuf" || name == "setsid" || name == "exec":
			c.signal(SignalEnvWrapper)
			args = dropWrapperFlags(name, args[1:])
			via = joinVia(via, name)
		case name == "xargs":
			c.signal(SignalEnvWrapper)
			if xargsUsesReplace(args[1:]) {
				// With -I/--replace the command template contains the
				// replacement token, so the executed command is data-driven
				// and cannot be classified statically (fail-closed).
				c.decide("xargs replacement-token template cannot be classified statically (fail-closed)")
				return
			}
			args = dropWrapperFlags("xargs", args[1:])
			via = joinVia(via, "xargs")
			if args != nil && len(args) == 0 {
				c.decide("xargs invokes a command supplied only at runtime")
				return
			}
		case name == "busybox":
			c.signal(SignalEnvWrapper)
			args = args[1:]
			via = joinVia(via, "busybox")
		case isExecutorWrapper(name):
			spec := executorWrappers[name]
			c.signal(SignalEnvWrapper)
			via = joinVia(via, name)
			rest := args[1:]
			skip := spec.skip
			i := 0
		executorScan:
			for i < len(rest) {
				tok := rest[i]
				if tok.dynamic {
					c.decide(name + " wrapper arguments cannot be resolved statically")
					return
				}
				if tok.text == "--" {
					i++
					break
				}
				if strings.HasPrefix(tok.text, "--") {
					lname := tok.text
					lval := ""
					attached := false
					if idx := strings.Index(lname, "="); idx >= 0 {
						lname, lval, attached = lname[:idx], lname[idx+1:], true
					}
					if containsString(spec.valueLong, lname) {
						if containsString(spec.commandLong, lname) {
							if !attached {
								if i+1 >= len(rest) || rest[i+1].dynamic {
									c.decide(name + " " + lname + " with an unresolvable payload")
									return
								}
								lval = rest[i+1].text
							}
							if strings.TrimSpace(lval) == "" {
								c.decide(name + " " + lname + " with an empty payload (fail-closed)")
								return
							}
							c.classifyString(lval, joinVia(via, name+" "+lname), depth+1)
							return
						}
						if name == "taskset" && lname == "--cpu-list" {
							skip = 0 // mask supplied via --cpu-list value
						}
						if !attached {
							i++
						}
						i++
						continue
					}
					if containsString(spec.noValueLong, lname) {
						i++
						continue
					}
					c.decide(name + " with unrecognized flag " + tok.text + " (fail-closed)")
					return
				}
				if !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
					break // first positional
				}
				cluster := tok.text[1:]
				for j := 0; j < len(cluster); j++ {
					ch := cluster[j]
					if spec.pidFlag != 0 && ch == spec.pidFlag {
						// pid mode: operates on an existing process, no
						// command executes.
						c.record(Command{Name: name, Via: via, Prefix: name})
						return
					}
					if strings.IndexByte(spec.valueShort, ch) >= 0 {
						payload := ""
						if j+1 < len(cluster) {
							payload = cluster[j+1:]
						} else if i+1 < len(rest) && !rest[i+1].dynamic {
							payload = rest[i+1].text
							i++ // skip the value token
						} else {
							if strings.IndexByte(spec.commandShort, ch) >= 0 {
								c.decide(name + " -" + string(ch) + " with an unresolvable payload (fail-closed)")
								return
							}
							c.decide(name + " flag -" + string(ch) + " with an unresolvable value (fail-closed)")
							return
						}
						if strings.IndexByte(spec.commandShort, ch) >= 0 {
							if strings.TrimSpace(payload) == "" {
								c.decide(name + " -" + string(ch) + " with an empty payload (fail-closed)")
								return
							}
							c.classifyString(payload, joinVia(via, name+" -c"), depth+1)
							return
						}
						if name == "taskset" && ch == 'c' {
							skip = 0 // mask supplied via -c value
						}
						i++ // move past the flag token
						continue executorScan
					}
					if strings.IndexByte(spec.noValueShort, ch) >= 0 {
						continue
					}
					c.decide(name + " with unrecognized flag -" + string(ch) + " (fail-closed)")
					return
				}
				i++
			}
			rest = rest[i:]
			if len(spec.commandShort) > 0 || len(spec.commandLong) > 0 {
				// GNU-style permutation: flock's -c/--command may appear
				// after the lockfile positional (FLOCK_COMMAND_ORDER_BYPASS).
				for k := 0; k < len(rest); k++ {
					tok := rest[k]
					if tok.dynamic {
						continue
					}
					if (len(tok.text) == 2 && strings.IndexByte(spec.commandShort, tok.text[1]) >= 0) ||
						containsString(spec.commandLong, tok.text) {
						if k+1 >= len(rest) || rest[k+1].dynamic {
							c.decide(name + " -c with an unresolvable payload (fail-closed)")
							return
						}
						c.classifyString(rest[k+1].text, joinVia(via, name+" -c"), depth+1)
						return
					}
				}
			}
			if spec.requireCommand {
				c.decide(name + " without a static command payload launches a shell (fail-closed)")
				return
			}
			if len(rest) <= skip {
				if spec.decideBare && len(rest) > 0 {
					c.decide(name + " without a command runs an interactive shell (fail-closed)")
					return
				}
				c.record(Command{Name: name, Via: via, Prefix: name})
				return
			}
			if !rest[skip].dynamic && strings.HasPrefix(rest[skip].text, "-") {
				// The "command" after the positional operands still looks
				// like a flag: the wrapper's argument layout is ambiguous
				// (e.g. GNU permutation moved a flag behind the operand).
				c.decide(name + " argument layout cannot be resolved statically (fail-closed)")
				return
			}
			args = rest[skip:]
		case name == "eval":
			c.signal(SignalEvalWrapper)
			var b strings.Builder
			dynamic := false
			for i, tok := range args[1:] {
				if tok.dynamic {
					dynamic = true
					break
				}
				if i > 0 {
					b.WriteByte(' ')
				}
				b.WriteString(tok.text)
			}
			if dynamic {
				c.decide("eval with a dynamic payload")
				return
			}
			c.classifyString(b.String(), joinVia(via, "eval"), depth+1)
			return
		case name == "." || name == "source":
			if len(args) < 2 {
				c.decide(name + " without a script path (fail-closed)")
				return
			}
			script := args[1]
			if script.dynamic {
				c.decide(name + " with a dynamic script path (fail-closed)")
				return
			}
			if c.writtenPaths[path.Clean(script.text)] {
				c.decide(name + " executes a script generated earlier in the command")
				return
			}
			c.record(Command{Name: name, Tokens: staticTokens(args), Via: via, Prefix: name})
			return
		case shellNames[name]:
			c.signal(SignalShellInvocation)
			rest := args[1:]
			script, found, stdin, ambiguous, positional := scanShellScriptFlag(rest, strictFlagShells[name])
			switch {
			case ambiguous:
				c.decide(name + " wrapper arguments cannot be resolved statically")
				return
			case found && script.dynamic:
				c.decide(name + " -c with a dynamic payload")
				return
			case found:
				c.classifyString(script.text, joinVia(via, name+" -c"), depth+1)
				return
			case stdin:
				// No static script source: the shell reads commands from
				// stdin (bare `bash`, `bash -s`, `bash -c` without operand,
				// curl ... | bash). Opaque → fail closed.
				c.decide(name + " reads commands from standard input (fail-closed)")
				return
			default:
				// `bash script.sh`: script contents are opaque but running a
				// static script file is a normal agent action; record the
				// signal without routing to the decision path. Any dynamic
				// word (e.g. bash <(curl ...), bash "$x") is decision-worthy.
				for _, tok := range rest {
					if tok.dynamic {
						c.decide(name + " invocation with a dynamic argument")
						return
					}
				}
				if positional.text != "" && c.writtenPaths[path.Clean(positional.text)] {
					c.decide(name + " executes a script generated earlier in the command")
					return
				}
				c.record(Command{Name: name, Tokens: staticTokens(rest), Via: via, Prefix: name})
				return
			}
		default:
			if name == "tee" {
				c.recordTeeWrites(args)
			}
			tokens := make([]string, 0, len(args))
			dynamic := false
			for _, tok := range args {
				tokens = append(tokens, tok.text)
				if tok.dynamic {
					dynamic = true
				}
			}
			cmd := Command{
				Name:    name,
				Tokens:  tokens,
				Prefix:  Prefix(tokens),
				Via:     via,
				Dynamic: dynamic,
			}
			c.record(cmd)
			c.matchDestructive(cmd, args, via, depth)
			return
		}
		if args == nil {
			c.decide(fmt.Sprintf("wrapper %q arguments cannot be resolved statically (fail-closed)", via))
			return
		}
	}
	// Wrapper chain consumed all tokens (e.g. bare `sudo`): nothing executes.
}

func joinVia(via, next string) string {
	if via == "" {
		return next
	}
	return via + " > " + next
}

func staticTokens(args []wordTok) []string {
	out := make([]string, 0, len(args))
	for _, tok := range args {
		out = append(out, tok.text)
	}
	return out
}

func (c *collector) record(cmd Command) {
	c.commands = append(c.commands, cmd)
}

// matchDestructive structurally matches the destructive-command class that
// the legacy needle list approximated, closing flag-order, wrapper and
// chaining evasions.
func (c *collector) matchDestructive(cmd Command, args []wordTok, via string, depth int) {
	switch {
	case cmd.Name == "rm":
		recursive, force, dynamicArg, endOptions := false, false, false, false
		for _, tok := range args[1:] {
			if tok.dynamic {
				// Any unresolved word may expand to "-rf" (word-splitting or
				// a destructive operand); fail closed even after `--`.
				dynamicArg = true
				continue
			}
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if endOptions {
				continue
			}
			isFlag := strings.HasPrefix(tok.text, "-") && tok.text != "-"
			if !isFlag {
				continue
			}
			if strings.HasPrefix(tok.text, "--") {
				switch tok.text {
				case "--recursive":
					recursive = true
				case "--force":
					force = true
				}
				continue
			}
			for _, r := range tok.text[1:] {
				switch r {
				case 'r', 'R':
					recursive = true
				case 'f':
					force = true
				}
			}
		}
		if recursive {
			c.decide("recursive rm delete" + forceSuffix(force))
			return
		}
		if dynamicArg {
			c.decide("rm with arguments that cannot be resolved statically")
			return
		}
	case strings.HasPrefix(cmd.Name, "mkfs"):
		c.decide("filesystem format command " + cmd.Name)
	case cmd.Name == "dd":
		for _, tok := range args[1:] {
			if tok.dynamic {
				c.decide("dd with an operand that cannot be resolved statically")
				return
			}
			if strings.HasPrefix(strings.ToLower(tok.text), "if=") {
				c.decide("dd raw device/image read operand")
				return
			}
		}
	case cmd.Name == "git":
		c.matchGit(args)
	case cmd.Name == "kubectl":
		sub, dynamic, found := firstSubcommand(args[1:], kubectlValueFlags)
		if dynamic {
			c.decide("kubectl with a dynamic subcommand (fail-closed)")
			return
		}
		if found && sub == "delete" {
			c.decide("kubectl delete")
		}
	case cmd.Name == "docker":
		c.matchDocker(args)
	case cmd.Name == "find":
		c.matchFind(args, via, depth)
	}
}

func forceSuffix(force bool) string {
	if force {
		return " (forced)"
	}
	return ""
}

// gitValueFlags are git global flags that consume a value token.
var gitValueFlags = map[string]bool{
	"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true,
}

var kubectlValueFlags = map[string]bool{
	"-n": true, "--namespace": true, "--context": true, "--cluster": true,
	"--user": true, "--server": true, "-s": true, "--kubeconfig": true,
	"--token": true, "--as": true, "--as-group": true,
}

var dockerValueFlags = map[string]bool{
	"-H": true, "--host": true, "--context": true, "--config": true, "--log-level": true,
}

// firstSubcommand finds the first positional token, skipping flags and the
// values of known value-flags. dynamic is true when scanning hit a word that
// cannot be resolved statically (the subcommand may be hidden).
func firstSubcommand(args []wordTok, vals map[string]bool) (sub string, dynamic, found bool) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic {
			return "", true, false
		}
		if tok.text == "--" {
			if i+1 < len(args) && !args[i+1].dynamic {
				return args[i+1].text, false, true
			}
			if i+1 < len(args) {
				return "", true, false
			}
			return "", false, false
		}
		if strings.HasPrefix(tok.text, "-") && tok.text != "-" {
			if vals[tok.text] {
				i++
				continue
			}
			if flag, value, attached := strings.Cut(tok.text, "="); attached && vals[flag] && value != "" {
				continue
			}
			return "", true, false
		}
		return tok.text, false, true
	}
	return "", false, false
}

func (c *collector) matchGit(args []wordTok) {
	sub, dynamic, found := firstSubcommand(args[1:], gitValueFlags)
	if dynamic {
		c.decide("git invocation with a dynamic subcommand (fail-closed)")
		return
	}
	if !found {
		return
	}
	rest := args[1:]
	switch sub {
	case "reset":
		endOptions := false
		for _, tok := range rest {
			if tok.dynamic {
				c.decide("git reset with unresolvable flags (fail-closed)")
				return
			}
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if endOptions {
				continue
			}
			if tok.text == "--hard" {
				c.decide("git reset --hard")
				return
			}
		}
	case "clean":
		force, dirs, endOptions := false, false, false
		for _, tok := range rest {
			if tok.dynamic {
				c.decide("git clean with unresolvable flags (fail-closed)")
				return
			}
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if endOptions || !strings.HasPrefix(tok.text, "-") {
				continue
			}
			if tok.text == "--force" {
				force = true
				continue
			}
			if strings.HasPrefix(tok.text, "--") {
				continue
			}
			for _, r := range tok.text[1:] {
				switch r {
				case 'f':
					force = true
				case 'd':
					dirs = true
				}
			}
		}
		if force && dirs {
			c.decide("git clean with forced directory delete")
		}
	}
}

func (c *collector) matchDocker(args []wordTok) {
	sub, dynamic, found := firstSubcommand(args[1:], dockerValueFlags)
	if dynamic {
		c.decide("docker invocation with a dynamic subcommand (fail-closed)")
		return
	}
	if !found {
		return
	}
	rest := args[1:]
	isRm := sub == "rm"
	if sub == "container" {
		next, nextDynamic, nextFound := firstSubcommand(rest[indexOfToken(rest, "container")+1:], nil)
		if nextDynamic {
			c.decide("docker container with a dynamic subcommand (fail-closed)")
			return
		}
		if nextFound && next == "rm" {
			isRm = true
		}
	}
	if !isRm {
		return
	}
	endOptions := false
	for _, tok := range rest {
		if tok.dynamic {
			c.decide("docker rm with unresolvable flags (fail-closed)")
			return
		}
		if tok.text == "--" {
			endOptions = true
			continue
		}
		if endOptions {
			continue
		}
		if tok.text == "--force" {
			c.decide("docker rm --force")
			return
		}
		if strings.HasPrefix(tok.text, "-") && !strings.HasPrefix(tok.text, "--") {
			for _, r := range tok.text[1:] {
				if r == 'f' {
					c.decide("docker rm -f")
					return
				}
			}
		}
	}
}

func indexOfToken(args []wordTok, text string) int {
	for i, tok := range args {
		if !tok.dynamic && tok.text == text {
			return i
		}
	}
	return -1
}

func (c *collector) matchFind(args []wordTok, via string, depth int) {
	for i, tok := range args[1:] {
		if tok.dynamic {
			c.decide("find with a dynamic expression (fail-closed)")
			return
		}
		if tok.text == "-delete" {
			c.decide("find -delete")
			return
		}
		if tok.text == "-exec" || tok.text == "-execdir" {
			// Recursively classify the exec payload (terminated by ";" or
			// "+") so wrappers such as sh -c cannot hide destructive work.
			payload := args[i+2:]
			end := len(payload)
			for j, p := range payload {
				if !p.dynamic && (p.text == ";" || p.text == "+") {
					end = j
					break
				}
				if p.dynamic {
					// A dynamic word inside the exec payload may hide the
					// executed command or its flags; fail closed.
					c.decide("find " + tok.text + " with a dynamic payload (fail-closed)")
					return
				}
			}
			if end == 0 {
				c.decide("find " + tok.text + " without a command (fail-closed)")
				return
			}
			c.classifyTokens(payload[:end], joinVia(via, "find "+tok.text), depth+1)
			if c.decideFlag {
				c.decide("find " + tok.text + " payload requires a decision")
				return
			}
		}
	}
}

// legacyNeedleHit reproduces the pre-AST substring classification verbatim.
func legacyNeedleHit(command string) string {
	lower := strings.ToLower(strings.TrimSpace(command))
	for _, needle := range legacyNeedles {
		if strings.Contains(lower, needle) || strings.HasPrefix(lower, strings.TrimSpace(needle)) {
			return needle
		}
	}
	return ""
}
