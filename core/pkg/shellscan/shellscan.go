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

	sawPipe   bool
	sawShell  bool
	sawEval   bool
	sawDecode bool
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
				c.sawPipe = true
				c.signal(SignalChaining)
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
	if c.sawDecode && (c.sawPipe && (c.sawShell || c.sawEval)) {
		c.signal(SignalEncodedWrapper)
		c.decide("encoded payload decoded into a shell or eval")
	}
}

func (c *collector) classifyRedirect(r *syntax.Redirect) {
	c.signal(SignalRedirect)
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrInOut, syntax.ClbOut:
		// write-capable redirect
	default:
		return
	}
	if r.Word == nil {
		return
	}
	tok := resolveWord(r.Word)
	if tok.dynamic {
		// A write redirect whose target cannot be resolved statically may
		// point at a protected file ($TARGET=.env); fail closed.
		c.decide("write redirect with an unresolvable target (fail-closed)")
		return
	}
	target := strings.ToLower(tok.text)
	// fd duplication targets ("&1", "&2") are not file writes.
	if strings.HasPrefix(target, "&") {
		return
	}
	for _, needle := range sensitiveRedirectTargets {
		if strings.Contains(target, needle) {
			c.signal(SignalSensitiveRedirect)
			c.decide(fmt.Sprintf("write redirect to sensitive target %q", tok.text))
			return
		}
	}
}

// classifyCall resolves one command call's words and classifies it,
// unwrapping sudo/env/eval/sh -c/xargs wrappers recursively.
func (c *collector) classifyCall(call *syntax.CallExpr, via string, depth int) {
	args := make([]wordTok, 0, len(call.Args))
	for _, w := range call.Args {
		args = append(args, resolveWord(w))
	}
	c.classifyTokens(args, via, depth)
}

type wordTok struct {
	text    string
	dynamic bool
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
		"-D": true, "-U": true, "-t": true,
		"--user": true, "--group": true, "--host": true, "--prompt": true,
		"--chdir": true, "--role": true, "--type": true, "--close-from": true,
		"--other-user": true, "--command-timeout": true,
	},
	"exec":   {"-a": true},
	"nice":   {"-n": true, "--adjustment": true},
	"stdbuf": {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"xargs": {
		"-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-d": true, "-E": true, "-a": true,
		"--replace": true, "--max-lines": true, "--max-args": true, "--max-procs": true,
		"--max-chars": true, "--delimiter": true, "--eof": true, "--arg-file": true,
	},
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
		// cluster or, when last, the next token.
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			if vals["-"+string(cluster[j])] {
				if j+1 == len(cluster) {
					i++
				}
				break
			}
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
func scanShellScriptFlag(rest []wordTok) (script wordTok, found, stdin, ambiguous, positional bool) {
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		if tok.dynamic {
			return wordTok{}, false, false, true, false
		}
		if tok.text == "--" {
			if i+1 < len(rest) {
				return wordTok{}, false, false, false, true // positional after --
			}
			return wordTok{}, false, true, false, false
		}
		if tok.text == "--help" || tok.text == "--version" {
			// Prints and exits; treat like a benign positional.
			return wordTok{}, false, false, false, true
		}
		if strings.HasPrefix(tok.text, "--") {
			if shellLongValueFlags[tok.text] {
				i++
			}
			continue
		}
		if !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			return wordTok{}, false, false, false, true // script file positional
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'c':
				if j+1 < len(cluster) {
					// Attached payload: bash -cCMD (e.g. -c'rm -rf /').
					return wordTok{text: cluster[j+1:]}, true, false, false, false
				}
				if i+1 < len(rest) {
					return rest[i+1], true, false, false, false
				}
				return wordTok{}, false, true, false, false // -c with no operand: stdin
			case 's':
				// -s reads commands from standard input: opaque.
				return wordTok{}, false, true, false, false
			case 'o', 'O':
				// -o option-name / bash -O shopt_option: value is attached
				// or the next token.
				if j+1 == len(cluster) {
					i++
				}
				j = len(cluster) // value consumes the rest of the cluster
			}
		}
	}
	return wordTok{}, false, true, false, false // no script source: stdin
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
			args = dropWrapperFlags("sudo", args[1:])
			via = joinVia(via, name)
		case name == "env":
			c.signal(SignalEnvWrapper)
			via = joinVia(via, "env")
			rest := args[1:]
			commandIdx := -1
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
						} else {
							payload = strings.TrimPrefix(tok.text, "--split-string=")
						}
						// env -S splits the payload into command + args.
						c.classifyString(payload, joinVia(via, "env -S"), depth+1)
						return
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
							} else {
								c.decide("env -S with an unresolvable payload")
								return
							}
							c.classifyString(payload, joinVia(via, "env -S"), depth+1)
							return
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
		case name == "nice" || name == "nohup" || name == "time" || name == "command" || name == "builtin" || name == "stdbuf" || name == "setsid" || name == "exec":
			c.signal(SignalEnvWrapper)
			args = dropWrapperFlags(name, args[1:])
			via = joinVia(via, name)
		case name == "xargs":
			c.signal(SignalEnvWrapper)
			args = dropWrapperFlags("xargs", args[1:])
			via = joinVia(via, "xargs")
			if len(args) == 0 {
				c.decide("xargs invokes a command supplied only at runtime")
				return
			}
		case name == "busybox":
			c.signal(SignalEnvWrapper)
			args = args[1:]
			via = joinVia(via, "busybox")
		case name == "eval":
			c.signal(SignalEvalWrapper)
			c.sawEval = true
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
		case shellNames[name]:
			c.signal(SignalShellInvocation)
			c.sawShell = true
			rest := args[1:]
			script, found, stdin, ambiguous, _ := scanShellScriptFlag(rest)
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
				c.record(Command{Name: name, Tokens: staticTokens(rest), Via: via, Prefix: name})
				return
			}
		default:
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
			c.matchDestructive(cmd, args)
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
func (c *collector) matchDestructive(cmd Command, args []wordTok) {
	switch {
	case cmd.Name == "rm":
		recursive, force, dynamicFlag := false, false, false
		for _, tok := range args[1:] {
			if tok.dynamic {
				// Any unresolved word may expand to "-rf" (word-splitting or
				// a variable whose value is flags); fail closed.
				dynamicFlag = true
				continue
			}
			if tok.text == "--" {
				break // everything after "--" is an operand
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
		if dynamicFlag {
			c.decide("rm with flags that cannot be resolved statically")
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
		c.matchFind(args)
	case cmd.Name == "base64":
		for _, tok := range args[1:] {
			if !tok.dynamic && (tok.text == "-d" || tok.text == "--decode" || tok.text == "-D") {
				c.sawDecode = true
			}
		}
	case cmd.Name == "xxd":
		for _, tok := range args[1:] {
			if !tok.dynamic && (tok.text == "-r" || strings.HasPrefix(tok.text, "-r")) {
				c.sawDecode = true
			}
		}
	case cmd.Name == "openssl":
		hasD, hasB64 := false, false
		for _, tok := range args[1:] {
			if tok.dynamic {
				continue
			}
			if tok.text == "-d" {
				hasD = true
			}
			if tok.text == "-base64" || tok.text == "-a" || tok.text == "-A" {
				hasB64 = true
			}
		}
		if hasD && hasB64 {
			c.sawDecode = true
		}
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
			}
			continue
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
		for _, tok := range rest {
			if tok.dynamic {
				c.decide("git reset with unresolvable flags (fail-closed)")
				return
			}
			if tok.text == "--hard" {
				c.decide("git reset --hard")
				return
			}
		}
	case "clean":
		force, dirs := false, false
		for _, tok := range rest {
			if tok.dynamic {
				c.decide("git clean with unresolvable flags (fail-closed)")
				return
			}
			if !strings.HasPrefix(tok.text, "-") || tok.text == "--" {
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
				case 'd', 'x':
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
	for _, tok := range rest {
		if tok.dynamic {
			c.decide("docker rm with unresolvable flags (fail-closed)")
			return
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

func (c *collector) matchFind(args []wordTok) {
	for i, tok := range args[1:] {
		if tok.dynamic {
			continue
		}
		if tok.text == "-delete" {
			c.decide("find -delete")
			return
		}
		if tok.text == "-exec" || tok.text == "-execdir" {
			// Scan the exec payload (terminated by ";" or "+") for rm -r.
			payload := args[i+2:]
			isRm := false
			recursive := false
			for _, p := range payload {
				if !p.dynamic && (p.text == ";" || p.text == "+") {
					break
				}
				if p.dynamic {
					// A dynamic word inside the exec payload may hide the
					// executed command or its flags; fail closed.
					c.decide("find " + tok.text + " with a dynamic payload (fail-closed)")
					return
				}
				if !isRm && path.Base(p.text) == "rm" {
					isRm = true
					continue
				}
				if isRm && strings.HasPrefix(p.text, "-") && !strings.HasPrefix(p.text, "--") {
					for _, r := range p.text[1:] {
						if r == 'r' || r == 'R' {
							recursive = true
						}
					}
				}
				if isRm && (p.text == "--recursive") {
					recursive = true
				}
			}
			if isRm && recursive {
				c.decide("find -exec recursive rm")
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
