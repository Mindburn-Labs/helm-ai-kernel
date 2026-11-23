package shellscan

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

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

// interpreterSpec describes a common language interpreter whose code source
// can be supplied directly on the command line or through standard input.
// We intentionally do not parse these languages: an opaque interpreter source
// is routed to the signed decision path instead.
type interpreterSpec struct {
	codeShort    string
	codeLong     []string
	valueShort   string
	valueLong    []string
	noValueShort string
	noValueLong  []string
}

// interpreterSpecFor resolves common versioned interpreter names without
// treating arbitrary commands that merely share a prefix as interpreters.
func interpreterSpecFor(name string) (interpreterSpec, bool) {
	if spec, ok := interpreterSpecs[name]; ok {
		return spec, true
	}
	if strings.HasPrefix(name, "python") && isInterpreterVersion(strings.TrimPrefix(name, "python")) {
		return interpreterSpecs["python"], true
	}
	if name == "nodejs" {
		return interpreterSpecs["node"], true
	}
	return interpreterSpec{}, false
}

func isInterpreterVersion(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// recordInlineInterpreterSensitiveWrite recognizes literal Python
// open(path, mode) calls without trying to interpret arbitrary source.
func (c *collector) recordInlineInterpreterSensitiveWrite(name string, source wordTok) {
	if source.dynamic || !strings.HasPrefix(name, "python") {
		return
	}
	compact := strings.NewReplacer("'", "", `"`, "", " ", "", "\t", "", "\r", "", "\n", "", "+", "").Replace(source.text)
	for {
		start := strings.Index(compact, "open(")
		if start < 0 {
			return
		}
		if start > 0 && (pythonIdentByte(compact[start-1]) || compact[start-1] == '.') {
			compact = compact[start+4:]
			continue
		}
		compact = compact[start+len("open("):]
		comma := strings.IndexByte(compact, ',')
		if comma < 0 {
			return
		}
		target, mode := compact[:comma], strings.TrimPrefix(compact[comma+1:], "mode=")
		if pythonOpenWriteMode(mode) {
			c.recordSensitiveTarget(wordTok{text: target}, "inline interpreter write", SignalSensitiveTarget)
			return
		}
	}
}

func pythonOpenWriteMode(mode string) bool {
	return strings.HasPrefix(mode, "w") || strings.HasPrefix(mode, "a") || strings.HasPrefix(mode, "x") ||
		strings.HasPrefix(mode, "r+") || strings.HasPrefix(mode, "rb+")
}

func pythonIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func (c *collector) classifyInterpreter(name string, args []wordTok, via string, spec interpreterSpec) {
	c.signal(SignalInterpreterInvocation)
	if len(args) == 0 {
		c.decide(name + " reads interpreter source from standard input (fail-closed)")
		return
	}

	terminalInfo := false
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic {
			c.decide(name + " interpreter invocation with a dynamic argument (fail-closed)")
			return
		}
		if tok.text == "-" {
			c.decide(name + " reads interpreter source from standard input (fail-closed)")
			return
		}
		if tok.text == "--" {
			if i+1 >= len(args) {
				c.decide(name + " reads interpreter source from standard input (fail-closed)")
				return
			}
			c.classifyInterpreterScript(name, args, i+1, via)
			return
		}
		if strings.HasPrefix(tok.text, "--") {
			flag := tok.text
			attached := false
			if idx := strings.IndexByte(flag, '='); idx >= 0 {
				flag, attached = flag[:idx], true
			}
			if containsString(spec.codeLong, flag) {
				source := wordTok{dynamic: true}
				if attached {
					source = wordTok{text: strings.TrimPrefix(tok.text, flag+"=")}
				} else if i+1 < len(args) {
					source = args[i+1]
				}
				c.recordInlineInterpreterSensitiveWrite(name, source)
				c.decide(name + " executes interpreter source via " + flag + " (fail-closed)")
				return
			}
			if containsString(spec.noValueLong, flag) && !attached {
				if flag == "--help" || flag == "--version" {
					terminalInfo = true
				}
				continue
			}
			if containsString(spec.valueLong, flag) {
				value := wordTok{}
				if attached {
					if len(tok.text) == len(flag)+1 {
						c.decide(name + " " + flag + " with an empty value (fail-closed)")
						return
					}
					value = wordTok{text: strings.TrimPrefix(tok.text, flag+"=")}
				} else {
					if i+1 >= len(args) || args[i+1].dynamic {
						c.decide(name + " " + flag + " with an unresolvable value (fail-closed)")
						return
					}
					value = args[i+1]
					i++
				}
				if isNodePreloadFlag(name, flag) && c.isWrittenPath(value.text) {
					c.decide(name + " executes a preload generated earlier in the command")
					return
				}
				continue
			}
			c.decide(name + " with an unrecognized flag " + tok.text + " (fail-closed)")
			return
		}
		if strings.HasPrefix(tok.text, "-") {
			cluster := tok.text[1:]
			for j := 0; j < len(cluster); j++ {
				flag := cluster[j]
				if strings.IndexByte(spec.codeShort, flag) >= 0 {
					source := wordTok{dynamic: true}
					if j+1 < len(cluster) {
						source = wordTok{text: cluster[j+1:]}
					} else if i+1 < len(args) {
						source = args[i+1]
					}
					c.recordInlineInterpreterSensitiveWrite(name, source)
					c.decide(name + " executes interpreter source via -" + string(flag) + " (fail-closed)")
					return
				}
				if strings.IndexByte(spec.noValueShort, flag) >= 0 {
					continue
				}
				if strings.IndexByte(spec.valueShort, flag) >= 0 {
					value := wordTok{}
					if j+1 == len(cluster) {
						if i+1 >= len(args) || args[i+1].dynamic {
							c.decide(name + " -" + string(flag) + " with an unresolvable value (fail-closed)")
							return
						}
						value = args[i+1]
						i++
					} else {
						value = wordTok{text: cluster[j+1:]}
					}
					if isNodePreloadShortFlag(name, flag) && c.isWrittenPath(value.text) {
						c.decide(name + " executes a preload generated earlier in the command")
						return
					}
					break
				}
				c.decide(name + " with an unrecognized flag -" + string(flag) + " (fail-closed)")
				return
			}
			continue
		}

		c.classifyInterpreterScript(name, args, i, via)
		return
	}

	if terminalInfo {
		tokens := make([]string, 0, len(args)+1)
		tokens = append(tokens, name)
		tokens = append(tokens, staticTokens(args)...)
		c.record(Command{Name: name, Tokens: tokens, Prefix: Prefix(tokens), Via: via})
		return
	}
	c.decide(name + " reads interpreter source from standard input (fail-closed)")
}

func (c *collector) classifyInterpreterScript(name string, args []wordTok, scriptIndex int, via string) {
	script := args[scriptIndex]
	if script.dynamic {
		c.decide(name + " interpreter invocation with a dynamic argument (fail-closed)")
		return
	}
	if c.isWrittenPath(script.text) {
		c.decide(name + " executes a script generated earlier in the command")
		return
	}
	c.guardScript(script.text)
	tokens := make([]string, 0, len(args)+1)
	tokens = append(tokens, name)
	tokens = append(tokens, staticTokens(args)...)
	c.record(Command{Name: name, Tokens: tokens, Prefix: Prefix(tokens), Via: via})
}

func isNodePreloadFlag(name, flag string) bool {
	return (name == "node" || name == "nodejs") && (flag == "--require" || flag == "--loader" || flag == "--experimental-loader")
}

func isNodePreloadShortFlag(name string, flag byte) bool {
	return (name == "node" || name == "nodejs") && flag == 'r'
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

// scanShellScriptFlag analyzes a shell invocation's arguments. It locates
// the script operand of a -c flag, honoring combined short-flag clusters
// (-lc), attached values (-cCMD), value-taking flags (-o option, bash -O
// shopt, long flags with values), "--" end-of-options, and -s/stdin mode.
//
// Returns: the -c script word (found), whether the shell will read commands
// from stdin because no static script source exists (stdin), whether scanning
// hit an unresolvable word (ambiguous), and whether a positional script file
// was seen (positional).
func scanShellScriptFlag(shell string, rest []wordTok) (script wordTok, found, stdin, ambiguous bool, positional wordTok) {
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
			flag := tok.text
			attached := false
			if idx := strings.IndexByte(flag, '='); idx >= 0 {
				flag, attached = flag[:idx], true
			}
			if shellLongValueFlags[shell][flag] {
				if attached {
					if len(tok.text) == len(flag)+1 {
						return wordTok{}, false, false, true, wordTok{}
					}
				} else {
					if i+1 >= len(rest) || rest[i+1].dynamic {
						return wordTok{}, false, false, true, wordTok{}
					}
					i++
				}
				continue
			}
			return wordTok{}, false, false, true, wordTok{}
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
				if strictFlagShells[shell] {
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
