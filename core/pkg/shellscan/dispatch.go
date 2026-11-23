package shellscan

import (
	"fmt"
	"path"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
)

func (c *collector) classifyTokens(args []wordTok, via string, depth int) {
	if depth > maxWrapperDepth {
		c.decide("wrapper nesting too deep to classify statically")
		return
	}
	for len(args) > 0 {
		head := args[0]
		if head.dynamic {
			c.decide("dynamic command word cannot be classified statically")
			return
		}
		if head.glob {
			c.signal(SignalGlobCommand)
			c.decide("glob in command position cannot be evaluated statically (fail-closed)")
			return
		}
		if c.isWrittenPath(head.text) {
			// A command path created earlier in this same compound command is
			// opaque executable source, even when invoked directly rather than
			// through a shell or language interpreter.
			c.decide("executes a script generated earlier in the command")
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
		if spec, ok := interpreterSpecFor(name); ok {
			c.classifyInterpreter(name, args[1:], via, spec)
			return
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
			// sudo takes NAME=value before the command; those words are its
			// environment, not the program it runs.
			for len(args) > 0 && !args[0].dynamic && assignmentWord(args[0].text) {
				if variable, value, _ := strings.Cut(args[0].text, "="); tracksVariable(variable) {
					c.env = append(c.env, envOverride{name: variable, value: value})
				}
				args = args[1:]
			}
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
				if name, value, ok := strings.Cut(tok.text, "="); ok {
					if tracksVariable(name) {
						c.env = append(c.env, envOverride{name: name, value: value})
					}
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
			if args != nil {
				// xargs appends stdin-derived arguments to the static template.
				// Preserve that unknown operand through recursive classification.
				args = append(args, wordTok{dynamic: true})
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
		case name == "trap":
			c.classifyTrap(args, via, depth)
			return
		case name == "." || name == "source":
			c.hasIndirection = true
			if len(args) < 2 {
				c.decide(name + " without a script path (fail-closed)")
				return
			}
			script := args[1]
			if script.dynamic {
				c.decide(name + " with a dynamic script path (fail-closed)")
				return
			}
			if c.isWrittenPath(script.text) {
				c.decide(name + " executes a script generated earlier in the command")
				return
			}
			c.guardScript(script.text)
			c.record(Command{Name: name, Tokens: staticTokens(args), Via: via, Prefix: name})
			return
		case shellNames[name]:
			c.signal(SignalShellInvocation)
			rest := args[1:]
			script, found, stdin, ambiguous, positional := scanShellScriptFlag(name, rest)
			switch {
			case ambiguous:
				c.decide(name + " wrapper arguments cannot be resolved statically")
				return
			case found && script.dynamic:
				c.decide(name + " -c with a dynamic payload")
				return
			case found && (name == "pwsh" || name == "powershell"):
				c.decide(name + " inline payload requires a PowerShell-aware decision (fail-closed)")
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
				// signal without routing to the decision path. The script path
				// itself was already required to be static by scanShellScriptFlag;
				// later dynamic words are ordinary script arguments, not source.
				if positional.text != "" && c.isWrittenPath(positional.text) {
					c.decide(name + " executes a script generated earlier in the command")
					return
				}
				c.guardScript(positional.text)
				c.record(Command{Name: name, Tokens: staticTokens(rest), Via: via, Prefix: name})
				return
			}
		default:
			if name == "tee" {
				c.recordTeeWrites(args)
			}
			tokens := make([]string, 0, len(args))
			perToken := make([]bool, 0, len(args))
			dynamic := false
			for _, tok := range args {
				tokens = append(tokens, tok.text)
				perToken = append(perToken, tok.dynamic)
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
				dynamic: perToken,
			}
			c.record(cmd)
			c.matchDestructive(cmd, args, via, depth)
			c.classifyWrappedNetworkTool(name, args, via, depth)
			return
		}
		if args == nil {
			c.decide(fmt.Sprintf("wrapper %q arguments cannot be resolved statically (fail-closed)", via))
			return
		}
	}
	// Wrapper chain consumed all tokens (e.g. bare `sudo`): nothing executes.
}

// assignmentWord reports whether a word has the NAME=value shape of an
// environment assignment.
func assignmentWord(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// classifyWrappedNetworkTool covers a prefix command this scanner has no
// entry for (watch, sshpass, a container run): when a later argument is a
// network tool followed by an address, the rest is classified as that tool's
// command line too. It only adds findings. An address is required so that an
// argument which merely names the tool, as in a package install, is left
// alone; echo and printf print their arguments and run nothing.
func (c *collector) classifyWrappedNetworkTool(name string, args []wordTok, via string, depth int) {
	if egressTool(name) || name == "echo" || name == "printf" {
		return
	}
	for i := 1; i < len(args); i++ {
		if args[i].dynamic || !egressTool(path.Base(slashPath(args[i].text))) {
			continue
		}
		for _, later := range args[i+1:] {
			if netdest.HasScheme(later.text) || strings.Contains(later.text, "@") {
				c.classifyTokens(args[i:], joinVia(via, name), depth+1)
				return
			}
		}
		return
	}
}

func (c *collector) classifyTrap(args []wordTok, via string, depth int) {
	c.record(Command{Name: "trap", Tokens: staticTokens(args), Prefix: "trap", Via: via})
	if len(args) < 2 {
		return
	}
	handlerIndex := 1
	if !args[handlerIndex].dynamic && args[handlerIndex].text == "--" {
		handlerIndex++
		if handlerIndex >= len(args) {
			return
		}
	}
	handler := args[handlerIndex]
	if handler.dynamic {
		c.decide("trap handler cannot be resolved statically (fail-closed)")
		return
	}
	if handler.text == "" || handler.text == "-" || handler.text == "-p" || handler.text == "-l" {
		return
	}
	c.classifyString(handler.text, joinVia(via, "trap"), depth+1)
	if c.decideFlag {
		c.decide("trap handler requires a decision")
	}
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
	c.guardOptionPaths(cmd)
	c.commands = append(c.commands, cmd)
}
