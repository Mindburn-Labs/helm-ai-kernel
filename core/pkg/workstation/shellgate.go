// shellgate.go — command-name extraction and the escalating shell gate for the
// workstation boundary.
//
// Attribution: the extraction and allowlist semantics implemented here are
// adapted from Rowboat (Apache-2.0), apps/cli/src/application/lib/command-executor.ts
// (extractCommandNames / isBlocked). This file is an original Go implementation
// of those mechanisms for the HELM workstation boundary; no Rowboat code is
// copied verbatim.
//
// Deliberate hardening deviations from the Rowboat semantics (fail-closed
// beats convenient):
//   - Wrapper unwrapping is recursive: `sudo env time rm x` extracts
//     {sudo, env, time, rm} instead of only the wrapper and its immediate next
//     token. More names must be allowlisted, never fewer.
//   - After a wrapper, leading ENV=value assignments and bare `-` flags are
//     skipped before resolving the wrapped command, so `env FOO=1 rm x`
//     extracts {env, rm} (Rowboat extracts {env, "foo=1"}, which blocks by
//     accident rather than by policy). Flags that take separate values
//     (e.g. `sudo -u root rm x`) are modeled per wrapper so their values
//     cannot shadow the wrapped command.
//   - Unknown gate profiles normalize to production (deny), never to dev.
//   - The gate is redirection-aware: output redirections (`>`, `>>`, `>|`)
//     and downloader output flags (`-o`, `--output`, `-O`, `--remote-name`,
//     `--output-document`) are treated as writes that always require an
//     approval (dev) or a denial (production), even when every command name
//     is allowlisted. An allowlisted `cat` must not become `cat x > /etc/y`.
//
// Threat-model limit (documented, accepted): gating is command-name and
// write-target based, not a full shell parser. Glob expansions and arguments
// that a program itself interprets as write destinations (e.g. `tee file`,
// `dd of=file`, `sed -i`) are out of scope; programs with intrinsic write
// behavior must stay off the allowlist. Redirection scanning understands
// quoted operators and targets but may still false-positive on unusual
// unquoted `>` usage — that fails closed.
package workstation

import (
	"regexp"
	"sort"
	"strings"
)

// commandSplitPattern splits a shell command line into segments at every
// construct that can start a new command: pipes, logical operators, command
// separators, background execution, command substitution (backticks and
// $(...)), and subshell open parens. Order matters: `||` and `&&` must
// precede their single-character prefixes so the leftmost-longest
// alternation consumes the right token. Without `&`, backtick, `$(`, and
// `(`, `echo hi & rm /x`, `echo `+"`rm /x`"+`, and `echo $(rm /x)` would
// slip past the gate with only `echo` allowlisted. `)` is deliberately not a
// split point: `ls $(pwd)/x` would otherwise yield a bogus `/x` "command"
// from the suffix after the substitution. sanitizeCommandToken truncates at
// `)` instead, so the segment yields `pwd`.
var commandSplitPattern = regexp.MustCompile(`\|\||&&|&|;|\||\n|` + "`" + `|\$\(|\(`)

// envAssignmentPattern matches leading ENV=value prefixes that are not command
// names (e.g. `FOO=bar ls`).
var envAssignmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// wrapperCommands are command wrappers whose first real argument is itself a
// command that must also be allowlisted.
var wrapperCommands = map[string]struct{}{
	"sudo":    {},
	"env":     {},
	"time":    {},
	"command": {},
}

// wrapperValueFlags are wrapper flags that consume the next token as a value
// (e.g. `sudo -u root`, `env -u NAME`, `time -o FILE`). The value token must
// be skipped with the flag so it neither shadows nor replaces the wrapped
// command: `sudo -u root rm /x` must extract {sudo, rm}, never stop at
// `root`. Long `--flag=value` forms carry no separate token and are skipped
// as bare flags.
var wrapperValueFlags = map[string]map[string]struct{}{
	"sudo": {
		"-u": {}, "--user": {}, "-g": {}, "--group": {}, "-h": {}, "--host": {},
		"-p": {}, "--prompt": {}, "-C": {}, "--chdir": {},
	},
	"env": {
		"-u": {}, "--unset": {}, "-C": {}, "--chdir": {}, "-S": {}, "--split-string": {},
	},
	"time": {
		"-o": {}, "--output": {}, "-f": {}, "--format": {},
	},
}

// ExtractCommandNames returns the sorted, de-duplicated, lowercased set of
// command names a shell command line would invoke. It is robust to chaining
// (&&, ||, |, ;, &), command substitution (backticks, $(...)), subshells,
// leading ENV=value assignments, and sudo/env/time/command wrappers.
func ExtractCommandNames(command string) []string {
	discovered := make(map[string]struct{})
	for _, segment := range commandSplitPattern.Split(command, -1) {
		tokens := strings.Fields(segment)
		if len(tokens) == 0 {
			continue
		}
		index := 0
		for index < len(tokens) && envAssignmentPattern.MatchString(tokens[index]) {
			index++
		}
		if index >= len(tokens) {
			continue
		}
		primary := sanitizeCommandToken(tokens[index])
		if primary == "" {
			continue
		}
		discovered[primary] = struct{}{}
		if _, isWrapper := wrapperCommands[primary]; isWrapper {
			for _, wrapped := range unwrapWrappedCommands(primary, tokens[index+1:]) {
				discovered[wrapped] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(discovered))
	for name := range discovered {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil
	}
	return names
}

// unwrapWrappedCommands resolves the command names hidden behind one or more
// nested wrappers, including the intermediate wrappers themselves. Leading
// ENV=value assignments and bare `-` flags after a wrapper are skipped; flags
// known to take a separate value (sudo -u, env -u, time -o, …) are skipped
// together with their value so the value cannot shadow the wrapped command.
func unwrapWrappedCommands(activeWrapper string, tokens []string) []string {
	var out []string
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if envAssignmentPattern.MatchString(token) {
			continue
		}
		if strings.HasPrefix(token, "-") {
			// Bare wrapper flag (e.g. `sudo -E`, `time -p`). Value-taking
			// flags consume the next token as well, so `sudo -u root rm /x`
			// still resolves `rm` instead of stopping at `root`. Unknown
			// value-taking flags may surface their value as a command name;
			// that false positive fails closed and is accepted.
			if _, takesValue := wrapperValueFlags[activeWrapper][token]; takesValue {
				i++
			}
			continue
		}
		name := sanitizeCommandToken(token)
		if name == "" {
			continue
		}
		out = append(out, name)
		if _, isWrapper := wrapperCommands[name]; isWrapper {
			activeWrapper = name
			continue
		}
		break
	}
	return out
}

// sanitizeCommandToken normalizes a raw token into a comparable command name:
// trimmed, unquoted, lowercased, and truncated at the first `)` so a command
// substitution suffix (`$(pwd)/x` → `pwd)/x`) cannot become a bogus command.
func sanitizeCommandToken(token string) string {
	cleaned := strings.ToLower(strings.Trim(strings.TrimSpace(token), `'"`))
	if idx := strings.IndexByte(cleaned, ')'); idx >= 0 {
		cleaned = cleaned[:idx]
	}
	return cleaned
}

// BlockedCommandNames returns the invoked command names that are not present
// in the allowlist. Semantics mirror Rowboat's isBlocked: an empty allowlist
// blocks everything, and `*` allows everything. Allowlist entries are
// normalized (trimmed, lowercased) before comparison.
func BlockedCommandNames(command string, allowlist []string) []string {
	invoked := ExtractCommandNames(command)
	if len(invoked) == 0 {
		return nil
	}
	if len(allowlist) == 0 {
		return invoked
	}
	allowed := make(map[string]struct{}, len(allowlist))
	for _, entry := range allowlist {
		if normalized := sanitizeCommandToken(entry); normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	if _, wildcard := allowed["*"]; wildcard {
		return nil
	}
	var blocked []string
	for _, name := range invoked {
		if _, ok := allowed[name]; !ok {
			blocked = append(blocked, name)
		}
	}
	return blocked
}

// outputValueFlags are flags whose value is a file the command writes to
// (curl/wget style). The value may be inline (`--output=file`), concatenated
// (`-ofile`), or the next token (`-o file`).
var outputValueFlags = map[string]struct{}{
	"-o":                {},
	"--output":          {},
	"--output-document": {},
}

// outputBooleanFlags are flags that make the command write to a
// command-chosen file name (curl -O / --remote-name).
var outputBooleanFlags = map[string]struct{}{
	"-O":                {},
	"--remote-name":     {},
	"--remote-name-all": {},
}

// ExtractWriteTargets returns the write destinations a shell command line
// would create or overwrite: output redirections (`>`, `>>`, `>|`, with
// optional fd prefixes like `2>`) and downloader-style output flags. File
// descriptor duplication (`2>&1`) is not a write. Operators inside quoted
// strings are ignored, while quoted destinations are retained.
func ExtractWriteTargets(command string) []string {
	seen := make(map[string]struct{})
	for _, target := range redirectionTargets(command) {
		seen[target] = struct{}{}
	}
	for _, target := range outputFlagTargets(command) {
		seen[target] = struct{}{}
	}
	for _, target := range inPlaceWriteTargets(command) {
		seen[target] = struct{}{}
	}
	targets := make([]string, 0, len(seen))
	for target := range seen {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return nil
	}
	return targets
}

// redirectionTargets scans for `>` / `>>` / `>|` output redirections. An
// optional fd prefix (`2>`, `&>`) is part of the operator; `>&` (fd
// duplication such as `2>&1`) is not a file write and is skipped.
func redirectionTargets(line string) []string {
	var targets []string
	var quote byte
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && quote != '\'' {
			i++
			continue
		}
		if line[i] == '\'' || line[i] == '"' {
			if quote == 0 {
				quote = line[i]
			} else if quote == line[i] {
				quote = 0
			}
			continue
		}
		if quote != 0 {
			continue
		}
		if line[i] != '>' {
			continue
		}
		j := i + 1
		if j < len(line) && line[j] == '>' { // append: >>
			j++
		}
		if j < len(line) && line[j] == '|' { // noclobber override: >|
			j++
		}
		if j < len(line) && line[j] == '&' { // fd duplication: 2>&1
			i = j
			continue
		}
		for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
			j++
		}
		start := j
		var targetQuote byte
		for j < len(line) {
			if line[j] == '\\' && targetQuote != '\'' && j+1 < len(line) {
				j += 2
				continue
			}
			if line[j] == '\'' || line[j] == '"' {
				if targetQuote == 0 {
					targetQuote = line[j]
				} else if targetQuote == line[j] {
					targetQuote = 0
				}
				j++
				continue
			}
			if targetQuote == 0 && strings.ContainsRune(" \t\r\n|;&<>()$`", rune(line[j])) {
				break
			}
			j++
		}
		if j > start {
			targets = append(targets, strings.Trim(line[start:j], `"'`))
		}
		i = j
	}
	return targets
}

// inPlaceWriteTargets catches allowlisted tools whose flags turn a read into
// an in-place write. yq is intentionally absent from the default allowlist,
// but a user-added yq must still require approval when invoked with -i.
func inPlaceWriteTargets(command string) []string {
	if !containsString(ExtractCommandNames(command), "yq") {
		return nil
	}
	for _, field := range strings.Fields(command) {
		if field == "-i" || field == "--in-place" {
			return []string{"<in-place>"}
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// outputFlagTargets scans for downloader-style output flags: `-o file`,
// `--output file`, `--output=file`, `-ofile`, `-O`, `--remote-name`,
// `--output-document`. A trailing `-o` with no value, or `-o -` (stdout), is
// not a write. Unknown programs that reuse `-o` for non-write purposes may
// false-positive; that fails closed.
func outputFlagTargets(line string) []string {
	fields := strings.Fields(line)
	var targets []string
	for i, field := range fields {
		name, inline := field, ""
		if strings.HasPrefix(field, "--") {
			if idx := strings.IndexByte(field, '='); idx >= 0 {
				name, inline = field[:idx], field[idx+1:]
			}
		} else if strings.HasPrefix(field, "-o") && len(field) > 2 && !strings.HasPrefix(field, "--") {
			name, inline = "-o", field[2:]
		}
		if _, ok := outputBooleanFlags[name]; ok {
			targets = append(targets, "<remote-file>")
			continue
		}
		if _, ok := outputValueFlags[name]; !ok {
			continue
		}
		switch {
		case inline != "" && inline != "-":
			targets = append(targets, inline)
		case i+1 < len(fields) && fields[i+1] != "-":
			targets = append(targets, fields[i+1])
		}
	}
	return targets
}

// ShellGateProfile selects the failure mode of the shell gate.
type ShellGateProfile string

const (
	// ShellGateProfileProduction fails closed: blocked commands are denied.
	ShellGateProfileProduction ShellGateProfile = "production"
	// ShellGateProfileDev escalates: blocked commands become pending approvals
	// instead of hard failures.
	ShellGateProfileDev ShellGateProfile = "dev"
)

// NormalizeShellGateProfile maps a raw profile string to a gate profile.
// Anything other than "dev" resolves to production — fail closed.
func NormalizeShellGateProfile(raw string) ShellGateProfile {
	if strings.EqualFold(strings.TrimSpace(raw), string(ShellGateProfileDev)) {
		return ShellGateProfileDev
	}
	return ShellGateProfileProduction
}

// ShellGateVerdict is the outcome of a shell gate evaluation.
type ShellGateVerdict string

const (
	// ShellGateVerdictAllow — every invoked command name is allowlisted.
	ShellGateVerdictAllow ShellGateVerdict = "allow"
	// ShellGateVerdictPendingApproval — dev profile escalation: the command is
	// not executed; it requires an approval ceremony first.
	ShellGateVerdictPendingApproval ShellGateVerdict = "pending_approval"
	// ShellGateVerdictDeny — production profile fail-closed denial.
	ShellGateVerdictDeny ShellGateVerdict = "deny"
)

// ShellGateDecision is the result of gating one shell command line.
type ShellGateDecision struct {
	Verdict      ShellGateVerdict `json:"verdict"`
	Profile      ShellGateProfile `json:"profile"`
	Command      string           `json:"command"`
	Invoked      []string         `json:"invoked_commands"`
	Blocked      []string         `json:"blocked_commands,omitempty"`
	WriteTargets []string         `json:"write_targets,omitempty"`
	Reason       string           `json:"reason,omitempty"`
}

// gateReason explains why a command did not pass the gate, covering both
// blocked command names and detected write targets.
func gateReason(decision ShellGateDecision, dev bool) string {
	mode := "are denied in the production profile"
	if dev {
		mode = "escalate to a pending approval in the dev profile"
	}
	var parts []string
	if len(decision.Blocked) > 0 {
		parts = append(parts, "blocked shell commands "+mode+": "+strings.Join(decision.Blocked, ", "))
	}
	if len(decision.WriteTargets) > 0 {
		parts = append(parts, "shell writes "+mode+": "+strings.Join(decision.WriteTargets, ", "))
	}
	return strings.Join(parts, "; ")
}

// GateShellCommand evaluates a shell command line against an allowlist under
// the given profile. Blocked command names and any detected write target
// (output redirection or output flag) are denied in the production profile
// (fail closed) and escalated to a pending approval in the dev profile — even
// when every command name is allowlisted, an allowlisted reader must not
// become a writer (`cat x > y`, `curl -o y url`).
func GateShellCommand(profile ShellGateProfile, command string, allowlist []string) ShellGateDecision {
	decision := ShellGateDecision{
		Profile:      profile,
		Command:      command,
		Invoked:      ExtractCommandNames(command),
		Blocked:      BlockedCommandNames(command, allowlist),
		WriteTargets: ExtractWriteTargets(command),
	}
	if len(decision.Blocked) == 0 && len(decision.WriteTargets) == 0 {
		decision.Verdict = ShellGateVerdictAllow
		return decision
	}
	if profile == ShellGateProfileDev {
		decision.Verdict = ShellGateVerdictPendingApproval
		decision.Reason = gateReason(decision, true)
		return decision
	}
	decision.Verdict = ShellGateVerdictDeny
	decision.Reason = gateReason(decision, false)
	return decision
}

// GateShellCommandWithStore loads the allowlist from the store and gates the
// command. A store failure fails closed: production denies, dev escalates,
// with every invoked command treated as blocked.
func GateShellCommandWithStore(profile ShellGateProfile, command string, store *ShellAllowlistStore) ShellGateDecision {
	allowlist, err := store.Allowlist()
	if err == nil {
		return GateShellCommand(profile, command, allowlist)
	}
	decision := ShellGateDecision{
		Profile:      profile,
		Command:      command,
		Invoked:      ExtractCommandNames(command),
		Blocked:      ExtractCommandNames(command),
		WriteTargets: ExtractWriteTargets(command),
		Reason:       "shell allowlist unavailable, failing closed: " + err.Error(),
	}
	if profile == ShellGateProfileDev {
		decision.Verdict = ShellGateVerdictPendingApproval
		return decision
	}
	decision.Verdict = ShellGateVerdictDeny
	return decision
}
