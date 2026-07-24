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
//     (e.g. `sudo -u root rm x`) may surface the value as a command name;
//     that false positive fails closed and is accepted.
//   - Unknown gate profiles normalize to production (deny), never to dev.
package workstation

import (
	"regexp"
	"sort"
	"strings"
)

// commandSplitPattern splits a shell command line into segments at every
// construct that can start a new command: pipes, logical operators, command
// separators, background execution, command substitution (backticks and
// $(...)), and subshells. Order matters: `||` and `&&` must precede their
// single-character prefixes so the leftmost-longest alternation consumes the
// right token. Without `&`, backtick, `$(`, and the subshell parens,
// `echo hi & rm /x`, `echo `+"`rm /x`"+`, and `echo $(rm /x)` would slip past
// the gate with only `echo` allowlisted.
var commandSplitPattern = regexp.MustCompile(`\|\||&&|&|;|\||\n|` + "`" + `|\$\(|\(|\)`)

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
			for _, wrapped := range unwrapWrappedCommands(tokens[index+1:]) {
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
// ENV=value assignments and bare `-` flags after a wrapper are skipped.
func unwrapWrappedCommands(tokens []string) []string {
	var out []string
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if envAssignmentPattern.MatchString(token) {
			continue
		}
		if strings.HasPrefix(token, "-") {
			// Bare wrapper flag (e.g. `sudo -E`, `time -p`). Flags that take a
			// separate value are not unwrapped; the value may surface as a
			// command name, which fails closed.
			continue
		}
		name := sanitizeCommandToken(token)
		if name == "" {
			continue
		}
		out = append(out, name)
		if _, isWrapper := wrapperCommands[name]; isWrapper {
			continue
		}
		break
	}
	return out
}

func sanitizeCommandToken(token string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(token), `'"`))
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
	Verdict ShellGateVerdict `json:"verdict"`
	Profile ShellGateProfile `json:"profile"`
	Command string           `json:"command"`
	Invoked []string         `json:"invoked_commands"`
	Blocked []string         `json:"blocked_commands,omitempty"`
	Reason  string           `json:"reason,omitempty"`
}

// GateShellCommand evaluates a shell command line against an allowlist under
// the given profile. Blocked commands are denied in the production profile
// (fail closed) and escalated to a pending approval in the dev profile.
func GateShellCommand(profile ShellGateProfile, command string, allowlist []string) ShellGateDecision {
	decision := ShellGateDecision{
		Profile: profile,
		Command: command,
		Invoked: ExtractCommandNames(command),
		Blocked: BlockedCommandNames(command, allowlist),
	}
	if len(decision.Blocked) == 0 {
		decision.Verdict = ShellGateVerdictAllow
		return decision
	}
	if profile == ShellGateProfileDev {
		decision.Verdict = ShellGateVerdictPendingApproval
		decision.Reason = "blocked shell commands escalate to a pending approval in the dev profile: " + strings.Join(decision.Blocked, ", ")
		return decision
	}
	decision.Verdict = ShellGateVerdictDeny
	decision.Reason = "blocked shell commands are denied in the production profile: " + strings.Join(decision.Blocked, ", ")
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
		Profile: profile,
		Command: command,
		Invoked: ExtractCommandNames(command),
		Blocked: ExtractCommandNames(command),
		Reason:  "shell allowlist unavailable, failing closed: " + err.Error(),
	}
	if profile == ShellGateProfileDev {
		decision.Verdict = ShellGateVerdictPendingApproval
		return decision
	}
	decision.Verdict = ShellGateVerdictDeny
	return decision
}
