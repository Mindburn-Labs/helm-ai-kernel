// Package shellscan classifies raw shell command strings against the abstract
// action IDs used by workstation policy profiles.
//
// It exists to close a bridge that did not exist. The PreToolUse hook receives
// a raw command string, while contracts.WorkstationObservePolicy.AllowedActions
// expresses permission as abstract IDs ("git.status", "shell.read"). With
// nothing mapping one to the other, Bash calls were governed by a denylist of
// twelve substrings — default-allow — while every other tool class in the same
// hook was default-deny with an allowlist. This package supplies the map so
// shell can adopt the same posture.
//
// Design invariants:
//
//   - Fail direction is DENY. An unrecognized command is simply not classified;
//     the caller routes it to the policy engine, which denies when no operate
//     permission is granted. A safe command that goes unrecognized is an
//     annoyance. An unsafe command that gets recognized is a breach. Only the
//     second failure mode matters, so the recognition list is deliberately
//     narrow and grows by evidence.
//
//   - Static analyzability is decided BEFORE allowlist matching, and
//     ClassifyReadOnly re-checks it rather than trusting callers. Prefix
//     matching on argv is sound only for a command that cannot chain,
//     substitute, or redirect — that ordering is what makes "git status &&
//     rm -rf /" fail on the metacharacter rather than pass on its first two
//     tokens. It also means this package needs no shell lexer, and the repo
//     has none.
//
//   - Every allowlisted entry must be read-only for ALL argument values, since
//     arguments beyond argv[0..1] are never inspected. "git branch" is absent
//     precisely because "git branch -D" deletes.
//
//   - Deterministic, no I/O, safe for concurrent use.
//
// The regex set is shared with core/pkg/mcp's argument scanner, which imports
// it from here so both surfaces agree on what counts as a shell metacharacter.
package shellscan

import (
	"regexp"
	"strings"
)

// Shared injection patterns. core/pkg/mcp/argscan.go consumes these so a single
// definition governs both MCP argument scanning and shell command analysis.
var (
	// ShellMetachar matches command chaining, expansion, substitution, NUL, and
	// the pipe/process-substitution redirect forms.
	ShellMetachar = regexp.MustCompile("[;&|`]|\\$\\(|\\$\\{|\\x00|>\\||<\\(")

	// CommandSubstitutionBacktick matches backtick command substitution.
	CommandSubstitutionBacktick = regexp.MustCompile("`[^`]*`")

	// ShellPayloadCommon matches a nested shell spawn carrying a payload.
	ShellPayloadCommon = regexp.MustCompile(`(?i)(^|[\s;&|])(sh|bash|zsh|ksh|dash)\s+(-c\s+|<\()`)
)

// Patterns that matter for raw command analysis but not for scanning JSON
// arguments, so they are local rather than shared.
//
// shellRedirect is the one that would otherwise be missed: ShellMetachar covers
// ">|" and "<(" but not a bare ">". Without this, "git show HEAD > ~/.ssh/
// authorized_keys" survives the metacharacter gate and then matches "git show"
// on the allowlist — turning a read-only entry into an arbitrary file write.
var (
	shellRedirect = regexp.MustCompile(`[<>]`)
	shellControl  = regexp.MustCompile(`[\r\n\x00]`)
)

// Observe action IDs. These must stay identical to the strings used in
// contracts.WorkstationObservePolicy.AllowedActions — see
// workstation.DefaultObserveDraftProfile.
const (
	ActionGitStatus  = "git.status"
	ActionGitDiff    = "git.diff"
	ActionShellRead  = "shell.read"
	ActionShellTest  = "shell.test"
	ActionShellBuild = "shell.build"
)

// gitReadOnlySubcommands maps a git subcommand to its action ID. Membership
// requires the subcommand to be read-only for every argument vector, because
// arguments are not inspected.
var gitReadOnlySubcommands = map[string]string{
	"status": ActionGitStatus,
	"diff":   ActionGitDiff,
	"log":    ActionGitDiff,
	"show":   ActionGitDiff,
}

// twoTokenCommands maps "argv0 argv1" to an action ID, for tools whose first
// token alone says nothing about mutation ("go" could be "go build" or
// "go clean").
var twoTokenCommands = map[string]string{
	"go test":     ActionShellTest,
	"go vet":      ActionShellTest,
	"go build":    ActionShellBuild,
	"cargo test":  ActionShellTest,
	"cargo build": ActionShellBuild,
	"npm test":    ActionShellTest,
	"make test":   ActionShellTest,
	"make build":  ActionShellBuild,
}

// readOnlyCommands maps a bare command name to an action ID, for commands that
// cannot mutate state regardless of arguments. "env" is deliberately absent —
// "env FOO=bar rm -rf /" executes rm.
var readOnlyCommands = map[string]string{
	"ls":     ActionShellRead,
	"pwd":    ActionShellRead,
	"cat":    ActionShellRead,
	"head":   ActionShellRead,
	"tail":   ActionShellRead,
	"wc":     ActionShellRead,
	"stat":   ActionShellRead,
	"file":   ActionShellRead,
	"echo":   ActionShellRead,
	"date":   ActionShellRead,
	"whoami": ActionShellRead,
	"uname":  ActionShellRead,
	"grep":   ActionShellRead,
	"rg":     ActionShellRead,
	"pytest": ActionShellTest,
}

// StaticallyAnalyzable reports whether command is a single simple command:
// no chaining, expansion, substitution, redirection, embedded newline, or
// nested shell spawn.
//
// An empty command is not analyzable, so it denies rather than falling through
// as a no-op.
func StaticallyAnalyzable(command string) bool {
	if strings.TrimSpace(command) == "" {
		return false
	}
	for _, re := range []*regexp.Regexp{
		ShellMetachar,
		CommandSubstitutionBacktick,
		ShellPayloadCommon,
		shellRedirect,
		shellControl,
	} {
		if re.MatchString(command) {
			return false
		}
	}
	return true
}

// ClassifyReadOnly maps command to an Observe action ID, reporting ok=false for
// anything it does not explicitly recognize. A false result is not a verdict —
// it means "this package cannot vouch for the command", and the caller must
// route it to the policy engine.
//
// The returned ID is only permission to proceed once the caller has confirmed
// it appears in the active profile's Observe.AllowedActions. Classification and
// authorization stay separate: this decides what a command *is*, the profile
// decides whether that is allowed.
func ClassifyReadOnly(command string) (string, bool) {
	// Re-checked rather than assumed. This makes the allowlist invariant hold
	// for any input, including from a caller that forgets the ordering.
	if !StaticallyAnalyzable(command) {
		return "", false
	}
	fields := strings.Fields(strings.ToLower(command))
	if len(fields) == 0 {
		return "", false
	}
	// git is matched on its subcommand and never falls through to the bare-name
	// table, so an unlisted subcommand cannot be rescued by a "git" entry.
	if fields[0] == "git" {
		if len(fields) < 2 {
			return "", false
		}
		action, ok := gitReadOnlySubcommands[fields[1]]
		return action, ok
	}
	if len(fields) >= 2 {
		if action, ok := twoTokenCommands[fields[0]+" "+fields[1]]; ok {
			return action, true
		}
	}
	action, ok := readOnlyCommands[fields[0]]
	return action, ok
}
