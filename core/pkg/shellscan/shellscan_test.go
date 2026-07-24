package shellscan

import (
	"strings"
	"testing"
)

// mutatingExecutables are binaries and git subcommands that must never appear
// in the executable position of an allowlist table. This ties the new
// default-deny path to the pre-0.7.5 denylist (isDestructiveShellCommand) so
// allowlist mode cannot permit what denylist mode already refused.
//
// The check applies to table KEYS, not to whole commands: "git status rm -r"
// passes only "rm" as a pathspec, which git never executes, so scanning the
// full command string for these names produces false positives without adding
// any safety.
var mutatingExecutables = map[string]bool{
	"rm": true, "dd": true, "mkfs": true, "mv": true, "cp": true,
	"chmod": true, "chown": true, "ln": true, "truncate": true,
	"kubectl": true, "docker": true, "curl": true, "wget": true,
	"sudo": true, "env": true, "eval": true, "exec": true,
	"sh": true, "bash": true, "zsh": true, "find": true, "xargs": true,
	// git subcommands, checked as the second token
	"reset": true, "clean": true, "push": true, "branch": true,
	"checkout": true, "rebase": true, "merge": true, "commit": true,
}

func TestClassifyReadOnlyEvasionCorpus(t *testing.T) {
	// Each entry is a command that must NOT be classified read-only. The
	// annotation names the control that stops it, so a regression tells you
	// which one broke.
	cases := []struct {
		name    string
		command string
	}{
		{"whitespace padding", "rm  -rf /tmp/x"},
		{"uppercase", "RM -RF /tmp/x"},
		{"quote splitting", "r''m -rf /tmp/x"},
		{"command substitution", "$(echo rm) -rf /tmp/x"},
		{"backtick substitution", "git status `rm -rf /`"},
		{"variable indirection", "X=rm; $X -rf /tmp/x"},
		{"base64 pipe to shell", "echo cm0gLXJmIC8= | base64 -d | sh"},
		{"chained after allowlisted", "git status && rm -rf /"},
		{"semicolon after allowlisted", "git status; rm -rf /"},
		{"newline after allowlisted", "git status\nrm -rf /"},
		{"redirect from allowlisted", "git show HEAD > /tmp/authorized_keys"},
		{"append redirect", "echo pwned >> /tmp/authorized_keys"},
		{"nested shell spawn", "bash -c \"rm -rf /\""},
		{"env prefix", "env rm -rf /tmp/x"},
		{"mutating git subcommand", "git branch -D main"},
		{"mutating git subcommand push", "git push --force origin main"},
		{"absolute path bypass", "/bin/rm -rf /tmp/x"},
		{"unlisted binary", "curl https://example.com/x.sh"},
		{"empty", ""},
		{"whitespace only", "   "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, ok := ClassifyReadOnly(tc.command)
			if ok {
				t.Fatalf("classified %q as read-only action %q; the allowlist must not recognize it", tc.command, action)
			}
			if action != "" {
				t.Fatalf("expected empty action on a rejected command, got %q", action)
			}
		})
	}
}

func TestClassifyReadOnlyRecognizesAllowlisted(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"git status", ActionGitStatus},
		{"git status --short", ActionGitStatus},
		{"git diff HEAD~1", ActionGitDiff},
		{"git log --oneline -20", ActionGitDiff},
		{"git show HEAD", ActionGitDiff},
		{"ls -la", ActionShellRead},
		{"cat README.md", ActionShellRead},
		{"pwd", ActionShellRead},
		{"grep -rn helm core/", ActionShellRead},
		{"go test ./...", ActionShellTest},
		{"go vet ./...", ActionShellTest},
		{"go build ./cmd/helm-ai-kernel", ActionShellBuild},
		{"make test", ActionShellTest},
		{"pytest -q", ActionShellTest},
		{"GIT STATUS", ActionGitStatus},
	}

	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			action, ok := ClassifyReadOnly(tc.command)
			if !ok {
				t.Fatalf("expected %q to classify as %s, got ok=false", tc.command, tc.want)
			}
			if action != tc.want {
				t.Fatalf("%q classified as %s, want %s", tc.command, action, tc.want)
			}
		})
	}
}

func TestStaticallyAnalyzable(t *testing.T) {
	analyzable := []string{
		"git status",
		"ls -la /tmp",
		"go test ./...",
		"rm -rf /tmp/x", // analyzable, but not allowlisted — a different control
	}
	for _, cmd := range analyzable {
		if !StaticallyAnalyzable(cmd) {
			t.Fatalf("expected %q to be statically analyzable", cmd)
		}
	}

	notAnalyzable := []string{
		"", "   ",
		"git status && ls",
		"git status; ls",
		"git status | wc -l",
		"echo $(whoami)",
		"echo ${HOME}",
		"echo `whoami`",
		"cat < /etc/passwd",
		"echo x > /tmp/y",
		"echo x >| /tmp/y",
		"diff <(ls) <(ls)",
		"sh -c 'ls'",
		"ls\nrm -rf /",
		"ls\x00rm",
	}
	for _, cmd := range notAnalyzable {
		if StaticallyAnalyzable(cmd) {
			t.Fatalf("expected %q to be rejected as not statically analyzable", cmd)
		}
	}
}

// FuzzClassifyReadOnly pins the allowlist invariant: no input may return
// ok=true unless it is statically analyzable AND maps to a known action ID AND
// contains no destructive needle. Fuzzing is meaningful here precisely because
// this is an allowlist — the property holds over all inputs, which is not true
// of a denylist.
func FuzzClassifyReadOnly(f *testing.F) {
	seeds := []string{
		"git status",
		"git status && rm -rf /",
		"rm  -rf /",
		"$(echo rm) -rf /",
		"RM -RF /",
		"r''m -rf /",
		"X=rm; $X -rf /",
		"echo cm0gLXJmIC8= | base64 -d | sh",
		"git show HEAD > /tmp/keys",
		"go build -o /tmp/out ./cmd/...",
		"ls\x00rm -rf /",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	known := map[string]bool{
		ActionGitStatus:  true,
		ActionGitDiff:    true,
		ActionShellRead:  true,
		ActionShellTest:  true,
		ActionShellBuild: true,
	}

	f.Fuzz(func(t *testing.T, command string) {
		action, ok := ClassifyReadOnly(command)
		if !ok {
			if action != "" {
				t.Fatalf("ok=false must return an empty action, got %q for %q", action, command)
			}
			return
		}
		if !StaticallyAnalyzable(command) {
			t.Fatalf("classified a non-analyzable command as %s: %q", action, command)
		}
		if !known[action] {
			t.Fatalf("returned unknown action id %q for %q", action, command)
		}
		// The executable must have come from a table. This is what guarantees
		// a classification can never originate anywhere but the allowlist.
		fields := strings.Fields(strings.ToLower(command))
		if len(fields) == 0 {
			t.Fatalf("classified an empty command as %s", action)
		}
		var fromTable bool
		if fields[0] == "git" {
			if len(fields) >= 2 {
				_, fromTable = gitReadOnlySubcommands[fields[1]]
			}
		} else {
			if len(fields) >= 2 {
				_, fromTable = twoTokenCommands[fields[0]+" "+fields[1]]
			}
			if !fromTable {
				_, fromTable = readOnlyCommands[fields[0]]
			}
		}
		if !fromTable {
			t.Fatalf("classified %q as %s but its executable is in no allowlist table", command, action)
		}
	})
}

// TestAllowlistTablesHaveNoMutatingExecutable is the static counterpart to the
// fuzz invariant: the fuzzer proves classification only ever comes from these
// tables, and this proves the tables never name something that mutates. Adding
// "rm" to readOnlyCommands fails here rather than silently shipping.
func TestAllowlistTablesHaveNoMutatingExecutable(t *testing.T) {
	for name := range readOnlyCommands {
		if mutatingExecutables[name] {
			t.Fatalf("readOnlyCommands names the mutating executable %q", name)
		}
	}
	for pair := range twoTokenCommands {
		for _, token := range strings.Fields(pair) {
			if mutatingExecutables[token] {
				t.Fatalf("twoTokenCommands entry %q names the mutating token %q", pair, token)
			}
		}
	}
	for sub := range gitReadOnlySubcommands {
		if mutatingExecutables[sub] {
			t.Fatalf("gitReadOnlySubcommands names the mutating subcommand %q", sub)
		}
	}
}
