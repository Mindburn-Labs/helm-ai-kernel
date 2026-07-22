package shellscan

import "testing"

// This file pins what shellscan deliberately does NOT establish, following the
// honest-gap precedent in core/pkg/threatscan/semantic_gap_test.go. A failure
// here means the boundary moved — either a gap closed (update the file) or a
// control regressed.

// TestTransitiveEffectsAreNotBounded records that classification bounds the
// SHAPE of a command, never the behavior of the program it starts. These
// commands are classified read-only and are authorized only because an operator
// put shell.test / shell.build in the profile's Observe.AllowedActions, which
// is an explicit statement that running the repository's own build and test
// code is acceptable. shellscan does not and cannot verify what that code does.
//
// The bound comes from elsewhere: the command still cannot chain, redirect, or
// substitute, so its blast radius is whatever the repository's own tooling
// already had.
func TestTransitiveEffectsAreNotBounded(t *testing.T) {
	cases := []struct {
		command string
		action  string
		gap     string
	}{
		{"go test ./...", ActionShellTest, "test binaries execute arbitrary repository code"},
		{"make test", ActionShellTest, "the Makefile target is arbitrary and not inspected"},
		{"make build", ActionShellBuild, "same as make test"},
		{"go build -o /tmp/attacker-chosen ./cmd/x", ActionShellBuild, "-o writes a binary to an argument-chosen path"},
		{"pytest -q", ActionShellTest, "conftest.py executes at collection time"},
	}

	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			action, ok := ClassifyReadOnly(tc.command)
			if !ok || action != tc.action {
				t.Fatalf("expected %q to classify as %s (known gap: %s), got %q ok=%v", tc.command, tc.action, tc.gap, action, ok)
			}
			t.Logf("accepted gap: %s — %s", tc.command, tc.gap)
		})
	}
}

// TestArgumentsAreNotInspected records that once the executable position is
// allowlisted, the remaining arguments are not examined. Found by
// FuzzClassifyReadOnly, which minimized to "git stAtus rm -r".
//
// This is safe for the four allowlisted git subcommands specifically: status,
// diff, log, and show treat unrecognized operands as pathspecs or revisions and
// never execute them. It would NOT be safe for a subcommand that takes a command
// operand, which is why the table is restricted to these four and why
// membership requires read-only behavior for every argument vector.
func TestArgumentsAreNotInspected(t *testing.T) {
	action, ok := ClassifyReadOnly("git status rm -r")
	if !ok || action != ActionGitStatus {
		t.Fatalf("expected pathspec arguments to be ignored, got %q ok=%v", action, ok)
	}
	t.Log("accepted gap: arguments after an allowlisted git subcommand are not inspected")
}

// TestExternalDiffDriverResidual records the one way an allowlisted git command
// can still invoke another program: diff, log, and show honor the diff.external
// config key and the GIT_EXTERNAL_DIFF environment variable, neither of which
// appears in argv.
//
// The argv-borne form is already blocked — "git -c diff.external=rm diff" puts
// "-c" in the subcommand position, so it never matches the table. What remains
// is ambient config the hook cannot see, which belongs to environment
// provenance rather than command classification.
func TestExternalDiffDriverResidual(t *testing.T) {
	if _, ok := ClassifyReadOnly("git -c diff.external=rm diff"); ok {
		t.Fatal("argv-borne external diff driver must not classify: -c occupies the subcommand position")
	}
	action, ok := ClassifyReadOnly("git diff HEAD~1")
	if !ok || action != ActionGitDiff {
		t.Fatalf("expected plain git diff to classify, got %q ok=%v", action, ok)
	}
	t.Log("accepted gap: ambient diff.external / GIT_EXTERNAL_DIFF is outside argv analysis")
}

// TestUndecidableCommandsRouteToDeny records the cases this package refuses to
// reason about. None is classified, so each falls through to the policy engine
// and is denied when no operate permission is granted. Denial is the correct
// outcome, not a limitation to fix.
func TestUndecidableCommandsRouteToDeny(t *testing.T) {
	undecidable := []struct {
		command string
		why     string
	}{
		{"eval \"$X\"", "eval defers the real command to runtime"},
		{"$EDITOR /etc/passwd", "argv[0] is itself a variable"},
		{"xargs rm", "the operand comes from stdin, which is not visible here"},
		{"find . -delete", "a mutating flag on a non-allowlisted binary"},
		{"nice -n 10 rm -rf /tmp/x", "a wrapper binary hides the real command"},
		{"sudo ls", "privilege elevation is never read-only"},
	}

	for _, tc := range undecidable {
		t.Run(tc.command, func(t *testing.T) {
			if action, ok := ClassifyReadOnly(tc.command); ok {
				t.Fatalf("expected %q to remain unclassified (%s), got %s", tc.command, tc.why, action)
			}
		})
	}
}
