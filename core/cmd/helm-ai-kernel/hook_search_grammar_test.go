// quantum_posture: these tests exercise hook receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// runAt is run with the call's working directory set to cwd.
func (env hookBypassEnv) runAt(t *testing.T, cwd, tool string, input map[string]any) (bool, string, []*contracts.WorkstationPolicyDecisionReceipt) {
	t.Helper()
	before := env.receiptSet(t)
	raw, err := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input, "session_id": "search-grammar", "cwd": cwd})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runHookPreToolCmd(env.args, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
		t.Fatalf("hook exit = %d stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	return strings.Contains(stdout.String(), `"permissionDecision":"deny"`), stdout.String(), env.newReceipts(t, before)
}

// braceGlob is a brace glob of count alternatives, each prefix followed by
// its index, and then suffix.
func braceGlob(prefix string, count int, suffix string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < count; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s%d", prefix, i)
	}
	b.WriteByte('}')
	b.WriteString(suffix)
	return b.String()
}

// The globs of one call share one expansion budget, so a call that sends
// many globs, each under what one glob may cost, is decided at once: the
// hook must answer well inside the client's timeout whatever the input is.
func TestHookDecidesEveryGlobOfACallUnderOneBudget(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")

	// Close to 4 MiB of distinct globs, each of 255 alternatives.
	var globs []any
	size := 0
	for i := 0; size < hookMaxInputBytes-(64<<10); i++ {
		glob := braceGlob(fmt.Sprintf("g%d_", i), 255, ".go")
		globs = append(globs, glob)
		size += len(glob) + 3
	}
	type outcome struct {
		denied  bool
		stdout  string
		reasons string
	}
	done := make(chan outcome, 1)
	go func() {
		denied, stdout, receipts := env.runAt(t, "/repo", "mcp__fs__search_files", map[string]any{"path": "/repo", "include": globs})
		done <- outcome{denied, stdout, describeReceipts(receipts)}
	}()
	// Keep the five-second watchdog below the ten-second classification
	// deadline and the client's thirty-second timeout. Serializing and hashing
	// this 4 MiB input under the race detector is not a one-second contract;
	// the call must still refuse on its expansion budget, not on the deadline.
	select {
	case got := <-done:
		if !got.denied || !strings.Contains(got.reasons, "TRUST_MATERIAL_ACCESS_DENIED") || !strings.Contains(got.stdout, "too large to expand") {
			t.Fatalf("denied=%v receipts=[%s] stdout=%s, want one denial that says the globs are too large to expand", got.denied, got.reasons, got.stdout)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("a call of %d globs (%d bytes) was not decided within five seconds", len(globs), size)
	}

	// Two globs that are each under the budget pass it together.
	for _, tc := range []struct {
		name  string
		globs []any
	}{
		{"alternatives", []any{braceGlob("a", 200, ".go"), braceGlob("b", 200, ".go")}},
		{"bytes", []any{strings.Repeat("x", 40<<10) + "*.go", strings.Repeat("y", 40<<10) + "*.go"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied, stdout, receipts := env.runAt(t, "/repo", "mcp__fs__search_files", map[string]any{"path": "/repo", "include": tc.globs})
			if !denied || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") || !strings.Contains(stdout, "too large to expand") {
				t.Fatalf("denied=%v receipts=[%s] stdout=%s, want the call refused as too large to expand", denied, describeReceipts(receipts), stdout)
			}
		})
	}
	// One glob well under the budget is decided as before.
	if denied, _, receipts := env.runAt(t, "/repo", "mcp__fs__search_files", map[string]any{"path": "/repo", "include": []any{braceGlob("a", 100, ".go")}}); denied || hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") {
		t.Fatalf("a glob under the budget was refused: [%s]", describeReceipts(receipts))
	}
}

// A search with no path starts in the working directory: "/" is above
// everything, a working directory above the data directory reaches it, and a
// search whose start cannot be resolved is taken to start above everything.
// A glob in the grammar that names nothing the key directory holds is not
// refused for that.
func TestHookSearchFromTheWorkingDirectory(t *testing.T) {
	builtin := newHookBypassEnv(t, "")
	for _, tc := range []struct {
		name, cwd, tool string
		input           map[string]any
		deny            bool
	}{
		{"root, recursive filter for the key directory", "/", "Grep", map[string]any{"glob": "**/.helm-ai-kernel/k*/*", "pattern": "."}, true},
		{"root, Glob for the key directory", "/", "Glob", map[string]any{"pattern": "**/.helm-ai-kern*/*/*"}, true},
		{"home, filter anchored with a leading slash", builtin.home, "Grep", map[string]any{"glob": "/.helm-ai-kernel/k*/*", "pattern": "."}, true},
		{"home, filter with a backslash", builtin.home, "Grep", map[string]any{"glob": `*.see\d`, "pattern": "."}, true},
		{"home, filter with a bracket", builtin.home, "Grep", map[string]any{"glob": "*.[ch]", "pattern": "."}, true},
		{"home, negated filter", builtin.home, "Grep", map[string]any{"glob": "!**/node_modules/**", "pattern": "."}, true},
		{"unresolvable start, filter for every file", "", "Grep", map[string]any{"path": "rel", "glob": "*", "pattern": "."}, true},
		{"unresolvable start, bracket filter", "", "Grep", map[string]any{"path": "rel", "glob": "[a]*.go", "pattern": "."}, true},

		{"root, sources", "/", "Grep", map[string]any{"glob": "src/**/*.go", "pattern": "TODO"}, false},
		{"home, sources", builtin.home, "Grep", map[string]any{"glob": "src/**/*.go", "pattern": "TODO"}, false},
		{"home, documents", builtin.home, "Grep", map[string]any{"glob": "docs/*.md", "pattern": "TODO"}, false},
		{"home, braces", builtin.home, "Glob", map[string]any{"pattern": "**/*.{c,h}{,pp}"}, false},
		{"unresolvable start, sources", "", "Grep", map[string]any{"path": "rel", "glob": "src/**/*.go", "pattern": "TODO"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied, stdout, receipts := builtin.runAt(t, tc.cwd, tc.tool, tc.input)
			if tc.deny != (denied && hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED")) {
				t.Fatalf("%s %v from %q: denied=%v receipts=[%s] stdout=%s, want trust-material denial %v", tc.tool, tc.input, tc.cwd, denied, describeReceipts(receipts), stdout, tc.deny)
			}
		})
	}
	// A glob outside the grammar is refused with a reason that names what
	// the hook did not read.
	_, stdout, _ := builtin.runAt(t, builtin.home, "Grep", map[string]any{"glob": "*.[ch]", "pattern": "."})
	if !strings.Contains(stdout, `a search glob with \"[\", which the hook does not read`) {
		t.Fatalf("the denial does not name the bracket: %s", stdout)
	}
}

// Claude Code splits Grep's glob on white space, and on commas when it has no
// braces, and gives ripgrep each part: each part is decided as a glob of its
// own. An MCP tool's pattern outside the grammar is taken as a regular
// expression: the search root is not walked for it, and it is refused only
// where the search starts at, inside or above the data directory. A root the
// hook cannot walk stands for a repository too large to walk.
func TestHookReadsSearchInputsAsTheirToolDoes(t *testing.T) {
	granted := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	builtin := granted
	builtin.args = []string{"--client", "claude-code", "--data-dir", granted.dataDir}
	unreadable, project := t.TempDir(), t.TempDir()
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
	if _, err := os.ReadDir(unreadable); err == nil {
		t.Skip("running with permissions that read any directory")
	}
	const (
		noDecision = iota
		noTrustDenial
		trustDenial
	)
	for _, tc := range []struct {
		name  string
		env   hookBypassEnv
		tool  string
		input map[string]any
		want  int
	}{
		{"comma-separated filters, repository too large to walk", builtin, "Grep", map[string]any{"path": unreadable, "glob": "*.ts,*.tsx", "pattern": "TODO"}, noDecision},
		{"space-separated filters, repository too large to walk", builtin, "Grep", map[string]any{"path": unreadable, "glob": "*.ts *.tsx", "pattern": "TODO"}, noDecision},
		{"comma-separated filters from home", builtin, "Grep", map[string]any{"path": builtin.home, "glob": "*.go,*.md", "pattern": "TODO"}, noDecision},
		{"a brace group keeps its commas", builtin, "Grep", map[string]any{"path": builtin.home, "glob": "*.{ts,tsx} *.go", "pattern": "TODO"}, noDecision},
		{"a space-separated part names a key file", granted, "Grep", map[string]any{"path": project, "glob": "*.go *.seed", "pattern": "."}, trustDenial},
		{"a comma-separated part names a key file", granted, "Grep", map[string]any{"path": project, "glob": "*.go,*.seed", "pattern": "."}, trustDenial},
		{"MCP regex, repository too large to walk", granted, "mcp__fs__search", map[string]any{"path": unreadable, "pattern": "foo|bar"}, noTrustDenial},
		{"MCP regex with escapes, repository too large to walk", granted, "mcp__fs__search", map[string]any{"path": unreadable, "pattern": `\bTODO\b`}, noTrustDenial},
		{"MCP regex from home", granted, "mcp__fs__search", map[string]any{"path": granted.home, "pattern": "foo|bar"}, trustDenial},
		{"MCP glob for a key file", granted, "mcp__fs__search", map[string]any{"path": project, "pattern": "**/*.seed"}, trustDenial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied, stdout, receipts := tc.env.runAt(t, "/repo", tc.tool, tc.input)
			trust := hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED")
			switch {
			case tc.want == noDecision && (denied || len(receipts) != 0),
				tc.want == noTrustDenial && trust,
				tc.want == trustDenial && (!denied || !trust):
				t.Fatalf("%s %v: denied=%v receipts=[%s] stdout=%s, want outcome %d", tc.tool, tc.input, denied, describeReceipts(receipts), stdout, tc.want)
			}
		})
	}
}
