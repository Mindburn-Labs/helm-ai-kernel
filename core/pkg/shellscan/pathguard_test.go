package shellscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// guardFixture lays out a home directory the way a workstation signer does: a
// data directory with a key directory inside, a policy file elsewhere, and a
// symlink that reaches the key directory under another name.
type guardFixture struct {
	home, data, keys, seed, policy, link string
	guard                                *PathGuard
}

func newGuardFixture(t *testing.T) guardFixture {
	t.Helper()
	home := t.TempDir()
	f := guardFixture{
		home: home,
		data: filepath.Join(home, ".signer"),
		keys: filepath.Join(home, ".signer", "keys"),
	}
	f.seed = filepath.Join(f.keys, "signer.seed")
	f.policy = filepath.Join(t.TempDir(), "policy.json")
	for _, dir := range []string{f.keys, filepath.Join(f.data, "receipts")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{f.seed, f.policy, filepath.Join(f.data, "receipts", "one.json")} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.link = filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(f.keys, f.link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f.guard = NewPathGuard(home)
	f.guard.ProtectTree(f.keys)
	f.guard.ProtectContainer(f.data)
	f.guard.ProtectFile(f.policy)
	f.guard.ProtectName("signer.seed")
	return f
}

func TestPathGuardMatchesEverySpellingOfAProtectedPath(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	cases := []struct {
		name, target, cwd string
		want              bool
	}{
		{"absolute file", f.seed, work, true},
		{"file in the tree that does not exist yet", filepath.Join(f.keys, "new.pub"), work, true},
		{"the tree itself", f.keys, work, true},
		{"the tree with a trailing slash", f.keys + "/", work, true},
		{"tilde", "~/.signer/keys/signer.seed", work, true},
		{"HOME variable", "$HOME/.signer/keys/signer.seed", work, true},
		{"braced HOME variable", "${HOME}/.signer/keys/signer.seed", work, true},
		{"dot segments", f.home + "/.signer/receipts/../keys/./signer.seed", work, true},
		{"doubled slashes", f.home + "//.signer//keys//signer.seed", work, true},
		{"upper case", strings.ToUpper(f.seed), work, true},
		{"relative from the data directory", "keys/signer.seed", f.data, true},
		{"relative from inside the tree", "signer.seed", f.keys, true},
		{"relative climb", "../.signer/keys/signer.seed", filepath.Join(f.home, "project"), true},
		{"through a symlink", filepath.Join(f.link, "signer.seed"), work, true},
		{"the symlink itself", f.link, work, true},
		{"new file under the symlink", filepath.Join(f.link, "new.pub"), work, true},
		{"explicit file", f.policy, work, true},
		{"explicit file, relative", filepath.Base(f.policy), filepath.Dir(f.policy), true},
		{"the container itself", f.data, work, true},
		{"the container by tilde", "~/.signer", work, true},
		{"protected name under an unknown directory", "backup/signer.seed", "", true},

		{"other content of the container", filepath.Join(f.data, "receipts", "one.json"), work, false},
		{"sibling with a longer name", f.keys + "-old/signer.pub", work, false},
		{"sibling of the container", f.data + "-backup", work, false},
		{"the home directory", f.home, work, false},
		{"unrelated file", filepath.Join(work, "README.md"), work, false},
		{"relative path with no working directory", "keys/other.pub", "", false},
		{"a bare mention of the protected name", "signer.seed", "", false},
		{"empty", "", work, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rule, got := f.guard.Match(tc.target, tc.cwd); got != tc.want {
				t.Fatalf("Match(%q, %q) = %q, %v; want %v", tc.target, tc.cwd, rule, got, tc.want)
			}
		})
	}
}

func TestPathGuardMatchesPatternsAndText(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	for pattern, want := range map[string]bool{
		"~/.signer/keys/*":      true,
		"~/.signer/k*/s*.seed":  true,
		"~/.signer/*":           true,
		"~/.sig*":               true,
		"~/.*":                  true,
		f.link + "/*":           true,
		"~/.signer/receipts/*":  false,
		"~/*":                   false, // listing home does not name the container
		"~/*/keys/*":            true,  // a search tool's wildcard may match a dot directory
		"**/*.go":               false,
		work + "/*.json":        false,
		"~/.signer/keys-old/*":  false,
		"~/.signer/receipts/**": false,
	} {
		if rule, got := f.guard.MatchPattern(pattern, work); got != want {
			t.Errorf("MatchPattern(%q) = %q, %v; want %v", pattern, rule, got, want)
		}
	}
	for text, want := range map[string]bool{
		"open('" + f.seed + "').read()":                          true,
		"os.path.expanduser('~/.signer/keys/signer.seed')":       true,
		"path.join(os.homedir(), '.signer/keys', 'signer.seed')": true,
		"fs.readFileSync(process.env.HOME + '/.signer/keys/x')":  true,
		"cat $HOME/.signer/keys/signer.seed":                     true,
		"see " + f.data + "/receipts/one.json":                   false,
		"the signer keeps its seed in a file called signer.seed": false,
		"~/.signer/keys-old is unrelated":                        false,
		"nothing to see":                                         false,
	} {
		if rule, got := f.guard.MatchText(text); got != want {
			t.Errorf("MatchText(%q) = %q, %v; want %v", text, rule, got, want)
		}
	}
}

func TestPathGuardNilAndEmptyAreInert(t *testing.T) {
	var none *PathGuard
	if _, ok := none.Match("/etc/passwd", "/"); ok {
		t.Fatal("nil guard matched")
	}
	if _, ok := none.MatchText("anything"); ok {
		t.Fatal("nil guard matched text")
	}
	if _, ok := none.MatchPattern("/*", "/"); ok {
		t.Fatal("nil guard matched a pattern")
	}
	empty := NewPathGuard("")
	empty.ProtectFile("")
	empty.ProtectTree(" ")
	empty.ProtectName("")
	if _, ok := empty.Match("/etc/passwd", "/"); ok {
		t.Fatal("empty guard matched")
	}
}

// The classifier reports a protected path through whatever shell syntax
// carries it, and stays quiet about its neighbours.
func TestClassifyReportsProtectedPaths(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	script := filepath.Join(work, "dump.py")
	if err := os.WriteFile(script, []byte("print(open('"+f.seed+"').read())\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(work, "build.py")
	if err := os.WriteFile(clean, []byte("print('ok')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hit := []string{
		"cat ~/.signer/keys/signer.seed",
		"base64 $HOME/.signer/keys/signer.seed",
		`xxd "${HOME}/.signer/keys/signer.seed"`,
		"cat ~/.signer/ke''ys/signer.seed",
		`cat ~/.signer/"keys"/signer.seed`,
		`cat ~/.signer/k\eys/signer.seed`,
		"cat ~/.signer/k*/s*.seed",
		"cat ~/.signer/keys/{signer.seed,other}",
		"cat ~/.signer/$SUB/signer.seed",
		"cat ~/.sig$REST",
		`cat "$HOME/.signer/keys/$NAME"`,
		"cat " + f.link + "/*",
		"cd ~/.signer/keys && cat *",
		"cd ~/.signer && cat keys/*",
		"cd && cat .signer/keys/signer.seed",
		"cd ~ && cat .signer/k*/*",
		"pushd ~/.signer/keys",
		"tar czf /tmp/k.tgz -C ~/.signer keys",
		"cp -R ~/.signer /tmp/copy",
		"head -c 64 < ~/.signer/keys/signer.seed",
		"echo 00 > ~/.signer/keys/signer.pub",
		"F=~/.signer/keys/signer.seed; cat \"$F\"",
		"sh -c 'cat ~/.signer/keys/signer.seed'",
		"eval 'cat ~/.signer/keys/signer.seed'",
		"sudo -u root cat ~/.signer/keys/signer.seed",
		"find ~/.signer/keys -type f -exec cat {} +",
		"echo ~/.signer/keys/signer.seed | xargs cat",
		"python3 -c \"open('" + f.seed + "')\"",
		"python3 <<'EOF'\nopen('" + f.seed + "')\nEOF",
		"python3 " + script,
		"python3 dump.py",
		"bash -c 'python3 dump.py'",
		"shopt -s dotglob; cat ~/*/keys/*",
		"cat " + f.policy,
	}
	for _, command := range hit {
		res := ClassifyAt(command, work, WithPathGuard(f.guard))
		if res.ProtectedPath == "" || !res.Decide {
			t.Errorf("ClassifyAt(%q) reported no protected path", command)
		}
	}
	miss := []string{
		"cat README.md",
		"ls ~/.signer/receipts",
		"cat ~/.signer/receipts/one.json",
		"cat ~/.signer/receipts/$ID.json",
		"ls ~/*",
		"cat ~/*/keys/*",
		"grep -rn signer.seed docs/",
		"python3 build.py",
		"python3 " + clean,
		"cd /tmp && cat keys/other.pub",
		"cat \"/Users/$USER/project/file\"",
	}
	for _, command := range miss {
		if res := ClassifyAt(command, work, WithPathGuard(f.guard)); res.ProtectedPath != "" {
			t.Errorf("ClassifyAt(%q) reported %q, want nothing", command, res.ProtectedPath)
		}
	}
	// Without a guard nothing is reported and nothing else changes.
	if res := ClassifyAt("cat ~/.signer/keys/signer.seed", work); res.ProtectedPath != "" || res.Decide {
		t.Fatalf("unguarded classification = %+v", res)
	}
}

// An argv is literal: no word is expanded, split or globbed, and a shell
// inside it is still unwrapped.
func TestClassifyArgvAt(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	cases := []struct {
		name      string
		argv      []string
		targets   []string
		protected bool
		generic   bool
	}{
		{name: "network tool", argv: []string{"curl", "-sS", "https://a.example/x", "https://b.example/y"}, targets: []string{"https://a.example", "https://b.example"}},
		{name: "argument with spaces is one argument", argv: []string{"curl", "https://a.example/x y"}, targets: []string{undetermined}},
		{name: "dollar is literal", argv: []string{"curl", "https://a.example/$HOME"}, targets: []string{"https://a.example"}},
		{name: "nested shell", argv: []string{"sh", "-c", "curl https://a.example/ && curl https://b.example/"}, targets: []string{"https://a.example", "https://b.example"}, generic: true},
		{name: "nested shell with a variable", argv: []string{"bash", "-c", `curl "$URL"`}, targets: []string{undetermined}, generic: true},
		{name: "env wrapper", argv: []string{"env", "HTTPS_PROXY=http://p.example:3128", "curl", "https://a.example/"}, targets: []string{"http://p.example:3128", "https://a.example"}, generic: true},
		{name: "plain command", argv: []string{"go", "test", "./..."}},
		{name: "destructive command", argv: []string{"rm", "-rf", "/tmp/x"}, generic: true},
		{name: "protected path", argv: []string{"base64", f.seed}, protected: true},
		{name: "protected path through tilde", argv: []string{"cat", "~/.signer/keys/signer.seed"}, protected: true},
		{name: "protected path inside a shell payload", argv: []string{"sh", "-c", "cat ~/.signer/keys/signer.seed"}, protected: true},
		{name: "empty", argv: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ClassifyArgvAt(tc.argv, work, WithPathGuard(f.guard))
			if got := networkTargets(res); !sameTargets(got, tc.targets) {
				t.Fatalf("network targets = %q, want %q", got, tc.targets)
			}
			if (res.ProtectedPath != "") != tc.protected {
				t.Fatalf("ProtectedPath = %q, want protected=%v", res.ProtectedPath, tc.protected)
			}
			if res.RequiresShellDecision != tc.generic {
				t.Fatalf("RequiresShellDecision = %v (%s), want %v", res.RequiresShellDecision, res.Reason, tc.generic)
			}
		})
	}
}

// The shell writes a negated class as "[!...]". A pattern that uses one is
// matched as the shell expands it, not with "!" taken as a member.
func TestPathGuardReadsShellBracketNegation(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	cases := []struct {
		pattern string
		want    bool
	}{
		{"~/.signer/[!r]*/*", true},
		{"~/.signer/[!r]*", true},
		// A class that excludes the first letter of the protected directory
		// cannot expand to it.
		{"~/.signer/[!k]*/*", false},
	}
	for _, tc := range cases {
		if rule, got := f.guard.MatchPattern(tc.pattern, work); got != tc.want {
			t.Errorf("MatchPattern(%q) = %q, %v; want %v", tc.pattern, rule, got, tc.want)
		}
	}
}
