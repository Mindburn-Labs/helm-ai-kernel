package shellscan

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// shellPattern matches a shell glob with dotglob on, the way a search tool's
// wildcard may match a dot directory.
func shellPattern(g *PathGuard, pattern, cwd string) (string, bool) {
	return g.matchPattern(slashPath(strings.TrimSpace(pattern)), -1, cwd, true)
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
		// "**" spans any number of directories, as globstar and the search
		// tools' glob syntax read it.
		"/**/keys/*":         true,
		"/**/s*.seed":        true,
		"/**/*.go":           false,
		f.home + "/**/*.go":  false,
		f.home + "/**/*":     true,
		f.home + "/**/k*/**": true,
	} {
		if rule, got := shellPattern(f.guard, pattern, work); got != want {
			t.Errorf("shellPattern(%q) = %q, %v; want %v", pattern, rule, got, want)
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
	if _, _, ok := none.MatchSearch(NewSearchCall("/", "")); ok {
		t.Fatal("nil guard matched a search")
	}
	if _, _, ok := (&PathGuard{}).MatchSearch(nil); ok {
		t.Fatal("a guard matched a nil search")
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
		// A word with a brace group is matched on its text before the group:
		// refused when that text is inside protected material or has begun
		// to spell its name.
		"cat ~/.signer/{keys,zz}/*",
		"cp -r ~/.sig{ner,x} /tmp/out",
		// A bracket class is outside the grammar: it is refused where it
		// starts at, inside or above protected material.
		"cat ~/.signer/k[]e]ys/*",
		`cat ~/.signer/k[\e]ys/*`,
		"cat ~/.signer/k[[:alpha:]]ys/*",
		"cat ~/.signer/[!r]*/*",
		"ls ~/[a-z]*",
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
		"cat src/[ab]*.go",
		"cat '~/.signer/k[e]ys/x'",
		"cp ~/.bashrc{,.bak}",
		"mkdir -p src/{api,web}/{lib,test}",
		"echo {a,b}",
		"touch src/f{1..1000}.go",
		"F=~/{.signer,zz}/keys; echo done",
		// Brace groups with an empty alternative, and words of many groups.
		"touch ~/proj/f{1..300}{.go,}",
		"echo {1..300}{,}",
		"echo {1..256}; cp ~/.bashrc{,.bak}",
		"echo {1..256}; ls f{a,}",
		"for i in {1..300}; do echo $i; done",
		"echo {1..1000}",
		`printf '%s\n' {a..z}{a..z}`,
		"touch ~/f{1..300}.txt",
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

// searchOf is a search from root with the given filters.
func searchOf(home, root string, filters ...string) *SearchCall {
	search := NewSearchCall(root, home)
	for _, filter := range filters {
		search.AddFilter(filter)
	}
	return search
}

// braceAlternatives is a brace glob of count alternatives, "{a0,a1,...}",
// followed by last as one more.
func braceAlternatives(count int, last string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "a%d,", i)
	}
	b.WriteString(last)
	b.WriteByte('}')
	return b.String()
}

// Inside the grammar a glob reaches protected material when it can name it
// from where the search starts, at any depth and from any anchoring, or names
// a protected file name anywhere. A filter that names nothing the key
// directory holds is not refused for starting above it.
func TestPathGuardDecidesGlobsInTheGrammar(t *testing.T) {
	f := newGuardFixture(t)
	elsewhere := t.TempDir()
	for _, tc := range []struct {
		root, glob string
		want       bool
	}{
		{f.home, "*.seed", true},
		{f.home, "**/*.seed", true},
		{f.home, "keys/*", true},
		{f.home, ".signer/k*/*", true},
		{f.home, "**/.signer/k*/*", true},
		{f.home, "{*.go,s*.seed}", true},
		{f.home, braceAlternatives(200, "*.s") + "{eed,zz}", true},
		{f.home, "*", true},
		{"/", "**/.signer/keys/*", true},
		{"", "**/.signer/keys/*", true},
		{f.keys, "*", true},
		{elsewhere, "signer.see?", true}, // a copy of a protected file is that file
		{elsewhere, "backup/{signer,other}.seed", true},

		{f.home, "src/**/*.go", false},
		{f.home, "docs/*.md", false},
		{f.home, "*/package.json", false},
		{f.home, "**/*.{ts,tsx}", false},
		{f.home, "keys/*/x", false}, // the key directory holds no directory
		{f.home, ".signer/receipts/*", false},
		{f.home, ".?/keys/*", false}, // a leading ".?" can stand for "..", not for ".signer"
		{"/", "src/*.go", false},
		{"", "src/**/*.go", false},
		{elsewhere, "*", false},
		{elsewhere, "keys/*", false},
		{elsewhere, "*.pub", false},
	} {
		if rule, reason, got := f.guard.MatchSearch(searchOf(f.home, tc.root, tc.glob)); got != tc.want {
			t.Errorf("MatchSearch(%q from %q) = %q (%s), %v; want %v", tc.glob, tc.root, rule, reason, got, tc.want)
		}
	}
	// A path pattern that names its own directory is read from there.
	for _, tc := range []struct {
		root, pattern string
		want          bool
	}{
		{elsewhere, f.home + "/.sig*/k*/*", true},
		{elsewhere, "~/.signer/k*/*", true},
		{filepath.Join(f.home, "project"), "../.sig*/k*/*", true},
		{filepath.Join(f.home, "a", "b"), "*/../../.sig*/k*/*", true},
		{elsewhere, f.keys, true},
		{elsewhere, f.home + "/**/*.go", false},
		{elsewhere, "./src/*.go", false},
	} {
		search := NewSearchCall(tc.root, f.home)
		search.AddPathPattern(tc.pattern)
		if rule, reason, got := f.guard.MatchSearch(search); got != tc.want {
			t.Errorf("MatchSearch(path %q from %q) = %q (%s), %v; want %v", tc.pattern, tc.root, rule, reason, got, tc.want)
		}
	}
}

// An absolute path pattern is read from the directory its literal head names,
// and from "/" when its first segment already has a wildcard, a brace or a
// bracket, as Claude Code's Glob roots it: the search root it was given does
// not change where such a pattern starts.
func TestPathGuardRootsAnAbsolutePatternAtItsLiteralHead(t *testing.T) {
	f := newGuardFixture(t)
	elsewhere := t.TempDir()
	parts := strings.Split(strings.Trim(filepath.ToSlash(f.home), "/"), "/")
	first, rest := parts[0], strings.Join(parts[1:], "/")
	for _, pattern := range []string{
		"/" + strings.TrimSuffix(strings.Repeat("*/", len(parts)), "/") + "/.sig*/k*/*",
		"/" + first[:1] + "*/" + rest + "/.sig*/k*/*",
		"/**/" + parts[len(parts)-1] + "/.sig*/k*/*",
		"/{" + first + ",x}/" + rest + "/.sig*/k*/*",
		"/[" + first[:1] + "]" + first[1:] + "/" + rest + "/.sig*/k*/*",
	} {
		search := NewSearchCall(elsewhere, f.home)
		search.AddPathPattern(pattern)
		if rule, reason, got := f.guard.MatchSearch(search); !got {
			t.Errorf("MatchSearch(path %q from %q) = %q (%s), %v; want it refused", pattern, elsewhere, rule, reason, got)
		}
	}
	for _, pattern := range []string{"/*/" + rest + "/src/**/*.go", "/" + first[:1] + "*/" + rest + "/docs/*.md"} {
		search := NewSearchCall(elsewhere, f.home)
		search.AddPathPattern(pattern)
		if rule, reason, got := f.guard.MatchSearch(search); got {
			t.Errorf("MatchSearch(path %q from %q) = %q (%s); want it passed", pattern, elsewhere, rule, reason)
		}
	}
}

// Outside the grammar a glob is not read. It is refused when the search
// starts at, inside or above protected material, with a reason that names
// what was not read, and otherwise when the search can reach a file with a
// protected name.
func TestPathGuardRefusesAGlobOutsideTheGrammarWhereItCanReach(t *testing.T) {
	f := newGuardFixture(t)
	empty := t.TempDir()
	copies := t.TempDir()
	if err := os.MkdirAll(filepath.Join(copies, "backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copies, "backup", "signer.seed"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		root, glob, construct string
		want                  bool
	}{
		{f.home, "*.see[]d]", `"["`, true},
		{f.home, `*.see\d`, `"\\"`, true},
		{f.home, "!**/node_modules/**", `"!"`, true},
		{f.home, "/.signer/k*/*", `a leading "/"`, true},
		{f.home, "*.seed ", "white space", true},
		{f.home, "{a,b", "never closed", true},
		{f.home, "a}", `"}" outside braces`, true},
		{f.home, "{a}", "one alternative", true},
		{f.home, "{a,{b,{c,{d,{e,f}}}}}.go", "nested deeper", true},
		{f.home, "src/../.signer/*", `".."`, true},
		{f.home, "a**b", `"**" inside`, true},
		{f.data, "[a-z]*", `"["`, true},
		{filepath.Join(f.data, "receipts"), "[a-z]*", `"["`, true},
		{"", "[a-z]*", `"["`, true},
		{copies, `*.see\d`, "a copy of HELM signing material", true},
		{empty, "*.see[]d]", "", false},
		{empty, "!**/node_modules/**", "", false},
		{filepath.Join(empty, "absent"), "[ab]*", "", false},
	} {
		rule, reason, got := f.guard.MatchSearch(searchOf(f.home, tc.root, tc.glob))
		if got != tc.want || !strings.Contains(reason, tc.construct) {
			t.Errorf("MatchSearch(%q from %q) = %q (%s), %v; want %v naming %s", tc.glob, tc.root, rule, reason, got, tc.want, tc.construct)
		}
	}
}

// A glob selects credential files by the rules SecretReadPath uses: inside
// the grammar when it can name one, outside it when the search can reach one.
func TestSearchCallSecretReadDecidesByReach(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".env"), []byte("TOKEN=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	for _, tc := range []struct {
		root, glob string
		want       bool
	}{
		{empty, ".env", true},
		{empty, "**/.en*", true},
		{empty, "*.pem", true},
		{empty, "{a,.env}", true},
		{empty, "**/id_rsa", true},
		{project, ".en[]v]", true},
		{project, `.en\v`, true},
		{project, "{.e[n]v,[}]}", true},
		// A credential file inside a directory is selected by a glob that
		// names the directory, or one whose "**" can stand for it.
		{empty, "**/*.json", true},
		{empty, ".docker/*.json", true},
		{empty, "*/config", true},
		{empty, "**/gcloud/*.db", true},
		{empty, ".ssh/*", true},
		{empty, "*/credentials", true},

		{empty, "*.json", false},
		{empty, "*.db", false},
		{empty, "*config", false},
		{empty, "config.json", false},
		{empty, "credentials", false},
		{empty, "gcloud/*.db", false},
		// A last segment that selects files in general is not aimed at one,
		// whatever directory the glob names.
		{empty, ".docker/*", false},
		{empty, ".env.example", false},
		{empty, "*.pub", false},
		{empty, "**/*.go", false},
		{empty, "*", false},
		{empty, "*.md", false},
		{empty, ".en[]v]", false},
		{empty, `.en\v`, false},
	} {
		if glob, reason, got := searchOf("", tc.root, tc.glob).SecretRead(); got != tc.want {
			t.Errorf("SecretRead(%q from %q) = %q (%s), %v; want %v", tc.glob, tc.root, glob, reason, got, tc.want)
		}
	}
}

// The globs of one call share one budget of alternatives and bytes. Past it
// the call is refused as reaching trust material without being expanded, and
// the work one call costs stays bounded however many globs it sends.
func TestSearchCallSharesOneBudgetAcrossItsGlobs(t *testing.T) {
	f := newGuardFixture(t)
	empty := t.TempDir()
	for _, tc := range []struct {
		name  string
		globs []string
		over  bool
	}{
		{"alternatives of one glob", []string{braceAlternatives(MaxSearchGlobAlternatives, "x")}, true},
		{"alternatives of two globs", []string{braceAlternatives(150, "x"), braceAlternatives(150, "y")}, true},
		{"bytes of two globs", []string{strings.Repeat("a", MaxSearchGlobBytes/2) + "*", strings.Repeat("b", MaxSearchGlobBytes/2) + "*"}, true},
		{"bytes of a brace expansion", []string{"{" + strings.Repeat("a", MaxSearchGlobBytes/3) + "," + strings.Repeat("b", MaxSearchGlobBytes/3) + "}{c,d}"}, true},
		{"globs outside the grammar count too", strings.Split(strings.Repeat("[x],", MaxSearchGlobAlternatives+1), ",")[:MaxSearchGlobAlternatives+1], true},
		{"bytes of globs outside the grammar", []string{"[" + strings.Repeat("a", MaxSearchGlobBytes/2), "[" + strings.Repeat("b", MaxSearchGlobBytes/2)}, true},
		{"under the budget", []string{braceAlternatives(100, "x"), braceAlternatives(100, "y"), strings.Repeat("c", MaxSearchGlobBytes/4)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			search := searchOf(f.home, empty, tc.globs...)
			rule, _, matched := f.guard.MatchSearch(search)
			_, _, secret := search.SecretRead()
			if over := matched && rule == UnexpandableSearchGlob; over != tc.over || secret != tc.over {
				t.Fatalf("MatchSearch = %q, %v; SecretRead = %v; want over budget %v", rule, matched, secret, tc.over)
			}
		})
	}
}

// generousBound is the most time a decision the tests time may take. The
// allocation bounds are what pin the work down; the time bound only has to
// catch a decision that has gone super-linear again (those took 30 s and more
// under the reviews' load), while leaving a wide margin for a loaded machine,
// where 250 ms has been exceeded by work that is linear. The hook's own
// deadline is 10 s.
const generousBound = 3 * time.Second

// A budget-sized call is decided at once, in bounded memory. Past the budget
// it is refused as reaching trust material and as a secret read; a glob
// nested past the grammar is refused above the data directory.
func TestPathGuardDecidesALargeSearchInBoundedTimeAndMemory(t *testing.T) {
	f := newGuardFixture(t)
	var many []string
	for size := 0; size < 4<<20; {
		glob := braceAlternatives(255, fmt.Sprintf("g%d.go", len(many)))
		many = append(many, glob)
		size += len(glob)
	}
	for _, tc := range []struct {
		name       string
		globs      []string
		overBudget bool
	}{
		{"1 MiB of two-way groups", []string{strings.Repeat("{a,b}", (1<<20)/5)}, true},
		{"one group of many alternatives", []string{braceAlternatives(20000, "x")}, true},
		{"deeply nested groups", []string{strings.Repeat("{a,", 4000) + strings.Repeat("}", 4000)}, false},
		{"4 MiB of distinct globs of 255 alternatives", many, true},
		{"a 4 MiB glob", []string{strings.Repeat("a/", 2<<20)}, true},
		{"few, long alternatives", []string{"{" + strings.Repeat("a", 512<<10) + "," + strings.Repeat("b", 512<<10) + "}" + strings.Repeat("{x,y}", 7)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			search := searchOf(f.home, f.home, tc.globs...)
			rule, _, matched := f.guard.MatchSearch(search)
			_, _, secret := search.SecretRead()
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if !matched || (rule == UnexpandableSearchGlob) != tc.overBudget || secret != tc.overBudget {
				t.Fatalf("MatchSearch = %q, %v; SecretRead = %v; want refused, over budget %v", rule, matched, secret, tc.overBudget)
			}
			if elapsed > generousBound {
				t.Fatalf("deciding the search took %s, want under %s", elapsed, generousBound)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
				t.Fatalf("deciding the search allocated %d bytes, want at most 16 MiB", allocated)
			}
		})
	}
}

// "**" matches no directory as well as any number of them.
func TestPathGuardReadsDoubleStarAsZeroOrMoreDirectories(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	if rule, got := shellPattern(f.guard, filepath.Dir(f.policy)+"/**/policy.json", work); !got {
		t.Fatalf("shellPattern(<dir>/**/policy.json) = %q, %v; want the policy file", rule, got)
	}
	if _, _, got := f.guard.MatchSearch(searchOf(f.home, filepath.Dir(f.policy), "**/**/policy.json")); !got {
		t.Fatal("a search filter **/**/policy.json did not reach the policy file")
	}
}

// A long pattern is compared by the segments a target can hold, so its
// length costs little and changes nothing.
func TestPathGuardDecidesALongPatternByItsLastSegments(t *testing.T) {
	f := newGuardFixture(t)
	start := time.Now()
	if rule, got := shellPattern(f.guard, strings.Repeat("/zz*", 4097), t.TempDir()); got {
		t.Fatalf("a pattern of 4097 segments matched %q", rule)
	}
	if _, _, got := f.guard.MatchSearch(searchOf(f.home, f.home, strings.Repeat("x/", 4000)+".signer/keys/*")); !got {
		t.Fatal("a filter of many leading directories did not reach the key directory")
	}
	if elapsed := time.Since(start); elapsed > generousBound {
		t.Fatalf("long patterns took %s, want under %s", elapsed, generousBound)
	}
}

// A wildcard aimed into a protected directory matches when it can name a file
// the directory holds, not only a protected name.
func TestPathGuardListsTheProtectedDirectory(t *testing.T) {
	f := newGuardFixture(t)
	if err := os.WriteFile(filepath.Join(f.keys, "extra.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if rule, got := shellPattern(f.guard, "~/.signer/k*/*.bin", work); !got {
		t.Fatalf("shellPattern(~/.signer/k*/*.bin) = %q, %v; want the file in the key directory", rule, got)
	}
	if rule, got := shellPattern(f.guard, "~/.signer/k*/*.absent", work); got {
		t.Fatalf("shellPattern(~/.signer/k*/*.absent) = %q, %v; want no match", rule, got)
	}
	if _, _, got := f.guard.MatchSearch(searchOf(f.home, f.home, "*.bin")); !got {
		t.Fatal("a filter for the extra file did not reach it")
	}
}

// A walk the guard cannot finish, because the root cannot be read or the call
// has more roots than the guard walks, cannot show that a glob outside the
// grammar misses everything: the search is refused.
func TestSearchCallRefusesWhatItCannotWalk(t *testing.T) {
	f := newGuardFixture(t)
	unreadable := t.TempDir()
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
	if _, err := os.ReadDir(unreadable); err == nil {
		t.Skip("running with permissions that read any directory")
	}
	search := searchOf(f.home, unreadable, "[a]*")
	if rule, reason, got := f.guard.MatchSearch(search); !got || rule != UnexpandableSearchGlob {
		t.Fatalf("MatchSearch of an unreadable root = %q (%s), %v; want it refused", rule, reason, got)
	}
	if _, _, got := search.SecretRead(); !got {
		t.Fatal("SecretRead of an unreadable root did not refuse")
	}
	many := NewSearchCall(t.TempDir(), f.home)
	for i := 0; i <= maxReachWalks; i++ {
		many.AddPathPattern(t.TempDir() + "/[a]*")
	}
	if rule, reason, got := f.guard.MatchSearch(many); !got || rule != UnexpandableSearchGlob {
		t.Fatalf("MatchSearch over %d roots = %q (%s), %v; want it refused", maxReachWalks+1, rule, reason, got)
	}
}

// A shell word is decided in time linear in its length. A segment longer
// than any file name is not matched name by name: the word is refused when it
// starts at, inside or above protected material, and passes otherwise. The
// guard may cost a small multiple of what classifying the same command
// without it costs, measured at the same moment so that load on the machine
// slows both; before this bound it cost a thousand times more.
func TestClassifyDecidesALongShellWordInBoundedTime(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	for _, tc := range []struct {
		name, command string
		protected     bool
	}{
		{"unclosed brackets elsewhere", "cat /tmp/*" + strings.Repeat("[", 1<<20), false},
		{"unclosed brackets above protected material", "cat ~/*" + strings.Repeat("[", 1<<20), true},
		{"a long segment elsewhere", "cat /tmp/*" + strings.Repeat("a", 1<<20), false},
		{"a long segment inside the data directory", "cat ~/.signer/*" + strings.Repeat("a", 1<<20), true},
		{"many double stars", "cat /tmp/" + strings.Repeat("**/", 1<<19) + "x", false},
		{"a long word after a brace sequence", "cat /tmp/{1..256}" + strings.Repeat("a", 1<<20), false},
		{"a long word after many brace groups", "cat /tmp/" + strings.Repeat("{a,b}", 8) + strings.Repeat("a", 1<<20), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			ClassifyAt(tc.command, work)
			unguarded := time.Since(start)
			bound := 10*unguarded + time.Second
			done := make(chan Result, 1)
			start = time.Now()
			go func() { done <- ClassifyAt(tc.command, work, WithPathGuard(f.guard)) }()
			select {
			case res := <-done:
				if (res.ProtectedPath != "") != tc.protected {
					t.Fatalf("ProtectedPath = %q, want protected %v", res.ProtectedPath, tc.protected)
				}
				if elapsed := time.Since(start); elapsed > bound {
					t.Fatalf("deciding the word took %s with the guard and %s without it, want under %s", elapsed, unguarded, bound)
				}
			case <-time.After(2 * bound):
				t.Fatalf("the word was not decided within %s; without the guard it took %s", 2*bound, unguarded)
			}
		})
	}
}

// A stopped guard ends every decision at once as a refusal, a walk of a
// search root included, so a classifier past its deadline stops instead of
// running on.
func TestPathGuardStopEndsEveryDecisionAsARefusal(t *testing.T) {
	f := newGuardFixture(t)
	work := t.TempDir()
	search := searchOf(f.home, work, "[a]*.go")
	if _, _, got := f.guard.MatchSearch(search); got {
		t.Fatal("a search that reaches nothing was refused before the guard was stopped")
	}
	f.guard.Stop()
	if rule, got := f.guard.Match(filepath.Join(work, "main.go"), work); !got || rule != stoppedRule {
		t.Fatalf("Match after Stop = %q, %v; want %q", rule, got, stoppedRule)
	}
	if rule, _, got := f.guard.MatchSearch(searchOf(f.home, work, "*.go")); !got || rule != stoppedRule {
		t.Fatalf("MatchSearch after Stop = %q, %v; want %q", rule, got, stoppedRule)
	}
	if res := ClassifyAt("cat README.md", work, WithPathGuard(f.guard)); res.ProtectedPath != stoppedRule {
		t.Fatalf("ClassifyAt after Stop reported %q, want %q", res.ProtectedPath, stoppedRule)
	}
	// The walk a glob outside the grammar needs stops too, and a walk that
	// did not finish is refused.
	fresh := searchOf(f.home, work, "[a]*.go")
	_, _, _ = f.guard.MatchSearch(fresh)
	if _, reason, got := fresh.SecretRead(); !got || !strings.Contains(reason, reachTooLarge) {
		t.Fatalf("SecretRead after Stop = %v (%s); want the unfinished walk refused", got, reason)
	}
}

// An MCP tool's pattern may be a path pattern or a regular expression. In
// the grammar it is decided as a path pattern; outside it, it is a regular
// expression: refused where the search starts at, inside or above protected
// material, and otherwise neither walked for nor refused.
func TestSearchCallReadsAPatternOutsideTheGrammarAsARegex(t *testing.T) {
	f := newGuardFixture(t)
	copies := t.TempDir()
	if err := os.WriteFile(filepath.Join(copies, "signer.seed"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unreadable := t.TempDir()
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
	for _, tc := range []struct {
		root, pattern string
		want          bool
	}{
		{f.home, "foo|bar", true},
		{f.home, "**/*.seed", true},
		{copies, "**/*.seed", true},
		{unreadable, "foo|bar", false},
		{unreadable, `\bTODO\b`, false},
		{copies, "sig.*seed", false},
	} {
		search := NewSearchCall(tc.root, f.home)
		search.AddPatternOrRegex(tc.pattern)
		rule, reason, got := f.guard.MatchSearch(search)
		_, _, secret := search.SecretRead()
		if got != tc.want || secret {
			t.Errorf("MatchSearch(pattern %q from %q) = %q (%s), %v, secret read %v; want %v and no secret read", tc.pattern, tc.root, rule, reason, got, secret, tc.want)
		}
	}
}
