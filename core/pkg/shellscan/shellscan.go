package shellscan

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Signal names recorded during classification. Signals are audit metadata for
// the decision receipt; they never grant anything by themselves.
const (
	SignalParseError            = "parse-error"
	SignalCommandSubstitution   = "command-substitution"
	SignalChaining              = "command-chaining"
	SignalRedirect              = "redirect"
	SignalEncodedWrapper        = "encoded-wrapper"
	SignalPathObfuscation       = "path-obfuscation"
	SignalPrivilegeWrapper      = "privilege-wrapper"
	SignalEnvWrapper            = "env-wrapper"
	SignalEvalWrapper           = "eval-wrapper"
	SignalShellInvocation       = "shell-invocation"
	SignalInterpreterInvocation = "interpreter-invocation"
	SignalSensitiveRedirect     = "sensitive-redirect"
	SignalSensitiveTarget       = "sensitive-target"
	SignalSensitiveDestructive  = "sensitive-destructive"
	SignalANSICQuoting          = "ansi-c-quoting"
	SignalBraceExpansion        = "brace-expansion"
	SignalGlobCommand           = "glob-command-word"
)

// maxWrapperDepth bounds recursive unwrapping of eval / sh -c payloads so
// adversarial nesting cannot exhaust the classifier.
const maxWrapperDepth = 8

// Command is one statically classified command node from the parsed AST.
type Command struct {
	Name    string   // basename of the command word (after wrapper unwrapping)
	Tokens  []string // statically resolved tokens (empty segments mark dynamic words)
	Prefix  string   // arity-aware prefix, e.g. "git checkout"
	Via     string   // wrapper chain this command was reached through ("" = direct)
	Dynamic bool     // true when any token could not be resolved statically

	// dynamic marks, per token, the ones that were not resolved statically.
	dynamic []bool
}

// EffectFact is a static-syntax indicator that callers can route to its
// governed policy class; it is not evidence that a runtime effect occurred.
// Target is intentionally raw in memory only; receipt writers must bind it
// before persistence.
type EffectFact struct {
	Class  string
	Action string
	Target string
	Reason string
}

// Result is the advisory classification of one raw shell command string.
type Result struct {
	// Decide is true when the command must be routed through the kernel's
	// signed decision path instead of passing through unclassified.
	Decide   bool
	Reason   string
	ParseOK  bool
	Commands []Command
	Signals  []string
	// RequiresShellDecision distinguishes an existing generic shell decision
	// from a recognized effect fact. It prevents callers from widening a
	// network or secret-read fact back into shell-operate by default.
	RequiresShellDecision bool
	// EffectFacts are additive AST-derived network and secret-read facts.
	// Callers must not persist Fact.Target verbatim.
	EffectFacts []EffectFact
	// SensitiveTarget is the static sensitive target that caused routing to
	// the signed decision path. Callers must avoid persisting it verbatim.
	SensitiveTarget string
	// RequiresShellPermission is true when a statically identified sensitive
	// target is combined with a concrete destructive shell effect. Consumers
	// must require shell permission in addition to the sensitive-file write.
	RequiresShellPermission bool
	// ProtectedPath is the first reference to material the caller's PathGuard
	// protects, or empty. It is set whatever command or syntax carried the
	// reference, and no effect class describes it: the caller refuses.
	ProtectedPath string
}

// legacyNeedles is the pre-AST substring list from hook_cmd.go, kept verbatim
// as a fallback layer so existing classification behavior is strictly
// preserved (the AST layer only ever adds detection).
var legacyNeedles = []string{
	"rm -rf ",
	"rm -fr ",
	"rm -r ",
	"git reset --hard",
	"git clean -fd",
	"git clean -xdf",
	"mkfs",
	"dd if=",
	"kubectl delete",
	"docker rm -f",
	"drop table",
	"truncate table",
}

// sensitiveFileRules match anywhere in a normalized write target: private
// keys and credentials, and shell or tool startup files that run code when
// rewritten. The hook's Write-tool path uses the same rules through
// SensitiveWriteTarget, so a shell write cannot bypass that protection.
var sensitiveFileRules = []string{
	".env",
	".pem",
	".key",
	".p12",
	".pfx",
	"id_rsa",
	"id_dsa",
	"id_ecdsa",
	"id_ed25519",
	"authorized_keys",
	".netrc",
	".curlrc",
	".wgetrc",
	".npmrc",
	".pypirc",
	".gitconfig",
	".bashrc",
	".bash_profile",
	".bash_login",
	".profile",
	".zshrc",
	".zshenv",
	".zprofile",
	".zlogin",
	".mcp.json",
	".claude.json",
	"managed-settings.json",
}

// sensitivePathRules match the normalized write target resolved against the
// working directory: repository internals, agent hook and client
// configuration, credential directories, and scheduler, privilege and
// autostart locations.
var sensitivePathRules = []string{
	".git/",
	".ssh/",
	".claude/settings.json",
	".claude/settings.local.json",
	".codex/hooks.json",
	".codex/config.toml",
	".hermes/config.yaml",
	".dsh/hooks.json",
	".dsh/cordis.patch.yml",
	".aws/credentials",
	".aws/config",
	".kube/config",
	".docker/config.json",
	".config/gcloud/",
	".config/git/config",
	".config/curlrc",
	".config/fish/config.fish",
	".config/systemd/",
	".config/autostart/",
	"library/launchagents/",
	"library/launchdaemons/",
	"start menu/programs/startup/",
	"/etc/profile",
	"/etc/cron",
	"/var/spool/cron/",
	"/usr/lib/cron/",
	"/etc/sudoers",
}

// SensitiveWriteTarget reports whether writing target could rewrite
// credentials, agent hook or client configuration, or a file that runs code
// at login, on a schedule or with privilege, and returns the matching rule.
// Matching is case-insensitive and runs on the normalized path: backslashes
// become slashes and ".", ".." and "//" segments are cleaned, so alternate
// spellings of one file match alike. Where a backslash is a byte of a file
// name, the path is also matched with its backslashes kept. Path rules also
// see the target resolved against cwd, so a relative write made inside a
// protected directory matches.
func SensitiveWriteTarget(target, cwd string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	cwd = strings.TrimSpace(cwd)
	if rule, ok := sensitiveWriteSpelling(slashPath(target), slashPath(cwd)); ok {
		return rule, true
	}
	// Where a backslash is a byte of a file name, ".." beside one is not a
	// parent directory: the path as the filesystem reads it is matched too.
	if native := nativePath(target); native != slashPath(target) || nativePath(cwd) != slashPath(cwd) {
		return sensitiveWriteSpelling(native, nativePath(cwd))
	}
	return "", false
}

func sensitiveWriteSpelling(target, cwd string) (string, bool) {
	cleaned := path.Clean(target)
	lower := strings.ToLower(cleaned)
	for _, rule := range sensitiveFileRules {
		if strings.Contains(lower, rule) {
			return rule, true
		}
	}
	resolved := cleaned
	if cwd != "" && !path.IsAbs(cleaned) {
		resolved = path.Join(cwd, cleaned)
	}
	// Wrapping in slashes lets a directory rule such as ".git/" match the
	// directory itself as well as anything below it.
	wrapped := "/" + strings.ToLower(resolved) + "/"
	for _, rule := range sensitivePathRules {
		if strings.Contains(wrapped, rule) {
			return rule, true
		}
	}
	return "", false
}

func slashPath(value string) string {
	return strings.ReplaceAll(value, `\`, "/")
}

// nativePath keeps a path as the local filesystem reads it. A backslash
// separates components only on Windows; elsewhere it is a byte of a file name,
// and rewriting it would resolve a different file from the one a tool opens.
func nativePath(value string) string {
	if filepath.Separator == '\\' {
		return slashPath(value)
	}
	return value
}

// Option adjusts one classification.
type Option func(*collector)

// WithEnvironment classifies the command as run with environ, the
// NAME=value entries of an environment it inherits: a proxy set there is a
// destination of every network command, and a variable that changes how a
// client connects, or what a shell runs first, makes the destinations
// undetermined. The command line's own assignments still apply after it.
func WithEnvironment(environ []string) Option {
	return func(c *collector) {
		for _, entry := range environ {
			if name, value, ok := strings.Cut(entry, "="); ok && tracksVariable(name) {
				c.env = append(c.env, envOverride{name: name, value: value})
			}
		}
	}
}

// WithPathGuard makes the classifier report, in Result.ProtectedPath, any
// reference to the material guard protects.
func WithPathGuard(guard *PathGuard) Option {
	return func(c *collector) {
		c.guard = guard
		if guard != nil {
			c.home = guard.home
		}
	}
}

// Classify parses and structurally classifies a raw shell command string.
// Fail-closed: anything the classifier cannot statically understand in a
// security-relevant position is decision-worthy, never safe.
func Classify(raw string) Result {
	return ClassifyAt(raw, "")
}

// ClassifyAt parses and structurally classifies a raw shell command string in
// cwd. Relative paths written and later executed in the same command are
// normalized against cwd before their generated-source relationship is tested.
func ClassifyAt(raw, cwd string, opts ...Option) Result {
	if strings.TrimSpace(raw) == "" {
		return Result{ParseOK: true}
	}
	c := newCollector(cwd, opts)
	// Fallback layer: legacy substring needles on the raw text.
	if needle := legacyNeedleHit(raw); needle != "" {
		c.decide(fmt.Sprintf("legacy needle %q", needle))
	}
	// dotglob and zsh's globdots let a wildcard match a leading dot.
	c.dotGlob = strings.Contains(raw, "dotglob") || strings.Contains(strings.ToLower(raw), "globdots")
	c.guardText(raw)
	c.classifyString(raw, "", 0)
	return c.result()
}

// ClassifyArgvAt classifies a command that will be executed directly from
// argv, with no shell in between: every element is a literal argument. A
// program in argv that is itself a shell or a wrapper is unwrapped as in
// ClassifyAt.
func ClassifyArgvAt(argv []string, cwd string, opts ...Option) Result {
	if len(argv) == 0 {
		return Result{ParseOK: true}
	}
	c := newCollector(cwd, opts)
	if needle := legacyNeedleHit(strings.Join(argv, " ")); needle != "" {
		c.decide(fmt.Sprintf("legacy needle %q", needle))
	}
	args := make([]wordTok, 0, len(argv))
	for _, arg := range argv {
		args = append(args, wordTok{text: arg})
		if c.protectedPath == "" {
			if rule, ok := c.guard.Match(arg, c.cwd); ok {
				c.protectedPath = rule
			}
		}
	}
	c.classifyTokens(args, "", 0)
	return c.result()
}

func newCollector(cwd string, opts []Option) *collector {
	if cwd != "" {
		cwd = path.Clean(cwd)
	}
	c := &collector{parseOK: true, cwd: cwd}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *collector) result() Result {
	effectFacts, factCrossesIndirection := classifyEffectFacts(c.commands, c.facts, c.env)
	if len(effectFacts) > 0 && (c.hasIndirection || factCrossesIndirection) {
		// Parsed syntax can identify a potential effect, but it cannot prove
		// runtime execution across expansion, eval, wrappers, or functions.
		// Preserve the generic path for that uncertainty instead of upgrading
		// the fact into a runtime claim.
		c.decide("shell effect crosses an indirection boundary (fail-closed)")
	}
	res := Result{
		Decide:                  c.decideFlag || len(effectFacts) > 0 || c.protectedPath != "",
		Reason:                  strings.Join(c.reasons, "; "),
		ParseOK:                 c.parseOK,
		Commands:                c.commands,
		Signals:                 c.signalList(),
		RequiresShellDecision:   c.decideFlag,
		EffectFacts:             effectFacts,
		SensitiveTarget:         c.sensitiveTarget,
		RequiresShellPermission: c.requiresShellPermission,
		ProtectedPath:           c.protectedPath,
	}
	if res.Reason == "" && len(effectFacts) > 0 {
		res.Reason = effectFacts[0].Reason
	}
	return res
}

// guardText checks free text, and guardWord one shell word, against the
// caller's PathGuard. The first reference found is kept.
func (c *collector) guardText(text string) {
	if c.protectedPath != "" {
		return
	}
	if rule, ok := c.guard.MatchText(text); ok {
		c.protectedPath = rule
	}
}

// maxGuardedScriptBytes bounds how much of a script file guardScript reads.
const maxGuardedScriptBytes = 1 << 20

// guardScript checks a script file that is about to be run for a reference to
// protected material. The script was written by a call that named only its
// own path, so its content is the first place the reference can be seen. The
// check is textual and the file can change before it runs: it catches the
// plain form, not a path the script computes.
func (c *collector) guardScript(script string) {
	if c.guard == nil || c.protectedPath != "" || script == "" {
		return
	}
	if !path.IsAbs(slashPath(script)) && (c.cwd == "" || c.cwdUnknown) {
		return
	}
	//nolint:gosec // G304: reading the script the caller is about to execute is the purpose; the content is only searched.
	file, err := os.Open(c.normalizedPath(script))
	if err != nil {
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxGuardedScriptBytes))
	if err != nil {
		return
	}
	c.guardText(string(content))
}

func (c *collector) guardWord(word *syntax.Word) {
	if c.guard == nil || c.protectedPath != "" {
		return
	}
	pattern, dynamicAt := guardWordPattern(word, c.home)
	cwd := c.cwd
	if c.cwdUnknown {
		cwd = ""
	}
	match := func(pattern string, dynamicAt int) bool {
		if rule, ok := c.guard.matchPattern(pattern, dynamicAt, cwd, c.dotGlob); ok {
			c.protectedPath = rule
			return true
		}
		// A working directory written with backslashes is also read with
		// them as separators, as it was before they were kept as name bytes.
		if converted := slashPath(cwd); converted != nativePath(cwd) {
			if rule, ok := c.guard.matchPattern(pattern, dynamicAt, converted, c.dotGlob); ok {
				c.protectedPath = rule
				return true
			}
		}
		return false
	}
	if match(pattern, dynamicAt) {
		return
	}
	// The value attached to a long option (--file=$HOME/input) is a path the
	// whole word hides. The option name must be literal text. The shell
	// expands a glob over the whole word, not over the value, so the value's
	// own text is matched literally.
	split := strings.IndexByte(pattern, '=')
	if split < 0 || split+1 >= len(pattern) || dynamicAt >= 0 && dynamicAt <= split || !strings.HasPrefix(unescapeLit(pattern[:split]), "--") || split < 3 {
		return
	}
	if dynamicAt < 0 {
		match(globEscape(unescapeLit(pattern[split+1:])), -1)
		return
	}
	known := globEscape(unescapeLit(pattern[split+1 : dynamicAt]))
	match(known+pattern[dynamicAt:], len(known))
}

// guardOptionPaths extracts values using the same option grammar as egress
// classification. A whole word such as -T/tmp/upload is not a filesystem
// path: only /tmp/upload can resolve through a symlink to protected material.
// This runs when recording a command, so shell, argv and unwrapped calls use
// the command's effective working directory.
func (c *collector) guardOptionPaths(command Command) {
	if c.guard == nil || c.protectedPath != "" || len(command.Tokens) < 2 {
		return
	}
	var spec cliSpec
	switch command.Name {
	case "curl":
		spec = curlSpec
	case "wget":
		spec = wgetSpec
	case "ssh":
		spec = sshSpec
	case "scp":
		spec = scpSpec
	case "sftp":
		spec = sftpSpec
	}
	cwd := c.cwd
	if c.cwdUnknown {
		cwd = ""
	}
	check := func(value string) {
		if c.protectedPath != "" || value == "" {
			return
		}
		if rule, ok := c.guard.Match(value, cwd); ok {
			c.protectedPath = rule
		}
	}
	if spec.value == nil {
		// A command without an option table: the value attached to a long
		// option (--files-from=FILE, --output=FILE) is a path the whole
		// word hides. A separate value is a word of its own, checked as one.
		for _, token := range command.Tokens[1:] {
			if _, value, attached := strings.Cut(token, "="); attached && strings.HasPrefix(token, "--") {
				check(value)
			}
		}
		return
	}
	// A download without a named output file is written under a name the
	// client takes from the URL. Curl saves that file, and one --output
	// names, below the directory --output-dir gives; wget saves the file it
	// names itself below --directory-prefix.
	var urls, outputs, outputDirs []string
	impliedNames := command.Name == "wget"
	walkCLI(spec, command.Tokens[1:], cliVisitor{
		option: func(name string, _ optRole, value string) {
			check(value)
			switch command.Name + " " + name {
			case "curl remote-name", "curl remote-name-all":
				impliedNames = true
			case "curl url":
				urls = append(urls, value)
			case "curl output-dir", "wget directory-prefix":
				outputDirs = append(outputDirs, value)
			case "curl output":
				outputs = append(outputs, value)
			case "wget output-document":
				impliedNames = false
			case "wget default-page":
				outputs = append(outputs, value) // the name saved for a URL that names none
			case "curl cert", "curl proxy-cert":
				// file[:password]. The file as curl reads it, and, because
				// its Windows build keeps a drive colon, every prefix that
				// ends at a colon.
				check(curlCertFile(value))
				for index := 0; index < len(value); index++ {
					if value[index] == ':' {
						check(strings.ReplaceAll(value[:index], `\:`, ":"))
					}
				}
			}
			if command.Name == "curl" {
				check(curlAtPath(value))
				if name == "data-urlencode" || name == "url-query" {
					check(curlEncodedFilePath(name, value))
				}
				if name == "form" {
					paths, _ := curlFormPaths(value)
					for _, path := range paths {
						check(path)
					}
				}
				if name == "write-out" {
					for _, path := range curlWriteOutPaths(value) {
						check(path)
					}
				}
			}
		},
		operand: func(token string) {
			if command.Name == "curl" || command.Name == "wget" {
				urls = append(urls, token)
			}
		},
		invalid: func(string) {}, // The egress classifier owns invalid-option refusal.
	})
	if impliedNames {
		for _, raw := range urls {
			outputs = append(outputs, downloadFileNames(command.Name, raw)...)
		}
	}
	// Which directory applies to which transfer is not modelled (curl --next
	// starts a transfer without one, and an empty directory means none):
	// every name is checked in the working directory and below every
	// directory the command gives. Curl joins the two even when the name is
	// absolute.
	for _, name := range outputs {
		check(name)
		for _, dir := range outputDirs {
			check(strings.TrimRight(dir, "/") + "/" + name)
		}
	}
}

// curlCertFile is the file part of a curl cert[:password] value as curl
// parses it outside Windows: `\\` is a backslash, `\:` a colon, any other
// backslash is kept, and the file ends at the first colon left. A value with
// neither character, or a pkcs11: URI, is the file as written.
func curlCertFile(value string) string {
	if !strings.ContainsAny(value, `:\`) || strings.HasPrefix(value, "pkcs11:") {
		return value
	}
	var file strings.Builder
	for index := 0; index < len(value); index++ {
		switch {
		case value[index] == ':':
			return file.String()
		case value[index] == '\\' && index+1 < len(value) && (value[index+1] == '\\' || value[index+1] == ':'):
			index++
			file.WriteByte(value[index])
		default:
			file.WriteByte(value[index])
		}
	}
	return file.String()
}

// urlAfterScheme drops "scheme://" from a URL. The separator counts only
// before the first "/", "?" or "#": later it is part of the path or query.
func urlAfterScheme(raw string) string {
	if index := strings.Index(raw, "://"); index >= 0 && !strings.ContainsAny(raw[:index], "/?#") {
		return raw[index+len("://"):]
	}
	return raw
}

// downloadFileNames lists the names a client may give the file it saves a
// URL to when the command line names none: the last segment of the URL path,
// as written and percent-decoded, and the client's name for an empty one.
// Wget appends the query. Curl also splits the segment at a backslash.
func downloadFileNames(tool, raw string) []string {
	rest, _, _ := strings.Cut(urlAfterScheme(raw), "#")
	rest, query, hasQuery := strings.Cut(rest, "?")
	segment := ""
	if index := strings.IndexByte(rest, '/'); index >= 0 {
		segment = rest[index+1:]
		segment = segment[strings.LastIndexByte(segment, '/')+1:]
	}
	names := []string{segment}
	if decoded, err := url.PathUnescape(segment); err == nil && decoded != segment {
		names = append(names, decoded)
	}
	if tool == "curl" {
		if index := strings.LastIndexByte(segment, '\\'); index >= 0 {
			names = append(names, segment[index+1:])
		}
		if segment == "" {
			names = append(names, "curl_response")
		}
		return names
	}
	if segment == "" {
		names = []string{"index.html"}
	}
	if hasQuery {
		// The query follows the name, as written and as wget decodes it
		// (a decoded "/" stays escaped).
		queries := []string{query}
		if decoded, err := url.PathUnescape(query); err == nil && decoded != query {
			queries = append(queries, strings.ReplaceAll(decoded, "/", "%2F"))
		}
		for _, name := range names {
			for _, suffix := range queries {
				names = append(names, name+"?"+suffix)
			}
		}
	}
	// --adjust-extension adds the suffix of the type the server reports.
	for _, name := range names {
		names = append(names, name+".html", name+".css")
	}
	return names
}

var transferReadCommands = map[string]bool{
	"cp":    true,
	"rsync": true,
	"scp":   true,
}

var secretReadPathNeedles = []string{
	".env",
	".pem",
	".p12",
	".key",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	".ssh/",
	".aws/credentials",
	".config/gcloud",
	".kube/config",
	".netrc",
	".npmrc",
	".pypirc",
	".docker/config.json",
}

// fileReaderCommands print or search the files they are given, so every
// operand of theirs is a path, including one with spaces in it.
var fileReaderCommands = map[string]bool{
	".": true, "awk": true, "cat": true, "egrep": true, "fgrep": true, "gawk": true,
	"grep": true, "head": true, "less": true, "mawk": true, "more": true, "nawk": true,
	"sed": true, "source": true, "tail": true,
}

// nonDisclosingCommands take a path without revealing what the file holds:
// they list, test, create, remove or re-permission it. Every other command
// given a credential path is treated as reading it, because a list of the
// programs that can read a file is never complete.
var nonDisclosingCommands = map[string]bool{
	"[": true, "basename": true, "cd": true, "chgrp": true, "chmod": true, "chown": true,
	"dirname": true, "echo": true, "ls": true, "mkdir": true, "popd": true, "printf": true,
	"pushd": true, "readlink": true, "realpath": true, "rm": true, "rmdir": true,
	"stat": true, "test": true, "touch": true, "unlink": true,
}

// secretGlobSamples are credential files as a search finds them, at least one
// for each rule in secretReadPathNeedles, so a glob can be asked whether it
// selects one.
var secretGlobSamples = []string{
	".env", ".env.local", "server.pem", "cert.p12", "tls.key", "id_rsa", "id_ed25519", "id_ecdsa",
	".ssh/id_rsa", ".ssh/config", ".aws/credentials", ".config/gcloud/credentials.db",
	".kube/config", ".netrc", ".npmrc", ".pypirc", ".docker/config.json",
}

type collector struct {
	decideFlag     bool
	reasons        []string
	commands       []Command
	signals        map[string]bool
	parseOK        bool
	hasIndirection bool

	writtenPaths            map[string]bool
	cwd                     string
	cwdUnknown              bool // a directory change the classifier could not resolve
	sensitiveTarget         string
	destructiveEffect       bool
	requiresShellPermission bool

	// literalWords are heredoc bodies and assignment values, which bash does
	// not brace-expand.
	literalWords map[*syntax.Word]bool

	// guard, when set, names paths whose mention is recorded in
	// protectedPath. home lets "cd" and "~" resolve the way the shell would.
	guard         *PathGuard
	home          string
	dotGlob       bool
	protectedPath string

	// facts are effects found in syntax that no command carries, such as a
	// redirect; env holds the variables the command line sets that change
	// where a network client connects.
	facts []EffectFact
	env   []envOverride
}

func (c *collector) decide(reason string) {
	c.decideFlag = true
	for _, existing := range c.reasons {
		if existing == reason {
			return
		}
	}
	c.reasons = append(c.reasons, reason)
}

func (c *collector) signal(name string) {
	if c.signals == nil {
		c.signals = map[string]bool{}
	}
	c.signals[name] = true
}

func (c *collector) signalList() []string {
	out := make([]string, 0, len(c.signals))
	for name := range c.signals {
		out = append(out, name)
	}
	// Deterministic order for tests and receipts.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (c *collector) normalizedPath(value string) string {
	value = path.Clean(value)
	if c.cwd != "" && !path.IsAbs(value) {
		return path.Join(c.cwd, value)
	}
	return value
}

func (c *collector) isWrittenPath(value string) bool {
	return c.writtenPaths != nil && c.writtenPaths[c.normalizedPath(value)]
}

// valueFlags lists wrapper flags that consume a value (short and long forms;
// long forms also match their --flag=value attached spelling).
var valueFlags = map[string]map[string]bool{
	"sudo": {
		"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-T": true,
		"-D": true, "-U": true, "-t": true, "-R": true,
		"--user": true, "--group": true, "--host": true, "--prompt": true,
		"--chdir": true, "--role": true, "--type": true, "--close-from": true,
		"--other-user": true, "--command-timeout": true,
	},
	"exec":   {"-a": true},
	"nice":   {"-n": true, "--adjustment": true},
	"stdbuf": {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"time":   {"-f": true, "-o": true, "--format": true, "--output": true},
	"xargs": {
		"-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-d": true, "-E": true, "-a": true,
		"-i": true, "-l": true, // deprecated aliases of -I / -L (take values)
		"--replace": true, "--max-lines": true, "--max-args": true, "--max-procs": true,
		"--max-chars": true, "--delimiter": true, "--eof": true, "--arg-file": true,
	},
}

// noValueShortFlags lists wrapper short flags known to take no value.
// Unknown short flags are NOT assumed valueless: they may consume the next
// token, so they are treated as ambiguous and route to the decision path.
var noValueShortFlags = map[string]map[string]bool{
	"sudo": {
		"-A": true, "-b": true, "-E": true, "-e": true, "-H": true, "-i": true,
		"-k": true, "-K": true, "-l": true, "-n": true, "-P": true, "-S": true,
		"-s": true, "-v": true, "-V": true,
	},
	"xargs":   {"-0": true, "-p": true, "-t": true, "-v": true, "-x": true, "-r": true, "-o": true},
	"setsid":  {"-f": true, "-w": true, "-c": true},
	"time":    {"-p": true, "-a": true, "-v": true, "-q": true},
	"exec":    {"-l": true, "-c": true},
	"command": {"-p": true},
	"builtin": {"-a": true, "-p": true},
}

// noValueLongFlags lists wrapper long flags known to take no value. Unknown
// long flags are treated as ambiguous (they may consume the next token) and
// route to the decision path.
var noValueLongFlags = map[string]map[string]bool{
	"sudo": {
		"--login": true, "--shell": true, "--edit": true, "--background": true,
		"--preserve-env": true, "--non-interactive": true, "--validate": true,
		"--reset-timestamp": true, "--remove-timestamp": true, "--kill": true,
		"--update": true, "--stdin": true, "--help": true, "--version": true,
	},
	"xargs": {
		"--interactive": true, "--verbose": true, "--exit": true, "--null": true,
		"--no-run-if-empty": true, "--open-tty": true, "--show-limits": true,
	},
	"setsid": {"--ctty": true, "--fork": true, "--wait": true},
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
	"mksh": true, "yash": true, "tcsh": true, "csh": true, "rc": true,
	"fish": true, "nu": true, "pwsh": true, "powershell": true,
	"elvish": true, "xonsh": true,
}

// strictFlagShells are shells whose single-dash options are not guaranteed
// POSIX-valueless (fish -d takes a value, pwsh uses -Word options). For
// these, unrecognized short-flag characters are ambiguous → decision path.
var strictFlagShells = map[string]bool{
	"fish": true, "nu": true, "pwsh": true, "powershell": true,
	"elvish": true, "xonsh": true,
}

var interpreterSpecs = map[string]interpreterSpec{
	"python": {
		codeShort:    "c",
		valueShort:   "WX",
		valueLong:    []string{"--check-hash-based-pycs"},
		noValueShort: "BEIOqsuv",
		noValueLong: []string{
			"--help", "--version", "--verbose", "--quiet", "--isolated",
			"--ignore-environment", "--no-site", "--no-user-site",
			"--bytes-warning", "--dont-write-bytecode",
		},
	},
	"perl": {
		codeShort:    "eE",
		noValueShort: "v",
		noValueLong:  []string{"--help", "--version"},
	},
	"ruby": {
		codeShort:    "e",
		noValueShort: "v",
		noValueLong:  []string{"--help", "--version"},
	},
	"node": {
		codeShort:    "ep",
		codeLong:     []string{"--eval", "--print"},
		valueShort:   "r",
		valueLong:    []string{"--input-type", "--require", "--loader", "--experimental-loader"},
		noValueShort: "hv",
		noValueLong:  []string{"--help", "--version"},
	},
}

// executorWrappers are process-executor prefixes (UNKNOWN_WRAPPER_BYPASS).
// Unknown flags on these wrappers route to the decision path.
var executorWrappers = map[string]executorSpec{
	"timeout": {
		valueShort: "sk", valueLong: []string{"--signal", "--kill-after"},
		noValueShort: "v", noValueLong: []string{"--preserve-status", "--foreground"},
		skip: 1, // DURATION
	},
	"flock": {
		valueShort: "wEc", valueLong: []string{"--timeout", "--conflict-exit-code", "--command"},
		noValueShort: "sxunoFv", noValueLong: []string{"--shared", "--exclusive", "--unlock", "--nonblock", "--close", "--fork", "--verbose"},
		commandShort: "c", commandLong: []string{"--command"},
		skip: 1, // LOCKFILE
	},
	"su": {
		valueShort: "cCgsGw", valueLong: []string{"--command", "--session-command", "--group", "--supp-group", "--shell", "--whitelist-environment"},
		noValueShort: "flmPp", noValueLong: []string{"--fast", "--login", "--preserve-environment", "--pty", "--help", "--version"},
		commandShort: "cC", commandLong: []string{"--command", "--session-command"},
		requireCommand: true,
	},
	"taskset": {
		valueShort: "c", valueLong: []string{"--cpu-list"},
		pidFlag: 'p',
		skip:    1, // MASK (absent when -c/--cpu-list supplies it)
	},
	"chrt": {
		valueShort:   "pTPD",
		valueLong:    []string{"--sched-runtime", "--sched-period", "--sched-deadline"},
		noValueShort: "frobiamd", noValueLong: []string{"--fifo", "--rr", "--other", "--batch", "--idle", "--deadline", "--all", "--max"},
		pidFlag: 'p',
		skip:    1, // PRIO
	},
	"ionice": {
		valueShort:   "cnp",
		valueLong:    []string{"--class", "--classdata", "--pid"},
		noValueShort: "t", noValueLong: []string{"--ignore"},
		pidFlag: 'p',
	},
	"chroot": {
		valueLong:   []string{"--userspec", "--groups"},
		noValueLong: []string{"--help", "--version"},
		skip:        1, // NEWROOT
		decideBare:  true,
	},
	"strace": {
		valueShort:   "eopusPES",
		valueLong:    []string{"--trace", "--output", "--user", "--env", "--string-limit", "--summary-sort-by", "--filter", "--detach-on"},
		noValueShort: "bfDxXykKcCwtTzZvVrAiqdF",
		noValueLong:  []string{"--follow-forks", "--summary", "--summary-wall-clock", "--timestamps", "--syscall-times", "--instruction-pointer", "--stack-trace", "--decode-fds", "--help", "--version"},
		pidFlag:      'p',
	},
	"ltrace": {
		valueShort:   "eolxsnFp",
		valueLong:    []string{"--output", "--filter", "--library", "--config", "--indent", "--strlen", "--pid"},
		noValueShort: "tifrdSCV",
		noValueLong:  []string{"--timestamp", "--follow-forks", "--demangle", "--help", "--version"},
		pidFlag:      'p',
	},
	"catchsegv": {},
	"valgrind": {
		noValueShort: "qv",
		valueLong: []string{
			"--tool", "--log-file", "--xml-file", "--xml-fd", "--suppressions",
			"--error-exitcode", "--leak-check", "--show-leak-kinds", "--track-origins",
			"--gen-suppressions", "--num-callers", "--max-stackframe", "--main-stacksize",
			"--max-threads", "--fair-sched", "--smc-check", "--read-var-info",
			"--freelist-vol", "--malloc-fill", "--free-fill", "--demangle",
			"--error-limit", "--show-below-main", "--partial-loads-ok",
			"--expensive-definedness-checks", "--keep-stacktraces", "--xml-user-comment",
		},
		noValueLong: []string{"--help", "--version", "--verbose", "--quiet"},
	},
}

// shellLongValueFlags are shell-specific long flags that consume a value.
var shellLongValueFlags = map[string]map[string]bool{
	"bash": {"--init-file": true, "--rcfile": true},
	"zsh":  {"--emulate": true},
	"nu":   {"--config": true, "--env-config": true},
}

// gitValueFlags are git global flags that consume a value token.
var gitValueFlags = map[string]bool{
	"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true,
}

var kubectlValueFlags = map[string]bool{
	"-n": true, "--namespace": true, "--context": true, "--cluster": true,
	"--user": true, "--server": true, "-s": true, "--kubeconfig": true,
	"--token": true, "--as": true, "--as-group": true, "--request-timeout": true,
}

var gitBoolFlags = map[string]bool{
	"--bare": true, "--glob-pathspecs": true, "--icase-pathspecs": true,
	"--literal-pathspecs": true, "--no-pager": true, "--no-replace-objects": true,
	"--noglob-pathspecs": true, "--paginate": true, "-P": true, "-p": true,
}

var kubectlBoolFlags = map[string]bool{
	"--disable-compression": true, "--insecure-skip-tls-verify": true,
	"--match-server-version": true, "--warnings-as-errors": true,
}

var dockerValueFlags = map[string]bool{
	"-H": true, "--host": true, "--context": true, "--config": true, "--log-level": true,
}

var awsValueFlags = map[string]bool{
	"--profile": true, "--region": true, "--output": true, "--endpoint-url": true,
	"--ca-bundle": true, "--cli-read-timeout": true, "--cli-connect-timeout": true,
	"--color": true, "--query": true,
}

var awsBoolFlags = map[string]bool{
	"--debug": true, "--no-verify-ssl": true, "--no-paginate": true,
	"--no-sign-request": true, "--no-cli-pager": true, "--cli-auto-prompt": true,
	"--no-cli-auto-prompt": true,
}

// legacyNeedleHit reproduces the pre-AST substring classification verbatim.
func legacyNeedleHit(command string) string {
	lower := strings.ToLower(strings.Join(strings.Fields(command), " "))
	for _, needle := range legacyNeedles {
		if strings.Contains(lower, needle) || strings.HasPrefix(lower, strings.TrimSpace(needle)) {
			return needle
		}
	}
	return ""
}
