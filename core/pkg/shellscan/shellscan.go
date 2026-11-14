package shellscan

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
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

// classifyEffectFacts derives narrowly-scoped facts from commands that the
// shell parser already resolved. It deliberately never tokenizes raw shell
// source, so wrapper, background, and subshell behavior stays owned by the
// AST traversal above. syntaxFacts are the facts that traversal found in
// redirects, where no command carries them.
func classifyEffectFacts(commands []Command, syntaxFacts []EffectFact, overrides []envOverride) ([]EffectFact, bool) {
	facts := make([]EffectFact, 0)
	seen := make(map[string]bool)
	factCrossesIndirection := false
	for _, command := range commands {
		factCount := len(facts)
		for _, target := range secretReadTargets(command) {
			facts = appendEffectFact(facts, seen, EffectFact{
				Class:  "secret",
				Action: "secret_read",
				Target: target,
				Reason: "secret read via " + command.Name,
			})
		}
		for _, fact := range networkFacts(command, overrides) {
			facts = appendEffectFact(facts, seen, fact)
		}
		if len(facts) > factCount && (command.Dynamic || command.Via != "") {
			factCrossesIndirection = true
		}
	}
	for _, fact := range syntaxFacts {
		facts = appendEffectFact(facts, seen, fact)
	}
	return undeterminedEgressOnly(facts), factCrossesIndirection
}

// undeterminedEgressOnly drops the named destinations once any part of the
// command's egress is undetermined. A receipt that named some hosts would
// read as the whole set, and the call is refused either way.
func undeterminedEgressOnly(facts []EffectFact) []EffectFact {
	undetermined := false
	for _, fact := range facts {
		undetermined = undetermined || fact.Class == "network" && fact.Target == netdest.Undetermined
	}
	if !undetermined {
		return facts
	}
	kept := facts[:0]
	for _, fact := range facts {
		if fact.Class != "network" || fact.Target == netdest.Undetermined {
			kept = append(kept, fact)
		}
	}
	return kept
}

func appendEffectFact(facts []EffectFact, seen map[string]bool, fact EffectFact) []EffectFact {
	key := fact.Class + "\x00" + fact.Action + "\x00" + fact.Target
	if seen[key] {
		return facts
	}
	seen[key] = true
	return append(facts, fact)
}

// isRemotePathSpec recognizes the scp/rsync host:path notation while keeping
// URLs and Windows drive paths out of local-secret classification.
func isRemotePathSpec(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "~") {
		return false
	}
	separator := strings.IndexByte(value, ':')
	if separator <= 0 {
		return false
	}
	host := value[:separator]
	if len(host) == 1 && ((host[0] >= 'a' && host[0] <= 'z') || (host[0] >= 'A' && host[0] <= 'Z')) {
		return false // Windows drive path.
	}
	return !strings.ContainsAny(host, `/\\`)
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

func secretReadTargets(command Command) []string {
	// Tokens[0] is the command word, except in the records the wrapper code
	// writes for a shell, which hold its arguments only.
	operands := command.Tokens
	if len(operands) > 0 && path.Base(slashPath(operands[0])) == command.Name {
		operands = operands[1:]
	}
	switch {
	case command.Name == "curl":
		return curlSecretReadTargets(operands)
	case transferReadCommands[command.Name]:
		return transferSecretReadTargets(operands)
	case nonDisclosingCommands[command.Name]:
		return nil
	case fileReaderCommands[command.Name]:
		return secretReaderTargets(operands)
	}
	// For any other program an argument with white space in it is taken as
	// text, such as a commit message that mentions a file name, not as a path.
	paths := make([]string, 0, len(operands))
	for _, operand := range operands {
		if !strings.ContainsAny(operand, " \t\n") {
			paths = append(paths, operand)
		}
	}
	return secretReaderTargets(paths)
}

func secretReaderTargets(tokens []string) []string {
	var targets []string
	endOptions := false
	for _, token := range tokens {
		if !endOptions && token == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(token, "-") && token != "-" {
			if index := strings.IndexByte(token, '='); index >= 0 {
				targets = appendLocalSecretTarget(targets, token[index+1:])
			}
			continue
		}
		// dd if=PATH and similar name=value operands carry the path as the value.
		if name, value, ok := strings.Cut(token, "="); ok && name != "" && !strings.ContainsAny(name, "/.") {
			targets = appendLocalSecretTarget(targets, value)
			continue
		}
		targets = appendLocalSecretTarget(targets, token)
	}
	return targets
}

// localFileURLPath decodes a local FILE URL exactly once. URL.Path is already
// percent-decoded; decoding it again would turn a literal percent escape in a
// filename into a different path. Curl ignores query and fragment suffixes for
// FILE reads; URL.Path excludes them and preserves a literal +.
func localFileURLPath(raw string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(raw), "file:") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil {
		return "", false
	}
	switch strings.ToLower(u.Host) {
	case "", "localhost", "127.0.0.1":
	default:
		return "", false
	}
	if !path.IsAbs(u.Path) || strings.ContainsRune(u.Path, 0) {
		return "", false
	}
	return u.Path, true
}

func curlSecretReadTargets(tokens []string) []string {
	var targets []string
	if len(tokens) > 0 {
		walkCLI(curlSpec, tokens, cliVisitor{
			option: func(name string, _ optRole, value string) {
				if name == "data-urlencode" || name == "url-query" {
					targets = appendLocalSecretTarget(targets, curlEncodedFilePath(name, value))
				}
				if name == "form" {
					paths, _ := curlFormPaths(value)
					for _, path := range paths {
						targets = appendLocalSecretTarget(targets, path)
					}
				}
			},
			operand: func(string) {},
			invalid: func(string) {}, // curlEgress refuses unsupported syntax.
		})
	}
	for index, token := range tokens {
		// A file: URL makes curl read a local file.
		if local, ok := localFileURLPath(token); ok {
			targets = appendLocalSecretTarget(targets, local)
		}
		targets = appendLocalSecretTarget(targets, curlInlineSecretPath(token))
		if index+1 >= len(tokens) {
			continue
		}
		switch token {
		case "-d", "--data", "--data-binary", "--data-ascii":
			targets = appendLocalSecretTarget(targets, curlAtPath(tokens[index+1]))
		case "-T", "--upload-file":
			targets = appendLocalSecretTarget(targets, tokens[index+1])
		}
	}
	return targets
}

func curlInlineSecretPath(token string) string {
	switch {
	case strings.HasPrefix(token, "-d@"):
		return strings.TrimPrefix(token, "-d@")
	case strings.HasPrefix(token, "--data=@"):
		return strings.TrimPrefix(token, "--data=@")
	case strings.HasPrefix(token, "--data-binary=@"):
		return strings.TrimPrefix(token, "--data-binary=@")
	case strings.HasPrefix(token, "--data-ascii=@"):
		return strings.TrimPrefix(token, "--data-ascii=@")
	case strings.HasPrefix(token, "-T") && len(token) > len("-T"):
		return strings.TrimPrefix(token, "-T")
	case strings.HasPrefix(token, "--upload-file="):
		return strings.TrimPrefix(token, "--upload-file=")
	default:
		return curlAtPath(token)
	}
}

func curlAtPath(value string) string {
	if strings.HasPrefix(value, "@") {
		return strings.TrimPrefix(value, "@")
	}
	return ""
}

// Curl's data_urlencode checks for '=' before '@': any '=' makes this
// literal content, even if an '@' occurs earlier. Otherwise the first '@'
// separates the optional field name from a filename, preserved verbatim.
// --url-query shares that grammar except that a leading '+' is literal.
func curlEncodedFilePath(option, value string) string {
	if option == "url-query" && strings.HasPrefix(value, "+") || strings.ContainsRune(value, '=') {
		return ""
	}
	if _, filename, ok := strings.Cut(value, "@"); ok {
		return filename
	}
	return ""
}

// curlWriteOutPaths lists the files a --write-out format sends its output to.
// Curl takes the text between "%output{" and the next "}" as the name. Newer
// releases read a leading ">>" as append and older ones as part of the name,
// so both are returned. Every marker is read, including one curl would print
// as text after "%%": a name too many is checked, never one too few.
func curlWriteOutPaths(format string) []string {
	const marker = "%output{"
	var paths []string
	for offset := 0; ; {
		index := strings.Index(format[offset:], marker)
		if index < 0 {
			return paths
		}
		offset += index + len(marker)
		end := strings.IndexByte(format[offset:], '}')
		if end < 0 {
			return paths
		}
		name := format[offset : offset+end]
		if name != "" {
			paths = append(paths, name)
		}
		if appended := strings.TrimPrefix(name, ">>"); appended != name && appended != "" {
			paths = append(paths, appended)
		}
	}
}

func transferSecretReadTargets(tokens []string) []string {
	operands := make([]string, 0, len(tokens))
	endOptions := false
	for _, token := range tokens {
		if !endOptions && token == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(token, "-") && token != "-" {
			continue
		}
		operands = append(operands, token)
	}
	if len(operands) < 2 {
		return nil
	}
	var targets []string
	for _, source := range operands[:len(operands)-1] {
		targets = appendLocalSecretTarget(targets, source)
	}
	return targets
}

func appendLocalSecretTarget(targets []string, value string) []string {
	if isLocalSecretPath(value) {
		return append(targets, value)
	}
	return targets
}

// SecretReadPath reports whether path names credential material by the rules
// a shell read of it is classified with, so a read through any other tool is
// decided alike.
func SecretReadPath(path string) bool {
	return isLocalSecretPath(path)
}

// secretGlobSamples are credential files as a search finds them, at least one
// for each rule in secretReadPathNeedles, so a glob can be asked whether it
// selects one.
var secretGlobSamples = []string{
	".env", ".env.local", "server.pem", "cert.p12", "tls.key", "id_rsa", "id_ed25519", "id_ecdsa",
	".ssh/id_rsa", ".ssh/config", ".aws/credentials", ".config/gcloud/credentials.db",
	".kube/config", ".netrc", ".npmrc", ".pypirc", ".docker/config.json",
}

// publicCounterpart reports a file that sits beside credential material and
// is named like it but holds none: a public key, or an example env file kept
// in the repository for its variable names.
func publicCounterpart(normalized string) bool {
	base := path.Base(path.Clean(normalized))
	if strings.HasSuffix(base, ".pub") {
		return true
	}
	switch base {
	case ".env.example", ".env.sample", ".env.template":
		return true
	}
	return false
}

func isLocalSecretPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || isRemotePathSpec(value) {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(value, `\\`, "/"))
	// A search tool reads a backslash in a glob as quoting the next byte, so
	// ".en\v" given to rg -g or grep --include selects ".env".
	for _, candidate := range []string{normalized, strings.ReplaceAll(normalized, `\`, "")} {
		if publicCounterpart(candidate) {
			continue
		}
		for _, needle := range secretReadPathNeedles {
			if strings.Contains(candidate, needle) {
				return true
			}
		}
	}
	return false
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

// classifyString parses a shell snippet and walks every command node,
// including those inside pipelines, substitutions and subshells.
func (c *collector) classifyString(src, via string, depth int) {
	if depth > maxWrapperDepth {
		c.decide("wrapper nesting too deep to classify statically")
		return
	}
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil {
		c.signal(SignalParseError)
		c.parseOK = false
		c.decide("unparseable shell command (fail-closed)")
		return
	}
	if len(file.Stmts) > 1 {
		c.signal(SignalChaining)
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			switch n.Op {
			case syntax.Pipe:
				c.signal(SignalChaining)
				if encodedPipeline(n) {
					c.signal(SignalEncodedWrapper)
					c.decide("encoded payload decoded into a shell or eval")
				}
			case syntax.AndStmt, syntax.OrStmt:
				c.signal(SignalChaining)
			}
		case *syntax.CmdSubst:
			c.classifySubstitution(n.Stmts)
		case *syntax.ProcSubst:
			c.classifySubstitution(n.Stmts)
		case *syntax.Assign:
			c.markLiteralWord(n.Value)
			c.recordAssignment(n)
		case *syntax.Stmt:
			c.classifyShellInput(n, via, depth)
		case *syntax.SglQuoted:
			if n.Dollar {
				c.signal(SignalANSICQuoting)
				c.decide("ANSI-C quoting cannot be evaluated statically (fail-closed)")
			}
		case *syntax.DblQuoted:
			if n.Dollar {
				c.signal(SignalANSICQuoting)
				c.decide("locale quoting cannot be evaluated statically (fail-closed)")
			}
		case *syntax.Word:
			c.guardWord(n)
			if !c.literalWords[n] && hasBraceExpansion(n) {
				c.signal(SignalBraceExpansion)
				c.decide("brace expansion cannot be evaluated statically (fail-closed)")
			}
		case *syntax.FuncDecl:
			c.hasIndirection = true
		case *syntax.Redirect:
			c.markLiteralWord(n.Hdoc)
			c.classifyRedirect(n)
		case *syntax.CallExpr:
			c.classifyCall(n, via, depth)
		}
		return true
	})
}

func (c *collector) markLiteralWord(w *syntax.Word) {
	if w == nil {
		return
	}
	if c.literalWords == nil {
		c.literalWords = map[*syntax.Word]bool{}
	}
	c.literalWords[w] = true
}

// recordAssignment keeps an assignment to a variable that network clients
// read. Scope is not modelled: a prefix assignment, an export and a plain
// assignment all count for every network command in the text.
func (c *collector) recordAssignment(assign *syntax.Assign) {
	if assign.Name == nil && assign.Naked && assign.Value != nil {
		// export "NAME=value" and declare -x 'NAME=value' reach the parser as
		// one quoted word, not as a name and a value; the shell still assigns.
		word := resolveWord(assign.Value)
		name, value, isAssignment := strings.Cut(word.text, "=")
		switch {
		case strings.HasPrefix(word.text, "-"):
			// an option of the builtin
		case word.dynamic && (!isAssignment || !assignmentWord(word.text)):
			c.env = append(c.env, envOverride{dynamic: true})
		case isAssignment && tracksVariable(name):
			c.env = append(c.env, envOverride{name: name, value: value, dynamic: word.dynamic})
		}
		return
	}
	if assign.Name == nil || !tracksVariable(assign.Name.Value) {
		return
	}
	override := envOverride{name: assign.Name.Value, dynamic: assign.Append || assign.Array != nil || assign.Index != nil}
	if assign.Value != nil {
		value := resolveWord(assign.Value)
		override.value, override.dynamic = value.text, override.dynamic || value.dynamic
	}
	c.env = append(c.env, override)
}

// classifyShellInput classifies a heredoc or here-string that feeds a shell
// its commands. The shell invocation itself still fails closed as reading
// standard input; this adds what the visible script would do.
func (c *collector) classifyShellInput(stmt *syntax.Stmt, via string, depth int) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	name := resolveCommandWord(call.Args[0])
	if name.dynamic || !shellNames[path.Base(name.text)] {
		return
	}
	for _, redirect := range stmt.Redirs {
		var body *syntax.Word
		switch redirect.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			body = redirect.Hdoc
		case syntax.WordHdoc:
			body = redirect.Word
		}
		if body == nil {
			continue
		}
		if script := resolveWord(body); !script.dynamic {
			c.classifyString(script.text, joinVia(via, path.Base(name.text)+" stdin"), depth+1)
		}
	}
}

// classifySubstitution decides whether a command or process substitution
// needs a decision of its own. Its inner commands are classified by the
// surrounding walk either way. A substitution whose every inner command is on
// the read-only allowlist with literal input yields opaque text, and the word
// holding it stays dynamic: command position, eval, sh -c, source,
// interpreters, redirect targets and destructive operands still fail closed
// on that word. Anything else requires a decision.
func (c *collector) classifySubstitution(stmts []*syntax.Stmt) {
	c.signal(SignalCommandSubstitution)
	c.hasIndirection = true
	if !readOnlySubstitution(stmts) {
		c.decide("command substitution runs a command outside the read-only allowlist (fail-closed)")
	}
}

// readOnlySubstitution reports whether every statement is one allowlisted
// read-only command with literal words and at most heredoc or here-string
// input: no pipelines, lists, assignments, other redirects or nested
// expansion.
func readOnlySubstitution(stmts []*syntax.Stmt) bool {
	if len(stmts) == 0 {
		return false
	}
	for _, stmt := range stmts {
		if stmt.Negated || stmt.Background || stmt.Coprocess {
			return false
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
			return false
		}
		args := make([]string, 0, len(call.Args))
		for _, word := range call.Args {
			tok := resolveWord(word)
			if tok.dynamic || tok.glob || hasBraceExpansion(word) {
				return false
			}
			args = append(args, tok.text)
		}
		literalInput := false
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.Hdoc, syntax.DashHdoc:
				literalInput = true
			case syntax.WordHdoc:
				if resolveWord(redirect.Word).dynamic {
					return false
				}
				literalInput = true
			default:
				return false
			}
		}
		if !readOnlySubstitutionCommand(args, literalInput) {
			return false
		}
	}
	return true
}

// readOnlySubstitutionCommand is the deliberately small allowlist of commands
// whose output may be captured without a decision.
func readOnlySubstitutionCommand(args []string, literalInput bool) bool {
	rest := args[1:]
	switch args[0] {
	case "cat":
		// Only the heredoc or here-string itself, never a file.
		return literalInput && len(rest) == 0
	case "echo", "printf", "basename", "dirname":
		return true
	case "pwd":
		for _, arg := range rest {
			if arg != "-L" && arg != "-P" {
				return false
			}
		}
		return true
	case "date":
		// Display formats only; an operand or -s/--set would set the clock.
		for _, arg := range rest {
			switch {
			case strings.HasPrefix(arg, "+"), arg == "-u", arg == "--utc", arg == "--universal",
				arg == "-R", arg == "--rfc-email", strings.HasPrefix(arg, "-I"),
				strings.HasPrefix(arg, "--iso-8601"), strings.HasPrefix(arg, "--rfc-3339="):
			default:
				return false
			}
		}
		return true
	case "git":
		// The subcommand must come first: global options such as -c can run
		// configured programs.
		if len(rest) == 0 {
			return false
		}
		switch rest[0] {
		case "rev-parse":
			return true
		case "log":
			for _, arg := range rest[1:] {
				if strings.HasPrefix(arg, "--output") {
					return false
				}
			}
			return true
		}
	}
	return false
}

func encodedPipeline(node *syntax.BinaryCmd) bool {
	decoded := false
	for _, call := range pipelineCalls(node) {
		if len(call.Args) == 0 {
			continue
		}
		args := make([]wordTok, 0, len(call.Args))
		for _, word := range call.Args {
			args = append(args, resolveWord(word))
		}
		if args[0].dynamic {
			continue
		}
		name := path.Base(path.Clean(args[0].text))
		if decoded && (name == "eval" || shellNames[name]) {
			return true
		}
		if isDecoderCall(name, args[1:]) {
			decoded = true
		}
	}
	return false
}

func pipelineCalls(node *syntax.BinaryCmd) []*syntax.CallExpr {
	var calls []*syntax.CallExpr
	var walkStmt func(*syntax.Stmt)
	walkStmt = func(stmt *syntax.Stmt) {
		if stmt == nil {
			return
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && binary.Op == syntax.Pipe {
			walkStmt(binary.X)
			walkStmt(binary.Y)
			return
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			calls = append(calls, call)
		}
	}
	walkStmt(node.X)
	walkStmt(node.Y)
	return calls
}

func isDecoderCall(name string, args []wordTok) bool {
	switch name {
	case "base64":
		for _, arg := range args {
			if !arg.dynamic && (arg.text == "-d" || arg.text == "--decode" || arg.text == "-D") {
				return true
			}
		}
	case "xxd":
		for _, arg := range args {
			if !arg.dynamic && strings.HasPrefix(arg.text, "-r") {
				return true
			}
		}
	case "openssl":
		hasDecode, hasBase64 := false, false
		for _, arg := range args {
			if arg.dynamic {
				continue
			}
			hasDecode = hasDecode || arg.text == "-d"
			hasBase64 = hasBase64 || arg.text == "-base64" || arg.text == "-a" || arg.text == "-A"
		}
		return hasDecode && hasBase64
	}
	return false
}

func (c *collector) classifyRedirect(r *syntax.Redirect) {
	c.signal(SignalRedirect)
	if r.Word == nil {
		return
	}
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrInOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		// write-capable redirect
	case syntax.DplOut:
		// ">&word" duplicates a descriptor when word is a number or "-", and
		// writes stdout and stderr to the file word otherwise.
		if word := resolveWord(r.Word); !word.dynamic && (word.text == "-" || fileDescriptor(word.text)) {
			return
		}
	case syntax.RdrIn:
		target := resolveWord(r.Word)
		if scan, ok := deviceSocketEgress(target); ok {
			c.facts = append(c.facts, scan.facts("a shell socket redirect")...)
		} else if !target.dynamic && isLocalSecretPath(target.text) {
			c.facts = append(c.facts, EffectFact{
				Class:  "secret",
				Action: "secret_read",
				Target: target.text,
				Reason: "secret read via input redirect",
			})
		}
		return
	default:
		return
	}
	target := resolveWord(r.Word)
	if scan, ok := deviceSocketEgress(target); ok {
		// Bash opens a socket for this path; no file is written.
		c.facts = append(c.facts, scan.facts("a shell socket redirect")...)
		return
	}
	c.recordWriteTarget(target, "write redirect")
}

// fileDescriptor reports whether a redirect word names a descriptor ("2",
// "10", or "3-" for a move) rather than a file.
func fileDescriptor(word string) bool {
	word = strings.TrimSuffix(word, "-")
	if word == "" {
		return false
	}
	for i := 0; i < len(word); i++ {
		if word[i] < '0' || word[i] > '9' {
			return false
		}
	}
	return true
}

func (c *collector) recordWriteTarget(tok wordTok, source string) {
	if tok.dynamic || tok.glob {
		c.recordDynamicSensitiveTarget(tok, source)
		c.decide(source + " with an unresolvable target (fail-closed)")
		return
	}
	target := strings.ToLower(tok.text)
	// fd duplication targets ("&1", "&2") are not file writes.
	if strings.HasPrefix(target, "&") {
		return
	}
	if c.writtenPaths == nil {
		c.writtenPaths = map[string]bool{}
	}
	c.writtenPaths[c.normalizedPath(tok.text)] = true
	c.recordSensitiveTarget(tok, "write redirect", SignalSensitiveRedirect)
	if c.cwdUnknown && !path.IsAbs(nativePath(tok.text)) {
		c.decide(source + " relative to an unresolved directory change (fail-closed)")
	}
}

// recordDynamicSensitiveTarget matches the static fragment of an opaque
// target (for example the decoded text of $'...' or the literal tail of
// "$HOME/.bashrc") so a recognizable protected file keeps its file class.
func (c *collector) recordDynamicSensitiveTarget(tok wordTok, operation string) {
	if rule, ok := SensitiveWriteTarget(tok.text, ""); ok {
		c.markSensitiveTarget(rule, operation, SignalSensitiveTarget)
	}
}

func (c *collector) recordSensitiveTarget(tok wordTok, operation, signal string) {
	if _, ok := SensitiveWriteTarget(tok.text, c.cwd); ok {
		c.markSensitiveTarget(tok.text, operation, signal)
	}
}

func (c *collector) markSensitiveTarget(target, operation, signal string) {
	if c.sensitiveTarget == "" {
		c.sensitiveTarget = target
	}
	c.signal(signal)
	c.recordCompoundEffect()
	c.decide(fmt.Sprintf("%s to sensitive target %q", operation, target))
}

// changeDirectory follows cd/pushd inside the command so later relative write
// targets resolve against the new directory. A directory the classifier
// cannot resolve (dynamic, globbed, "-", $HOME, a stack entry) makes later
// relative write targets opaque instead.
func (c *collector) changeDirectory(args []wordTok) {
	endOptions := false
	for _, tok := range args {
		if tok.dynamic || tok.glob {
			c.cwdUnknown = true
			return
		}
		if !endOptions && tok.text == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(tok.text, "-") && tok.text != "-" {
			continue // -L, -P, -e, -@
		}
		if tok.text == "-" || strings.HasPrefix(tok.text, "+") {
			c.cwdUnknown = true
			return
		}
		target := nativePath(tok.text)
		if c.home != "" && (target == "~" || strings.HasPrefix(target, "~/")) {
			target = c.home + target[1:]
		}
		if path.IsAbs(target) {
			c.cwdUnknown = false
		}
		c.cwd = c.normalizedPath(target)
		return
	}
	// No operand: cd changes to $HOME.
	if c.home == "" {
		c.cwdUnknown = true
		return
	}
	c.cwd, c.cwdUnknown = c.home, false
}

// recordDestructiveEffect marks a statically identified effect that needs a
// shell-operate permission when it is combined with a protected file target.
// It deliberately excludes opaque or merely suspicious commands: callers use
// it only after matching a concrete destructive operation.
func (c *collector) recordDestructiveEffect() {
	c.destructiveEffect = true
	c.recordCompoundEffect()
}

func (c *collector) recordCompoundEffect() {
	if !c.destructiveEffect || c.sensitiveTarget == "" {
		return
	}
	c.requiresShellPermission = true
	c.signal(SignalSensitiveDestructive)
}

func (c *collector) recordTeeWrites(args []wordTok) {
	endOptions := false
	targets := make([]wordTok, 0, len(args)-1)
	for _, tok := range args[1:] {
		if tok.dynamic {
			targets = append(targets, tok)
			continue
		}
		if !endOptions && tok.text == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(tok.text, "-") && tok.text != "-" {
			switch {
			case !strings.HasPrefix(tok.text, "--") && strings.Trim(tok.text[1:], "aip") == "",
				tok.text == "--append", tok.text == "--ignore-interrupts",
				tok.text == "--output-error", strings.HasPrefix(tok.text, "--output-error="):
				continue
			case tok.text == "--help", tok.text == "--version":
				return
			default:
				c.decide("tee with unrecognized flag " + tok.text + " (fail-closed)")
				continue
			}
		}
		if tok.text != "-" {
			targets = append(targets, tok)
		}
	}
	for _, target := range targets {
		c.recordWriteTarget(target, "tee write")
	}
}

// classifyCall resolves one command call's words and classifies it,
// unwrapping sudo/env/eval/sh -c/xargs wrappers recursively.
func (c *collector) classifyCall(call *syntax.CallExpr, via string, depth int) {
	args := make([]wordTok, 0, len(call.Args))
	for i, w := range call.Args {
		tok := resolveWord(w)
		if i == 0 && !tok.dynamic {
			tok = resolveCommandWord(w)
		}
		args = append(args, tok)
	}
	c.classifyTokens(args, via, depth)
}

type wordTok struct {
	text    string
	dynamic bool
	// glob is true when an unquoted part holds a pathname-expansion pattern,
	// so the word names whatever files match at run time.
	glob bool
}

// hasGlobPattern reports whether an unquoted literal holds an unescaped "*",
// "?" or bracket expression. A lone "[" (the test builtin) is not a pattern.
func hasGlobPattern(lit string) bool {
	// A "[" is glob syntax when a "]" follows it anywhere; the last "]" is
	// found once, so a word of many "[" costs one pass, not one per "[".
	lastClose := strings.LastIndexByte(lit, ']')
	for i := 0; i < len(lit); i++ {
		switch lit[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		case '[':
			if lastClose > i {
				return true
			}
		}
	}
	return false
}

// hasBraceExpansion reports whether bash would brace-expand the word. It
// splits a copy so the parsed word stays intact for the other resolvers.
func hasBraceExpansion(w *syntax.Word) bool {
	split := *w
	if !syntax.SplitBraces(&split) {
		return false
	}
	for _, part := range split.Parts {
		if _, ok := part.(*syntax.BraceExp); ok {
			return true
		}
	}
	return false
}

// decodeANSIC decodes the escapes of a $'...' body. The result is only used
// to recognize a protected target; the word itself stays opaque.
func decodeANSIC(value string) string {
	decoded, _, err := expand.Format(nil, value, nil)
	if err != nil {
		return value
	}
	return decoded
}

func unescapeLit(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Inside shell double quotes, only these escapes lose their backslash.
// A quoted curl form can itself contain quotes; preserve the argv curl sees.
func unescapeDoubleQuoted(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\n':
				i++
				continue
			case '$', '`', '"', '\\':
				i++
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func resolveCommandWord(w *syntax.Word) wordTok {
	var b strings.Builder
	glob := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			glob = glob || hasGlobPattern(p.Value)
			b.WriteString(unescapeLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				return wordTok{dynamic: true}
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return wordTok{dynamic: true}
			}
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return wordTok{dynamic: true}
				}
				b.WriteString(unescapeDoubleQuoted(lit.Value))
			}
		default:
			return wordTok{dynamic: true}
		}
	}
	return wordTok{text: b.String(), glob: glob}
}

func resolveWord(w *syntax.Word) wordTok {
	var b strings.Builder
	dynamic, glob := false, false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			glob = glob || hasGlobPattern(p.Value)
			b.WriteString(unescapeLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				b.WriteString(decodeANSIC(p.Value))
				dynamic = true
				continue
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			// $"..." is locale-translated at run time.
			dynamic = dynamic || p.Dollar
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					b.WriteString(unescapeDoubleQuoted(lit.Value))
				} else {
					dynamic = true
				}
			}
		default:
			// ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob, ...
			dynamic = true
		}
	}
	return wordTok{text: b.String(), dynamic: dynamic, glob: glob}
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

// dropWrapperFlags removes leading flag tokens (and their values) from args.
// It returns nil when the flag sequence cannot be resolved statically —
// dynamic words or unrecognized long flags in flag position are ambiguous
// because they may hide the wrapped command or its flags.
func dropWrapperFlags(cmd string, args []wordTok) []wordTok {
	vals := valueFlags[cmd]
	novals := noValueLongFlags[cmd]
	shortNovals := noValueShortFlags[cmd]
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok.text == "--" {
			i++
			break
		}
		if tok.dynamic {
			return nil
		}
		if !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			break
		}
		if strings.HasPrefix(tok.text, "--") {
			name := tok.text
			attached := false
			if idx := strings.Index(name, "="); idx >= 0 {
				name, attached = name[:idx], true
			}
			if vals[name] {
				if attached {
					i++
				} else {
					i += 2
				}
				continue
			}
			if novals[name] {
				i++
				continue
			}
			return nil // unknown long flag may consume the next token
		}
		// Short-flag cluster: a value-taking flag consumes the rest of the
		// cluster or, when last, the next token. Unknown short flags are NOT
		// assumed valueless (WRAPPER_SHORT_VALUE_BYPASS): they are ambiguous.
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			key := "-" + string(cluster[j])
			if vals[key] {
				if j+1 == len(cluster) {
					i++
				}
				break // value consumes the rest of the cluster
			}
			if shortNovals[key] {
				continue
			}
			return nil
		}
		i++
	}
	if i > len(args) {
		return nil
	}
	return args[i:]
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

// interpreterSpec describes a common language interpreter whose code source
// can be supplied directly on the command line or through standard input.
// We intentionally do not parse these languages: an opaque interpreter source
// is routed to the signed decision path instead.
type interpreterSpec struct {
	codeShort    string
	codeLong     []string
	valueShort   string
	valueLong    []string
	noValueShort string
	noValueLong  []string
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

// interpreterSpecFor resolves common versioned interpreter names without
// treating arbitrary commands that merely share a prefix as interpreters.
func interpreterSpecFor(name string) (interpreterSpec, bool) {
	if spec, ok := interpreterSpecs[name]; ok {
		return spec, true
	}
	if strings.HasPrefix(name, "python") && isInterpreterVersion(strings.TrimPrefix(name, "python")) {
		return interpreterSpecs["python"], true
	}
	if name == "nodejs" {
		return interpreterSpecs["node"], true
	}
	return interpreterSpec{}, false
}

func isInterpreterVersion(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// recordInlineInterpreterSensitiveWrite recognizes literal Python
// open(path, mode) calls without trying to interpret arbitrary source.
func (c *collector) recordInlineInterpreterSensitiveWrite(name string, source wordTok) {
	if source.dynamic || !strings.HasPrefix(name, "python") {
		return
	}
	compact := strings.NewReplacer("'", "", `"`, "", " ", "", "\t", "", "\r", "", "\n", "", "+", "").Replace(source.text)
	for {
		start := strings.Index(compact, "open(")
		if start < 0 {
			return
		}
		if start > 0 && (pythonIdentByte(compact[start-1]) || compact[start-1] == '.') {
			compact = compact[start+4:]
			continue
		}
		compact = compact[start+len("open("):]
		comma := strings.IndexByte(compact, ',')
		if comma < 0 {
			return
		}
		target, mode := compact[:comma], strings.TrimPrefix(compact[comma+1:], "mode=")
		if pythonOpenWriteMode(mode) {
			c.recordSensitiveTarget(wordTok{text: target}, "inline interpreter write", SignalSensitiveTarget)
			return
		}
	}
}

func pythonOpenWriteMode(mode string) bool {
	return strings.HasPrefix(mode, "w") || strings.HasPrefix(mode, "a") || strings.HasPrefix(mode, "x") ||
		strings.HasPrefix(mode, "r+") || strings.HasPrefix(mode, "rb+")
}

func pythonIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func (c *collector) classifyInterpreter(name string, args []wordTok, via string, spec interpreterSpec) {
	c.signal(SignalInterpreterInvocation)
	if len(args) == 0 {
		c.decide(name + " reads interpreter source from standard input (fail-closed)")
		return
	}

	terminalInfo := false
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic {
			c.decide(name + " interpreter invocation with a dynamic argument (fail-closed)")
			return
		}
		if tok.text == "-" {
			c.decide(name + " reads interpreter source from standard input (fail-closed)")
			return
		}
		if tok.text == "--" {
			if i+1 >= len(args) {
				c.decide(name + " reads interpreter source from standard input (fail-closed)")
				return
			}
			c.classifyInterpreterScript(name, args, i+1, via)
			return
		}
		if strings.HasPrefix(tok.text, "--") {
			flag := tok.text
			attached := false
			if idx := strings.IndexByte(flag, '='); idx >= 0 {
				flag, attached = flag[:idx], true
			}
			if containsString(spec.codeLong, flag) {
				source := wordTok{dynamic: true}
				if attached {
					source = wordTok{text: strings.TrimPrefix(tok.text, flag+"=")}
				} else if i+1 < len(args) {
					source = args[i+1]
				}
				c.recordInlineInterpreterSensitiveWrite(name, source)
				c.decide(name + " executes interpreter source via " + flag + " (fail-closed)")
				return
			}
			if containsString(spec.noValueLong, flag) && !attached {
				if flag == "--help" || flag == "--version" {
					terminalInfo = true
				}
				continue
			}
			if containsString(spec.valueLong, flag) {
				value := wordTok{}
				if attached {
					if len(tok.text) == len(flag)+1 {
						c.decide(name + " " + flag + " with an empty value (fail-closed)")
						return
					}
					value = wordTok{text: strings.TrimPrefix(tok.text, flag+"=")}
				} else {
					if i+1 >= len(args) || args[i+1].dynamic {
						c.decide(name + " " + flag + " with an unresolvable value (fail-closed)")
						return
					}
					value = args[i+1]
					i++
				}
				if isNodePreloadFlag(name, flag) && c.isWrittenPath(value.text) {
					c.decide(name + " executes a preload generated earlier in the command")
					return
				}
				continue
			}
			c.decide(name + " with an unrecognized flag " + tok.text + " (fail-closed)")
			return
		}
		if strings.HasPrefix(tok.text, "-") {
			cluster := tok.text[1:]
			for j := 0; j < len(cluster); j++ {
				flag := cluster[j]
				if strings.IndexByte(spec.codeShort, flag) >= 0 {
					source := wordTok{dynamic: true}
					if j+1 < len(cluster) {
						source = wordTok{text: cluster[j+1:]}
					} else if i+1 < len(args) {
						source = args[i+1]
					}
					c.recordInlineInterpreterSensitiveWrite(name, source)
					c.decide(name + " executes interpreter source via -" + string(flag) + " (fail-closed)")
					return
				}
				if strings.IndexByte(spec.noValueShort, flag) >= 0 {
					continue
				}
				if strings.IndexByte(spec.valueShort, flag) >= 0 {
					value := wordTok{}
					if j+1 == len(cluster) {
						if i+1 >= len(args) || args[i+1].dynamic {
							c.decide(name + " -" + string(flag) + " with an unresolvable value (fail-closed)")
							return
						}
						value = args[i+1]
						i++
					} else {
						value = wordTok{text: cluster[j+1:]}
					}
					if isNodePreloadShortFlag(name, flag) && c.isWrittenPath(value.text) {
						c.decide(name + " executes a preload generated earlier in the command")
						return
					}
					break
				}
				c.decide(name + " with an unrecognized flag -" + string(flag) + " (fail-closed)")
				return
			}
			continue
		}

		c.classifyInterpreterScript(name, args, i, via)
		return
	}

	if terminalInfo {
		tokens := make([]string, 0, len(args)+1)
		tokens = append(tokens, name)
		tokens = append(tokens, staticTokens(args)...)
		c.record(Command{Name: name, Tokens: tokens, Prefix: Prefix(tokens), Via: via})
		return
	}
	c.decide(name + " reads interpreter source from standard input (fail-closed)")
}

func (c *collector) classifyInterpreterScript(name string, args []wordTok, scriptIndex int, via string) {
	script := args[scriptIndex]
	if script.dynamic {
		c.decide(name + " interpreter invocation with a dynamic argument (fail-closed)")
		return
	}
	if c.isWrittenPath(script.text) {
		c.decide(name + " executes a script generated earlier in the command")
		return
	}
	c.guardScript(script.text)
	tokens := make([]string, 0, len(args)+1)
	tokens = append(tokens, name)
	tokens = append(tokens, staticTokens(args)...)
	c.record(Command{Name: name, Tokens: tokens, Prefix: Prefix(tokens), Via: via})
}

func isNodePreloadFlag(name, flag string) bool {
	return (name == "node" || name == "nodejs") && (flag == "--require" || flag == "--loader" || flag == "--experimental-loader")
}

func isNodePreloadShortFlag(name string, flag byte) bool {
	return (name == "node" || name == "nodejs") && flag == 'r'
}

// splitEnvPayload splits an env -S/--split-string payload into words using
// the shell parser (env's splitting is shell-like: quotes are honored).
// The payload must reduce to a single simple command line.
func splitEnvPayload(payload string) ([]wordTok, bool) {
	if strings.TrimSpace(payload) == "" {
		return nil, true
	}
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(payload), "")
	if err != nil || len(file.Stmts) != 1 || file.Stmts[0].Negated || file.Stmts[0].Background {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 {
		return nil, false
	}
	out := make([]wordTok, 0, len(call.Args))
	for _, w := range call.Args {
		out = append(out, resolveWord(w))
	}
	return out, true
}

// executorSpec describes a process-executor wrapper whose leading positional
// operands configure the execution instead of naming the command.
type executorSpec struct {
	valueShort     string   // letters of value-taking short flags
	valueLong      []string // long flags taking a value
	noValueShort   string   // letters of no-value short flags
	noValueLong    []string // long flags taking no value
	commandShort   string   // short flags whose values are command strings
	commandLong    []string // long flags whose values are command strings
	pidFlag        byte     // short flag meaning "operate on a pid; no command executes" (0 = none)
	skip           int      // leading positionals before the command (duration, mask, lockfile, jail dir)
	decideBare     bool     // invocation with operands but no command is opaque (chroot runs a shell)
	requireCommand bool     // no command-string flag means an opaque shell (su)
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

// hasSudoShellFlag reports whether sudo/doas arguments contain -s/-i (or
// --shell/--login), honoring value-taking flags so their values are not
// misread as flags (e.g. -ui is -u with value "i", not the -i shell flag).
func hasSudoShellFlag(args []wordTok) bool {
	vals := valueFlags["sudo"]
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic || tok.text == "--" || !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			return false
		}
		if strings.HasPrefix(tok.text, "--") {
			name := tok.text
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			if name == "--shell" || name == "--login" {
				return true
			}
			if vals[name] && !strings.Contains(tok.text, "=") {
				i++ // skip the value token
			}
			continue
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			key := "-" + string(cluster[j])
			if vals[key] {
				if j+1 == len(cluster) {
					i++ // value is the next token
				}
				break // value consumes the rest of the cluster
			}
			if cluster[j] == 's' || cluster[j] == 'i' {
				return true
			}
		}
	}
	return false
}

// xargsUsesReplace reports whether xargs arguments use -I/--replace
// (including the deprecated -i alias), which makes the command template
// data-driven and unclassifiable.
func xargsUsesReplace(args []wordTok) bool {
	vals := valueFlags["xargs"]
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic || tok.text == "--" || !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			return false
		}
		if strings.HasPrefix(tok.text, "--") {
			name := tok.text
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			if name == "--replace" {
				return true
			}
			if vals[name] && !strings.Contains(tok.text, "=") {
				i++ // skip the value token
			}
			continue
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			key := "-" + string(cluster[j])
			if vals[key] {
				if cluster[j] == 'I' || cluster[j] == 'i' {
					return true
				}
				if j+1 == len(cluster) {
					i++ // value is the next token
				}
				break // value consumes the rest of the cluster
			}
		}
	}
	return false
}

// isExecutorWrapper reports whether name is a registered process-executor
// wrapper.
func isExecutorWrapper(name string) bool {
	_, ok := executorWrappers[name]
	return ok
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// shellLongValueFlags are shell-specific long flags that consume a value.
var shellLongValueFlags = map[string]map[string]bool{
	"bash": {"--init-file": true, "--rcfile": true},
	"zsh":  {"--emulate": true},
	"nu":   {"--config": true, "--env-config": true},
}

// scanShellScriptFlag analyzes a shell invocation's arguments. It locates
// the script operand of a -c flag, honoring combined short-flag clusters
// (-lc), attached values (-cCMD), value-taking flags (-o option, bash -O
// shopt, long flags with values), "--" end-of-options, and -s/stdin mode.
//
// Returns: the -c script word (found), whether the shell will read commands
// from stdin because no static script source exists (stdin), whether scanning
// hit an unresolvable word (ambiguous), and whether a positional script file
// was seen (positional).
func scanShellScriptFlag(shell string, rest []wordTok) (script wordTok, found, stdin, ambiguous bool, positional wordTok) {
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		if tok.dynamic {
			return wordTok{}, false, false, true, wordTok{}
		}
		if tok.text == "--" {
			if i+1 < len(rest) {
				return wordTok{}, false, false, false, rest[i+1] // positional after --
			}
			return wordTok{}, false, true, false, wordTok{}
		}
		if tok.text == "--help" || tok.text == "--version" {
			// Prints and exits; treat like a benign positional.
			return wordTok{}, false, false, false, tok
		}
		if strings.HasPrefix(tok.text, "--") {
			flag := tok.text
			attached := false
			if idx := strings.IndexByte(flag, '='); idx >= 0 {
				flag, attached = flag[:idx], true
			}
			if shellLongValueFlags[shell][flag] {
				if attached {
					if len(tok.text) == len(flag)+1 {
						return wordTok{}, false, false, true, wordTok{}
					}
				} else {
					if i+1 >= len(rest) || rest[i+1].dynamic {
						return wordTok{}, false, false, true, wordTok{}
					}
					i++
				}
				continue
			}
			return wordTok{}, false, false, true, wordTok{}
		}
		if tok.text == "-" {
			return wordTok{}, false, true, false, wordTok{}
		}
		if !strings.HasPrefix(tok.text, "-") {
			return wordTok{}, false, false, false, tok // script file positional
		}
		cluster := tok.text[1:]
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'c':
				if j+1 < len(cluster) {
					// Attached payload: bash -cCMD (e.g. -c'rm -rf /').
					return wordTok{text: cluster[j+1:]}, true, false, false, wordTok{}
				}
				if i+1 < len(rest) {
					return rest[i+1], true, false, false, wordTok{}
				}
				return wordTok{}, false, true, false, wordTok{} // -c with no operand: stdin
			case 's':
				// -s reads commands from standard input: opaque.
				return wordTok{}, false, true, false, wordTok{}
			case 'o', 'O':
				// -o option-name / bash -O shopt_option: value is attached
				// or the next token.
				if j+1 == len(cluster) {
					i++
				}
				j = len(cluster) // value consumes the rest of the cluster
			default:
				// POSIX single-letter shell options are valueless, so
				// letters are safe to skip for POSIX shells. For strict
				// shells (fish/pwsh/nu/...) letter options may take values,
				// so any unrecognized option is ambiguous. Non-letter
				// characters (digits, punctuation) are never standard
				// options and are always ambiguous. Both fail closed.
				if strictFlagShells[shell] {
					return wordTok{}, false, false, true, wordTok{}
				}
				if !((cluster[j] >= 'a' && cluster[j] <= 'z') || (cluster[j] >= 'A' && cluster[j] <= 'Z')) {
					return wordTok{}, false, false, true, wordTok{}
				}
			}
		}
	}
	return wordTok{}, false, true, false, wordTok{} // no script source: stdin
}

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

// matchDestructive structurally matches the destructive-command class that
// the legacy needle list approximated, closing flag-order, wrapper and
// chaining evasions.
func (c *collector) matchDestructive(cmd Command, args []wordTok, via string, depth int) {
	switch {
	case cmd.Name == "rm":
		if c.recordRemoveWriteTargets(cmd.Name, args) {
			c.recordDestructiveEffect()
		}
		recursive, force, dynamicArg, endOptions := false, false, false, false
		for _, tok := range args[1:] {
			if tok.dynamic {
				// Any unresolved word may expand to "-rf" (word-splitting or
				// a destructive operand); fail closed even after `--`.
				dynamicArg = true
				continue
			}
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if endOptions {
				continue
			}
			isFlag := strings.HasPrefix(tok.text, "-") && tok.text != "-"
			if !isFlag {
				continue
			}
			if strings.HasPrefix(tok.text, "--") {
				switch {
				case strings.HasPrefix("--recursive", tok.text):
					recursive = true
				case strings.HasPrefix("--force", tok.text):
					force = true
				case tok.text != "--help" && tok.text != "--version" && tok.text != "--verbose" && tok.text != "--preserve-root" && tok.text != "--no-preserve-root":
					c.decide("rm with an unrecognized long option " + tok.text + " (fail-closed)")
					return
				}
				continue
			}
			for _, r := range tok.text[1:] {
				switch r {
				case 'r', 'R':
					recursive = true
				case 'f':
					force = true
				}
			}
		}
		if recursive {
			c.decide("recursive rm delete" + forceSuffix(force))
			return
		}
		if dynamicArg {
			c.decide("rm with arguments that cannot be resolved statically")
			return
		}
	case strings.HasPrefix(cmd.Name, "mkfs"):
		c.recordDestructiveEffect()
		c.decide("filesystem format command " + cmd.Name)
	case cmd.Name == "dd":
		for _, tok := range args[1:] {
			if tok.dynamic {
				c.decide("dd with an operand that cannot be resolved statically")
				return
			}
			if strings.HasPrefix(strings.ToLower(tok.text), "if=") {
				c.recordDestructiveEffect()
				c.decide("dd raw device/image read operand")
				return
			}
		}
	case cmd.Name == "git":
		c.matchGit(args, depth)
	case cmd.Name == "dropdb":
		c.recordDestructiveEffect()
		c.decide("dropdb destroys a database")
	case cmd.Name == "psql" || cmd.Name == "mysql":
		c.matchDatabaseClient(cmd.Name, args)
	case cmd.Name == "terraform":
		c.matchTerraform(args)
	case cmd.Name == "aws":
		c.matchAWS(args)
	case cmd.Name == "kubectl":
		sub, _, dynamic, found := firstSubcommand(args[1:], kubectlValueFlags, kubectlBoolFlags)
		if dynamic {
			c.decide("kubectl with a dynamic subcommand (fail-closed)")
			return
		}
		if found && sub == "delete" {
			c.recordDestructiveEffect()
			c.decide("kubectl delete")
		}
	case cmd.Name == "docker":
		c.matchDocker(args)
	case cmd.Name == "find":
		c.matchFind(args, via, depth)
	case cmd.Name == "awk" || cmd.Name == "gawk" || cmd.Name == "mawk" || cmd.Name == "nawk":
		c.matchAwk(args)
	case cmd.Name == "ssh":
		c.decide("ssh remote execution requires a decision")
	case cmd.Name == "cp" || cmd.Name == "mv" || cmd.Name == "install":
		c.recordCopyWrite(cmd.Name, args)
	case cmd.Name == "rmdir" || cmd.Name == "unlink":
		if c.recordRemoveWriteTargets(cmd.Name, args) {
			c.recordDestructiveEffect()
		}
	case cmd.Name == "cd" || cmd.Name == "pushd":
		c.changeDirectory(args[1:])
	case cmd.Name == "popd":
		c.cwdUnknown = true
	case cmd.Name == "tar":
		c.matchTar(args, via, depth)
	}
}

func (c *collector) matchAwk(args []wordTok) {
	for _, tok := range args[1:] {
		if tok.dynamic {
			c.decide("awk program cannot be resolved statically (fail-closed)")
			return
		}
		if strings.Contains(strings.ToLower(tok.text), "system(") {
			c.decide("awk system call requires a decision")
			return
		}
	}
}

func (c *collector) recordCopyWrite(name string, args []wordTok) {
	if len(args) >= 3 && args[len(args)-1].dynamic {
		c.recordWriteTarget(args[len(args)-1], name+" write")
		return
	}
	var operands []wordTok
	directoryMode := false
	for i := 1; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic {
			c.decide(name + " with an unresolvable target (fail-closed)")
			return
		}
		if tok.text == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		switch tok.text {
		case "-t", "--target-directory":
			if i+1 >= len(args) {
				c.decide(name + " with an unresolvable target (fail-closed)")
				return
			}
			for _, source := range args[i+2:] {
				c.recordCopyIntoDirectory(name, args[i+1], source)
			}
			return
		case "-d", "--directory":
			directoryMode = true
			continue
		}
		if strings.HasPrefix(tok.text, "--target-directory=") {
			directory := wordTok{text: strings.TrimPrefix(tok.text, "--target-directory=")}
			for _, source := range args[i+1:] {
				c.recordCopyIntoDirectory(name, directory, source)
			}
			return
		}
		if !strings.HasPrefix(tok.text, "-") || tok.text == "-" {
			operands = append(operands, tok)
		}
	}
	if directoryMode {
		for _, target := range operands {
			c.recordWriteTarget(target, name+" write")
		}
		return
	}
	if len(operands) >= 2 {
		destination := operands[len(operands)-1]
		if c.copyDestinationIsDirectory(destination) {
			for _, source := range operands[:len(operands)-1] {
				c.recordCopyIntoDirectory(name, destination, source)
			}
			return
		}
		c.recordWriteTarget(destination, name+" write")
	}
}

// copyDestinationIsDirectory resolves static destinations against the event
// CWD when it is available. A protected directory name remains conservative
// when the path cannot be resolved (for example, because the scanner is used
// without CWD or a concurrent filesystem change makes the lookup stale): it
// is treated as a directory so copying hooks/settings cannot bypass routing.
func (c *collector) copyDestinationIsDirectory(destination wordTok) bool {
	if destination.dynamic {
		return false
	}
	if strings.HasSuffix(destination.text, "/") {
		return true
	}
	if c.cwd != "" {
		if info, err := os.Stat(c.normalizedPath(destination.text)); err == nil && info.IsDir() {
			return true
		}
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(destination.text, `\`, "/")))
	return base == ".codex" || base == ".claude" || base == ".git"
}

func (c *collector) recordCopyIntoDirectory(name string, directory, source wordTok) {
	c.recordWriteTarget(wordTok{
		text:    path.Join(directory.text, path.Base(source.text)),
		dynamic: directory.dynamic || source.dynamic,
	}, name+" write")
}

func (c *collector) recordRemoveWriteTargets(name string, args []wordTok) bool {
	foundTarget := false
	endOptions := false
	for _, tok := range args[1:] {
		if tok.dynamic {
			continue // Static targets only; opaque shell remains advisory.
		}
		if !endOptions {
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if strings.HasPrefix(tok.text, "-") && tok.text != "-" {
				continue
			}
		}
		c.recordWriteTarget(tok, name+" remove")
		foundTarget = true
	}
	return foundTarget
}

func (c *collector) matchTar(args []wordTok, via string, depth int) {
	for i, tok := range args[1:] {
		if tok.dynamic {
			continue
		}
		payload := ""
		switch {
		case strings.HasPrefix(tok.text, "--checkpoint-action="):
			payload = strings.TrimPrefix(tok.text, "--checkpoint-action=")
		case tok.text == "--checkpoint-action":
			if i+2 >= len(args) || args[i+2].dynamic {
				c.decide("tar checkpoint action cannot be resolved statically (fail-closed)")
				return
			}
			payload = args[i+2].text
		}
		if strings.HasPrefix(payload, "exec=") {
			c.classifyString(strings.TrimPrefix(payload, "exec="), joinVia(via, "tar checkpoint"), depth+1)
			if c.decideFlag {
				c.decide("tar checkpoint action requires a decision")
			}
			return
		}
	}
}

func forceSuffix(force bool) string {
	if force {
		return " (forced)"
	}
	return ""
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

// firstSubcommand finds the first positional token, skipping flags and the
// values of known value-flags. dynamic is true when scanning hit a word that
// cannot be resolved statically (the subcommand may be hidden).
func firstSubcommand(args []wordTok, vals, bools map[string]bool) (sub string, index int, dynamic, found bool) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic {
			return "", -1, true, false
		}
		if tok.text == "--" {
			if i+1 < len(args) && !args[i+1].dynamic {
				return args[i+1].text, i + 1, false, true
			}
			if i+1 < len(args) {
				return "", -1, true, false
			}
			return "", -1, false, false
		}
		if strings.HasPrefix(tok.text, "-") && tok.text != "-" {
			if vals[tok.text] {
				if i+1 >= len(args) || args[i+1].dynamic {
					return "", -1, true, false
				}
				i++
				continue
			}
			if bools[tok.text] {
				continue
			}
			if flag, value, attached := strings.Cut(tok.text, "="); attached && vals[flag] && value != "" {
				continue
			}
			return "", -1, true, false
		}
		return tok.text, i, false, true
	}
	return "", -1, false, false
}

func (c *collector) matchGit(args []wordTok, depth int) {
	sub, subIndex, dynamic, found := firstSubcommand(args[1:], gitValueFlags, gitBoolFlags)
	if dynamic {
		c.decide("git invocation with a dynamic subcommand (fail-closed)")
		return
	}
	if !found {
		return
	}
	rest := args[1:]
	configs, ambiguous := gitConfigEntries(rest[:subIndex])
	if ambiguous {
		c.decide("git -c configuration cannot be resolved statically (fail-closed)")
		return
	}
	cleanForceDisabled := false
	for _, config := range configs {
		key, value, ok := strings.Cut(config.text, "=")
		if !ok {
			c.decide("git -c configuration is malformed (fail-closed)")
			return
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "clean.requireforce" {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "false", "0", "no", "off":
				cleanForceDisabled = true
			}
		}
		if strings.TrimPrefix(key, "alias.") == strings.ToLower(sub) {
			if strings.HasPrefix(value, "!") {
				c.classifyString(strings.TrimPrefix(value, "!"), "git alias "+sub, depth+1)
				if c.decideFlag {
					c.decide("git shell alias requires a decision")
				}
				return
			}
			// Ordinary Git aliases expand to Git arguments rather than a shell
			// snippet. Preserve the Git command so force-push and other native
			// rules classify the expanded invocation instead of treating "push"
			// as an unknown executable.
			c.classifyString("git "+value, "git alias "+sub, depth+1)
			if c.decideFlag {
				c.decide("git alias requires a decision")
			}
			return
		}
	}
	switch sub {
	case "reset":
		endOptions := false
		for _, tok := range rest {
			if tok.dynamic {
				c.decide("git reset with unresolvable flags (fail-closed)")
				return
			}
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if endOptions {
				continue
			}
			if tok.text == "--hard" {
				c.recordDestructiveEffect()
				c.decide("git reset --hard")
				return
			}
		}
	case "clean":
		force, dirs, endOptions := false, false, false
		for _, tok := range rest {
			if tok.dynamic {
				c.decide("git clean with unresolvable flags (fail-closed)")
				return
			}
			if tok.text == "--" {
				endOptions = true
				continue
			}
			if endOptions || !strings.HasPrefix(tok.text, "-") {
				continue
			}
			if tok.text == "--force" {
				force = true
				continue
			}
			if strings.HasPrefix(tok.text, "--") {
				continue
			}
			for _, r := range tok.text[1:] {
				switch r {
				case 'f':
					force = true
				case 'd':
					dirs = true
				}
			}
		}
		if dirs && (force || cleanForceDisabled) {
			c.recordDestructiveEffect()
			c.decide("git clean with forced directory delete")
		}
	case "push":
		c.matchGitPush(rest[subIndex+1:])
	}
}

// matchGitPush handles every statically visible force-push form. A lease
// based on a mutable remote-tracking ref is not an immutable proof, so even
// explicit --force-with-lease forms must reach the signed decision path.
func (c *collector) matchGitPush(args []wordTok) {
	for _, tok := range args {
		if tok.dynamic {
			c.decide("git push with unresolvable arguments (fail-closed)")
			return
		}
		if strings.HasPrefix(tok.text, "--force") || strings.HasPrefix("--force", tok.text) {
			c.recordDestructiveEffect()
			c.decide("git push force option requires a decision")
			return
		}
		if strings.HasPrefix(tok.text, "-") && !strings.HasPrefix(tok.text, "--") {
			for _, flag := range tok.text[1:] {
				if flag == 'f' {
					c.recordDestructiveEffect()
					c.decide("git push force option requires a decision")
					return
				}
			}
		}
		if strings.HasPrefix(tok.text, "+") {
			c.recordDestructiveEffect()
			c.decide("git push forced refspec requires a decision")
			return
		}
	}
}

func (c *collector) matchTerraform(args []wordTok) {
	sub, subIndex, dynamic, found := firstSubcommand(args[1:], nil, nil)
	if dynamic {
		c.decide("terraform invocation with a dynamic subcommand (fail-closed)")
		return
	}
	if !found {
		return
	}
	rest := args[subIndex+2:]
	for _, tok := range rest {
		if tok.dynamic {
			c.decide("terraform " + sub + " with unresolvable arguments (fail-closed)")
			return
		}
	}
	switch sub {
	case "destroy":
		c.recordDestructiveEffect()
		c.decide("terraform destroy")
	case "apply":
		for _, tok := range rest {
			if tok.text == "-destroy" || tok.text == "--destroy" || strings.HasPrefix(tok.text, "-destroy=") || strings.HasPrefix(tok.text, "--destroy=") {
				c.recordDestructiveEffect()
				c.decide("terraform apply -destroy")
				return
			}
		}
	}
}

func (c *collector) matchAWS(args []wordTok) {
	service, serviceIndex, dynamic, found := firstSubcommand(args[1:], awsValueFlags, awsBoolFlags)
	if dynamic {
		c.decide("aws invocation with a dynamic service (fail-closed)")
		return
	}
	if !found || service != "s3" {
		return
	}
	operation, _, dynamic, found := firstSubcommand(args[serviceIndex+2:], nil, nil)
	if dynamic {
		c.decide("aws s3 invocation with a dynamic operation (fail-closed)")
		return
	}
	if found && operation == "rm" {
		c.recordDestructiveEffect()
		c.decide("aws s3 rm")
	}
}

func (c *collector) matchDatabaseClient(name string, args []wordTok) {
	foundQuery := false
	for i := 1; i < len(args); i++ {
		tok := args[i]
		if tok.dynamic {
			c.decide(name + " with an unresolvable argument (fail-closed)")
			return
		}
		query := ""
		switch {
		case tok.text == "-c" || tok.text == "--command" || tok.text == "-e" || tok.text == "--execute":
			if i+1 >= len(args) || args[i+1].dynamic {
				c.decide(name + " with an unresolvable query (fail-closed)")
				return
			}
			query = args[i+1].text
			i++
		case strings.HasPrefix(tok.text, "--command="):
			query = strings.TrimPrefix(tok.text, "--command=")
		case strings.HasPrefix(tok.text, "--execute="):
			query = strings.TrimPrefix(tok.text, "--execute=")
		}
		if query == "" {
			continue
		}
		foundQuery = true
		if sqlHasDropDatabase(query) {
			c.recordDestructiveEffect()
			c.decide(name + " DROP DATABASE")
			return
		}
	}
	if !foundQuery && !databaseClientHelpOnly(args) {
		c.decide(name + " input cannot be resolved statically (fail-closed)")
	}
}

func databaseClientHelpOnly(args []wordTok) bool {
	return len(args) == 2 && !args[1].dynamic && (args[1].text == "--help" || args[1].text == "--version" || args[1].text == "-?")
}

func sqlHasDropDatabase(query string) bool {
	query = strings.ToLower(query)
	if sqlHasDropDatabaseWords(query) || sqlHasDropDatabaseWords(stripSQLComments(query)) {
		return true
	}
	// SQL dialects support several string and quoting forms. If a query has a
	// DROP token and comment syntax that this lightweight normalizer cannot
	// prove is inert, send it to the decision path instead of risking a bypass.
	return (strings.Contains(query, "--") || strings.Contains(query, "/*")) && sqlHasDropWord(query)
}

func sqlHasDropDatabaseWords(query string) bool {
	words := sqlWords(query)
	for i := 0; i+1 < len(words); i++ {
		if words[i] == "drop" && words[i+1] == "database" {
			return true
		}
	}
	return false
}

func sqlHasDropWord(query string) bool {
	for _, word := range sqlWords(query) {
		if word == "drop" {
			return true
		}
	}
	return false
}

func sqlWords(query string) []string {
	return strings.FieldsFunc(query, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_')
	})
}

func stripSQLComments(query string) string {
	for {
		start := strings.Index(query, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(query[start+2:], "*/")
		if end < 0 {
			return query[:start]
		}
		query = query[:start] + " " + query[start+end+4:]
	}
	lines := strings.Split(query, "\n")
	for i, line := range lines {
		if comment := strings.Index(line, "--"); comment >= 0 {
			lines[i] = line[:comment]
		}
	}
	return strings.Join(lines, "\n")
}

func gitConfigEntries(args []wordTok) ([]wordTok, bool) {
	var entries []wordTok
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok.text == "-c" {
			if i+1 >= len(args) || args[i+1].dynamic {
				return nil, true
			}
			entries = append(entries, args[i+1])
			i++
			continue
		}
		if !tok.dynamic && strings.HasPrefix(tok.text, "-c") && len(tok.text) > 2 {
			entries = append(entries, wordTok{text: tok.text[2:]})
		}
	}
	return entries, false
}

func (c *collector) matchDocker(args []wordTok) {
	sub, subIndex, dynamic, found := firstSubcommand(args[1:], dockerValueFlags, nil)
	if dynamic {
		c.decide("docker invocation with a dynamic subcommand (fail-closed)")
		return
	}
	if !found {
		return
	}
	rest := args[1:]
	isRm := sub == "rm"
	if sub == "container" {
		next, _, nextDynamic, nextFound := firstSubcommand(rest[subIndex+1:], nil, nil)
		if nextDynamic {
			c.decide("docker container with a dynamic subcommand (fail-closed)")
			return
		}
		if nextFound && next == "rm" {
			isRm = true
		}
	}
	if !isRm {
		return
	}
	endOptions := false
	for _, tok := range rest {
		if tok.dynamic {
			c.decide("docker rm with unresolvable flags (fail-closed)")
			return
		}
		if tok.text == "--" {
			endOptions = true
			continue
		}
		if endOptions {
			continue
		}
		if tok.text == "--force" {
			c.recordDestructiveEffect()
			c.decide("docker rm --force")
			return
		}
		if strings.HasPrefix(tok.text, "-") && !strings.HasPrefix(tok.text, "--") {
			for _, r := range tok.text[1:] {
				if r == 'f' {
					c.recordDestructiveEffect()
					c.decide("docker rm -f")
					return
				}
			}
		}
	}
}

func (c *collector) matchFind(args []wordTok, via string, depth int) {
	for i, tok := range args[1:] {
		if tok.dynamic {
			c.decide("find with a dynamic expression (fail-closed)")
			return
		}
		if tok.text == "-delete" {
			c.recordDestructiveEffect()
			c.decide("find -delete")
			return
		}
		if tok.text == "-exec" || tok.text == "-execdir" || tok.text == "-ok" || tok.text == "-okdir" {
			// Recursively classify the exec payload (terminated by ";" or
			// "+") so wrappers such as sh -c cannot hide destructive work.
			payload := append([]wordTok(nil), args[i+2:]...)
			end := len(payload)
			for j, p := range payload {
				if !p.dynamic && (p.text == ";" || p.text == "+") {
					end = j
					break
				}
				if p.dynamic {
					c.decide("find " + tok.text + " with a dynamic payload (fail-closed)")
					return
				}
				if p.text == "{}" {
					payload[j].dynamic = true
				}
			}
			if end == 0 {
				c.decide("find " + tok.text + " without a command (fail-closed)")
				return
			}
			c.classifyTokens(payload[:end], joinVia(via, "find "+tok.text), depth+1)
			if c.decideFlag {
				c.decide("find " + tok.text + " payload requires a decision")
				return
			}
			return
		}
	}
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
