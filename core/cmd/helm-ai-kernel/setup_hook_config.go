package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	resyntax "regexp/syntax"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
	"mvdan.cc/sh/v3/syntax"
)

// populateSetupPolicyProfileDigest validates a custom policy before setup
// writes a hook command, then records the exact raw-file digest that the hook
// must continue to see on every later decision. Re-running setup is the
// explicit operator approval path for a changed policy file.
func populateSetupPolicyProfileDigest(opts *setupOptions) error {
	opts.PolicyProfileSHA256 = ""
	if strings.TrimSpace(opts.PolicyProfile) == "" {
		return nil
	}
	_, digest, err := workstation.LoadPolicyProfileFileWithDigest(opts.PolicyProfile)
	if err != nil {
		return err
	}
	opts.PolicyProfileSHA256 = digest
	return nil
}

// discoverSetupStatusPolicyProfile recovers a custom profile only from one
// matching, statically parseable installed hook. The later status comparison
// still uses the full current command, including the recomputed digest.
func discoverSetupStatusPolicyProfile(opts *setupOptions, path, bin string) error {
	expectedKey := hookCommandKey(setupHookCommand(*opts, bin))
	var commands []string
	if opts.Target == "hermes" {
		commands = hermesInstalledHookCommands(path)
	} else if opts.Target == "deepseek" {
		commands = deepseekInstalledHookCommands(path)
	} else {
		root, err := readJSONObject(path)
		if err != nil {
			return fmt.Errorf("read hook config: %w", err)
		}
		hooks, ok := root["hooks"].(map[string]any)
		if !ok {
			return nil
		}
		for _, item := range arrayValue(hooks, "PreToolUse") {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for _, hook := range arrayValue(obj, "hooks") {
				if command := hookCommandFromAny(hook); command != "" {
					commands = append(commands, command)
				}
			}
		}
	}
	var profilePath, matchedCommand string
	matched := false
	for _, command := range commands {
		if hookCommandKey(command) != expectedKey {
			continue
		}
		if matched {
			// The same command in another entry names the same profile;
			// only commands that differ leave the profile in doubt.
			if command == matchedCommand {
				continue
			}
			return fmt.Errorf("ambiguous matching installed hook commands")
		}
		matchedCommand = command
		profile, _, custom, err := installedHookPolicyProfile(command)
		if err != nil {
			return fmt.Errorf("parse matching installed hook command: %w", err)
		}
		matched = true
		if custom {
			profilePath = profile
		}
	}
	if profilePath != "" {
		opts.PolicyProfile = profilePath
	}
	return nil
}

func installedHookPolicyProfile(command string) (profile, digest string, custom bool, err error) {
	words, err := staticSetupHookWords(command)
	if err != nil {
		return "", "", false, err
	}
	seenProfile, seenDigest := false, false
	for i := 0; i < len(words); i++ {
		if words[i] != "--policy-profile" && words[i] != "--policy-profile-sha256" {
			continue
		}
		if i+1 == len(words) || words[i+1] == "--policy-profile" || words[i+1] == "--policy-profile-sha256" {
			return "", "", false, fmt.Errorf("%s requires one static argument", words[i])
		}
		i++
		if words[i-1] == "--policy-profile" {
			if seenProfile {
				return "", "", false, errors.New("duplicate --policy-profile")
			}
			profile, seenProfile = words[i], true
		} else {
			if seenDigest {
				return "", "", false, errors.New("duplicate --policy-profile-sha256")
			}
			digest, seenDigest = words[i], true
		}
	}
	if seenProfile != seenDigest || (seenProfile && (profile == "" || digest == "")) {
		return "", "", false, errors.New("matching installed hook has unpaired --policy-profile arguments")
	}
	return profile, digest, seenProfile, nil
}

func staticSetupHookWords(command string) ([]string, error) {
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, err
	}
	if len(file.Stmts) != 1 {
		return nil, fmt.Errorf("must contain one command")
	}
	stmt := file.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || len(stmt.Redirs) != 0 {
		return nil, fmt.Errorf("must be a direct command without shell operators")
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return nil, fmt.Errorf("must be a direct static command")
	}
	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		value, ok := staticSetupHookWord(word)
		if !ok {
			return nil, fmt.Errorf("contains a non-static argument")
		}
		words = append(words, value)
	}
	return words, nil
}

func staticSetupHookWord(word *syntax.Word) (string, bool) {
	var value strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			value.WriteString(unescapeSetupHookLiteral(part.Value))
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			value.WriteString(part.Value)
		case *syntax.DblQuoted:
			if part.Dollar {
				return "", false
			}
			for _, inner := range part.Parts {
				literal, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				value.WriteString(literal.Value)
			}
		default:
			return "", false
		}
	}
	return value.String(), true
}

func unescapeSetupHookLiteral(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

func installSetupHook(opts setupOptions, bin string) error {
	if opts.Target == "hermes" {
		return upsertHermesHookConfig(setupHookConfigPath(opts), setupHookMatcher(opts.Target), setupHookCommand(opts, bin), setupPrivateFileRoot(opts))
	}
	if opts.Target == "deepseek" {
		hookPath := setupHookConfigPath(opts)
		if err := upsertDeepSeekHookConfig(hookPath, setupHookMatcher(opts.Target), setupHookCommand(opts, bin), setupPrivateFileRoot(opts)); err != nil {
			return err
		}
		return upsertDeepSeekProfile(setupClientConfigPath(opts), hookPath, setupPrivateFileRoot(opts))
	}
	return upsertHookConfig(setupHookConfigPath(opts), setupHookMatcher(opts.Target), setupHookCommand(opts, bin), setupPrivateFileRoot(opts))
}

func removeSetupHook(opts setupOptions, bin string) error {
	if opts.Target == "hermes" {
		return removeHermesHookConfig(setupHookConfigPath(opts), setupHookCommand(opts, bin), setupPrivateFileRoot(opts))
	}
	if opts.Target == "deepseek" {
		hookPath := setupHookConfigPath(opts)
		if err := removeDeepSeekHookConfig(hookPath, setupHookCommand(opts, bin), setupPrivateFileRoot(opts)); err != nil {
			return err
		}
		return removeDeepSeekProfile(setupClientConfigPath(opts), hookPath, setupPrivateFileRoot(opts))
	}
	return removeHookConfig(setupHookConfigPath(opts), setupHookCommand(opts, bin), setupPrivateFileRoot(opts))
}

func setupHookInstalled(opts setupOptions, path, bin string) bool {
	if filepath.Clean(path) != filepath.Clean(setupHookConfigPath(opts)) {
		return false
	}
	readPath := path
	if root := setupPrivateFileRoot(opts); root != "" {
		resolved, err := privateFileWritePath(path, root)
		if err != nil {
			return false
		}
		readPath = resolved
	}
	if opts.Target == "hermes" {
		return hermesHookInstalled(readPath, setupHookCommand(opts, bin))
	}
	if opts.Target == "deepseek" {
		command := setupHookCommand(opts, bin)
		if !deepseekHookInstalled(readPath, command) {
			return false
		}
		return deepseekProfileInstalled(setupClientConfigPath(opts), readPath)
	}
	config, err := readJSONObject(readPath)
	if err != nil {
		return false
	}
	hooks, ok := config["hooks"].(map[string]any)
	if !ok {
		return false
	}
	return hookCommandConfigPresent(arrayValue(hooks, "PreToolUse"), setupHookCommand(opts, bin))
}

func setupHookConfigPath(opts setupOptions) string {
	switch opts.Target {
	case "claude-code":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".claude", "settings.json")
		}
		return setupUserPath(".claude", "settings.json")
	case "codex":
		if opts.Scope == "project" {
			return filepath.Join(opts.Workspace, ".codex", "hooks.json")
		}
		return setupUserPath(".codex", "hooks.json")
	case "hermes":
		return hermesConfigPath(opts)
	case "deepseek":
		return deepseekHookPath(opts)
	default:
		return ""
	}
}

// setupHookMatcher lists the tools a client sends to the hook. A tool left out
// is never seen. The list holds the client's tools that run a command or
// code, write a file, read one, fetch a URL or call an MCP server, as far as
// the hook has a class for them. The tools left out are named in CTL-035
// bypass_assumptions and in docs/INTEGRATIONS/<client>.md:
//   - Claude Code: WebSearch (it names no URL, so the hook could only refuse
//     it), Task (a subagent, whose own tool calls reach the hook) and
//     TodoWrite (the client's own task list).
//   - Hermes: web_search, skill_manage, memory, cronjob_manage and
//     process_manage, which the hook has no class for.
func setupHookMatcher(target string) string {
	switch target {
	case "codex":
		return "^(Bash|apply_patch|mcp__.*)$"
	case "hermes":
		return "^(terminal|write_file|patch|read_file|search_files|web_extract|execute_code|browser_navigate|vision_analyze|mcp_.*)$"
	case "deepseek":
		return "^(bash|write|edit|read|grep|glob|webfetch|mcp_.*)$"
	default:
		return "^(Bash|Edit|Write|MultiEdit|NotebookEdit|Read|Grep|Glob|WebFetch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*)$"
	}
}

// setupHookMatcherTools lists concrete tools and the MCP family pattern.
// A single example name cannot establish coverage of that family.
func setupHookMatcherTools(target string) []string {
	body := strings.TrimSuffix(strings.TrimPrefix(setupHookMatcher(target), "^("), ")$")
	return strings.Split(body, "|")
}

// setupHookMatcherMissing lists the tools this release routes to the hook
// that matcher does not route.
func setupHookMatcherMissing(target, matcher string) []string {
	return setupHookMatchersMissing(target, []string{matcher})
}

// setupHookMatchersMissing lists the tools this release routes to the hook
// that none of matchers routes: a tool reaches the hook when any entry that
// holds it routes the tool.
func setupHookMatchersMissing(target string, matchers []string) []string {
	var missing []string
	for _, tool := range setupHookMatcherTools(target) {
		routed := false
		for _, matcher := range matchers {
			if setupMatcherCoversTool(target, matcher, tool) {
				routed = true
				break
			}
		}
		if !routed {
			missing = append(missing, tool)
		}
	}
	return missing
}

// setupMatcherCoversTool proves family coverage only for simple unrestricted
// prefix branches. More complex custom expressions remain unverified; sampling
// any finite set of MCP names cannot prove that future names reach the hook.
func setupMatcherCoversTool(target, matcher, tool string) bool {
	if tool != "mcp__.*" && tool != "mcp_.*" {
		return setupMatcherRoutes(target, matcher, tool)
	}
	if matcher == "" || matcher == "*" {
		return true
	}
	if target == "claude-code" && claudePlainMatcher.MatchString(matcher) {
		return false
	}
	re, err := resyntax.Parse(matcher, resyntax.Perl)
	return err == nil && setupRegexCoversMCP(re, strings.TrimSuffix(tool, ".*"), false, false)
}

func setupRegexCoversMCP(re *resyntax.Regexp, prefix string, start, end bool) bool {
	switch re.Op {
	case resyntax.OpCapture:
		return setupRegexCoversMCP(re.Sub[0], prefix, start, end)
	case resyntax.OpAlternate:
		for _, branch := range re.Sub {
			if setupRegexCoversMCP(branch, prefix, start, end) {
				return true
			}
		}
	case resyntax.OpConcat:
		parts := re.Sub
		if parts[0].Op == resyntax.OpBeginText || parts[0].Op == resyntax.OpBeginLine {
			start, parts = true, parts[1:]
		}
		if len(parts) > 0 && (parts[len(parts)-1].Op == resyntax.OpEndText || parts[len(parts)-1].Op == resyntax.OpEndLine) {
			end, parts = true, parts[:len(parts)-1]
		}
		if len(parts) == 1 {
			return setupRegexCoversMCP(parts[0], prefix, start, end)
		}
		if len(parts) == 2 && parts[0].Op == resyntax.OpLiteral && parts[1].Op == resyntax.OpStar {
			wildcard := parts[1].Sub[0].Op
			return strings.HasPrefix(prefix, string(parts[0].Rune)) && (wildcard == resyntax.OpAnyChar || wildcard == resyntax.OpAnyCharNotNL)
		}
	case resyntax.OpLiteral:
		literal := string(re.Rune)
		return !end && ((!start && strings.Contains(prefix, literal)) || strings.HasPrefix(prefix, literal))
	case resyntax.OpStar:
		return re.Sub[0].Op == resyntax.OpAnyChar || re.Sub[0].Op == resyntax.OpAnyCharNotNL
	case resyntax.OpEmptyMatch:
		return !end
	}
	return false
}

// claudePlainMatcher is the matcher Claude Code reads as tool names rather
// than as a regular expression: letters, digits, "_" and "|" only.
var claudePlainMatcher = regexp.MustCompile(`^[A-Za-z0-9_|]+$`)

// setupMatcherRoutes reports whether a client sends tool to a hook entry with
// this matcher. An empty matcher or "*" routes every tool. Claude Code reads
// a matcher of plain names as a list of exact names separated by "|" and any
// other matcher as a regular expression that may match anywhere in the name,
// and setup reads a Claude Code matcher the same way. The matchers of the
// other clients are read as regular expressions that may match anywhere in
// the name; a client that anchors them, or reads a plain name exactly,
// routes no more than setup reports, and may route less. A matcher that does
// not compile routes no tool.
func setupMatcherRoutes(target, matcher, tool string) bool {
	if matcher == "" || matcher == "*" {
		return true
	}
	if target == "claude-code" && claudePlainMatcher.MatchString(matcher) {
		for _, name := range strings.Split(matcher, "|") {
			if name == tool {
				return true
			}
		}
		return false
	}
	compiled, err := regexp.Compile(matcher)
	return err == nil && compiled.MatchString(tool)
}

// setupHookEntry is one hook entry that holds the HELM hook: its matcher and
// whether it also holds other hooks.
type setupHookEntry struct {
	matcher string
	shared  bool
}

// setupInstalledHookEntries reads the client's hook configuration for the
// entries that hold the HELM hook.
func setupInstalledHookEntries(opts setupOptions, path, bin string) []setupHookEntry {
	readPath := path
	if root := setupPrivateFileRoot(opts); root != "" {
		resolved, err := privateFileWritePath(path, root)
		if err != nil {
			return nil
		}
		readPath = resolved
	}
	key := hookCommandKey(setupHookCommand(opts, bin))
	var entries []setupHookEntry
	if opts.Target == "hermes" {
		root, err := readYAMLObject(readPath)
		if err != nil {
			return nil
		}
		for _, item := range hermesPreToolCallEntries(hermesHooksMap(root)) {
			if obj, ok := item.(map[string]any); ok && hookCommandKey(yamlString(obj["command"])) == key {
				entries = append(entries, setupHookEntry{matcher: yamlString(obj["matcher"])})
			}
		}
		return entries
	}
	root, err := readJSONObject(readPath)
	if err != nil {
		return nil
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	for _, item := range arrayValue(hooks, "PreToolUse") {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hookItems, _ := obj["hooks"].([]any)
		for _, h := range hookItems {
			if hookCommandKey(hookCommandFromAny(h)) == key {
				matcher, _ := obj["matcher"].(string)
				entries = append(entries, setupHookEntry{matcher: matcher, shared: len(hookItems) > 1})
				break
			}
		}
	}
	return entries
}

// observeSetupHookMatcher reports the matcher of an installed hook and
// whether it routes every tool this release routes. An outdated matcher
// leaves calls the hook would decide unseen, so the install is degraded.
func observeSetupHookMatcher(opts setupOptions, summary *setupSummary) {
	if !summary.HookInstalled {
		return
	}
	entries := setupInstalledHookEntries(opts, summary.HookConfigPath, summary.BinaryPath)
	if len(entries) == 0 {
		return
	}
	matchers := setupHookEntryMatchers(entries)
	summary.HookMatcher = matchers[0]
	summary.HookMatchers = matchers
	summary.HookMatcherExpected = setupHookMatcher(opts.Target)
	summary.HookMatcherMissingTools = setupHookMatchersMissing(opts.Target, matchers)
	summary.HookMatcherOutdated = len(summary.HookMatcherMissingTools) > 0
	if !summary.HookMatcherOutdated {
		return
	}
	summary.ClientState = "degraded"
	summary.Lifecycle = ""
	// setup rewrites the matcher of an entry that holds only the HELM hook.
	// An entry it shares with other hooks is the user's own, so for one of
	// those the fix is an edit, which the warning names.
	for _, entry := range entries {
		if !entry.shared {
			summary.HookMatcherUpgradeCommand = setupUpgradeCommand(opts)
			return
		}
	}
	summary.Warnings = append(summary.Warnings, setupSharedHookEntryWarnings(opts, summary.HookConfigPath, summary.BinaryPath)...)
}

func setupHookEntryMatchers(entries []setupHookEntry) []string {
	matchers := make([]string, 0, len(entries))
	for _, entry := range entries {
		matchers = append(matchers, entry.matcher)
	}
	return matchers
}

// setupSharedHookEntryWarnings names each hook entry that holds the HELM
// hook beside other hooks and does not route every tool this release routes.
// setup does not rewrite such an entry: its matcher also decides which calls
// reach the user's other hooks.
func setupSharedHookEntryWarnings(opts setupOptions, path, bin string) []string {
	entries := setupInstalledHookEntries(opts, path, bin)
	// A tool another entry routes to the hook reaches it anyway, so only the
	// tools no entry routes are named.
	missing := setupHookMatchersMissing(opts.Target, setupHookEntryMatchers(entries))
	if len(missing) == 0 {
		return nil
	}
	var warnings []string
	for _, entry := range entries {
		if !entry.shared || len(setupHookMatcherMissing(opts.Target, entry.matcher)) == 0 {
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s: the hook entry with matcher %s also holds other hooks, so setup left its matcher alone; coverage of %s is missing or unverified. Set its matcher to %s, or move the HELM hook into an entry of its own and run setup again.",
			path, entry.matcher, strings.Join(missing, ", "), setupHookMatcher(opts.Target)))
	}
	return warnings
}

func setupHookCommand(opts setupOptions, bin string) string {
	command := shellQuote(bin) + " hook pre-tool --client " + opts.Target + " --data-dir " + shellQuote(opts.DataDir)
	if strings.TrimSpace(opts.SigningSeedFile) != "" {
		command += " --signing-seed-file " + shellQuote(opts.SigningSeedFile)
	}
	if strings.TrimSpace(opts.PolicyProfile) != "" {
		command += " --policy-profile " + shellQuote(opts.PolicyProfile)
		if strings.TrimSpace(opts.PolicyProfileSHA256) != "" {
			command += " --policy-profile-sha256 " + shellQuote(opts.PolicyProfileSHA256)
		}
	}
	return command
}

func upsertHookConfig(path, matcher, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, "PreToolUse")
	if hookCommandPresent(pre, command) {
		// Same hook identity: rewrite the stored command in place so a
		// re-install with a new --signing-seed-file updates the config
		// instead of silently keeping the old seed path.
		key := hookCommandKey(command)
		for _, item := range pre {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			hookItems, ok := obj["hooks"].([]any)
			if !ok {
				continue
			}
			for _, h := range hookItems {
				hookObj, ok := h.(map[string]any)
				if !ok {
					continue
				}
				if hookCommandKey(hookCommandFromAny(h)) == key {
					hookObj["command"] = command
					// An entry that holds only this hook takes the current
					// matcher too, so a re-install routes the tools a newer
					// release classifies. A shared entry is the user's own.
					if len(hookItems) == 1 {
						obj["matcher"] = matcher
					}
				}
			}
		}
		return writeJSONObject(path, root, allowedRoot)
	}
	entry := map[string]any{
		"matcher": matcher,
		"hooks": []any{
			map[string]any{
				"type":          "command",
				"command":       command,
				"timeout":       float64(30),
				"statusMessage": "Checking HELM policy",
			},
		},
	}
	hooks["PreToolUse"] = append(pre, entry)
	root["hooks"] = hooks
	return writeJSONObject(path, root, allowedRoot)
}

func removeHookConfig(path, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, "PreToolUse")
	filtered := make([]any, 0, len(pre))
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		hookItems, ok := obj["hooks"].([]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		keptHooks := make([]any, 0, len(hookItems))
		for _, h := range hookItems {
			if hookCommandKey(hookCommandFromAny(h)) != hookCommandKey(command) {
				keptHooks = append(keptHooks, h)
			}
		}
		if len(keptHooks) > 0 {
			obj["hooks"] = keptHooks
			filtered = append(filtered, obj)
		}
	}
	hooks["PreToolUse"] = filtered
	root["hooks"] = hooks
	return writeJSONObject(path, root, allowedRoot)
}

func objectValue(root map[string]any, key string) map[string]any {
	if obj, ok := root[key].(map[string]any); ok {
		return obj
	}
	obj := map[string]any{}
	root[key] = obj
	return obj
}

func arrayValue(root map[string]any, key string) []any {
	if arr, ok := root[key].([]any); ok {
		return arr
	}
	return []any{}
}

// hookManagedFileArgPattern matches optional managed arguments of an installed
// hook command, with their shell-quoted or bare arguments. The
// argument alternation mirrors shellQuote output: a sequence of
// single-quoted chunks, escaped quotes (the '\” idiom), and bare
// non-space characters.
var hookManagedFileArgPattern = regexp.MustCompile(` --(?:signing-seed-file|policy-profile|policy-profile-sha256) (?:'[^']*'|\\'|[^\s'])+`)

// hookSignerFileArgPattern omits only the signer source. A user may omit a
// secret seed path when inspecting setup, but policy path and digest must stay
// part of the status comparison so a stale custom policy is never reported as
// active.
var hookSignerFileArgPattern = regexp.MustCompile(` --signing-seed-file (?:'[^']*'|\\'|[^\s'])+`)

// hookCommandKey reduces an installed hook command to its generic identity
// for reinstall/remove. Managed arguments are deployment details, so `setup
// remove` must match the hook whether or not (and with whichever path form)
// they were passed on its own invocation.
func hookCommandKey(command string) string {
	return hookManagedFileArgPattern.ReplaceAllString(command, "")
}

// hookCommandConfigKey preserves the approved policy path and digest for
// status checks while allowing the signer source to remain private.
func hookCommandConfigKey(command string) string {
	return hookSignerFileArgPattern.ReplaceAllString(command, "")
}

func hookCommandPresent(pre []any, command string) bool {
	key := hookCommandKey(command)
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := obj["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range hooks {
			if hookCommandKey(hookCommandFromAny(h)) == key {
				return true
			}
		}
	}
	return false
}

func hookCommandConfigPresent(pre []any, command string) bool {
	key := hookCommandConfigKey(command)
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := obj["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range hooks {
			if hookCommandConfigKey(hookCommandFromAny(h)) == key {
				return true
			}
		}
	}
	return false
}

func hookCommandFromAny(v any) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	command, _ := obj["command"].(string)
	return command
}
