// quantum_posture: the destination-set digest in this file is a classical
// SHA-256 commitment; no signing or post-quantum primitive is used here.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
)

// hookToolKind is what a tool does, as far as the hook needs to know to pick
// the effect it decides on. A name the hook has not been taught is
// hookToolUnknown and is decided as such, never passed through.
type hookToolKind int

const (
	hookToolUnknown hookToolKind = iota
	hookToolShell
	hookToolWrite
	hookToolRead
	hookToolFetch
	hookToolMCP
	// hookToolCode runs code the hook cannot read as a command line.
	hookToolCode
	// hookToolImage loads an image from a URL or a local file.
	hookToolImage
	// hookToolMCPResource reads from an MCP server through the client
	// rather than through an mcp__server__tool name.
	hookToolMCPResource
)

// hookToolKinds maps the lower-cased tool names of the supported clients.
// Claude Code capitalises its names; Hermes and the DeepSeek harness do not.
var hookToolKinds = map[string]hookToolKind{
	"bash": hookToolShell, "terminal": hookToolShell,

	"edit": hookToolWrite, "write": hookToolWrite, "multiedit": hookToolWrite,
	"notebookedit": hookToolWrite, "apply_patch": hookToolWrite,
	"write_file": hookToolWrite, "patch": hookToolWrite,

	"read": hookToolRead, "notebookread": hookToolRead, "read_file": hookToolRead,
	"grep": hookToolRead, "glob": hookToolRead, "ls": hookToolRead,
	"search_files": hookToolRead, "list_files": hookToolRead,

	"webfetch": hookToolFetch, "web_fetch": hookToolFetch, "web_extract": hookToolFetch,
	"websearch": hookToolFetch, "web_search": hookToolFetch, "browser_navigate": hookToolFetch,

	"execute_code":   hookToolCode,
	"vision_analyze": hookToolImage,

	"readmcpresourcetool": hookToolMCPResource, "listmcpresourcestool": hookToolMCPResource,
}

func hookToolKindOf(tool string) hookToolKind {
	if strings.HasPrefix(tool, "mcp_") {
		return hookToolMCP
	}
	return hookToolKinds[strings.ToLower(tool)]
}

// workstationPathGuard names the files the local signer and its verifier
// depend on: the key directory of the data directory in use and of the
// default one, a seed supplied by flag, and the policy profile. The data
// directory itself is protected only when named directly, so receipts under
// it stay readable.
func workstationPathGuard(dataDir, seedFile, policyProfile string) *shellscan.PathGuard {
	guard := shellscan.NewPathGuard(homeDirOrEmpty())
	for _, dir := range []string{dataDir, defaultSetupDataDir()} {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		guard.ProtectTree(filepath.Join(dir, workstationSigningKeyDirectory))
		guard.ProtectContainer(dir)
	}
	guard.ProtectFile(seedFile)
	guard.ProtectFile(policyProfile)
	guard.ProtectName(workstationSigningSeedName)
	guard.ProtectName(workstationSigningPublicKeyName)
	return guard
}

// trustMaterialClassification is the one decision for a call that reaches
// the signer's own files. It replaces every other classification of the
// call: nothing else about it needs deciding once it is refused.
func trustMaterialClassification(tool, target string, metadata map[string]string) []hookClassification {
	return []hookClassification{{
		ShouldDecide:  true,
		Class:         "secret",
		Target:        target,
		Action:        "trust_material_access",
		ToolID:        firstNonEmptyString(tool, "secret.read"),
		Reason:        "access to HELM signing or trust material",
		Metadata:      metadata,
		TrustMaterial: true,
	}}
}

// kernelCLIName is the name setup installs the binary under.
const kernelCLIName = "helm-ai-kernel"

// signerInvocation reports a command that runs this binary to sign with the
// workstation key or to change the installed hook: setup (other than status
// or a dry run), hook, and the workstation subcommands that issue receipts.
// Those reach the signing material as surely as reading the seed does, and an
// agent has no task that needs them. The match is on the program name, so a
// renamed copy of the binary is not recognised.
func signerInvocation(commands []shellscan.Command) (string, bool) {
	names := map[string]bool{kernelCLIName: true}
	if executable, err := os.Executable(); err == nil {
		names[filepath.Base(executable)] = true
	}
	for _, command := range commands {
		if !names[command.Name] || len(command.Tokens) < 2 {
			continue
		}
		var operands []string
		dryRun := false
		for _, token := range command.Tokens[1:] {
			if strings.HasPrefix(token, "-") {
				dryRun = dryRun || token == "--dry-run" || token == "-dry-run"
				continue
			}
			operands = append(operands, token)
		}
		if command.Dynamic {
			// A computed argument can be any of the subcommands below.
			return kernelCLIName, true
		}
		if len(operands) == 0 {
			continue
		}
		next := ""
		if len(operands) > 1 {
			next = operands[1]
		}
		switch operands[0] {
		case "hook":
			return kernelCLIName + " hook", true
		case "setup":
			if next != "status" && !dryRun {
				return kernelCLIName + " setup", true
			}
		case "workstation":
			switch next {
			case "decide", "enforce", "import", "capture":
				return kernelCLIName + " workstation " + next, true
			}
		}
	}
	return "", false
}

// hookMaxEgressDestinations is the most destinations one call may name and
// still be decided one destination at a time. Past it the call is one
// undetermined decision: a client may run a call whose hook outlives its
// timeout, so the work and the receipts one call costs stay bounded.
const hookMaxEgressDestinations = 64

// hookMaxSecretTargets bounds the secret-read decisions of one call the same
// way: past it the call is one secret-read decision for all of them.
const hookMaxSecretTargets = 64

// shellClassifications turns a scan of a shell command, or of an argv that is
// about to be executed, into the decisions the call needs.
func shellClassifications(tool, command string, scan shellscan.Result) []hookClassification {
	metadata := shellscanReceiptMetadata(scan)
	if scan.ProtectedPath != "" {
		return trustMaterialClassification(tool, scan.ProtectedPath, metadata)
	}
	if target, ok := signerInvocation(scan.Commands); ok {
		return trustMaterialClassification(tool, target, metadata)
	}
	var destinations, secrets []string
	for _, fact := range scan.EffectFacts {
		switch fact.Class {
		case "network":
			destinations = append(destinations, fact.Target)
		case "secret":
			secrets = append(secrets, fact.Target)
		}
	}
	// The count and digest of the destination set are computed once and
	// copied into each network receipt of the call.
	binding := egressBinding(destinations)
	facts := capEffectFacts(scan.EffectFacts, len(destinations), len(secrets))
	classifications := make([]hookClassification, 0, len(facts)+2)
	for _, fact := range facts {
		if classification, ok := hookClassificationFromShellscanFact(fact, metadata); ok {
			switch fact.Class {
			case "network":
				maps.Copy(classification.Metadata, binding)
			case "secret":
				if len(secrets) > hookMaxSecretTargets {
					classification.Metadata["secret.target_count"] = strconv.Itoa(len(secrets))
				}
			}
			classifications = append(classifications, classification)
			continue
		}
		// A future scanner fact must never become an ungoverned effect just
		// because this hook has not learned its dedicated policy class yet.
		classifications = append(classifications, hookClassification{
			ShouldDecide: true,
			Class:        "shell-operate",
			Target:       command,
			Action:       "shell_operate",
			ToolID:       "shell",
			Reason:       "unrecognized shell effect fact",
			Metadata:     maps.Clone(metadata),
		})
	}
	if scan.RequiresShellDecision {
		classifications = append(classifications, shellscanGenericClassification(command, scan, metadata))
	}
	return appendRequiredShellPermission(classifications, command)
}

// capEffectFacts keeps the facts of a call that names no more destinations
// or secret paths than one call may. Past a limit the facts of that class
// become one: an undetermined destination, which no allowlist holds, or the
// first secret path, decided under the same permission as every other.
func capEffectFacts(facts []shellscan.EffectFact, destinations, secrets int) []shellscan.EffectFact {
	if destinations <= hookMaxEgressDestinations && secrets <= hookMaxSecretTargets {
		return facts
	}
	kept := make([]shellscan.EffectFact, 0, hookMaxEgressDestinations+hookMaxSecretTargets)
	network, secret := false, false
	for _, fact := range facts {
		switch {
		case fact.Class == "network" && destinations > hookMaxEgressDestinations:
			if network {
				continue
			}
			network = true
			fact = shellscan.EffectFact{
				Class:  "network",
				Action: "network_egress",
				Target: netdest.Undetermined,
				Reason: fmt.Sprintf("network egress: destination could not be determined (the call names %d destinations, more than the %d one call may name)", destinations, hookMaxEgressDestinations),
			}
		case fact.Class == "secret" && secrets > hookMaxSecretTargets:
			if secret {
				continue
			}
			secret = true
			fact.Reason = fmt.Sprintf("%s and %d other secret paths", fact.Reason, secrets-1)
		}
		kept = append(kept, fact)
	}
	return kept
}

// egressBinding is what every network receipt of a call records about the
// whole destination set: how many destinations the call names and a digest
// of the set. One receipt names one destination; the digest lets a reader
// holding it tell whether the others are in hand.
func egressBinding(destinations []string) map[string]string {
	sorted := slices.Clone(destinations)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return map[string]string{
		"egress.destination_count":      strconv.Itoa(len(sorted)),
		"egress.destination_set_sha256": "sha256:" + hex.EncodeToString(sum[:]),
	}
}

// hookToolStrings walks a tool input and calls visit for every string in it,
// with the key the string was found under. Keys are visited in order so the
// first match, and with it the receipt, is the same on every run.
func hookToolStrings(value any, key string, visit func(key, text string)) {
	switch typed := value.(type) {
	case string:
		visit(key, typed)
	case map[string]any:
		names := make([]string, 0, len(typed))
		for name := range typed {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			hookToolStrings(typed[name], name, visit)
		}
	case []any:
		for _, item := range typed {
			hookToolStrings(item, key, visit)
		}
	}
}

// writeContentKeys hold the text a write tool puts into a file. Mentioning a
// protected path in a file is not reaching it, so these are not searched.
var writeContentKeys = map[string]bool{
	"content": true, "new_string": true, "old_string": true, "new_source": true,
	"command": true, "cmd": true, "patch": true, "diff": true,
}

// globInputKeys hold glob syntax. A content search's "pattern" is a regular
// expression instead, which globToolPattern tells apart by the tool.
var globInputKeys = map[string]bool{"pattern": true, "glob": true, "include": true, "file_glob": true}

// globFilterKeys hold a filter the search applies to file names at any depth
// below its root, as ripgrep's --glob does. A Glob tool's "pattern" is
// anchored at the root instead.
var globFilterKeys = map[string]bool{"glob": true, "include": true, "file_glob": true}

func globToolPattern(tool, key string) bool {
	return globInputKeys[key] && !(key == "pattern" && strings.EqualFold(tool, "grep"))
}

// searchRoot is the absolute directory a search tool starts in: its "path"
// argument, resolved against the working directory, or the working
// directory itself. It is "" when neither says.
func searchRoot(base, cwd string) string {
	switch {
	case base == "":
		return cwd
	case filepath.IsAbs(base) || strings.HasPrefix(base, "~") || strings.HasPrefix(base, "$HOME"):
		return base
	case cwd != "":
		return filepath.Join(cwd, base)
	}
	return ""
}

// guardedToolTarget reports the first reference to signing or trust material
// in a tool input that is not a shell command. A tool the hook knows is
// checked on its path arguments; any other tool on every string it was given.
func guardedToolTarget(guard *shellscan.PathGuard, kind hookToolKind, payload preToolPayload) (string, bool) {
	found := ""
	base := inputString(payload.ToolInput, "path")
	hookToolStrings(payload.ToolInput, "", func(key, text string) {
		if found != "" {
			return
		}
		if kind == hookToolWrite && writeContentKeys[key] {
			for _, target := range applyPatchTargets(text) {
				if rule, ok := guard.Match(target, payload.CWD); ok {
					found = rule
					return
				}
			}
			return
		}
		if globToolPattern(payload.ToolName, key) {
			// A search pattern is glob syntax, relative to the search root; a
			// filter selects names at any depth below it.
			if rule, ok := guard.MatchSearchGlob(text, searchRoot(base, payload.CWD), globFilterKeys[key]); ok {
				found = rule
			}
			return
		}
		if rule, ok := guard.Match(text, payload.CWD); ok {
			found = rule
		}
	})
	return found, found != ""
}

// applyPatchTargets lists the files a Codex or Hermes patch names.
func applyPatchTargets(patch string) []string {
	var targets []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"} {
			if strings.HasPrefix(line, prefix) {
				targets = append(targets, strings.TrimSpace(strings.TrimPrefix(line, prefix)))
			}
		}
	}
	return targets
}

// readToolClassifications decides a read tool the way the same read through a
// shell is decided: a credential path is a secret read, anything else passes.
// A search glob that selects credential files at any depth is such a read
// too, as `grep -r --include=.env` is through a shell.
func readToolClassifications(tool string, payload preToolPayload) []hookClassification {
	target := ""
	hookToolStrings(payload.ToolInput, "", func(key, text string) {
		if target != "" {
			return
		}
		switch {
		case globToolPattern(payload.ToolName, key):
			if shellscan.SecretReadPath(text) || shellscan.SecretGlob(text) {
				target = text
			}
		case globInputKeys[key]:
			// A content search's regular expression is not a path.
		case shellscan.SecretReadPath(text):
			target = text
		}
	})
	if target == "" {
		return nil
	}
	return []hookClassification{{
		ShouldDecide: true,
		Class:        "secret",
		Target:       target,
		Action:       "secret_read",
		ToolID:       "secret.read",
		Reason:       "secret read via " + tool,
	}}
}

// fetchToolClassifications decides a fetch or search tool as network egress:
// one decision per destination, the host of each URL the tool was given. The
// URL is read from `url` or `uri`, and from a `urls` list for the tools that
// take several. A tool given no URL, such as a search, sends its query
// somewhere the hook cannot name, and one URL that cannot be parsed makes the
// call undetermined as a whole.
func fetchToolClassifications(tool string, payload preToolPayload) []hookClassification {
	var raws []string
	if raw := inputString(payload.ToolInput, "url", "uri"); raw != "" {
		raws = append(raws, raw)
	}
	listed, listOK := inputStringList(payload.ToolInput, "urls")
	raws = append(raws, listed...)
	return fetchClassifications(tool, raws, listOK)
}

// fetchClassifications decides the URLs a tool was given: one decision per
// destination, or one undetermined decision when a URL cannot be parsed, none
// was given, or there are more than one call may name.
func fetchClassifications(tool string, raws []string, listOK bool) []hookClassification {
	undetermined := ""
	var targets []string
	switch {
	case !listOK:
		undetermined = "the urls field is not a list of URLs"
	case len(raws) == 0:
		undetermined = "the call names no URL"
	}
	seen := make(map[string]bool, len(raws))
	for _, raw := range raws {
		destination, err := netdest.Parse(raw)
		if err != nil {
			undetermined = "a URL could not be parsed"
			break
		}
		if target := destination.String(); !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	binding := egressBinding(targets)
	if undetermined == "" && len(targets) > hookMaxEgressDestinations {
		undetermined = fmt.Sprintf("the call names %d destinations, more than the %d one call may name", len(targets), hookMaxEgressDestinations)
	}
	reason := "network egress via " + tool
	if undetermined != "" {
		if len(targets) <= hookMaxEgressDestinations {
			binding = egressBinding([]string{netdest.Undetermined})
		}
		targets = []string{netdest.Undetermined}
		reason += ": destination could not be determined (" + undetermined + ")"
	}
	classifications := make([]hookClassification, 0, len(targets))
	for _, target := range targets {
		metadata := maps.Clone(binding)
		classifications = append(classifications, hookClassification{
			ShouldDecide: true,
			Class:        "network",
			Target:       target,
			Action:       "network_egress",
			ToolID:       "network.egress",
			Reason:       reason,
			Metadata:     metadata,
		})
	}
	return classifications
}

// inputStringList reads a list of strings from the first of keys that is
// present. ok is false when the field is there but is not a list of strings,
// so a caller can refuse it instead of reading it as empty.
func inputStringList(input map[string]any, keys ...string) (values []string, ok bool) {
	for _, key := range keys {
		raw, present := input[key]
		if !present || raw == nil {
			continue
		}
		list, isList := raw.([]any)
		if !isList {
			return nil, false
		}
		for _, item := range list {
			text, isString := item.(string)
			if !isString || strings.TrimSpace(text) == "" {
				return nil, false
			}
			values = append(values, strings.TrimSpace(text))
		}
		return values, true
	}
	return nil, true
}

// unknownToolClassifications routes a tool the hook has no class for to the
// decision path as a tool call, with its input bound into the receipt. It
// needs the same permission as an MCP tool call: both are calls into a tool
// whose effect the hook cannot see.
func unknownToolClassifications(tool string) []hookClassification {
	return []hookClassification{{
		ShouldDecide: true,
		Class:        "mcp",
		Target:       tool,
		Action:       "unclassified_tool_call",
		ToolID:       tool,
		Reason:       "tool call the hook does not classify",
		Metadata:     map[string]string{"tool_classification": "unknown"},
	}}
}

// opaqueShellClassification decides a call that runs code the hook cannot
// read as a command line, as an interpreter given a program would be: a
// shell operation that needs the shell.operate permission.
func opaqueShellClassification(target, reason string) hookClassification {
	return hookClassification{
		ShouldDecide: true,
		Class:        "shell-operate",
		Target:       target,
		Action:       "shell_operate",
		ToolID:       "shell",
		Reason:       "shell operation: " + reason,
	}
}

// shellCommandText reads the command a shell tool was given. ok is false when
// no command is given or one is given as something other than a string: the
// hook cannot read what such a call would run.
func shellCommandText(input map[string]any) (command string, ok bool) {
	present := false
	for _, key := range []string{"command", "cmd"} {
		value, found := input[key]
		if !found {
			continue
		}
		text, isString := value.(string)
		if !isString {
			return "", false
		}
		if !present {
			command, present = strings.TrimSpace(text), true
		}
	}
	return command, present
}

// canonicalToolInput renders a tool input as the text a receipt target binds
// when the input is all there is to name the call by.
func canonicalToolInput(input map[string]any) string {
	canonical, err := canonicalize.JCS(input)
	if err != nil {
		return "<tool input>"
	}
	return string(canonical)
}

// codeToolClassifications decides a tool that runs a program, such as
// Hermes execute_code. The program is not a command line the hook can read,
// so the call is an opaque shell operation; its text has already been
// searched for the signer's files.
func codeToolClassifications(tool string, payload preToolPayload) []hookClassification {
	target, ok := payload.ToolInput["code"].(string)
	if !ok || strings.TrimSpace(target) == "" {
		target = canonicalToolInput(payload.ToolInput)
	}
	return []hookClassification{opaqueShellClassification(target, "code execution via "+tool)}
}

// imageToolClassifications decides a tool that loads an image, such as Hermes
// vision_analyze: a local file is a read and is decided like Read, anything
// else is a URL and is network egress. A value with no scheme that is not a
// path is taken as a host, so a name the hook cannot place is decided, not
// passed.
func imageToolClassifications(tool string, payload preToolPayload) []hookClassification {
	source := inputString(payload.ToolInput, "image_url", "url")
	lower := strings.ToLower(source)
	switch {
	case strings.HasPrefix(lower, "data:"):
		// The image is in the call itself.
		return nil
	case strings.HasPrefix(lower, "file://"):
		source = source[len("file://"):]
		fallthrough
	case localFileReference(source) || existsBelow(payload.CWD, source):
		local := payload
		local.ToolInput = map[string]any{"path": source}
		return readToolClassifications(tool, local)
	}
	var raws []string
	if source != "" {
		raws = append(raws, source)
	}
	return fetchClassifications(tool, raws, true)
}

// existsBelow reports a relative path that names an existing file in the
// working directory, which a tool given it reads rather than fetches.
func existsBelow(cwd, value string) bool {
	if cwd == "" || value == "" || !filepath.IsAbs(cwd) {
		return false
	}
	_, err := os.Stat(filepath.Join(cwd, value))
	return err == nil
}

// localFileReference reports a value written as a path on this machine.
func localFileReference(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(value, "~") ||
		strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") ||
		len(value) > 2 && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}

// mcpResourceClassifications decides a read or listing of MCP resources made
// through the client, as Claude Code's ReadMcpResourceTool and
// ListMcpResourcesTool do. It is an MCP call to the named server, decided
// like mcp__server__tool. The resources of the HELM server setup installs are
// governed by that server, as its tools are.
func mcpResourceClassifications(tool string, payload preToolPayload) []hookClassification {
	server := inputString(payload.ToolInput, "server")
	if server == setupMCPServerName {
		return nil
	}
	target, action := tool, "mcp_resource_list"
	if strings.EqualFold(tool, "ReadMcpResourceTool") {
		action = "mcp_resource_read"
	}
	if server != "" {
		target = tool + ":" + server
	}
	return []hookClassification{{
		ShouldDecide: true,
		Class:        "mcp",
		Target:       target,
		Action:       action,
		ToolID:       tool,
		Reason:       "MCP resource access",
		Metadata:     map[string]string{"mcp_server": server},
	}}
}
