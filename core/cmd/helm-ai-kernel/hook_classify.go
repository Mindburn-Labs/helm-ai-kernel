package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

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
	"websearch": hookToolFetch, "web_search": hookToolFetch,
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

// shellClassifications turns a scan of a shell command, or of an argv that is
// about to be executed, into the decisions the call needs.
func shellClassifications(tool, command string, scan shellscan.Result) []hookClassification {
	if scan.ProtectedPath != "" {
		return trustMaterialClassification(tool, scan.ProtectedPath, shellscanReceiptMetadata(scan))
	}
	if target, ok := signerInvocation(scan.Commands); ok {
		return trustMaterialClassification(tool, target, shellscanReceiptMetadata(scan))
	}
	var destinations []string
	for _, fact := range scan.EffectFacts {
		if fact.Class == "network" {
			destinations = append(destinations, fact.Target)
		}
	}
	classifications := make([]hookClassification, 0, len(scan.EffectFacts)+2)
	for _, fact := range scan.EffectFacts {
		if classification, ok := hookClassificationFromShellscanFact(fact, scan); ok {
			if fact.Class == "network" {
				bindEgressDestinations(classification.Metadata, destinations)
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
			Metadata:     shellscanReceiptMetadata(scan),
		})
	}
	if scan.RequiresShellDecision {
		classifications = append(classifications, shellscanGenericClassification(command, scan))
	}
	return appendRequiredShellPermission(classifications, command)
}

// bindEgressDestinations records, in every network receipt of a call, how
// many destinations the call has and a digest of the whole set. One receipt
// names one destination; the digest lets a reader holding it tell whether
// the others are in hand.
func bindEgressDestinations(metadata map[string]string, destinations []string) {
	sorted := append([]string(nil), destinations...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	metadata["egress.destination_count"] = strconv.Itoa(len(sorted))
	metadata["egress.destination_set_sha256"] = "sha256:" + hex.EncodeToString(sum[:])
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
var globInputKeys = map[string]bool{"pattern": true, "glob": true, "include": true}

func globToolPattern(tool, key string) bool {
	return globInputKeys[key] && !(key == "pattern" && strings.EqualFold(tool, "grep"))
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
			// A search pattern is glob syntax, relative to the search root.
			root := payload.CWD
			if base != "" {
				if filepath.IsAbs(base) || strings.HasPrefix(base, "~") {
					root = ""
					text = strings.TrimSuffix(base, "/") + "/" + text
				} else if root != "" {
					root = filepath.Join(root, base)
				}
			}
			if rule, ok := guard.MatchPattern(text, root); ok {
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
func readToolClassifications(tool string, payload preToolPayload) []hookClassification {
	target := ""
	hookToolStrings(payload.ToolInput, "", func(key, text string) {
		if target == "" && !globInputKeys[key] && shellscan.SecretReadPath(text) {
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

	undetermined := ""
	var targets []string
	switch {
	case !listOK:
		undetermined = "the urls field is not a list of URLs"
	case len(raws) == 0:
		undetermined = "the call names no URL"
	}
	for _, raw := range raws {
		destination, err := netdest.Parse(raw)
		if err != nil {
			undetermined = "a URL could not be parsed"
			break
		}
		if target := destination.String(); !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	reason := "network egress via " + tool
	if undetermined != "" {
		targets = []string{netdest.Undetermined}
		reason += ": destination could not be determined (" + undetermined + ")"
	}
	classifications := make([]hookClassification, 0, len(targets))
	for _, target := range targets {
		metadata := map[string]string{}
		bindEgressDestinations(metadata, targets)
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
