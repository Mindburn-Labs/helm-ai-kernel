package shellscan

import (
	"net/url"
	"path"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
)

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
