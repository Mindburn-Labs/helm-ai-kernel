package shellscan

import (
	"os"
	"path"
	"strings"
)

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
