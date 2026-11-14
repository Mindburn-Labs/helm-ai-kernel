package shellscan

import (
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
)

// git reaches a remote from a handful of subcommands, and takes the address
// from an argument or, when given a remote name or nothing, from repository
// configuration. An address written on the command line is a destination and
// is decided like any other. A configured remote is the operator's setting:
// using it is not classified, and every way the command line could repoint it
// (an address stored with remote or config, a -c override, a connection
// variable) is.

var gitGlobalValueOptions = map[string]bool{
	"-C": true, "--git-dir": true, "--work-tree": true, "--namespace": true, "--super-prefix": true,
	"--attr-source": true,
}

var gitGlobalFlags = map[string]bool{
	"--version": true, "-v": true, "--help": true, "-h": true, "--html-path": true,
	"--man-path": true, "--info-path": true, "-p": true, "--paginate": true, "-P": true,
	"--no-pager": true, "--no-replace-objects": true, "--no-lazy-fetch": true,
	"--no-optional-locks": true, "--no-advice": true, "--bare": true, "--exec-path": true,
	"--literal-pathspecs": true, "--glob-pathspecs": true, "--noglob-pathspecs": true,
	"--icase-pathspecs": true, "--no-literal-pathspecs": true, "--list-cmds": true,
}

// gitNetworkSubcommands are the subcommands subcommand() can resolve to a
// connection. A command line that cannot be parsed up to its subcommand is
// undetermined when one of these words appears in it.
var gitNetworkSubcommands = names(`
	clone fetch pull push ls-remote fetch-pack send-pack http-fetch http-push
	remote submodule archive config`)

func gitSpec(valueLetters, flagLetters, valueNames, flagNames string, roles map[string]optRole) cliSpec {
	short, value, flag := letters(valueLetters, flagLetters)
	for name := range names(valueNames) {
		value[name] = rolePlain
	}
	for name := range names(flagNames) {
		flag[name] = rolePlain
	}
	spec := cliSpec{short: short, value: value, flag: flag, equals: true, optional: map[string]optRole{
		// These take a value only as --name=value; alone they are a switch.
		"recurse-submodules": roleOpaque, "force-with-lease": rolePlain, "signed": rolePlain,
		"rebase": rolePlain, "gpg-sign": rolePlain, "log": rolePlain,
	}}
	for name, role := range roles {
		if _, takesValue := value[name]; takesValue {
			value[name] = role
			continue
		}
		flag[name] = role
	}
	return spec
}

const gitFetchFlags = `
	verbose quiet all no-all append atomic dry-run porcelain force keep multiple
	auto-maintenance no-auto-maintenance auto-gc no-auto-gc write-commit-graph
	no-write-commit-graph write-fetch-head no-write-fetch-head prune prune-tags no-tags tags
	refetch unshallow update-shallow no-recurse-submodules set-upstream update-head-ok
	progress no-progress show-forced-updates no-show-forced-updates ipv4 ipv6 stdin
	negotiate-only prefetch`

const gitFetchValues = `
	depth deepen shallow-since shallow-exclude negotiation-tip refmap upload-pack jobs
	filter server-option recurse-submodules-default submodule-prefix`

var gitSpecs = map[string]cliSpec{
	"clone": gitSpec("boujc", "vqnls46", `
		branch origin upload-pack reference reference-if-able separate-git-dir depth
		shallow-since shallow-exclude jobs template config filter server-option bundle-uri
		revision ref-format`, `
		verbose quiet progress no-progress no-checkout bare mirror local no-local
		no-hardlinks shared recursive single-branch no-single-branch no-tags tags
		shallow-submodules no-shallow-submodules remote-submodules no-remote-submodules
		sparse also-filter-submodules dissociate reject-shallow no-reject-shallow ipv4 ipv6`,
		map[string]optRole{"bundle-uri": roleURL, "config": roleConfig, "c": roleConfig, "recursive": roleOpaque}),
	"fetch": gitSpec("jo", "vqafkpPntu46", gitFetchValues, gitFetchFlags,
		map[string]optRole{"all": roleOpaque, "multiple": roleOpaque}),
	"pull": gitSpec("josX", "vqafkpPntur46e", gitFetchValues+" strategy strategy-option cleanup", gitFetchFlags+`
		no-rebase ff no-ff ff-only squash no-squash commit no-commit edit no-edit stat no-stat
		autostash no-autostash verify no-verify verify-signatures no-verify-signatures
		allow-unrelated-histories signoff no-signoff no-gpg-sign no-log`,
		map[string]optRole{"all": roleOpaque, "multiple": roleOpaque}),
	"push": gitSpec("o", "vqndfu46", "repo receive-pack exec push-option", `
		verbose quiet all branches mirror tags follow-tags no-follow-tags atomic no-atomic
		dry-run porcelain delete prune force no-force-with-lease force-if-includes
		no-force-if-includes set-upstream thin no-thin progress no-progress verify no-verify
		no-signed no-recurse-submodules ipv4 ipv6`,
		map[string]optRole{"repo": roleURL}),
	"ls-remote": gitSpec("o", "qhtb", "upload-pack exec sort server-option", `
		quiet heads branches tags refs get-url symref exit-code`, nil),
}

// gitConfigMovesConnection reports whether a configuration key changes the
// host git connects to, or the program it connects with.
func gitConfigMovesConnection(key string) bool {
	for _, prefix := range []string{"url.", "remote.", "include.", "includeif.", "protocol.", "submodule.", "branch."} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	switch key {
	case "core.sshcommand", "core.gitproxy",
		// A bundle URI is a second address git downloads from.
		"fetch.bundleuri", "transfer.bundleuri", "clone.bundleuri",
		// These name a program git runs while it connects.
		"core.askpass", "core.hookspath", "core.fsmonitor", "credential.helper":
		return true
	}
	if strings.HasPrefix(key, "credential.") && strings.HasSuffix(key, ".helper") {
		return true
	}
	// URL-scoped HTTP settings override the general value. Resolve entries
	// can send the request to an address absent from its repository URL.
	if strings.HasPrefix(key, "http.") && strings.HasSuffix(key, ".curloptresolve") {
		return true
	}
	return (strings.HasPrefix(key, "http.") || strings.HasPrefix(key, "https.")) && strings.HasSuffix(key, "proxy")
}

type gitInvocation struct {
	scan *egressScan
	// http is set once a destination is reached over HTTP, where git follows
	// a redirect on its first request unless told not to.
	http        bool
	noRedirects bool
	// redirectsByURL is set when a per-URL http.<url>.followRedirects key
	// turns redirects on: it overrides the general key for the URLs it
	// matches, and which URLs those are is not worked out here.
	redirectsByURL bool
	// storesOnly marks a subcommand that records an address without
	// connecting to it (remote add, config).
	storesOnly bool
	// configured is set when the remote comes from git configuration rather
	// than from the command line.
	configured bool
}

func (g *gitInvocation) config(entry string) {
	key, value, _ := strings.Cut(entry, "=")
	key = strings.ToLower(strings.TrimSpace(key))
	if strings.HasPrefix(key, "http.") && strings.HasSuffix(key, ".followredirects") {
		// git keeps the last value given for a key, so each entry replaces
		// the one before it, and a key without a value means true.
		off := false
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "false", "no", "off", "0":
			off = true
		}
		if key == "http.followredirects" {
			g.noRedirects = off
		} else if !off {
			g.redirectsByURL = true
		}
		return
	}
	if gitConfigMovesConnection(key) {
		g.scan.refuse("configuration " + key + " changes where git connects")
	}
}

// repository classifies one repository argument. named says a bare word is a
// remote name (fetch, pull, push) rather than a local directory (clone).
func (g *gitInvocation) repository(value string, named bool) {
	switch {
	case value == "" || strings.HasPrefix(value, dynamicToken):
		g.scan.refuse("the repository argument is computed at run time")
	case netdest.HasScheme(value):
		scheme := strings.ToLower(value[:strings.Index(value, "://")])
		if scheme == "file" {
			return
		}
		// git+ssh and ssh+git are spellings of ssh.
		if scheme == "git+ssh" || scheme == "ssh+git" {
			value = "ssh" + value[len(scheme):]
		}
		if destination, ok := g.scan.addTarget(value, "", "the repository URL"); ok && (destination.Scheme == "http" || destination.Scheme == "https") {
			g.http = true
		}
	case strings.Contains(value, "::"):
		g.scan.refuse("a remote helper runs a program to connect")
	case localPathArgument(value):
	default:
		if host, _, ok := remoteSpec(value); ok {
			g.scan.addHost("ssh", host, "", "the repository address")
			return
		}
		g.configured = g.configured || named
	}
}

func localPathArgument(value string) bool {
	return value == "." || value == ".." || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") || strings.HasPrefix(value, "~")
}

// remoteArguments adds every argument that is a remote address and reports
// whether there was one. It serves the subcommands whose remaining arguments
// are names and addresses only.
func (g *gitInvocation) remoteArguments(args []string) bool {
	found := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || localPathArgument(arg) || strings.HasPrefix(strings.ToLower(arg), "file:") {
			continue
		}
		if _, _, scpLike := remoteSpec(arg); !netdest.HasScheme(arg) && !scpLike && !strings.Contains(arg, "::") {
			continue
		}
		g.repository(arg, false)
		found = true
	}
	return found
}

func firstOperand(args []string) (string, []string) {
	for i, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return arg, args[i+1:]
		}
	}
	return "", nil
}

// subcommand resolves one git subcommand and reports whether it connects.
func (g *gitInvocation) subcommand(sub string, args []string) bool {
	if spec, ok := gitSpecs[sub]; ok {
		var operands []string
		walkCLI(spec, args, cliVisitor{
			invalid: g.scan.refuse,
			operand: func(token string) { operands = append(operands, token) },
			option: func(name string, role optRole, value string) {
				switch role {
				case roleURL:
					g.repository(value, sub == "push")
				case roleConfig:
					g.config(value)
				case roleOpaque:
					switch {
					case name != "recurse-submodules" && name != "recursive":
						g.configured = true // --all, --multiple: the configured remotes
					case value != "no" && value != "false" && value != "off" && value != "check":
						// .gitmodules is repository content, not operator configuration.
						g.scan.refuse("submodule addresses come from repository content")
					}
				}
			},
		})
		switch {
		case len(operands) > 0:
			g.repository(operands[0], sub != "clone")
			// A URL after the repository is not a refspec; it is reported
			// rather than assumed to be inert.
			for _, operand := range operands[1:] {
				if netdest.HasScheme(operand) {
					g.repository(operand, false)
				}
			}
		case sub == "clone":
			return false // a usage error: nothing connects
		case len(g.scan.destinations) == 0:
			g.configured = true
		}
		return true
	}
	switch sub {
	case "fetch-pack", "send-pack", "http-fetch", "http-push":
		return g.remoteArguments(args)
	case "remote":
		action, rest := firstOperand(args)
		switch action {
		case "add", "set-url":
			g.storesOnly = action == "set-url" || !containsString(rest, "-f") && !containsString(rest, "--fetch")
			return g.remoteArguments(rest)
		case "update", "prune":
			g.configured = true
			return true
		case "show":
			g.configured = !containsString(rest, "-n")
			return g.configured
		case "set-head":
			g.configured = containsString(rest, "-a") || containsString(rest, "--auto")
			return g.configured
		}
	case "submodule":
		action, rest := firstOperand(args)
		switch action {
		case "add":
			return g.remoteArguments(rest)
		case "set-url":
			g.storesOnly = true
			return g.remoteArguments(rest)
		case "update":
			g.scan.refuse("submodule addresses come from repository content")
			return true
		}
	case "archive":
		for i, arg := range args {
			if value, ok := strings.CutPrefix(arg, "--remote="); ok {
				g.repository(value, true)
				return true
			}
			if arg == "--remote" && i+1 < len(args) {
				g.repository(args[i+1], true)
				return true
			}
		}
	case "config":
		return g.configWrite(args)
	}
	return false
}

// configWrite handles `git config` when it sets a key that moves later
// connections: the address it stores is decided now, because the command that
// later uses it will name only the remote.
func (g *gitInvocation) configWrite(args []string) bool {
	var operands []string
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--get"), arg == "--list", arg == "-l", strings.HasPrefix(arg, "--unset"),
			arg == "--edit", arg == "-e", strings.HasPrefix(arg, "--rename-section"), strings.HasPrefix(arg, "--remove-section"):
			return false
		case strings.HasPrefix(arg, "-"):
		default:
			operands = append(operands, arg)
		}
	}
	if len(operands) > 0 {
		switch operands[0] {
		case "get", "list", "unset", "edit", "rename-section", "remove-section":
			return false
		case "set":
			operands = operands[1:]
		}
	}
	// The key is not always the first operand: --file, --type, --default and
	// --comment take a value that lands among the operands here. Rather than
	// keep the arity of every option, take the first operand that is a key
	// which moves a connection and has a value after it.
	for len(operands) >= 2 && !gitConfigMovesConnection(strings.ToLower(operands[0])) {
		operands = operands[1:]
	}
	if len(operands) < 2 {
		return false
	}
	key := strings.ToLower(operands[0])
	g.storesOnly = true
	// A url.<base>.insteadOf rewrite carries its address in the key, and a
	// proxy or ssh command is not an address at all.
	if !strings.HasPrefix(key, "remote.") || !g.remoteArguments(operands[1:2]) {
		g.scan.refuse("configuration " + key + " changes where git connects")
	}
	return true
}

// gitEgress reports where a git command connects. configured is true when it
// uses a remote from git configuration and nothing on the command line names
// or moves the destination.
func gitEgress(tokens []string) (scan egressScan, network, configured bool) {
	g := gitInvocation{scan: &scan}
	var configs []string
	i := 0
globals:
	for ; i < len(tokens); i++ {
		token := tokens[i]
		name, _, attached := strings.Cut(token, "=")
		switch {
		case token == "-" || !strings.HasPrefix(token, "-"):
			break globals
		case token == "-c":
			if i+1 < len(tokens) {
				i++
				configs = append(configs, tokens[i])
			}
		case name == "--config-env":
			scan.refuse("--config-env takes configuration from the environment")
			if !attached {
				i++
			}
		case gitGlobalValueOptions[name]:
			if !attached {
				i++
			}
		case name == "--exec-path" && attached:
			scan.refuse("--exec-path replaces the programs git runs")
		case gitGlobalFlags[name]:
		default:
			// The subcommand cannot be located behind an option whose arity is
			// unknown. If the rest names an address or a subcommand that can
			// connect, the command is undetermined: it must not fall through
			// to a plain command with no network decision.
			for _, rest := range tokens[i+1:] {
				_, _, scpLike := remoteSpec(rest)
				_, networkWord := gitNetworkSubcommands[rest]
				if networkWord || netdest.HasScheme(rest) || scpLike && strings.Contains(rest, "@") {
					return egressScan{undetermined: "git option " + token + " is not recognized"}, true, false
				}
			}
			return egressScan{}, false, false
		}
	}
	if i >= len(tokens) || !g.subcommand(tokens[i], tokens[i+1:]) {
		return egressScan{}, false, false
	}
	for _, config := range configs {
		g.config(config)
	}
	if g.http && (!g.noRedirects || g.redirectsByURL) && !g.storesOnly {
		scan.refuse("git follows a redirect on its first HTTP request; pass -c http.followRedirects=false")
	}
	return scan, true, g.configured && len(scan.destinations) == 0 && scan.undetermined == ""
}
