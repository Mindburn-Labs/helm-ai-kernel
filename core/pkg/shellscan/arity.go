// Package shellscan provides structural (AST-based) classification of shell
// commands for the workstation pre-tool hook.
//
// The classifier is advisory input to the kernel's existing decision path. It
// never authorizes anything itself: it only decides whether a raw shell
// command string is opaque or destructive enough that the hook must route it
// through the signed workstation decision (permit/receipt) path instead of
// letting it pass through unclassified. Fail-closed semantics are preserved:
// anything the classifier cannot statically understand is treated as
// decision-worthy, never as safe.
//
// The design follows the opencode shell permission scan (see
// research/opencode-study/03-core-tools.md and 25-helm-map-agent-side.md):
// parse the command into a bash AST, walk every command node (including
// pipelines, substitutions and subshells), and classify each command's
// arity-aware prefix instead of matching needles against the raw string.
package shellscan

// arity maps a command prefix to how many leading tokens constitute the
// "human-meaningful command". Flags never count as tokens; only subcommands
// do. Longest matching prefix wins. Ported from opencode
// packages/opencode/src/permission/arity.ts (generated dictionary; see
// research/opencode-study/03-core-tools.md section c).
var arity = map[string]int{
	"cat":     1,
	"cd":      1,
	"chmod":   1,
	"chown":   1,
	"cp":      1,
	"echo":    1,
	"env":     1,
	"export":  1,
	"grep":    1,
	"kill":    1,
	"killall": 1,
	"ln":      1,
	"ls":      1,
	"mkdir":   1,
	"mv":      1,
	"ps":      1,
	"pwd":     1,
	"rm":      1,
	"rmdir":   1,
	"sleep":   1,
	"source":  1,
	"tail":    1,
	"touch":   1,
	"unset":   1,
	"which":   1,

	"aws":                 3,
	"az":                  3,
	"bazel":               2,
	"brew":                2,
	"bun":                 2,
	"bun run":             3,
	"bun x":               3,
	"cargo":               2,
	"cargo add":           3,
	"cargo run":           3,
	"cdk":                 2,
	"cf":                  2,
	"cmake":               2,
	"composer":            2,
	"consul":              2,
	"consul kv":           3,
	"crictl":              2,
	"deno":                2,
	"deno task":           3,
	"doctl":               3,
	"docker":              2,
	"docker builder":      3,
	"docker compose":      3,
	"docker container":    3,
	"docker image":        3,
	"docker network":      3,
	"docker volume":       3,
	"eksctl":              2,
	"eksctl create":       3,
	"firebase":            2,
	"flyctl":              2,
	"gcloud":              3,
	"gh":                  3,
	"git":                 2,
	"git config":          3,
	"git remote":          3,
	"git stash":           3,
	"go":                  2,
	"gradle":              2,
	"helm":                2,
	"heroku":              2,
	"hugo":                2,
	"ip":                  2,
	"ip addr":             3,
	"ip link":             3,
	"ip netns":            3,
	"ip route":            3,
	"kind":                2,
	"kind create":         3,
	"kubectl":             2,
	"kubectl kustomize":   3,
	"kubectl rollout":     3,
	"kustomize":           2,
	"make":                2,
	"mc":                  2,
	"mc admin":            3,
	"minikube":            2,
	"mongosh":             2,
	"mysql":               2,
	"mvn":                 2,
	"ng":                  2,
	"npm":                 2,
	"npm exec":            3,
	"npm init":            3,
	"npm run":             3,
	"npm view":            3,
	"nvm":                 2,
	"nx":                  2,
	"openssl":             2,
	"openssl req":         3,
	"openssl x509":        3,
	"pip":                 2,
	"pipenv":              2,
	"pnpm":                2,
	"pnpm dlx":            3,
	"pnpm exec":           3,
	"pnpm run":            3,
	"poetry":              2,
	"podman":              2,
	"podman container":    3,
	"podman image":        3,
	"psql":                2,
	"pulumi":              2,
	"pulumi stack":        3,
	"pyenv":               2,
	"python":              2,
	"rake":                2,
	"rbenv":               2,
	"redis-cli":           2,
	"rustup":              2,
	"serverless":          2,
	"sfdx":                3,
	"skaffold":            2,
	"sls":                 2,
	"sst":                 2,
	"swift":               2,
	"systemctl":           2,
	"terraform":           2,
	"terraform workspace": 3,
	"tmux":                2,
	"turbo":               2,
	"ufw":                 2,
	"vault":               2,
	"vault auth":          3,
	"vault kv":            3,
	"vercel":              2,
	"volta":               2,
	"wp":                  2,
	"yarn":                2,
	"yarn dlx":            3,
	"yarn run":            3,
}

// Prefix returns the arity-derived, human-meaningful command prefix for a
// tokenized command (e.g. ["git","checkout","main"] -> "git checkout",
// ["npm","run","dev"] -> "npm run dev"). Longest matching prefix wins;
// unknown commands fall back to the first token. Tokens that look like flags
// stop prefix growth unless a longer dictionary entry matched first.
func Prefix(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	for length := len(tokens); length > 1; length-- {
		key := joinTokens(tokens[:length])
		if n, ok := arity[key]; ok && n <= len(tokens) {
			return joinTokens(tokens[:n])
		}
	}
	if n, ok := arity[tokens[0]]; ok && n <= len(tokens) {
		return joinTokens(tokens[:n])
	}
	return tokens[0]
}

func joinTokens(tokens []string) string {
	out := ""
	for i, tok := range tokens {
		if i > 0 {
			out += " "
		}
		out += tok
	}
	return out
}
