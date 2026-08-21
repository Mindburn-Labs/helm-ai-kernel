package tui

import (
	"regexp"
	"strings"
)

// ParseArgv splits a composer line into a command name and argv.
// It never invokes a shell: quotes group a field; pipes and metacharacters
// stay literals. This is not shlex-for-execution — it is argv construction.
func ParseArgv(line string) (name string, args []string) {
	fields := splitArgv(strings.TrimSpace(line))
	if len(fields) == 0 {
		return "", nil
	}
	if fields[0] == "helm-ai-kernel" {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], append([]string(nil), fields[1:]...)
}

func splitArgv(line string) []string {
	var fields []string
	var cur strings.Builder
	quote := rune(0)
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		fields = append(fields, cur.String())
		cur.Reset()
	}
	for _, r := range line {
		switch {
		case quote != 0:
			cur.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return fields
}

// Invocation formats a command as the operator would type it.
func Invocation(name string, args []string) string {
	parts := append([]string{"helm-ai-kernel", name}, args...)
	return strings.Join(parts, " ")
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

func helpOnly(args []string) bool {
	return hasFlag(args, "--help") || hasFlag(args, "-h")
}

// IsListenerVerb reports commands that would bind a port or start a long-lived
// process the TUI cannot abort without leaking a listener.
func IsListenerVerb(name string, args []string) bool {
	if helpOnly(args) {
		return false
	}
	switch name {
	case "server":
		return true
	case "serve":
		return hasFlag(args, "--policy") || hasFlag(args, "--addr") || hasFlag(args, "--port")
	case "quickstart":
		return !hasFlag(args, "--dry-run")
	case "onboard":
		return !hasFlag(args, "--dry-run")
	case "setup":
		return hasFlag(args, "--quickstart") && !hasFlag(args, "--dry-run")
	case "dev", "proxy", "spend-proxy", "connect", "login", "up":
		return true
	case "mcp":
		return hasExactArg(args, "serve") || hasExactArg(args, "bridge")
	case "receipts":
		return hasExactArg(args, "tail")
	case "scan":
		// Bare scan walks --path . and writes a salt file. Esc cannot
		// abort Kernel Run, so the TUI refuses every non-help form.
		return true
	default:
		return false
	}
}

func hasExactArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// IsDestructive reports mutating verbs that must not run from a one-key default.
// Safe status/preview forms stay executable. Palette DefaultArgs must never
// classify as destructive.
func IsDestructive(name string, args []string) bool {
	if helpOnly(args) {
		return false
	}
	switch name {
	case "teardown":
		return len(args) > 0
	case "freeze", "unfreeze":
		return !hasFlag(args, "--status")
	case "setup", "onboard":
		return hasFlag(args, "--yes")
	case "launch":
		return len(args) > 0 && (args[0] == "delete" || args[0] == "promote")
	case "init", "scaffold":
		// Bare init/scaffold write helm/ (keys, policy, config). --help is inspect.
		return true
	case "incident":
		return hasExactArg(args, "ack") || hasExactArg(args, "create")
	case "mcp":
		return isMCPMutate(args)
	case "policy":
		// policy init defaults --template to deny-first and writes policies/.
		return hasExactArg(args, "init")
	default:
		return false
	}
}

func isMCPMutate(args []string) bool {
	if hasExactArg(args, "revoke") ||
		hasExactArg(args, "authorize-call") ||
		hasExactArg(args, "approve") ||
		hasExactArg(args, "install") ||
		hasExactArg(args, "pack") ||
		hasExactArg(args, "proof") {
		return true
	}
	return hasExactArg(args, "auth-profile") && hasExactArg(args, "put")
}

// ListenerRefuseMessage is shown instead of starting a bind or cwd walk from the TUI.
const ListenerRefuseMessage = "Fail-closed: the operator TUI will not start an unbounded listener or walk. Cancel cannot reclaim a bind."

const DestructivePrompt = "Type the full invocation to proceed. A single key never mutates the boundary."

// pemDashClass matches ASCII and unicode dash characters used in PEM fences.
const pemDashClass = `[-\x{2010}-\x{2015}\x{2212}\x{FE58}\x{FE63}\x{FF0D}]`

var (
	reBearer  = regexp.MustCompile(`(?i)(bearer[\s\p{Z}]+)[A-Za-z0-9._\-+=/]{8,}`)
	reAPIKey  = regexp.MustCompile(`(?i)((?:api[_-]?key|access[_-]?key|secret[_-]?key)["']?\s*[:=]\s*["']?)[A-Za-z0-9._\-+=/]{8,}`)
	reToken   = regexp.MustCompile(`(?i)((?:token|password|authorization)["']?\s*[:=]\s*["']?)[A-Za-z0-9._\-+=/]{12,}`)
	rePEM     = regexp.MustCompile(`(?i)` + pemDashClass + `{5}BEGIN [A-Z ]*PRIVATE KEY` + pemDashClass + `{5}[\s\S]*?` + pemDashClass + `{5}END [A-Z ]*PRIVATE KEY` + pemDashClass + `{5}`)
	reHELMKey = regexp.MustCompile(`(?i)((?:[A-Z][A-Z0-9_]*_)?(?:HELM_ADMIN_API_KEY|SECRET_ACCESS_KEY|API_KEY|ACCESS_KEY|SECRET_KEY|PASSWORD|TOKEN)=)[^\s]+`)
	// Prefix tokens require a long secret body so "sk-id" / "ghp_x" stay visible.
	rePrefixToken = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|glpat-[A-Za-z0-9_-]{16,})`)
	// Bare JWT: three base64url segments, header must look like JSON (`eyJ`).
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}`)
)

// RedactSecrets replaces credential-shaped blobs in captured command output.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	out := rePEM.ReplaceAllString(s, "[REDACTED PRIVATE KEY]")
	out = reBearer.ReplaceAllString(out, "${1}[REDACTED]")
	out = rePrefixToken.ReplaceAllString(out, "[REDACTED]")
	out = reJWT.ReplaceAllString(out, "[REDACTED]")
	out = reAPIKey.ReplaceAllString(out, "${1}[REDACTED]")
	out = reToken.ReplaceAllString(out, "${1}[REDACTED]")
	out = reHELMKey.ReplaceAllString(out, "${1}[REDACTED]")
	return out
}

// MatchCeremonyToken accepts ConfirmDecision semantics (case-insensitive
// APPROVE or DENY). Anything else is a failed closed no-op.
func MatchCeremonyToken(token string) (action string, ok bool) {
	switch strings.ToUpper(strings.TrimSpace(token)) {
	case "APPROVE":
		return "APPROVE", true
	case "DENY":
		return "DENY", true
	default:
		return "", false
	}
}

// ProofNextActions suggests Kernel evidence verbs when output already names them.
func ProofNextActions(stdout, stderr string) []string {
	body := strings.ToLower(stdout + "\n" + stderr)
	var next []string
	add := func(name string) {
		for _, n := range next {
			if n == name {
				return
			}
		}
		next = append(next, name)
	}
	if strings.Contains(body, "evidencepack") || strings.Contains(body, "receipt") {
		add("verify")
		add("receipts")
		add("export")
	}
	return next
}
