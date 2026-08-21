package tui

import (
	"strings"
	"testing"
)

func TestParseArgvNeverShells(t *testing.T) {
	name, args := ParseArgv(`verify "; echo pwned"`)
	if name != "verify" {
		t.Fatalf("name=%q", name)
	}
	if len(args) != 1 || args[0] != `"; echo pwned"` {
		t.Fatalf("args=%v — metacharacters must stay one argv slot", args)
	}
	name, args = ParseArgv("helm-ai-kernel freeze --status")
	if name != "freeze" || len(args) != 1 || args[0] != "--status" {
		t.Fatalf("got %s %v", name, args)
	}
}

func TestDefaultArgsAreFailClosed(t *testing.T) {
	for _, name := range []string{
		"setup", "freeze", "unfreeze", "teardown", "server", "serve",
		"quickstart", "dev", "proxy", "connect", "login", "onboard",
		"init", "scaffold", "mcp", "incident", "scan",
	} {
		args := DefaultArgs(name)
		if IsDestructive(name, args) {
			t.Fatalf("default %s %v is destructive", name, args)
		}
		if IsListenerVerb(name, args) && name != "server" && name != "dev" && name != "proxy" && name != "connect" && name != "login" {
			t.Fatalf("default %s %v starts a listener", name, args)
		}
		for _, a := range args {
			if a == "--yes" {
				t.Fatalf("default %s includes --yes", name)
			}
		}
	}
}

func TestListenerAndDestructiveClassification(t *testing.T) {
	if !IsListenerVerb("server", nil) {
		t.Fatal("bare server must be a listener")
	}
	if IsListenerVerb("serve", nil) {
		t.Fatal("bare serve is missing --policy and must execute the usage path")
	}
	if !IsListenerVerb("serve", []string{"--policy", "p.toml"}) {
		t.Fatal("serve --policy must be refused")
	}
	if !IsListenerVerb("quickstart", nil) {
		t.Fatal("quickstart without --dry-run binds")
	}
	if IsListenerVerb("quickstart", []string{"--dry-run"}) {
		t.Fatal("quickstart --dry-run is safe")
	}
	if !IsListenerVerb("onboard", nil) {
		t.Fatal("bare onboard forwards to quickstart")
	}
	if !IsListenerVerb("setup", []string{"--quickstart"}) {
		t.Fatal("setup --quickstart binds")
	}
	if IsListenerVerb("setup", []string{"--quickstart", "--dry-run"}) {
		t.Fatal("setup --quickstart --dry-run is preview")
	}
	if !IsListenerVerb("receipts", []string{"tail", "--agent", "x"}) {
		t.Fatal("receipts tail is a listener")
	}
	if !IsListenerVerb("receipts", []string{"--format=json", "tail"}) {
		t.Fatal("receipts --format=json tail is a listener")
	}
	if !IsListenerVerb("mcp", []string{"--json", "serve"}) {
		t.Fatal("mcp --json serve is a listener")
	}
	if !IsListenerVerb("mcp", []string{"bridge"}) {
		t.Fatal("mcp bridge is a listener")
	}
	if IsListenerVerb("receipts", []string{"status"}) {
		t.Fatal("receipts status is inspect")
	}
	if IsListenerVerb("receipts", []string{"list"}) {
		t.Fatal("receipts list is inspect")
	}
	if IsListenerVerb("mcp", []string{"scan"}) {
		t.Fatal("mcp scan is inspect")
	}
	if IsListenerVerb("mcp", DefaultArgs("mcp")) {
		t.Fatal("palette default mcp scan is inspect")
	}
	if !IsListenerVerb("receipts", []string{"tail"}) {
		t.Fatal("receipts tail is a listener")
	}
	if IsDestructive("freeze", []string{"--status"}) {
		t.Fatal("freeze --status is inspect")
	}
	if !IsDestructive("freeze", []string{"--principal", "alice"}) {
		t.Fatal("freeze --principal must confirm")
	}
	if !IsDestructive("setup", []string{"claude-code", "--yes"}) {
		t.Fatal("setup --yes must confirm")
	}
	if IsDestructive("setup", []string{"claude-code", "--dry-run"}) {
		t.Fatal("setup --dry-run is preview")
	}
	if !IsDestructive("teardown", []string{"run-1", "--cascade"}) {
		t.Fatal("teardown with id is destructive")
	}
	if IsDestructive("teardown", nil) {
		t.Fatal("teardown with no args is usage")
	}
	if !IsDestructive("mcp", []string{"revoke", "--server-id", "s1"}) {
		t.Fatal("mcp revoke must confirm")
	}
	if !IsDestructive("mcp", []string{"--json", "authorize-call", "--server-id", "s1"}) {
		t.Fatal("mcp authorize-call must confirm even with leading flags")
	}
	if !IsDestructive("mcp", []string{"install", "--client", "claude-code"}) {
		t.Fatal("mcp install writes and must confirm")
	}
	if !IsDestructive("mcp", []string{"auth-profile", "put"}) {
		t.Fatal("mcp auth-profile put writes and must confirm")
	}
	if IsDestructive("mcp", []string{"auth-profile", "list"}) {
		t.Fatal("mcp auth-profile list is inspect")
	}
	if IsDestructive("mcp", []string{"scan"}) {
		t.Fatal("mcp scan is inspect")
	}
	if IsDestructive("mcp", DefaultArgs("mcp")) {
		t.Fatal("palette default mcp scan is not destructive")
	}
	if !IsDestructive("init", nil) {
		t.Fatal("bare init writes helm/")
	}
	if IsDestructive("init", []string{"--help"}) {
		t.Fatal("init --help is inspect")
	}
	if IsDestructive("init", DefaultArgs("init")) {
		t.Fatal("palette default init is not destructive")
	}
	if !IsDestructive("scaffold", nil) {
		t.Fatal("bare scaffold writes helm/")
	}
	if IsDestructive("scaffold", []string{"--help"}) {
		t.Fatal("scaffold --help is inspect")
	}
	if IsDestructive("scaffold", DefaultArgs("scaffold")) {
		t.Fatal("palette default scaffold is not destructive")
	}
	if !IsDestructive("incident", []string{"ack", "INC-1"}) {
		t.Fatal("incident ack must confirm")
	}
	if !IsDestructive("incident", []string{"create", "--title", "x"}) {
		t.Fatal("incident create writes and must confirm")
	}
	if IsDestructive("incident", []string{"list"}) {
		t.Fatal("incident list is inspect")
	}
	if IsDestructive("incident", DefaultArgs("incident")) {
		t.Fatal("palette default incident list is not destructive")
	}
	if got := DefaultArgs("scan"); len(got) != 1 || got[0] != "--help" {
		t.Fatalf("palette scan default=%v, want [--help] (cwd walk is unbounded)", got)
	}
	if IsListenerVerb("scan", DefaultArgs("scan")) {
		t.Fatal("scan --help is inspect")
	}
	if IsDestructive("scan", DefaultArgs("scan")) {
		t.Fatal("scan --help is not destructive")
	}
	if !IsListenerVerb("scan", nil) {
		t.Fatal("bare scan is an unbounded walk")
	}
	if !IsListenerVerb("scan", []string{"--path", "."}) {
		t.Fatal("scan --path is an unbounded walk")
	}
	if !IsDestructive("policy", []string{"init"}) {
		t.Fatal("policy init writes policies/ and must confirm")
	}
	if !IsDestructive("policy", []string{"init", "--template", "deny-first"}) {
		t.Fatal("policy init --template writes and must confirm")
	}
	if IsDestructive("policy", []string{"init", "--help"}) {
		t.Fatal("policy init --help is inspect")
	}
	if IsDestructive("policy", []string{"export", "--dialect", "cedar"}) {
		t.Fatal("policy export is a view")
	}
	for _, row := range policyActions() {
		if IsDestructive(row.name, row.args) {
			t.Fatalf("policy picker row %s %v is destructive", row.name, row.args)
		}
		if IsListenerVerb(row.name, row.args) {
			t.Fatalf("policy picker row %s %v is a listener", row.name, row.args)
		}
	}
}

func TestRedactSecrets(t *testing.T) {
	in := "Authorization: Bearer supersecretvalue123\nHELM_ADMIN_API_KEY=abcd1234efgh\n-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"
	out := RedactSecrets(in)
	for _, leak := range []string{"supersecretvalue123", "abcd1234efgh", "MIIB"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") && !strings.Contains(out, "[REDACTED PRIVATE KEY]") {
		t.Fatalf("expected redaction markers:\n%s", out)
	}
}

func TestMatchCeremonyToken(t *testing.T) {
	if _, ok := MatchCeremonyToken("a"); ok {
		t.Fatal("single letter must not approve")
	}
	if _, ok := MatchCeremonyToken("yes"); ok {
		t.Fatal("yes must not approve")
	}
	if action, ok := MatchCeremonyToken("approve"); !ok || action != "APPROVE" {
		t.Fatalf("EqualFold APPROVE: %s %v", action, ok)
	}
	if action, ok := MatchCeremonyToken("DENY"); !ok || action != "DENY" {
		t.Fatalf("DENY: %s %v", action, ok)
	}
}
