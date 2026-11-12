// quantum_posture: these tests exercise hook receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func manyDestinationsCommand(count int) string {
	var command strings.Builder
	command.WriteString("curl")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&command, " https://h%d.example/", i)
	}
	return command.String()
}

// A client may run a call whose hook outlives the hook timeout, so the time
// the hook takes must not grow with the square of what the call names.
func TestHookDecidesACallWithManyDestinationsOnce(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	input := map[string]any{"command": manyDestinationsCommand(20000)}

	start := time.Now()
	denied, receipts := env.run(t, "Bash", input)
	elapsed := time.Since(start)

	if !denied || len(receipts) != 1 || !hasDenial(receipts, "EGRESS_DESTINATION_UNDETERMINED") {
		t.Fatalf("20,000 destinations: denied=%v receipts=[%s], want one DENY/EGRESS_DESTINATION_UNDETERMINED", denied, describeReceipts(receipts))
	}
	if got := receipts[0].Request.Metadata["egress.destination_count"]; got != "20000" {
		t.Fatalf("egress.destination_count = %q, want the number of destinations the call named", got)
	}
	if elapsed > time.Second {
		t.Fatalf("the hook took %s to decide 20,000 destinations, want well under a second", elapsed)
	}
}

// One call may name at most hookMaxEgressDestinations destinations; past that
// it is one undetermined decision, not one receipt per host.
func TestHookCapsTheDestinationsOfOneCall(t *testing.T) {
	networkTargets := func(classifications []hookClassification) []string {
		var targets []string
		for _, classification := range classifications {
			if classification.Class == "network" {
				targets = append(targets, classification.Target)
			}
		}
		return targets
	}
	urls := func(count int) []any {
		list := make([]any, 0, count)
		for i := 0; i < count; i++ {
			list = append(list, fmt.Sprintf("https://h%d.example/", i))
		}
		return list
	}
	for _, tc := range []struct {
		name  string
		tool  string
		input func(count int) map[string]any
	}{
		{"shell command", "Bash", func(count int) map[string]any { return map[string]any{"command": manyDestinationsCommand(count)} }},
		{"fetch tool", "web_extract", func(count int) map[string]any { return map[string]any{"urls": urls(count)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			atLimit := networkTargets(classifyPreToolPayloads(preToolPayload{ToolName: tc.tool, ToolInput: tc.input(64)}, nil))
			if len(atLimit) != 64 || atLimit[0] != "https://h0.example" {
				t.Fatalf("64 destinations gave %d network decisions (first %v), want one per destination", len(atLimit), atLimit[:min(len(atLimit), 1)])
			}
			overLimit := classifyPreToolPayloads(preToolPayload{ToolName: tc.tool, ToolInput: tc.input(65)}, nil)
			targets := networkTargets(overLimit)
			if len(targets) != 1 || targets[0] != netdest.Undetermined {
				t.Fatalf("65 destinations gave network targets %v, want one undetermined decision", targets)
			}
			for _, classification := range overLimit {
				if classification.Class == "network" && classification.Metadata["egress.destination_count"] != "65" {
					t.Fatalf("the undetermined decision does not say how many destinations were named: %+v", classification.Metadata)
				}
			}
		})
	}
}

// The hook reads a bounded amount of standard input. A larger payload is not
// classified, and it is not passed either: it is denied with a receipt.
func TestHookDeniesAPayloadOverTheInputLimit(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	payload := func(size int) []byte {
		prefix, suffix := `{"tool_name":"Bash","session_id":"big","cwd":"/repo","tool_input":{"command":"echo `, `"}}`
		return []byte(prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix)
	}
	run := func(raw []byte) (string, []string) {
		t.Helper()
		before := map[string]bool{}
		for _, path := range globReceipts(t, env.dataDir) {
			before[path] = true
		}
		var stdout, stderr bytes.Buffer
		if code := runHookPreToolCmd(env.args, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
			t.Fatalf("hook exit = %d stderr = %s", code, stderr.String())
		}
		var written []string
		for _, path := range globReceipts(t, env.dataDir) {
			if !before[path] {
				written = append(written, path)
			}
		}
		return stdout.String(), written
	}

	// 4 MiB is the limit: a payload of exactly that size is still read.
	if stdout, written := run(payload(4 << 20)); stdout != "" || len(written) != 0 {
		t.Fatalf("a payload at the limit was not classified as the plain echo it is: stdout=%s receipts=%v", stdout, written)
	}

	stdout, written := run(payload(4<<20 + 1))
	if !strings.Contains(stdout, `"permissionDecision":"deny"`) || len(written) != 1 {
		t.Fatalf("a payload over the limit: stdout=%s receipts=%v, want a denial with one receipt", stdout, written)
	}
	receipt, err := workstation.LoadDecisionReceipt(written[0])
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := workstation.VerifyDecisionReceiptSignature(receipt); err != nil || !ok {
		t.Fatalf("receipt signature ok=%v err=%v", ok, err)
	}
	if receipt.Verdict != contracts.WorkstationVerdictDeny || receipt.ReasonCode != "TOOL_INPUT_TOO_LARGE" {
		t.Fatalf("receipt = %s/%s, want DENY/TOOL_INPUT_TOO_LARGE", receipt.Verdict, receipt.ReasonCode)
	}
	if receipt.Request.Metadata["call_id"] == "" || receipt.Request.Metadata["tool_input_limit_bytes"] != strconv.Itoa(4<<20) {
		t.Fatalf("receipt does not bind the call or name the limit: %+v", receipt.Request.Metadata)
	}
}

// A call that is denied leaves no ALLOW receipt behind: a reader of the
// receipt directory must not count an allowed action for a call that never ran.
func TestHookDeniedCallLeavesNoAllowReceipt(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	denied, receipts := env.run(t, "Bash", map[string]any{"command": "curl https://api.github.com/zen https://other.example/x"})
	if !denied || len(receipts) == 0 {
		t.Fatalf("denied=%v receipts=[%s], want a denial with a receipt", denied, describeReceipts(receipts))
	}
	for _, receipt := range receipts {
		if receipt.Verdict != contracts.WorkstationVerdictDeny {
			t.Fatalf("a denied call left a %s receipt for %s on disk: [%s]", receipt.Verdict, receipt.Request.EffectType, describeReceipts(receipts))
		}
		if receipt.Request.Metadata["call_verdict"] != contracts.WorkstationVerdictDeny {
			t.Fatalf("receipt does not carry the outcome of its call: %+v", receipt.Request.Metadata)
		}
	}
	if !hasDenial(receipts, "EGRESS_DESTINATION_NOT_ALLOWED") {
		t.Fatalf("no receipt names the refused destination: [%s]", describeReceipts(receipts))
	}
}

// Every receipt of one call carries the same call identifier, the number of
// receipts the call wrote, its outcome and a digest of the tool input, all in
// the signed bytes.
func TestHookReceiptsBindTheCallAndItsInput(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	input := map[string]any{"command": "curl https://api.github.com/zen && cat /home/agent/.ssh/id_rsa"}
	canonicalInput, err := canonicalize.JCS(input)
	if err != nil {
		t.Fatal(err)
	}
	wantInput := canonicalize.ComputeArtifactHash(canonicalInput)

	denied, receipts := env.run(t, "Bash", input)
	if denied || len(receipts) < 2 {
		t.Fatalf("denied=%v receipts=[%s], want an allowed call with a network and a secret receipt", denied, describeReceipts(receipts))
	}
	callID := receipts[0].Request.Metadata["call_id"]
	if callID == "" {
		t.Fatalf("receipt carries no call identifier: %+v", receipts[0].Request.Metadata)
	}
	for _, receipt := range receipts {
		metadata := receipt.Request.Metadata
		if metadata["call_id"] != callID {
			t.Fatalf("receipts of one call carry different call identifiers: %q and %q", callID, metadata["call_id"])
		}
		if metadata["call_receipts"] != strconv.Itoa(len(receipts)) || metadata["call_verdict"] != contracts.WorkstationVerdictAllow {
			t.Fatalf("receipt does not carry the size and outcome of its call: %+v", metadata)
		}
		if metadata["tool_input_binding"] != "jcs-sha256" || metadata["tool_input_sha256"] != wantInput {
			t.Fatalf("receipt does not bind the tool input: %+v, want %s", metadata, wantInput)
		}
	}

	_, again := env.run(t, "Bash", input)
	if len(again) == 0 || again[0].Request.Metadata["call_id"] == callID {
		t.Fatalf("a second call reused the call identifier %q", callID)
	}
}

// A network receipt's target is the digest of the destination, not of the URL
// an earlier release hashed, so the binding carries a name of its own.
func TestHookNetworkReceiptNamesItsTargetBinding(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	_, receipts := env.run(t, "Bash", map[string]any{"command": "curl https://api.github.com/zen"})
	if len(receipts) != 1 || receipts[0].Request.Metadata["target_binding"] != "sha256:utf-8:network-destination" {
		t.Fatalf("network receipt target_binding = %+v, want sha256:utf-8:network-destination", receipts)
	}
	if receipts[0].Request.Target != fingerprintHookTarget("https://api.github.com") {
		t.Fatalf("network receipt target = %q, want the digest of the destination", receipts[0].Request.Target)
	}
	_, receipts = env.run(t, "Read", map[string]any{"file_path": "/home/agent/.ssh/id_rsa"})
	if len(receipts) != 1 || receipts[0].Request.Metadata["target_binding"] != "sha256:utf-8" {
		t.Fatalf("a receipt whose target is the text itself keeps sha256:utf-8: %+v", receipts)
	}
}

// fixtures/workstation/compat/receipts/acf0b340-hook-network-deny.json was
// written by the hook built from the commit this branch started from
// (acf0b340), for the Bash call `curl https://api.github.com/zen` under the
// built-in profile, with the key in ../acf0b340-workstation-ed25519.pub. Its
// target is the digest of the whole URL under the binding "sha256:utf-8".
// Receipts already on disk must keep verifying.
func TestWorkstationVerifyDecisionAcceptsAReceiptFromTheBaseRelease(t *testing.T) {
	compat := filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "compat")
	receipt := filepath.Join(compat, "receipts", "acf0b340-hook-network-deny.json")
	base, err := workstation.LoadDecisionReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if base.Request.Target != fingerprintHookTarget("https://api.github.com/zen") || base.Request.Metadata["target_binding"] != hookTargetBindingText {
		t.Fatalf("the base fixture is not the receipt this test describes: %+v", base.Request)
	}
	key := filepath.Join(t.TempDir(), "base.pub")
	raw, err := os.ReadFile(filepath.Join(compat, "acf0b340-workstation-ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "workstation", "verify-decision", "--receipt", receipt, "--trusted-public-key-file", key, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify-decision exit = %d stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["integrity_valid"] != true || result["signer_trusted"] != true || result["verdict"] != "DENY" {
		t.Fatalf("verify-decision result = %v", result)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "workstation", "denied", "--input", receipt, "--trusted-public-key-file", key, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("denied exit = %d stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "EGRESS_ALLOWLIST_EMPTY") || !strings.Contains(stdout.String(), workstation.SignatureTrustedKey) {
		t.Fatalf("the operator view does not count the base receipt as signed by the trusted key:\n%s", stdout.String())
	}
}

// Tools that run code or load a URL are decided as that effect, whatever the
// matcher: a widened matcher must not turn them into a plain tool call.
func TestHookClassifiesCodeAndBrowserTools(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	cases := []struct {
		name       string
		tool       string
		input      map[string]any
		verdict    string // "" = passes without a decision
		reason     string
		effectType string
	}{
		{"code execution", "execute_code", map[string]any{"code": "print(1)"}, "ALLOW", "", contracts.EffectTypeWorkstationShellCommand},
		{"code execution without code", "execute_code", map[string]any{}, "ALLOW", "", contracts.EffectTypeWorkstationShellCommand},
		{"browser to an allowed host", "browser_navigate", map[string]any{"url": "https://api.github.com/zen"}, "ALLOW", "", contracts.EffectTypeWorkstationNetworkEgress},
		{"browser to another host", "browser_navigate", map[string]any{"url": "https://other.example/"}, "DENY", "EGRESS_DESTINATION_NOT_ALLOWED", contracts.EffectTypeWorkstationNetworkEgress},
		{"browser without a URL", "browser_navigate", map[string]any{}, "DENY", "EGRESS_DESTINATION_UNDETERMINED", contracts.EffectTypeWorkstationNetworkEgress},
		{"image from another host", "vision_analyze", map[string]any{"image_url": "https://other.example/a.png", "question": "what"}, "DENY", "EGRESS_DESTINATION_NOT_ALLOWED", contracts.EffectTypeWorkstationNetworkEgress},
		{"image named without a scheme", "vision_analyze", map[string]any{"image_url": "other.example/a.png"}, "DENY", "EGRESS_DESTINATION_NOT_ALLOWED", contracts.EffectTypeWorkstationNetworkEgress},
		{"image from a local file", "vision_analyze", map[string]any{"image_url": "/repo/shot.png"}, "", "", ""},
		{"image that is a credential file", "vision_analyze", map[string]any{"image_url": "/home/agent/.ssh/id_rsa"}, "ALLOW", "", contracts.EffectTypeWorkstationSecretRead},
		{"MCP resource read", "ReadMcpResourceTool", map[string]any{"server": "github", "uri": "repo://x"}, "ALLOW", "", contracts.EffectTypeWorkstationMCPToolCall},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			denied, receipts := env.run(t, tc.tool, tc.input)
			if tc.verdict == "" {
				if denied || len(receipts) != 0 {
					t.Fatalf("denied=%v receipts=[%s], want no decision", denied, describeReceipts(receipts))
				}
				return
			}
			if len(receipts) != 1 || receipts[0].Verdict != tc.verdict || receipts[0].ReasonCode != tc.reason || receipts[0].Request.EffectType != tc.effectType {
				t.Fatalf("denied=%v receipts=[%s], want one %s/%s %s receipt", denied, describeReceipts(receipts), tc.verdict, tc.reason, tc.effectType)
			}
			if denied != (tc.verdict == "DENY") {
				t.Fatalf("denied=%v with a %s receipt", denied, tc.verdict)
			}
			if receipts[0].Request.Metadata["tool_classification"] == "unknown" {
				t.Fatalf("%s was decided as a tool the hook does not know: %+v", tc.tool, receipts[0].Request)
			}
		})
	}

	// Under the built-in profile code execution is an operate-class shell
	// effect, and the code it carries is searched for the signer's files.
	builtin := newHookBypassEnv(t, "")
	denied, receipts := builtin.run(t, "execute_code", map[string]any{"code": "print(1)"})
	if !denied || len(receipts) != 1 || receipts[0].Request.EffectType != contracts.EffectTypeWorkstationShellCommand || receipts[0].ReasonCode != "OPERATE_PERMISSIONS_EMPTY" {
		t.Fatalf("execute_code under the built-in profile: denied=%v receipts=[%s]", denied, describeReceipts(receipts))
	}
	seed := filepath.Join(env.dataDir, "keys", "workstation-ed25519.seed")
	denied, receipts = env.run(t, "execute_code", map[string]any{"code": "print(open('" + seed + "').read())"})
	if !denied || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") {
		t.Fatalf("execute_code that names the signing seed: denied=%v receipts=[%s]", denied, describeReceipts(receipts))
	}
	// The MCP server setup installs governs its own resources.
	if denied, receipts := env.run(t, "ReadMcpResourceTool", map[string]any{"server": setupMCPServerName, "uri": "helm://x"}); denied || len(receipts) != 0 {
		t.Fatalf("a resource of the HELM server was decided: denied=%v receipts=[%s]", denied, describeReceipts(receipts))
	}
}

// A search tool's glob filter selects files at any depth below the search
// root, so a filter that names the signer's key files, or a credential file,
// is that read.
func TestHookGlobFiltersReachProtectedFiles(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	cases := []struct {
		name   string
		tool   string
		input  map[string]any
		reason string // "" = passes without a decision; "secret" = an allowed secret read
	}{
		{"recursive glob for the seed above the data directory", "Grep", map[string]any{"path": env.home, "glob": "**/*.seed", "pattern": "."}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"plain glob for the seed above the data directory", "Grep", map[string]any{"path": env.home, "glob": "*.seed", "pattern": "."}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"file_glob for the seed", "search_files", map[string]any{"path": env.home, "file_glob": "*.seed", "pattern": "."}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"file_glob for the public key with no root", "search_files", map[string]any{"file_glob": "workstation-ed25519.*", "pattern": "."}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"Glob pattern for the key directory", "Glob", map[string]any{"path": env.home, "pattern": "**/keys/*"}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"Glob pattern for the seed by name", "Glob", map[string]any{"pattern": "**/workstation-ed25519.seed"}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"glob for an env file", "Grep", map[string]any{"glob": ".env", "output_mode": "content", "pattern": "."}, "secret"},
		{"wildcard glob for an env file", "Grep", map[string]any{"glob": "**/.en*", "pattern": "."}, "secret"},
		{"file_glob for private keys", "search_files", map[string]any{"file_glob": "*.pem", "pattern": "."}, "secret"},
		{"Glob pattern for a private key", "Glob", map[string]any{"pattern": "**/id_rsa"}, "secret"},
		// A filter selects names at any depth below the search root, so one
		// that names the key directory reaches it from the home directory.
		{"glob filter for the key directory at any depth", "Grep", map[string]any{"path": env.home, "glob": "keys/*", "pattern": "."}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"file_glob filter for the key directory at any depth", "search_files", map[string]any{"path": env.home, "file_glob": "keys/*", "pattern": "."}, "TRUST_MATERIAL_ACCESS_DENIED"},
		{"include filter for the key directory at any depth", "mcp__fs__search_files", map[string]any{"path": env.home, "include": "keys/*"}, "TRUST_MATERIAL_ACCESS_DENIED"},

		{"recursive glob for sources", "Glob", map[string]any{"pattern": "**/*.go"}, ""},
		{"filter for documents", "Grep", map[string]any{"glob": "*.md", "pattern": "TODO"}, ""},
		{"file_glob for sources", "search_files", map[string]any{"file_glob": "*.py", "pattern": "TODO"}, ""},
		{"recursive glob for sources above the data directory", "Glob", map[string]any{"path": env.home, "pattern": "**/*.go"}, ""},
		{"filter that selects every file", "Grep", map[string]any{"glob": "*", "pattern": "TODO"}, ""},
		{"example env files by glob", "Grep", map[string]any{"glob": ".env.example", "pattern": "KEY"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			denied, receipts := env.run(t, tc.tool, tc.input)
			switch tc.reason {
			case "":
				if denied || len(receipts) != 0 {
					t.Fatalf("%s %v: denied=%v receipts=[%s], want no decision", tc.tool, tc.input, denied, describeReceipts(receipts))
				}
			case "secret":
				if denied || len(receipts) != 1 || receipts[0].Request.EffectType != contracts.EffectTypeWorkstationSecretRead {
					t.Fatalf("%s %v: denied=%v receipts=[%s], want one secret-read decision", tc.tool, tc.input, denied, describeReceipts(receipts))
				}
			default:
				if !denied || !hasDenial(receipts, tc.reason) {
					t.Fatalf("%s %v: denied=%v receipts=[%s], want DENY/%s", tc.tool, tc.input, denied, describeReceipts(receipts), tc.reason)
				}
			}
		})
	}
}

// A shell tool whose command is missing or is not a string cannot be read, so
// it is decided as an opaque shell operation instead of being passed.
func TestHookDecidesAShellCallWithoutAStringCommand(t *testing.T) {
	builtin := newHookBypassEnv(t, "")
	for _, tc := range []struct {
		name  string
		tool  string
		input map[string]any
	}{
		{"command is a list", "Bash", map[string]any{"command": []any{"cat", "x"}}},
		{"command is an object", "Bash", map[string]any{"command": map[string]any{"run": "cat x"}}},
		{"command is a number", "terminal", map[string]any{"command": 7}},
		{"command is absent", "Bash", map[string]any{"description": "nothing to run"}},
		{"cmd is a list beside an empty command", "Bash", map[string]any{"command": "", "cmd": []any{"rm", "-rf", "/"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied, receipts := builtin.run(t, tc.tool, tc.input)
			if !denied || len(receipts) != 1 || receipts[0].Request.EffectType != contracts.EffectTypeWorkstationShellCommand || receipts[0].ReasonCode != "OPERATE_PERMISSIONS_EMPTY" {
				t.Fatalf("%s %v: denied=%v receipts=[%s], want one denied shell-operate decision", tc.tool, tc.input, denied, describeReceipts(receipts))
			}
		})
	}
	// A command that is a string is read as before.
	if denied, receipts := builtin.run(t, "Bash", map[string]any{"command": "cat README.md"}); denied || len(receipts) != 0 {
		t.Fatalf("a plain read was decided: denied=%v receipts=[%s]", denied, describeReceipts(receipts))
	}
	// The signer's files stay closed even under a profile that grants
	// shell.operate, whatever shape the command has.
	granted := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	seed := filepath.Join(granted.dataDir, "keys", "workstation-ed25519.seed")
	if denied, receipts := granted.run(t, "Bash", map[string]any{"command": []any{"cat", seed}}); !denied || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") {
		t.Fatalf("a list command that names the seed: denied=%v receipts=[%s]", denied, describeReceipts(receipts))
	}
}

// Public keys and example env files are not credentials: reading them is a
// plain read through a read tool and through a shell alike.
func TestHookLeavesPublicKeysAndExampleEnvFilesAlone(t *testing.T) {
	builtin := newHookBypassEnv(t, "")
	for _, tc := range []struct {
		tool  string
		input map[string]any
	}{
		{"Read", map[string]any{"file_path": "/repo/.env.example"}},
		{"Read", map[string]any{"file_path": "/repo/.env.sample"}},
		{"Read", map[string]any{"file_path": "/repo/config/.env.template"}},
		{"Read", map[string]any{"file_path": "/repo/tests/fixtures/id_rsa.pub"}},
		{"Read", map[string]any{"file_path": "/home/agent/.ssh/id_ed25519.pub"}},
		{"Bash", map[string]any{"command": "cat .env.example"}},
		{"Bash", map[string]any{"command": "cat tests/fixtures/id_rsa.pub"}},
	} {
		if denied, receipts := builtin.run(t, tc.tool, tc.input); denied || len(receipts) != 0 {
			t.Errorf("%s %v: denied=%v receipts=[%s], want no decision", tc.tool, tc.input, denied, describeReceipts(receipts))
		}
	}
	for _, tc := range []struct {
		tool  string
		input map[string]any
	}{
		{"Read", map[string]any{"file_path": "/repo/.env"}},
		{"Read", map[string]any{"file_path": "/repo/.env.example.local"}},
		{"Read", map[string]any{"file_path": "/repo/.env.example/../.env"}},
		{"Read", map[string]any{"file_path": "/home/agent/.ssh/id_ed25519"}},
		{"Read", map[string]any{"file_path": "/home/agent/.aws/credentials"}},
		{"Bash", map[string]any{"command": "cat ~/.ssh/id_rsa ~/.ssh/id_rsa.pub"}},
	} {
		if denied, receipts := builtin.run(t, tc.tool, tc.input); !denied || !hasDenial(receipts, "OPERATE_PERMISSIONS_EMPTY") {
			t.Errorf("%s %v: denied=%v receipts=[%s], want a denied secret read", tc.tool, tc.input, denied, describeReceipts(receipts))
		}
	}
}
