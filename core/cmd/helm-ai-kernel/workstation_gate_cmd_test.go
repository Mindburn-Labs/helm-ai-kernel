package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/workstation"
)

func gateTestAllowlist(t *testing.T, entries []string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/shell-allowlist.json"
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal allowlist: %v", err)
	}
	if err := writeFile0600(path, data); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
	return path
}

func writeFile0600(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func runGateForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWorkstationGateCmd(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestWorkstationGateAllow(t *testing.T) {
	allowlist := gateTestAllowlist(t, []string{"ls", "cat"})
	code, out, _ := runGateForTest(t, "--allowlist", allowlist, "--command", "cat f | ls")
	if code != exitGateAllow {
		t.Fatalf("exit = %d, want %d (out: %s)", code, exitGateAllow, out)
	}
	if !strings.Contains(out, "allow") {
		t.Fatalf("output missing allow verdict:\n%s", out)
	}
}

func TestWorkstationGateProductionDeny(t *testing.T) {
	allowlist := gateTestAllowlist(t, []string{"ls"})
	code, out, _ := runGateForTest(t, "--allowlist", allowlist, "--command", "ls && rm -rf /tmp/x")
	if code != exitGateDeny {
		t.Fatalf("exit = %d, want %d (out: %s)", code, exitGateDeny, out)
	}
	if !strings.Contains(out, "deny") || !strings.Contains(out, "rm") {
		t.Fatalf("output missing deny verdict and blocked command:\n%s", out)
	}
}

func TestPrintGateDecisionSanitizesTerminalText(t *testing.T) {
	var out bytes.Buffer
	printGateDecision(&out, workstation.ShellGateDecision{
		Command: "\x1b[2Jrm\rspoof",
		Invoked: []string{"rm\x00"},
		Blocked: []string{"rm\x1b"},
		Reason:  "blocked\u202Etxt",
	}, "/tmp/\x1ballowlist")
	if strings.Count(out.String(), "\x1b") != 2 || strings.Contains(out.String(), "\x1b[2J") {
		t.Fatalf("gate output contains attacker-controlled terminal escape: %q", out.String())
	}
	for _, control := range []string{"\r", "\x00", "\u202E"} {
		if strings.Contains(out.String(), control) {
			t.Fatalf("gate output contains terminal control %q: %q", control, out.String())
		}
	}
}

func TestWorkstationGateDevEscalates(t *testing.T) {
	allowlist := gateTestAllowlist(t, []string{"ls"})
	code, out, _ := runGateForTest(t, "--profile", "dev", "--allowlist", allowlist, "--command", "ls && rm -rf /tmp/x")
	if code != exitGatePendingApproval {
		t.Fatalf("exit = %d, want %d (out: %s)", code, exitGatePendingApproval, out)
	}
	if !strings.Contains(out, "pending_approval") {
		t.Fatalf("output missing pending_approval verdict:\n%s", out)
	}
}

func TestWorkstationGateUnknownProfileFailsClosed(t *testing.T) {
	allowlist := gateTestAllowlist(t, []string{"ls"})
	code, _, _ := runGateForTest(t, "--profile", "staging", "--allowlist", allowlist, "--command", "rm x")
	if code != exitGateDeny {
		t.Fatalf("exit = %d, want %d for unknown profile", code, exitGateDeny)
	}
}

func TestWorkstationGateCorruptAllowlistFailsClosed(t *testing.T) {
	path := t.TempDir() + "/shell-allowlist.json"
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt allowlist: %v", err)
	}
	code, _, _ := runGateForTest(t, "--allowlist", path, "--command", "ls")
	if code != exitGateDeny {
		t.Fatalf("exit = %d, want %d for corrupt allowlist in production", code, exitGateDeny)
	}
	code, _, _ = runGateForTest(t, "--profile", "dev", "--allowlist", path, "--command", "ls")
	if code != exitGatePendingApproval {
		t.Fatalf("exit = %d, want %d for corrupt allowlist in dev", code, exitGatePendingApproval)
	}
}

func TestWorkstationGateRequestApprovalCreatesCeremony(t *testing.T) {
	var gotBody createApprovalRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != approvalAPIBasePath {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(contracts.ApprovalCeremony{
			ApprovalID: "ap-gate-1",
			Subject:    gotBody.Subject,
			Action:     gotBody.Action,
			State:      contracts.ApprovalCeremonyPending,
		})
	}))
	defer server.Close()
	t.Setenv(serviceAPIKeyEnv, "test-key")

	allowlist := gateTestAllowlist(t, []string{"ls"})
	code, out, errOut := runGateForTest(t,
		"--profile", "dev",
		"--allowlist", allowlist,
		"--request-approval",
		"--url", server.URL,
		"--command", "sudo rm /x",
	)
	if code != exitGatePendingApproval {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitGatePendingApproval, errOut)
	}
	if gotBody.Subject != "shell_command" || gotBody.Action != "shell_operate" {
		t.Fatalf("approval request = %+v", gotBody)
	}
	if !strings.Contains(gotBody.Reason, "rm") || !strings.Contains(gotBody.Reason, "sudo") {
		t.Fatalf("approval reason must name blocked commands: %q", gotBody.Reason)
	}
	if !strings.Contains(gotBody.Reason, workstation.ShellCommandBinding("sudo rm /x")) {
		t.Fatalf("approval reason must bind the exact command: %q", gotBody.Reason)
	}
	if gotBody.BindingHash != workstation.ShellCommandBindingRef("sudo rm /x") {
		t.Fatalf("approval binding = %q, want immutable command hash", gotBody.BindingHash)
	}
	if gotBody.RequestedBy != "agent.local" {
		t.Fatalf("default requester = %q, want agent.local distinct from watch approver", gotBody.RequestedBy)
	}
	if !strings.Contains(out, "ap-gate-1") {
		t.Fatalf("output must surface the created approval id:\n%s", out)
	}
}

func TestWorkstationGateConsumesExactApprovalOnce(t *testing.T) {
	command := "rm /x"
	approval := contracts.ApprovalCeremony{
		ApprovalID:  "ap-bound",
		Subject:     workstation.ShellGateApprovalSubject,
		Action:      workstation.ShellGateApprovalAction,
		State:       contracts.ApprovalCeremonyAllowed,
		RequestedBy: "operator.cli",
		BindingHash: workstation.ShellCommandBindingRef(command),
		Reason:      "approved; " + workstation.ShellCommandBinding(command),
	}
	revokeCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != approvalAPIBasePath+"/"+approval.ApprovalID+"/consume" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["binding_hash"] != approval.BindingHash || approval.State != contracts.ApprovalCeremonyAllowed {
			http.Error(w, "not approved for binding", http.StatusBadRequest)
			return
		}
		revokeCount++
		approval.State = contracts.ApprovalCeremonyRevoked
		_ = json.NewEncoder(w).Encode(approval)
	}))
	defer server.Close()
	t.Setenv(serviceAPIKeyEnv, "test-key")

	allowlist := gateTestAllowlist(t, []string{"ls"})
	args := []string{
		"--profile", "dev",
		"--allowlist", allowlist,
		"--data-dir", t.TempDir(),
		"--approval-id", approval.ApprovalID,
		"--url", server.URL,
		"--command", command,
	}
	code, out, errOut := runGateForTest(t, args...)
	if code != exitGateAllow {
		t.Fatalf("first consume exit = %d, want allow; out=%s err=%s", code, out, errOut)
	}
	args[5] = t.TempDir()
	code, _, errOut = runGateForTest(t, args...)
	if code != 1 || !strings.Contains(errOut, "400") || revokeCount != 1 {
		t.Fatalf("cross-ledger reuse exit=%d revokes=%d err=%s, want server-side consumed rejection", code, revokeCount, errOut)
	}
}

func TestWorkstationGateRejectsApprovalForDifferentCommand(t *testing.T) {
	approval := contracts.ApprovalCeremony{
		ApprovalID:  "ap-wrong",
		Subject:     workstation.ShellGateApprovalSubject,
		Action:      workstation.ShellGateApprovalAction,
		State:       contracts.ApprovalCeremonyAllowed,
		RequestedBy: "operator.cli",
		BindingHash: workstation.ShellCommandBindingRef("rm /tmp/safe"),
		Reason:      "approved; " + workstation.ShellCommandBinding("rm /tmp/safe"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["binding_hash"] != approval.BindingHash {
			http.Error(w, "wrong binding", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(approval)
	}))
	defer server.Close()
	t.Setenv(serviceAPIKeyEnv, "test-key")

	code, _, errOut := runGateForTest(t,
		"--profile", "dev",
		"--allowlist", gateTestAllowlist(t, []string{"ls"}),
		"--data-dir", t.TempDir(),
		"--approval-id", approval.ApprovalID,
		"--url", server.URL,
		"--command", "rm /etc/passwd",
	)
	if code != 1 || !strings.Contains(errOut, "400") {
		t.Fatalf("exit = %d err=%s, want command-binding rejection", code, errOut)
	}
}

func TestWorkstationGateRequestApprovalServerDown(t *testing.T) {
	t.Setenv(serviceAPIKeyEnv, "test-key")
	allowlist := gateTestAllowlist(t, []string{"ls"})
	code, _, errOut := runGateForTest(t,
		"--profile", "dev",
		"--allowlist", allowlist,
		"--request-approval",
		"--url", "http://127.0.0.1:1",
		"--command", "rm /x",
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 when the approval request fails", code)
	}
	if !strings.Contains(errOut, "approval request failed") {
		t.Fatalf("stderr missing failure detail:\n%s", errOut)
	}
}

func TestWorkstationGateJSONOutput(t *testing.T) {
	allowlist := gateTestAllowlist(t, []string{"ls"})
	code, out, _ := runGateForTest(t, "--allowlist", allowlist, "--json", "--command", "echo $(rm /x)")
	if code != exitGateDeny {
		t.Fatalf("exit = %d, want %d", code, exitGateDeny)
	}
	var decision map[string]any
	if err := json.Unmarshal([]byte(out), &decision); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if decision["verdict"] != "deny" {
		t.Fatalf("verdict = %v, want deny", decision["verdict"])
	}
}

func TestWorkstationGateRequiresCommand(t *testing.T) {
	code, _, _ := runGateForTest(t, "--profile", "dev")
	if code != 2 {
		t.Fatalf("exit = %d, want 2 for missing command", code)
	}
}
