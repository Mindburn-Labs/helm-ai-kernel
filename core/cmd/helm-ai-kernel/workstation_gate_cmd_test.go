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
	t.Setenv(watchAdminAPIKeyEnv, "test-key")

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
	if !strings.Contains(out, "ap-gate-1") {
		t.Fatalf("output must surface the created approval id:\n%s", out)
	}
}

func TestWorkstationGateRequestApprovalServerDown(t *testing.T) {
	t.Setenv(watchAdminAPIKeyEnv, "test-key")
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
