package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func testWatchRuntime(input string, client *watchFakeClient, interactive, outputTTY bool) watchRuntime {
	return watchRuntime{
		input:     strings.NewReader(input),
		caps:      ui.Capabilities{Interactive: interactive, Color: false, Unicode: false, Width: 100},
		outputTTY: outputTTY,
		newClient: func(string, string) (approvalClient, error) { return client, nil },
	}
}

func TestWatchJSONAndNonTTYAreSnapshotOnly(t *testing.T) {
	t.Setenv(watchAdminAPIKeyEnv, "environment-key")
	item := watchTestCeremony("ap-1", time.Unix(1, 0))
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "json", args: []string{"--json"}},
		{name: "pipe", args: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &watchFakeClient{items: []contracts.ApprovalCeremony{item}}
			var stdout, stderr bytes.Buffer
			code := runWatchCmdWithRuntime(test.args, &stdout, &stderr, testWatchRuntime("ap-1\nAPPROVE\nAPPROVE\n", client, true, test.name == "json"))
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}
			if len(client.transitions) != 0 || strings.Contains(stdout.String(), "Type APPROVE") || strings.Contains(stdout.String(), "\x1b") || stderr.Len() != 0 {
				t.Fatalf("noninteractive watch had chrome or transition: stdout=%q stderr=%q transitions=%+v", stdout.String(), stderr.String(), client.transitions)
			}
			if test.name == "json" {
				var decoded struct {
					Pending []map[string]any `json:"pending"`
				}
				if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil || len(decoded.Pending) != 1 {
					t.Fatalf("JSON snapshot = %q, decode error = %v", stdout.String(), err)
				}
			} else if !strings.Contains(stdout.String(), "HELM WATCH snapshot") || !strings.Contains(stdout.String(), "ap-1") {
				t.Fatalf("plain snapshot = %q", stdout.String())
			}
		})
	}
}

func TestWatchRedactsReflectedResolvedAPIKeyErrors(t *testing.T) {
	const apiKey = "reflected-admin-key"
	t.Setenv(watchAdminAPIKeyEnv, apiKey)
	reflected := errors.New("remote response reflected Bearer " + apiKey)
	if !errors.Is(redactWatchError(reflected, apiKey), reflected) {
		t.Fatal("redaction must preserve the wrapped error for structured callers")
	}

	t.Run("snapshot stderr", func(t *testing.T) {
		client := &watchFakeClient{listErr: reflected}
		var stdout, stderr bytes.Buffer
		code := runWatchCmdWithRuntime([]string{"--json"}, &stdout, &stderr, testWatchRuntime("", client, false, true))
		if code != 1 || stdout.Len() != 0 {
			t.Fatalf("snapshot code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), apiKey) || !strings.Contains(stderr.String(), "[REDACTED]") {
			t.Fatalf("snapshot error leaked resolved API key: %q", stderr.String())
		}
	})

	t.Run("client construction", func(t *testing.T) {
		runtime := testWatchRuntime("", nil, false, true)
		runtime.newClient = func(_, key string) (approvalClient, error) {
			if key != apiKey {
				t.Fatalf("constructor key = %q", key)
			}
			return nil, reflected
		}
		var stdout, stderr bytes.Buffer
		code := runWatchCmdWithRuntime([]string{"--json"}, &stdout, &stderr, runtime)
		if code != 2 || stdout.Len() != 0 {
			t.Fatalf("constructor code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), apiKey) || !strings.Contains(stderr.String(), "[REDACTED]") {
			t.Fatalf("constructor error leaked resolved API key: %q", stderr.String())
		}
	})

	t.Run("interactive chrome", func(t *testing.T) {
		client := &watchFakeClient{
			items:         []contracts.ApprovalCeremony{watchTestCeremony("ap-1", time.Unix(1, 0))},
			transitionErr: reflected,
		}
		var stdout, stderr bytes.Buffer
		code := runWatchCmdWithRuntime(nil, &stdout, &stderr, testWatchRuntime("ap-1\nAPPROVE\nAPPROVE\n\n", client, true, true))
		if code != 0 || stdout.Len() != 0 {
			t.Fatalf("interactive code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), apiKey) || !strings.Contains(stderr.String(), "[REDACTED]") || !strings.Contains(stderr.String(), "HELM watch") {
			t.Fatalf("interactive watch chrome leaked resolved API key: %q", stderr.String())
		}
	})
}

func TestWatchInteractiveTransitionRequiresExactSecondConfirmation(t *testing.T) {
	item := watchTestCeremony("ap-1", time.Unix(1, 0))
	client := &watchFakeClient{items: []contracts.ApprovalCeremony{item}}
	var chrome bytes.Buffer
	code := runWatchInteractive(client, "operator.cli", strings.NewReader("ap-1\nAPPROVE\nnot-approved\n\n"), &chrome, ui.Capabilities{Interactive: true, Width: 100})
	if code != 0 {
		t.Fatalf("exit code = %d, chrome=%s", code, chrome.String())
	}
	if len(client.transitions) != 0 {
		t.Fatalf("transition occurred without exact confirmation: %+v", client.transitions)
	}
	out := chrome.String()
	for _, want := range []string{"Review required", "Action: APPROVE", "Approval ID: ap-1", "Challenge hash", "Ceremony hash", "Type APPROVE to confirm", "No state change recorded"} {
		if !strings.Contains(out, want) {
			t.Errorf("interactive review missing %q:\n%s", want, out)
		}
	}
}

func TestWatchInteractiveRoutesApproveAndDenyThroughConfirmation(t *testing.T) {
	for _, test := range []struct {
		name   string
		action string
		want   string
	}{
		{name: "approve", action: "APPROVE", want: "approve"},
		{name: "deny", action: "DENY", want: "deny"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &watchFakeClient{items: []contracts.ApprovalCeremony{watchTestCeremony("ap-1", time.Unix(1, 0))}}
			input := "ap-1\n" + test.action + "\n" + test.action + "\n\n"
			var chrome bytes.Buffer
			code := runWatchInteractive(client, "operator.cli", strings.NewReader(input), &chrome, ui.Capabilities{Interactive: true, Width: 100})
			if code != 0 {
				t.Fatalf("exit code = %d, chrome=%s", code, chrome.String())
			}
			if len(client.transitions) != 1 {
				t.Fatalf("transitions = %+v", client.transitions)
			}
			got := client.transitions[0]
			if got.action != test.want || got.approvalID != "ap-1" || got.actor != "operator.cli" || got.reason == "" {
				t.Fatalf("transition = %+v", got)
			}
		})
	}
}

func TestWatchInteractiveKeepsCredentialBoundCeremoniesReadOnly(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*contracts.ApprovalCeremony)
	}{
		{
			name: "auth method",
			mutate: func(item *contracts.ApprovalCeremony) {
				item.AuthMethod = "webauthn"
			},
		},
		{
			name: "challenge",
			mutate: func(item *contracts.ApprovalCeremony) {
				item.ChallengeID = "challenge-1"
			},
		},
		{
			name: "challenge hash",
			mutate: func(item *contracts.ApprovalCeremony) {
				item.ChallengeHash = "sha256:challenge"
			},
		},
		{
			name: "assertion",
			mutate: func(item *contracts.ApprovalCeremony) {
				item.AssertionHash = "sha256:assertion"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := watchTestCeremony("ap-1", time.Unix(1, 0))
			test.mutate(&item)
			client := &watchFakeClient{items: []contracts.ApprovalCeremony{item}}
			var chrome bytes.Buffer

			code := runWatchInteractive(client, "operator.cli", strings.NewReader("ap-1\n\n"), &chrome, ui.Capabilities{Interactive: true, Width: 100})
			if code != 0 {
				t.Fatalf("exit code = %d, chrome=%s", code, chrome.String())
			}
			if len(client.transitions) != 0 {
				t.Fatalf("credential-bound ceremony issued transition: %+v", client.transitions)
			}
			if !strings.Contains(chrome.String(), "read-only in watch") || !strings.Contains(chrome.String(), "verified approval flow") {
				t.Fatalf("watch did not explain the read-only state:\n%s", chrome.String())
			}
			if strings.Contains(chrome.String(), "Type APPROVE") {
				t.Fatalf("watch opened a confirmation prompt for a credential-bound ceremony:\n%s", chrome.String())
			}
		})
	}
}

type pendingWatchTransitionClient struct {
	items        []contracts.ApprovalCeremony
	transitioned contracts.ApprovalCeremony
	listCalls    int
	transitions  []watchTransition
}

func (f *pendingWatchTransitionClient) ListApprovals(context.Context) ([]contracts.ApprovalCeremony, error) {
	f.listCalls++
	return append([]contracts.ApprovalCeremony(nil), f.items...), nil
}

func (f *pendingWatchTransitionClient) TransitionApproval(_ context.Context, approvalID, action, actor, reason string) (contracts.ApprovalCeremony, error) {
	f.transitions = append(f.transitions, watchTransition{approvalID: approvalID, action: action, actor: actor, reason: reason})
	return f.transitioned, nil
}

func TestWatchInteractiveDoesNotReportPendingApproveAsSuccess(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason string
	}{
		{name: "timelock", reason: "approval timelock has not elapsed"},
		{name: "quorum", reason: "approval requires a 2-party quorum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := watchTestCeremony("ap-1", time.Unix(1, 0))
			pending := item
			pending.State = contracts.ApprovalCeremonyPending
			pending.Reason = test.reason
			client := &pendingWatchTransitionClient{
				items:        []contracts.ApprovalCeremony{item},
				transitioned: pending,
			}

			var chrome bytes.Buffer
			code := runWatchInteractive(client, "operator.cli", strings.NewReader("ap-1\nAPPROVE\nAPPROVE\n\n"), &chrome, ui.Capabilities{Interactive: true, Width: 100})
			if code != 0 {
				t.Fatalf("exit code = %d, chrome=%s", code, chrome.String())
			}
			if len(client.transitions) != 1 {
				t.Fatalf("transitions = %+v", client.transitions)
			}
			if client.listCalls < 2 {
				t.Fatalf("list calls = %d, want refresh after non-terminal transition", client.listCalls)
			}
			out := chrome.String()
			for _, want := range []string{
				"[WAIT] APPROVE did not reach approved state for ap-1",
				"Server state: pending.",
				test.reason,
			} {
				if !strings.Contains(out, want) {
					t.Errorf("watch output missing %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "APPROVE recorded for ap-1") {
				t.Fatalf("pending approval was reported as success:\n%s", out)
			}
		})
	}
}

func TestWatchInteractiveRefreshFailureDisablesActions(t *testing.T) {
	client := &watchFakeClient{listErr: errors.New("server\x1b[2J unavailable")}
	var chrome bytes.Buffer
	code := runWatchInteractive(client, "operator.cli", strings.NewReader("ap-1\nAPPROVE\nAPPROVE\n"), &chrome, ui.Capabilities{Interactive: true, Width: 100})
	if code != 1 {
		t.Fatalf("exit code = %d, chrome=%s", code, chrome.String())
	}
	if len(client.transitions) != 0 {
		t.Fatalf("transition occurred after failed refresh: %+v", client.transitions)
	}
	out := chrome.String()
	if strings.Contains(out, "\x1b") || !strings.Contains(out, "Actions are disabled") || strings.Contains(out, "Type APPROVE") {
		t.Fatalf("failed-refresh chrome = %q", out)
	}
}

func TestResolveWatchAPIKeyRejectsUnsafeFilesAndArgvSecret(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "admin.key")
	if err := os.WriteFile(keyFile, []byte("file-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveWatchAPIKey(keyFile); err != nil || got != "file-key" {
		t.Fatalf("resolve private file = %q, %v", got, err)
	}
	if err := os.Chmod(keyFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveWatchAPIKey(keyFile); err == nil || !strings.Contains(err.Error(), "group") {
		t.Fatalf("insecure key file error = %v", err)
	}
	symlink := filepath.Join(dir, "link.key")
	if err := os.Symlink(keyFile, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveWatchAPIKey(symlink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink key file error = %v", err)
	}

	t.Setenv(watchAdminAPIKeyEnv, "environment-key")
	var stdout, stderr bytes.Buffer
	code := runWatchCmdWithRuntime([]string{"--api-key", "argv-secret"}, &stdout, &stderr, testWatchRuntime("", &watchFakeClient{}, false, false))
	if code != 2 || strings.Contains(stderr.String(), "argv-secret") {
		t.Fatalf("argv secret rejection code=%d stderr=%q", code, stderr.String())
	}
}
