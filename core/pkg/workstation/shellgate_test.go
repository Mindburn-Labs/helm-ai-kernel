package workstation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestExtractCommandNames(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{"simple", "ls -la", []string{"ls"}},
		{"pipe", "cat f | grep x", []string{"cat", "grep"}},
		{"and", "echo a && rm b", []string{"echo", "rm"}},
		{"or", "false || echo ok", []string{"echo", "false"}},
		{"or is not two pipes", "cat a.json || cat b.json", []string{"cat"}},
		{"semicolon", "ls; pwd", []string{"ls", "pwd"}},
		{"background", "sleep 1 & rm -rf /tmp/x", []string{"rm", "sleep"}},
		{"backticks", "echo `rm /x`", []string{"echo", "rm"}},
		{"dollar paren", "echo $(rm /x)", []string{"echo", "rm"}},
		{"subshell", "(rm /x)", []string{"rm"}},
		{"subshell chained", "echo hi && (cd /tmp && make)", []string{"cd", "echo", "make"}},
		{"newline", "ls\nrm /x", []string{"ls", "rm"}},
		{"env prefix", "FOO=bar ls", []string{"ls"}},
		{"multiple env prefixes", "FOO=bar BAZ=qux sudo rm /x", []string{"rm", "sudo"}},
		{"env prefix only", "FOO=bar", nil},
		{"sudo wrapper", "sudo rm /x", []string{"rm", "sudo"}},
		{"env wrapper", "env rm /x", []string{"env", "rm"}},
		{"time wrapper", "time ls", []string{"ls", "time"}},
		{"command wrapper", "command ls", []string{"command", "ls"}},
		{"nested wrappers", "sudo time rm /x", []string{"rm", "sudo", "time"}},
		{"nested wrappers with env", "sudo env FOO=1 rm /x", []string{"env", "rm", "sudo"}},
		{"env wrapper skips assignments", "env FOO=bar rm /x", []string{"env", "rm"}},
		{"wrapper with flag", "time -p ls", []string{"ls", "time"}},
		{"wrapper alone", "sudo", []string{"sudo"}},
		{"quoted command", "'rm' /x", []string{"rm"}},
		{"double quoted command", `"curl" https://example.com`, []string{"curl"}},
		{"uppercase lowered", "SUDO RM /x", []string{"rm", "sudo"}},
		{"mixed chaining", "cat a | grep b && jq . || echo done", []string{"cat", "echo", "grep", "jq"}},
		{"substitution inside args", "ls $(pwd)/x", []string{"/x", "ls", "pwd"}},
		{"empty", "", nil},
		{"whitespace", "   ", nil},
		{"separator only", "|", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractCommandNames(tc.command)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExtractCommandNames(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

func TestBlockedCommandNames(t *testing.T) {
	allowlist := []string{"cat", "grep", "ls", "sudo", "echo"}
	cases := []struct {
		name      string
		command   string
		allowlist []string
		want      []string
	}{
		{"all allowed", "cat f | grep x", allowlist, nil},
		{"one blocked", "cat f | rm x", allowlist, []string{"rm"}},
		{"blocked behind wrapper", "sudo rm /x", allowlist, []string{"rm"}},
		{"blocked behind substitution", "echo $(rm /x)", allowlist, []string{"rm"}},
		{"wildcard allows everything", "rm -rf /", []string{"*"}, nil},
		{"empty allowlist blocks everything", "ls", nil, []string{"ls"}},
		{"no commands blocks nothing", "", allowlist, nil},
		{"allowlist entries normalized", "LS -la", []string{" ls "}, nil},
		{"wrapper not allowlisted", "sudo ls", []string{"ls"}, []string{"sudo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BlockedCommandNames(tc.command, tc.allowlist)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("BlockedCommandNames(%q, %v) = %v, want %v", tc.command, tc.allowlist, got, tc.want)
			}
		})
	}
}

func TestGateShellCommandProfiles(t *testing.T) {
	allowlist := []string{"ls"}

	t.Run("allowed in production", func(t *testing.T) {
		decision := GateShellCommand(ShellGateProfileProduction, "ls -la", allowlist)
		if decision.Verdict != ShellGateVerdictAllow {
			t.Fatalf("verdict = %s, want allow", decision.Verdict)
		}
	})

	t.Run("allowed in dev", func(t *testing.T) {
		decision := GateShellCommand(ShellGateProfileDev, "ls", allowlist)
		if decision.Verdict != ShellGateVerdictAllow {
			t.Fatalf("verdict = %s, want allow", decision.Verdict)
		}
	})

	t.Run("blocked in production denies", func(t *testing.T) {
		decision := GateShellCommand(ShellGateProfileProduction, "rm -rf /", allowlist)
		if decision.Verdict != ShellGateVerdictDeny {
			t.Fatalf("verdict = %s, want deny", decision.Verdict)
		}
		if !reflect.DeepEqual(decision.Blocked, []string{"rm"}) {
			t.Fatalf("blocked = %v, want [rm]", decision.Blocked)
		}
	})

	t.Run("blocked in dev escalates to pending approval", func(t *testing.T) {
		decision := GateShellCommand(ShellGateProfileDev, "rm -rf /", allowlist)
		if decision.Verdict != ShellGateVerdictPendingApproval {
			t.Fatalf("verdict = %s, want pending_approval", decision.Verdict)
		}
		if decision.Reason == "" {
			t.Fatal("escalation must carry a reason")
		}
	})

	t.Run("unknown profile fails closed as production", func(t *testing.T) {
		if got := NormalizeShellGateProfile("staging"); got != ShellGateProfileProduction {
			t.Fatalf("NormalizeShellGateProfile(staging) = %s, want production", got)
		}
		decision := GateShellCommand(NormalizeShellGateProfile("STAGING"), "rm x", allowlist)
		if decision.Verdict != ShellGateVerdictDeny {
			t.Fatalf("verdict = %s, want deny for unknown profile", decision.Verdict)
		}
	})
}

func writeShellAllowlist(t *testing.T, path string, payload any, mode os.FileMode) time.Time {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal allowlist: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat allowlist: %v", err)
	}
	return info.ModTime()
}

func TestShellAllowlistStoreSeedsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workstation", ShellAllowlistFilename)
	store := NewShellAllowlistStore(path)

	got, err := store.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist: %v", err)
	}
	want := append([]string(nil), DefaultShellAllowlist...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("seeded allowlist = %v, want %v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("seeded file missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("seeded file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestShellAllowlistStoreFormats(t *testing.T) {
	cases := []struct {
		name    string
		payload any
		want    []string
	}{
		{"bare array", []string{"LS", " cat ", "ls", ""}, []string{"cat", "ls"}},
		{"allowedCommands object", map[string]any{"allowedCommands": []string{"JQ", "ls"}}, []string{"jq", "ls"}},
		{"truthy map", map[string]any{"ls": true, "rm": false, "cat": 1, "dd": 0, "pwd": "yes", "xargs": ""}, []string{"cat", "ls", "pwd"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ShellAllowlistFilename)
			writeShellAllowlist(t, path, tc.payload, 0o600)
			got, err := NewShellAllowlistStore(path).Allowlist()
			if err != nil {
				t.Fatalf("Allowlist: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Allowlist = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShellAllowlistStoreMtimeReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), ShellAllowlistFilename)
	store := NewShellAllowlistStore(path)

	firstMtime := writeShellAllowlist(t, path, []string{"ls"}, 0o600)
	got, err := store.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"ls"}) {
		t.Fatalf("Allowlist = %v, want [ls]", got)
	}

	// Rewrite with the same mtime and size: cache must be served.
	if err := os.WriteFile(path, []byte(`["dd"]`), 0o600); err != nil {
		t.Fatalf("rewrite allowlist: %v", err)
	}
	if err := os.Chtimes(path, firstMtime, firstMtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	got, err = store.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist after same-mtime rewrite: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"ls"}) {
		t.Fatalf("cached Allowlist = %v, want [ls]", got)
	}

	// Rewrite with a newer mtime: cache must reload.
	secondMtime := firstMtime.Add(2 * time.Second)
	if err := os.WriteFile(path, []byte(`["dd","ls"]`), 0o600); err != nil {
		t.Fatalf("rewrite allowlist: %v", err)
	}
	if err := os.Chtimes(path, secondMtime, secondMtime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	got, err = store.Allowlist()
	if err != nil {
		t.Fatalf("Allowlist after mtime bump: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"dd", "ls"}) {
		t.Fatalf("reloaded Allowlist = %v, want [dd ls]", got)
	}
}

func TestShellAllowlistStoreFailClosed(t *testing.T) {
	t.Run("corrupt file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ShellAllowlistFilename)
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write corrupt allowlist: %v", err)
		}
		if _, err := NewShellAllowlistStore(path).Allowlist(); err == nil {
			t.Fatal("corrupt allowlist must fail closed with an error")
		}
	})

	t.Run("scalar payload", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ShellAllowlistFilename)
		if err := os.WriteFile(path, []byte(`"ls"`), 0o600); err != nil {
			t.Fatalf("write scalar allowlist: %v", err)
		}
		if _, err := NewShellAllowlistStore(path).Allowlist(); err == nil {
			t.Fatal("scalar allowlist must fail closed with an error")
		}
	})

	t.Run("gate fails closed on store error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ShellAllowlistFilename)
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write corrupt allowlist: %v", err)
		}
		store := NewShellAllowlistStore(path)

		prod := GateShellCommandWithStore(ShellGateProfileProduction, "ls", store)
		if prod.Verdict != ShellGateVerdictDeny {
			t.Fatalf("production verdict = %s, want deny", prod.Verdict)
		}
		dev := GateShellCommandWithStore(ShellGateProfileDev, "ls", store)
		if dev.Verdict != ShellGateVerdictPendingApproval {
			t.Fatalf("dev verdict = %s, want pending_approval", dev.Verdict)
		}
	})
}

func TestGateShellCommandWithStoreEscalationFlow(t *testing.T) {
	path := filepath.Join(t.TempDir(), ShellAllowlistFilename)
	writeShellAllowlist(t, path, []string{"ls", "cat"}, 0o600)
	store := NewShellAllowlistStore(path)

	// Step 1: a blocked command escalates in dev.
	blocked := GateShellCommandWithStore(ShellGateProfileDev, "cat f | rm x", store)
	if blocked.Verdict != ShellGateVerdictPendingApproval {
		t.Fatalf("verdict = %s, want pending_approval", blocked.Verdict)
	}
	if !reflect.DeepEqual(blocked.Blocked, []string{"rm"}) {
		t.Fatalf("blocked = %v, want [rm]", blocked.Blocked)
	}

	// Step 2: the operator approves by adding rm to the user-editable allowlist.
	writeShellAllowlist(t, path, []string{"ls", "cat", "rm"}, 0o600)

	// Step 3: the same command now passes the gate without a store reset —
	// the mtime cache must have reloaded.
	allowed := GateShellCommandWithStore(ShellGateProfileDev, "cat f | rm x", store)
	if allowed.Verdict != ShellGateVerdictAllow {
		t.Fatalf("verdict after allowlist edit = %s, want allow", allowed.Verdict)
	}
}
