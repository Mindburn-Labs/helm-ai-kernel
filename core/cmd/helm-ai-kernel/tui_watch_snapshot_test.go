package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/tui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestTUIRunCommandWatchIsSnapshotOnly(t *testing.T) {
	if got := tui.DefaultArgs("watch"); len(got) != 1 || got[0] != "--once" {
		t.Fatalf("composer default watch args = %v, want [--once]", got)
	}

	var posts atomic.Int32
	item := watchTestCeremony("ap-tui-1", time.Unix(1, 0))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]contracts.ApprovalCeremony{item})
			return
		}
		posts.Add(1)
		http.Error(w, "TUI watch must not transition", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(watchURLEnv, srv.URL)
	t.Setenv(watchAdminAPIKeyEnv, "tui-watch-snapshot-key")

	for _, args := range [][]string{nil, {"--once"}, {"--json"}} {
		done := make(chan struct{})
		var stdout, stderr string
		var code int
		go func() {
			defer close(done)
			stdout, stderr, code = tuiRunCommand("watch", args)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("tuiRunCommand(watch %v) hung — interactive approval loop?", args)
		}

		out := stdout + stderr
		if posts.Load() != 0 {
			t.Fatalf("watch %v posted a Decide/transition", args)
		}
		for _, bad := range []string{
			"Approval ID to review",
			"Decision for",
			"Type APPROVE",
			"unbounded listener",
			"state=approved",
			"state=denied",
		} {
			if strings.Contains(out, bad) {
				t.Fatalf("watch %v started an interactive or Decide path (%q):\n%s", args, bad, out)
			}
		}
		if code != 0 {
			t.Fatalf("watch %v exit %d stderr=%s", args, code, stderr)
		}
		if len(args) == 1 && args[0] == "--json" {
			if !strings.Contains(stdout, `"pending"`) {
				t.Fatalf("watch --json missing snapshot:\n%s", stdout)
			}
			continue
		}
		if !strings.Contains(stdout, "HELM WATCH snapshot") {
			t.Fatalf("watch %v missing snapshot chrome:\n%s", args, stdout)
		}
	}
}
