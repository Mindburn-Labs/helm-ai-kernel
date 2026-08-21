package tui

import (
	"context"
	"strings"
	"testing"
)

func TestComposerWatchIsSnapshotOnly(t *testing.T) {
	if got := DefaultArgs("watch"); len(got) != 1 || got[0] != "--once" {
		t.Fatalf("DefaultArgs(watch)=%v, want [--once]", got)
	}

	var decided []string
	var ran [][]string
	host := Host{
		Watch: func(ctx context.Context) ([]Approval, error) {
			return []Approval{{ID: "a1", Subject: "deploy"}}, nil
		},
		Decide: func(ctx context.Context, id, token string) (string, string, int) {
			decided = append(decided, id+":"+token)
			return "state=approved id=" + id, "", 0
		},
		RunCommand: func(name string, args []string) (string, string, int) {
			ran = append(ran, append([]string{name}, args...))
			return "HELM WATCH snapshot", "", 0
		},
	}

	for _, line := range []string{"watch", "watch --once"} {
		decided = decided[:0]
		ran = ran[:0]
		m := New(host)
		m.width, m.height = 120, 36
		m.composer = line
		m.composing = true
		next, cmd := m.executeComposer()
		got := next.(model)
		if cmd != nil {
			if msg := cmd(); msg != nil {
				next, _ = got.Update(msg)
				got = next.(model)
			}
		}
		if len(decided) != 0 {
			t.Fatalf("%q called Decide: %v", line, decided)
		}
		if got.activeOverlay() == overlayCeremony {
			t.Fatalf("%q opened the ceremony Decide path", line)
		}
		for _, inv := range ran {
			if inv[0] != "watch" {
				t.Fatalf("%q ran %v", line, inv)
			}
			if !hasArg(inv, "--once") && !hasArg(inv, "--json") {
				t.Fatalf("%q runner was not snapshot-only: %v", line, inv)
			}
		}
		view := got.View()
		if strings.Contains(view, "unbounded listener") {
			t.Fatalf("%q treated watch as a bind:\n%s", line, view)
		}
		if got.screen != ScreenWatch && len(ran) == 0 {
			t.Fatalf("%q opened neither Watch snapshot nor --once runner: screen=%v", line, got.screen)
		}
	}
}
