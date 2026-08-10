package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestSuggestCommandsFindsNearestRealCommand pins #6: a typo yields the nearest
// registered command, not the marketing banner.
func TestSuggestCommandsFindsNearestRealCommand(t *testing.T) {
	cases := map[string]string{
		"setuo":   "setup",
		"scna":    "scan",
		"recipts": "receipts",
		"verison": "version",
	}
	for typo, want := range cases {
		got := suggestCommands(typo)
		if len(got) == 0 || got[0] != want {
			t.Fatalf("suggestCommands(%q) = %v, want first = %q", typo, got, want)
		}
	}
	// A token that resembles nothing returns no suggestion (no false confidence).
	if got := suggestCommands("qzxwvu"); len(got) != 0 {
		t.Fatalf("suggestCommands(nonsense) = %v, want empty", got)
	}
}

// TestUnknownCommandPrintsSuggestionNotBanner pins that the dispatcher's
// unknown-command path routes through the suggester and does not dump the front
// door.
func TestUnknownCommandPrintsSuggestionNotBanner(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "setuo"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown command exit=%d, want 2", code)
	}
	out := stderr.String()
	if !strings.Contains(out, "Did you mean: setup?") {
		t.Fatalf("no suggestion offered:\n%s", out)
	}
	if strings.Contains(out, "Your first governed-agent run") {
		t.Fatalf("dumped the front-door banner on a typo:\n%s", out)
	}
}

// TestQuickstartErrorRouteGivesTheNextCommand pins #4: the top start failures
// carry an actionable route.
func TestQuickstartErrorRouteGivesTheNextCommand(t *testing.T) {
	opts := quickstartOptions{Port: 7714}
	if route := quickstartErrorRoute(errors.New("listen tcp 127.0.0.1:7714: bind: address already in use"), opts); !strings.Contains(route, "--port") {
		t.Fatalf("bind-in-use route must mention --port: %q", route)
	}
	if route := quickstartErrorRoute(errors.New("open /System/x: permission denied"), opts); !strings.Contains(route, "--data-dir") {
		t.Fatalf("permission route must mention --data-dir: %q", route)
	}
	if route := quickstartErrorRoute(errors.New("some unrelated failure"), opts); route != "" {
		t.Fatalf("unrelated error should carry no route, got %q", route)
	}
}
