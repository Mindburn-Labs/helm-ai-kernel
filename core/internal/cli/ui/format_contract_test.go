package ui

import (
	"strings"
	"testing"
)

func TestConsumeOperatorFormatRejectsUnknown(t *testing.T) {
	_, _, err := ConsumeOperatorFormat([]string{"--format", "yaml"})
	if err == nil || !strings.Contains(err.Error(), "expected text|json") {
		t.Fatalf("yaml must fail closed: %v", err)
	}
}

func TestConsumeOperatorFormatJSONRewrites(t *testing.T) {
	rest, jsonOut, err := ConsumeOperatorFormat([]string{"status", "--format=json", "--limit", "4"})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonOut {
		t.Fatal("expected jsonOut")
	}
	got := strings.Join(WithJSONAlias(rest, jsonOut), " ")
	if got != "status --limit 4 --json" {
		t.Fatalf("rewrite=%q", got)
	}
}

func TestConsumeOperatorFormatKeepsLegacyJSON(t *testing.T) {
	rest, jsonOut, err := ConsumeOperatorFormat([]string{"--json", "--format=text"})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonOut {
		t.Fatal("--json must still select JSON under OR semantics")
	}
	if strings.Join(rest, " ") != "--json" {
		t.Fatalf("rest=%v", rest)
	}
}

func TestConsumeOperatorFormatRejectsFlagCaseAndNull(t *testing.T) {
	if _, _, err := ConsumeOperatorFormat([]string{"--Format=yaml"}); err == nil {
		t.Fatal("--Format=yaml must fail closed")
	}
	if _, _, err := ConsumeOperatorFormat([]string{"--format=json\x00"}); err == nil {
		t.Fatal("NUL format must fail closed")
	}
}

func TestConsumeOperatorFormatStopsAtTerminator(t *testing.T) {
	rest, jsonOut, err := ConsumeOperatorFormat([]string{"--", "--format=yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if jsonOut {
		t.Fatal("terminator must hide --format")
	}
	if strings.Join(rest, " ") != "-- --format=yaml" {
		t.Fatalf("rest=%v", rest)
	}
}
