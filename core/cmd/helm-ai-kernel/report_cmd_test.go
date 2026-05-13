package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReportRejectsHTMLFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runReportCmd([]string{"--format", "html"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit 2 for HTML format, got %d", code)
	}
	if !strings.Contains(stderr.String(), "supported formats: text, json") {
		t.Fatalf("expected supported format error, got %q", stderr.String())
	}
}
