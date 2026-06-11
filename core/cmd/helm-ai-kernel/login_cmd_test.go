package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoginCmdRejectsPasswordArgv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runLoginCmd([]string{"--email", "a@example.com", "--password", "secret"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--password is disabled") {
		t.Fatalf("stderr missing argv password refusal: %s", stderr.String())
	}
}
