// quantum_posture: offline CLI tests reject malformed classical public-key inputs.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSpendProxyExportEmptyLogFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSpendProxyExport([]string{"--receipts-dir", t.TempDir(), "--out", t.TempDir()}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("export on empty receipts dir: exit = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "receipt log is empty") &&
		!strings.Contains(stderr.String(), "nothing to export") {
		t.Fatalf("stderr = %q, want empty-log error", stderr.String())
	}
}

func TestSpendProxyExportFlagErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"export", "--bogus-flag"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2 for unknown flag", code)
	}
}

func TestSpendProxySavingsExportRequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"savings-export"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--capture and --config are required") {
		t.Fatalf("stderr = %q, want capture/config requirement", stderr.String())
	}
}

func TestSpendProxySavingsVerifyRequiresPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"savings-verify"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--pack is required") {
		t.Fatalf("stderr = %q, want pack requirement", stderr.String())
	}
}

func TestSpendProxyExportRefusesAMalformedPublicKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runSpendProxyExport([]string{"--receipts-dir", t.TempDir(), "--out", t.TempDir(), "--public-key", "ed25519:abcd"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--public-key") {
		t.Fatalf("exit = %d, stderr = %q; want 2 naming --public-key", code, stderr.String())
	}
}
