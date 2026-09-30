package main

import (
	"bytes"
	"strings"
	"testing"
)

// HELM-756: scan and verify-scan are one-release stubs that name the new
// binary and exit 2 without scanning anything.
func TestScanCommandsPointToHelmRiskScan(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"helm-ai-kernel", "scan", "--path", "."}, "helm-risk-scan scan"},
		{[]string{"helm-ai-kernel", "verify-scan", "--bundle", "pack.tar"}, "helm-risk-scan verify"},
	} {
		var stdout, stderr bytes.Buffer
		code := Run(tc.args, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%v: code=%d, want 2", tc.args, code)
		}
		if !strings.Contains(stderr.String(), tc.want) {
			t.Fatalf("%v: stderr %q does not name %q", tc.args, stderr.String(), tc.want)
		}
		if strings.Contains(stdout.String(), "Content hash:") {
			t.Fatalf("%v: stub ran a scan: %s", tc.args, stdout.String())
		}
	}
}
