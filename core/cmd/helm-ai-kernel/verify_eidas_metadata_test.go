package main

// quantum_posture: these tests pin a metadata-only CLI boundary and make no
// post-quantum or classical timestamp-verification assurance.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyEIDASHelpStatesMetadataOnlyBoundary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--help"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("verify --help exit=%d, want 2; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	help := stderr.String()
	for _, want := range []string{
		"Require eIDAS-labelled anchor metadata",
		"metadata-only, not RFC 3161 or EU Trusted List cryptographic verification",
		"this does not verify the timestamp token",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("verify --help missing truthful eIDAS boundary %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, "Require every receipt to carry an eIDAS-qualified") {
		t.Fatalf("verify --help still claims cryptographic/legal qualification:\n%s", help)
	}
}

func TestCheckEIDASAnchorMetadataDoesNotClaimQualification(t *testing.T) {
	root := t.TempDir()
	anchorsDir := filepath.Join(root, "02_PROOFGRAPH", "anchors")
	if err := os.MkdirAll(anchorsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeEIDASMetadataFixture(t, filepath.Join(anchorsDir, "declared.json"), map[string]any{
		"backend":         "eidas-qtsp",
		"integrated_time": time.Now().UTC().Format(time.RFC3339),
		// Deliberately not an RFC 3161 token. A pass proves this CLI gate only
		// inventories metadata and must never be presented as token verification.
		"signature": "not-an-rfc3161-token",
	})

	results := checkEIDASAnchorMetadata(root, 24*time.Hour)
	if len(results) != 1 {
		t.Fatalf("metadata results=%+v, want exactly one", results)
	}
	result := results[0]
	if !result.Pass || result.Name != "eidas:anchor_metadata" {
		t.Fatalf("metadata result=%+v, want a metadata-only pass", result)
	}
	detail := strings.ToLower(result.Detail)
	if !strings.Contains(detail, "metadata only") || !strings.Contains(detail, "were not verified") {
		t.Fatalf("metadata result does not disclose verification boundary: %+v", result)
	}
	if strings.Contains(detail, "qualified") {
		t.Fatalf("metadata-only result claims qualification: %+v", result)
	}
}

func TestCheckEIDASAnchorMetadataRejectsInvalidIntegratedTime(t *testing.T) {
	root := t.TempDir()
	anchorsDir := filepath.Join(root, "02_PROOFGRAPH", "anchors")
	if err := os.MkdirAll(anchorsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeEIDASMetadataFixture(t, filepath.Join(anchorsDir, "invalid-time.json"), map[string]any{
		"backend":         "eidas-qtsp",
		"integrated_time": "not-rfc3339",
	})

	results := checkEIDASAnchorMetadata(root, 24*time.Hour)
	if len(results) != 1 || results[0].Pass || results[0].Name != "eidas:anchor_metadata" {
		t.Fatalf("invalid integrated_time must fail metadata-shape check: %+v", results)
	}
	if !strings.Contains(results[0].Reason, "must declare integrated_time as RFC3339 metadata") {
		t.Fatalf("invalid integrated_time failure is not actionable: %+v", results[0])
	}
}

func writeEIDASMetadataFixture(t *testing.T, path string, value map[string]any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
