package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lpregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

func TestLaunchPromoteDryRunRequiresCompleteManifestAndRefs(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest.json")
	digest := "sha256:" + strings.Repeat("a", 64)
	manifest := map[string]any{
		"schema_version":     "helm.launchpad.artifacts.v1",
		"generated_at":       "2026-05-18T00:00:00Z",
		"github_run_id":      "123",
		"github_run_attempt": "1",
		"artifacts": []map[string]string{{
			"app_id":                    "openclaw",
			"app_version":               "v2026.5.12",
			"upstream_repo":             "https://github.com/openclaw/openclaw",
			"upstream_ref":              "v2026.5.12",
			"upstream_commit":           strings.Repeat("b", 40),
			"license_spdx":              "MIT",
			"license_ref":               "https://github.com/openclaw/openclaw/blob/v2026.5.12/LICENSE",
			"redistribution":            "allowed_by_MIT_with_upstream_notice",
			"image":                     "ghcr.io/mindburn-labs/helm-launchpad/openclaw@" + digest,
			"digest":                    digest,
			"signature_tool":            "cosign",
			"signature_ref":             "cosign://ghcr.io/mindburn-labs/helm-launchpad/openclaw@" + digest,
			"sbom_tool":                 "syft",
			"sbom_ref":                  "artifact://sbom-openclaw.spdx.json",
			"vulnerability_scan_tool":   "grype",
			"vulnerability_scan_ref":    "artifact://grype-openclaw.json",
			"vulnerability_scan_status": "completed",
			"provenance_ref":            "github-actions://123/1",
			"artifact_verification_ref": "github-actions://123/1/artifact-verification/openclaw",
			"live_e2e_run_id":           "github-actions://123/1/live-e2e/openclaw",
			"evidence_pack_ref":         "github-actions://123/1/evidencepack/openclaw",
			"teardown_receipt_ref":      "github-actions://123/1/teardown/openclaw",
		}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	catalog := &lpregistry.Catalog{
		Root: root,
		Apps: []lpregistry.AppSpec{{
			ID:             "openclaw",
			Name:           "OpenClaw",
			Version:        "v2026.5.12",
			Availability:   lpregistry.AvailabilityOSSCandidate,
			Redistribution: "allowed_by_mit_pending_helm_signed_artifact",
			Install:        lpregistry.InstallSpec{Strategy: "signed_oci"},
			License:        lpregistry.LicenseSpec{Status: "verified", SPDX: "MIT"},
			Conformance:    lpregistry.ConformanceSpec{LicenseVerified: true, PolicyPackPresent: true},
		}},
	}

	var stdout, stderr bytes.Buffer
	code := runLaunchPromote([]string{
		"--manifest", manifestPath,
		"--app", "openclaw",
		"--json",
	}, catalog, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLaunchPromote code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"availability": "oss_supported"`) {
		t.Fatalf("promotion dry run did not emit oss_supported app: %s", stdout.String())
	}
}
