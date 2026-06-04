package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
	lpregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
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

func TestLaunchEvidenceExportVerifiesDirectoryAndArchive(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_HOME", root)

	packDir, err := lpreceipts.WriteEvidencePack(root, "launch-evidence-test", map[string][]byte{
		"receipts/kernel-verdict.json": []byte(`{"receipt_id":"r1","decision_id":"d1","decision_hash":"sha256:test","status":"ALLOW","verdict":"ALLOW","lamport_clock":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:  "launch-evidence-test",
		DataDir: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	archive, err := lpreceipts.WriteEvidencePackArchive(packDir)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(root)
	if err := store.Save(session.LaunchRun{
		LaunchID:            "launch-evidence-test",
		AppID:               "openclaw",
		SubstrateID:         "local-container",
		State:               session.StateDeleted,
		KernelVerdict:       "ALLOW",
		TeardownReceiptRefs: []string{"launchpad.teardown:sha256:test"},
		EvidencePackRefs:    []string{packDir, archive},
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runLaunchEvidence([]string{"launch-evidence-test", "--export", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLaunchEvidence code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"verified": true`) {
		t.Fatalf("evidence export did not verify refs: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), `"verified": false`) {
		t.Fatalf("evidence export had failed verification: %s", stdout.String())
	}
}

func TestLaunchSecretsSetAndStatusUseLogicalBindingWithoutPrintingValue(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_HOME", root)
	t.Setenv("HELM_TEST_OPENROUTER", "sk-test-secret-value")

	var stdout, stderr bytes.Buffer
	code := runLaunchSecrets([]string{"set", "model_gateway", "--provider", "openrouter", "--value-env", "HELM_TEST_OPENROUTER", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLaunchSecrets set code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "sk-test-secret-value") {
		t.Fatalf("secret value leaked in set output: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"value_env": "HELM_TEST_OPENROUTER"`) {
		t.Fatalf("binding output missing value env: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLaunchSecrets([]string{"status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLaunchSecrets status code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "sk-test-secret-value") {
		t.Fatalf("secret value leaked in status output: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"available": true`) {
		t.Fatalf("status did not show available binding: %s", stdout.String())
	}
}

func TestLaunchCloudGateCreatesDigitalOceanProvisionedRun(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_HOME", root)
	t.Setenv("DIGITALOCEAN_TOKEN", "do-test-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer do-test-token" {
			t.Fatalf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v2/droplets":
			_, _ = w.Write([]byte(`{"droplet":{"id":123}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/firewalls":
			_, _ = w.Write([]byte(`{"firewall":{"id":"fw-123"}}`))
		default:
			t.Fatalf("unexpected provider call %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	t.Setenv("HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT", server.URL)

	compiled := plan.LaunchPlan{
		LaunchID:       "launch-cloud-create",
		AppID:          "openclaw",
		AppVersion:     "v2026.5.12",
		SubstrateID:    "digitalocean",
		Principal:      "test.operator",
		PlanHash:       "sha256:" + strings.Repeat("a", 64),
		ArtifactImage:  "ghcr.io/mindburn-labs/helm-launchpad/openclaw@sha256:test",
		ArtifactDigest: "sha256:test",
		KernelVerdict:  "ALLOW",
		Status:         "VALIDATED",
	}
	substrate := lpregistry.SubstrateSpec{ID: "digitalocean", Kind: "cloud", Provisioner: "digitalocean"}

	var stdout, stderr bytes.Buffer
	code := runLaunchCloudGate(compiled, substrate, true, "approval-1", 25, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLaunchCloudGate code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "do-test-token") || strings.Contains(stderr.String(), "do-test-token") {
		t.Fatalf("provider token leaked in cloud output")
	}
	var response launchCloudGateResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "PROVISIONED" || response.KernelVerdict != "ALLOW" {
		t.Fatalf("unexpected cloud response: %+v", response)
	}
	if response.ProviderResourceRefs["droplet"] != "123" || response.ProviderResourceRefs["firewall"] != "fw-123" {
		t.Fatalf("missing provider refs: %+v", response.ProviderResourceRefs)
	}
	if len(response.EvidencePackRefs) == 0 {
		t.Fatalf("cloud response missing EvidencePack refs: %+v", response)
	}
	run, err := session.NewStore(root).Get("launch-cloud-create")
	if err != nil {
		t.Fatalf("cloud run not saved: %v", err)
	}
	if run.RuntimeHandles.CloudResourceIDs["provider"] != "digitalocean" {
		t.Fatalf("cloud provider handle not saved: %+v", run.RuntimeHandles.CloudResourceIDs)
	}
}

func TestLaunchCloudGateRequiresProviderSecret(t *testing.T) {
	t.Setenv("DIGITALOCEAN_TOKEN", "")
	t.Setenv("HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN", "")
	compiled := plan.LaunchPlan{
		LaunchID:      "launch-cloud-missing-secret",
		AppID:         "openclaw",
		AppVersion:    "v2026.5.12",
		SubstrateID:   "digitalocean",
		Principal:     "test.operator",
		PlanHash:      "sha256:" + strings.Repeat("b", 64),
		KernelVerdict: "ALLOW",
		Status:        "VALIDATED",
	}
	substrate := lpregistry.SubstrateSpec{ID: "digitalocean", Kind: "cloud", Provisioner: "digitalocean"}

	var stdout, stderr bytes.Buffer
	code := runLaunchCloudGate(compiled, substrate, true, "approval-1", 25, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected missing provider secret to fail")
	}
	if !strings.Contains(stdout.String(), "ERR_LAUNCHPAD_CLOUD_PROVIDER_SECRET_MISSING") {
		t.Fatalf("missing provider secret reason not returned: %s", stdout.String())
	}
}

func TestLaunchDeleteCascadesDigitalOceanResources(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HELM_LAUNCHPAD_HOME", root)
	t.Setenv("DIGITALOCEAN_TOKEN", "do-delete-token")
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer do-delete-token" {
			t.Fatalf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/v2/firewalls/fw-123":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/v2/droplets/123":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v2/droplets":
			_, _ = w.Write([]byte(`{"droplets":[]}`))
		default:
			t.Fatalf("unexpected provider call %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	t.Setenv("HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT", server.URL)

	store := session.NewStore(root)
	if err := store.Save(session.LaunchRun{
		LaunchID:          "launch-cloud-delete",
		AppID:             "openclaw",
		AppVersion:        "v2026.5.12",
		SubstrateID:       "digitalocean",
		Principal:         "test.operator",
		PlanHash:          "sha256:" + strings.Repeat("c", 64),
		State:             session.StateProvisioning,
		KernelVerdict:     "ALLOW",
		LaunchReceiptRefs: []string{"receipt:digitalocean:launch-cloud-delete:provision"},
		RuntimeHandles: session.RuntimeHandles{CloudResourceIDs: map[string]string{
			"provider": "digitalocean",
			"droplet":  "123",
			"firewall": "fw-123",
		}},
		IdempotencyKeys: map[string]string{"cloud": "digitalocean:test"},
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runLaunchDelete([]string{"launch-cloud-delete", "--cascade"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLaunchDelete code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "do-delete-token") || strings.Contains(stderr.String(), "do-delete-token") {
		t.Fatalf("provider token leaked in delete output")
	}
	if strings.Join(calls, ",") != "DELETE /v2/firewalls/fw-123,DELETE /v2/droplets/123,GET /v2/droplets" {
		t.Fatalf("unexpected provider calls: %#v", calls)
	}
	if !strings.Contains(stdout.String(), `"state": "DELETED"`) {
		t.Fatalf("delete did not mark launch deleted: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `receipt:digitalocean:launch-cloud-delete:teardown`) {
		t.Fatalf("delete missing provider teardown receipt: %s", stdout.String())
	}
}
