package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func runEnvelopeVerifyJSON(t *testing.T, args ...string) (int, contracts.EvidenceEnvelopeVerification) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runEvidenceEnvelopeVerify(append(args, "--json"), &stdout, &stderr)
	var result contracts.EvidenceEnvelopeVerification
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("verify %v: output is not a verification result: %v\n%s", args, err, stdout.String())
	}
	return code, result
}

// runEnvelopeVerifyText returns the exit code, the status the text output
// prints for each check, and both streams.
func runEnvelopeVerifyText(args ...string) (int, map[string]string, string, string) {
	var stdout, stderr bytes.Buffer
	code := runEvidenceEnvelopeVerify(args, &stdout, &stderr)
	statuses := map[string]string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && strings.HasPrefix(line, "  ") {
			statuses[fields[0]] = fields[1]
		}
	}
	return code, statuses, stdout.String(), stderr.String()
}

// Verified means the supplied values were compared with a manifest the command
// loaded. With no such manifest nothing was checked, so nothing passes.
func TestEvidenceEnvelopeVerifyChecksNothingWithoutARecordedManifest(t *testing.T) {
	t.Setenv("HELM_BOUNDARY_REGISTRY_PATH", filepath.Join(t.TempDir(), "surfaces.json"))

	for name, args := range map[string][]string{
		"unknown manifest id": {"--manifest-id", "nope", "--manifest-hash", "abc", "--native-root", "def"},
		"no manifest id":      {"--manifest-hash", "abc", "--native-root", "def"},
	} {
		code, result := runEnvelopeVerifyJSON(t, args...)
		if code != 1 || result.Verified {
			t.Fatalf("%s: exit = %d, verified = %t, want exit 1 and not verified", name, code, result.Verified)
		}
		if len(result.Checks) == 0 {
			t.Fatalf("%s: the result names no checks", name)
		}
		for check, status := range result.Checks {
			if status != "SKIPPED" {
				t.Fatalf("%s: check %s = %s, but nothing was checked", name, check, status)
			}
		}
		if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "nothing was checked") {
			t.Fatalf("%s: errors = %q, want one that says nothing was checked", name, result.Errors)
		}

		textCode, statuses, stdout, stderr := runEnvelopeVerifyText(args...)
		if textCode != 1 || !strings.Contains(stdout, "verified=false") || !strings.Contains(stderr, "nothing was checked") {
			t.Fatalf("%s: text exit = %d, stdout=%q stderr=%q, want exit 1 and the reason", name, textCode, stdout, stderr)
		}
		if len(statuses) != len(result.Checks) {
			t.Fatalf("%s: text output lists %v, the result holds %v", name, statuses, result.Checks)
		}
	}
}

// A manifest recorded without its payload leaves the payload checks nothing to
// compare. A payload rebuilt from the manifest would only match itself, so
// those checks are skipped and the envelope is not verified.
func TestEvidenceEnvelopeVerifyDoesNotPassAnUnrecordedPayload(t *testing.T) {
	registryPath := filepath.Join(t.TempDir(), "surfaces.json")
	t.Setenv("HELM_BOUNDARY_REGISTRY_PATH", registryPath)

	manifest, _, err := buildEvidenceEnvelope("manifest-only", "dsse", "sha256:native-evidence-root", "", false)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := boundarypkg.NewFileBackedSurfaceRegistry(registryPath, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.PutEnvelope(manifest); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"native_authority": "PASS",
		"manifest_hash":    "PASS",
		"payload_hash":     "SKIPPED",
		"envelope_role":    "SKIPPED",
	}
	code, result := runEnvelopeVerifyJSON(t, "--manifest-id", "manifest-only")
	if code != 1 || result.Verified {
		t.Errorf("exit = %d, verified = %t, want exit 1 and not verified", code, result.Verified)
	}
	for check, status := range want {
		if result.Checks[check] != status {
			t.Errorf("check %s = %q, want %s (checks: %v)", check, result.Checks[check], status, result.Checks)
		}
	}
	if result.PayloadHash != "" {
		t.Errorf("payload_hash = %q, but no payload was recorded", result.PayloadHash)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "no payload is recorded") {
		t.Errorf("errors = %q, want the one reason the payload checks did not run", result.Errors)
	}

	textCode, statuses, stdout, stderr := runEnvelopeVerifyText("--manifest-id", "manifest-only")
	if textCode != 1 || !strings.Contains(stdout, "verified=false") || !strings.Contains(stderr, "no payload is recorded") {
		t.Errorf("text exit = %d, stdout=%q stderr=%q, want exit 1 and the reason", textCode, stdout, stderr)
	}
	for check, status := range want {
		if statuses[check] != status {
			t.Errorf("text output shows %s = %q, want %s:\n%s", check, statuses[check], status, stdout)
		}
	}
}

func TestEvidenceEnvelopeVerifyComparesSuppliedValuesWithRecordedManifest(t *testing.T) {
	t.Setenv("HELM_BOUNDARY_REGISTRY_PATH", filepath.Join(t.TempDir(), "surfaces.json"))

	const nativeRoot = "sha256:native-evidence-root"
	var created, stderr bytes.Buffer
	if code := runEvidenceEnvelopeCreate([]string{"--manifest-id", "manifest-1", "--envelope", "dsse", "--native-hash", nativeRoot, "--json"}, &created, &stderr); code != 0 {
		t.Fatalf("create envelope: exit = %d, stderr = %s", code, stderr.String())
	}
	var record struct {
		Manifest contracts.EvidenceEnvelopeManifest `json:"manifest"`
	}
	if err := json.Unmarshal(created.Bytes(), &record); err != nil || record.Manifest.ManifestHash == "" {
		t.Fatalf("created envelope has no manifest hash: %v\n%s", err, created.String())
	}
	manifestHash := record.Manifest.ManifestHash

	for name, tc := range map[string]struct {
		args  []string
		check string
	}{
		"wrong manifest hash": {[]string{"--manifest-hash", "sha256:other", "--native-root", nativeRoot}, "manifest_hash"},
		"wrong native root":   {[]string{"--manifest-hash", manifestHash, "--native-root", "sha256:other"}, "native_root"},
	} {
		code, result := runEnvelopeVerifyJSON(t, append([]string{"--manifest-id", "manifest-1"}, tc.args...)...)
		if code != 1 || result.Verified || result.Checks[tc.check] != "FAIL" || len(result.Errors) == 0 {
			t.Errorf("%s: exit = %d, verified = %t, checks = %v, errors = %q, want exit 1 and %s FAIL", name, code, result.Verified, result.Checks, result.Errors, tc.check)
		}
	}

	code, result := runEnvelopeVerifyJSON(t, "--manifest-id", "manifest-1", "--manifest-hash", manifestHash, "--native-root", nativeRoot)
	if code != 0 || !result.Verified || result.Checks["manifest_hash"] != "PASS" || result.Checks["native_root"] != "PASS" {
		t.Errorf("matching values: exit = %d, result = %+v", code, result)
	}

	code, result = runEnvelopeVerifyJSON(t, "--manifest-id", "manifest-1")
	if code != 0 || !result.Verified || result.ManifestHash != manifestHash || result.NativeRoot != nativeRoot {
		t.Errorf("recorded manifest alone: exit = %d, result = %+v", code, result)
	}
	if _, compared := result.Checks["native_root"]; compared {
		t.Errorf("native_root reported without a supplied value to compare: %+v", result.Checks)
	}
}
