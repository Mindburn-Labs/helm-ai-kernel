package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerify_ManifestHash(t *testing.T) {
	manifest := sampleManifest()
	data := canonicalManifestBytes(manifest)
	hash := ComputeManifestHash(data)

	ok := Verify(manifest, data, hash)
	if !ok.Verified {
		t.Errorf("Verify with matching hash: Verified = false (errors: %v)", ok.Errors)
	}

	bad := Verify(manifest, data, "sha256:deadbeef")
	if bad.Verified {
		t.Error("Verify with bad claimed hash: Verified = true")
	}
	if len(bad.Errors) == 0 {
		t.Error("Verify with bad claimed hash: empty Errors")
	}
}

func TestVerify_Signature(t *testing.T) {
	manifest := sampleManifest()
	manifest.Signatures = []PackSignature{
		{SignerID: "helm-core", Algorithm: "sha256", Signature: "redacted"},
	}
	data := canonicalManifestBytes(manifest)
	result := Verify(manifest, data, "")
	if !result.Verified {
		t.Errorf("Verified = false, want true (errors: %v)", result.Errors)
	}
	if result.VerificationMode != "signed" {
		t.Errorf("VerificationMode = %q, want signed", result.VerificationMode)
	}

	unsigned := sampleManifest()
	unsignedData := canonicalManifestBytes(unsigned)
	result = Verify(unsigned, unsignedData, "")
	if result.VerificationMode != "integrity" {
		t.Errorf("unsigned VerificationMode = %q, want integrity", result.VerificationMode)
	}
}

func TestVerify_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PackManifestV2)
		wantErr string
	}{
		{"missing pack_id", func(m *PackManifestV2) { m.PackID = "" }, "pack_id"},
		{"missing name", func(m *PackManifestV2) { m.Name = "" }, "name"},
		{"missing version", func(m *PackManifestV2) { m.Version = "" }, "version"},
		{"missing channel", func(m *PackManifestV2) { m.Channel = "" }, "channel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := sampleManifest()
			tc.mutate(&manifest)
			data := canonicalManifestBytes(manifest)
			result := Verify(manifest, data, "")
			if result.Verified {
				t.Errorf("Verified = true, want false for %s", tc.name)
			}
			joined := strings.Join(result.Errors, " | ")
			if !strings.Contains(joined, tc.wantErr) {
				t.Errorf("errors = %q, want substring %q", joined, tc.wantErr)
			}
		})
	}
}

func TestParseManifest_YAML(t *testing.T) {
	body := []byte(`pack_id: "example.compliance/hipaa"
name: "HIPAA Guardrails"
version: "0.1.0"
channel: "core"
minimum_edition: "oss"
extension_points:
  - "route"
  - "policy"
secrets:
  - name: "EXAMPLE_TOKEN"
    description: "redacted"
    required: true
`)
	manifest, err := ParseManifest(body, ".yaml")
	if err != nil {
		t.Fatalf("ParseManifest yaml: %v", err)
	}
	if manifest.PackID != "example.compliance/hipaa" {
		t.Errorf("PackID = %q", manifest.PackID)
	}
	if manifest.Channel != PackChannelCore {
		t.Errorf("Channel = %q, want core", manifest.Channel)
	}
	if len(manifest.ExtensionPoints) != 2 {
		t.Errorf("ExtensionPoints = %v, want 2 entries", manifest.ExtensionPoints)
	}
	if len(manifest.Secrets) != 1 || !manifest.Secrets[0].Required {
		t.Errorf("Secrets = %+v, want 1 required entry", manifest.Secrets)
	}
}

func TestParseManifest_JSON(t *testing.T) {
	body := []byte(`{"pack_id":"example.compliance/hipaa","name":"HIPAA Guardrails","version":"0.1.0","channel":"core","minimum_edition":"oss"}`)
	manifest, err := ParseManifest(body, ".json")
	if err != nil {
		t.Fatalf("ParseManifest json: %v", err)
	}
	if manifest.PackID != "example.compliance/hipaa" {
		t.Errorf("PackID = %q", manifest.PackID)
	}
	if manifest.Channel != PackChannelCore {
		t.Errorf("Channel = %q, want core", manifest.Channel)
	}
}

func TestParseManifest_ChannelDefault(t *testing.T) {
	body := []byte(`{"pack_id":"p","name":"n","version":"0.1.0"}`)
	manifest, err := ParseManifest(body, ".json")
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if manifest.Channel != PackChannelCommunity {
		t.Errorf("default Channel = %q, want community", manifest.Channel)
	}
}

func TestLoadManifest_FileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.yaml")
	body := []byte(`pack_id: "example.compliance/hipaa"
name: "HIPAA Guardrails"
version: "0.1.0"
channel: "community"
minimum_edition: "oss"
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manifest, data, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if manifest.PackID != "example.compliance/hipaa" {
		t.Errorf("PackID = %q", manifest.PackID)
	}
	if len(data) != len(body) {
		t.Errorf("data len = %d, want %d", len(data), len(body))
	}

	// Missing file path surfaces as error.
	if _, _, err := LoadManifest(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("LoadManifest(missing): err = nil")
	}
}
