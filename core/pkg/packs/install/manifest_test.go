package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// TestParseManifest_YAML verifies the YAML decoder path and the channel
// default fallback.
func TestParseManifest_YAML(t *testing.T) {
	data := []byte(`pack_id: demo-pack
name: Demo Pack
version: 0.1.0
channel: community
secrets:
  - name: API_KEY
    required: true
`)
	manifest, hash, err := ParseManifest(data, ".yaml")
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if manifest.PackID != "demo-pack" || manifest.Version != "0.1.0" {
		t.Fatalf("wrong fields: %+v", manifest)
	}
	if manifest.Channel != contracts.PackChannelCommunity {
		t.Fatalf("Channel: got %q", manifest.Channel)
	}
	if len(manifest.Secrets) != 1 || manifest.Secrets[0].Name != "API_KEY" || !manifest.Secrets[0].Required {
		t.Fatalf("Secrets: %+v", manifest.Secrets)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("hash format: %q", hash)
	}
}

// TestParseManifest_JSON verifies the JSON decoder path.
func TestParseManifest_JSON(t *testing.T) {
	data := []byte(`{"pack_id":"demo-pack","name":"Demo","version":"0.1.0","channel":"core"}`)
	manifest, _, err := ParseManifest(data, ".json")
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if manifest.Channel != contracts.PackChannelCore {
		t.Fatalf("Channel: %q", manifest.Channel)
	}
}

// TestParseManifest_ChannelDefault verifies missing channel defaults to
// community (preserving the behavior commercial callers relied on).
func TestParseManifest_ChannelDefault(t *testing.T) {
	data := []byte(`{"pack_id":"demo","name":"Demo","version":"0.1.0"}`)
	manifest, _, err := ParseManifest(data, ".json")
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if manifest.Channel != contracts.PackChannelCommunity {
		t.Fatalf("default Channel: %q", manifest.Channel)
	}
}

// TestLoadManifest_FileRoundtrip writes a manifest to t.TempDir() and
// loads it back, checking the file-path code path.
func TestLoadManifest_FileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.yaml")
	body := []byte("pack_id: demo-pack\nname: Demo Pack\nversion: 0.1.0\nchannel: community\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manifest, hash, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if manifest.PackID != "demo-pack" {
		t.Fatalf("PackID: %q", manifest.PackID)
	}
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("hash format: %q", hash)
	}
	if want := ComputeManifestHash(body); want != hash {
		t.Fatalf("hash mismatch: LoadManifest %q vs ComputeManifestHash %q", hash, want)
	}
}

// TestVerify_ManifestHash confirms the hash round-trip: the same bytes
// always produce the same hash.
func TestVerify_ManifestHash(t *testing.T) {
	body := []byte(`{"pack_id":"demo","name":"Demo","version":"0.1.0","channel":"community"}`)
	hash1 := ComputeManifestHash(body)
	hash2 := ComputeManifestHash(body)
	if hash1 != hash2 {
		t.Fatalf("hash not deterministic: %q vs %q", hash1, hash2)
	}
	// Tampered bytes produce a different hash.
	tampered := append([]byte{}, body...)
	tampered[10] ^= 0xff
	if ComputeManifestHash(tampered) == hash1 {
		t.Fatalf("tampered bytes produced matching hash")
	}
}

// TestVerify_Signature checks that a signed manifest reports mode=signed
// and that a signatureless manifest reports mode=integrity.
func TestVerify_Signature(t *testing.T) {
	base := contracts.PackManifestV2{
		PackID:  "demo",
		Name:    "Demo",
		Version: "0.1.0",
		Channel: contracts.PackChannelCommunity,
	}
	result, err := Verify(base, "sha256:abc")
	if err != nil {
		t.Fatalf("Verify unsigned: %v", err)
	}
	if result.VerificationMode != "integrity" {
		t.Fatalf("unsigned mode: want integrity, got %q", result.VerificationMode)
	}

	signed := base
	signed.Signatures = []contracts.PackSignature{{SignerID: "alice", Algorithm: "ed25519", Signature: "sig-bytes"}}
	sresult, err := Verify(signed, "sha256:abc")
	if err != nil {
		t.Fatalf("Verify signed: %v", err)
	}
	if sresult.VerificationMode != "signed" {
		t.Fatalf("signed mode: want signed, got %q", sresult.VerificationMode)
	}
	if sresult.SignerID != "alice" {
		t.Fatalf("SignerID: %q", sresult.SignerID)
	}
	if sresult.Algorithm != "ed25519" {
		t.Fatalf("Algorithm: %q", sresult.Algorithm)
	}
}

// TestVerify_MissingFields rejects malformed manifests.
func TestVerify_MissingFields(t *testing.T) {
	cases := []struct {
		name     string
		manifest contracts.PackManifestV2
	}{
		{"missing pack_id", contracts.PackManifestV2{Name: "n", Version: "0.1.0", Channel: contracts.PackChannelCommunity}},
		{"missing name", contracts.PackManifestV2{PackID: "p", Version: "0.1.0", Channel: contracts.PackChannelCommunity}},
		{"missing version", contracts.PackManifestV2{PackID: "p", Name: "n", Channel: contracts.PackChannelCommunity}},
		{"unknown channel", contracts.PackManifestV2{PackID: "p", Name: "n", Version: "0.1.0", Channel: contracts.PackChannel("weird")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(tc.manifest, "sha256:abc"); err == nil {
				t.Fatalf("%s: want error", tc.name)
			}
		})
	}
}

// TestChannelClassification confirms the known/installable predicates.
func TestChannelClassification(t *testing.T) {
	cases := []struct {
		ch    contracts.PackChannel
		known bool
		oss   bool
	}{
		{contracts.PackChannelCore, true, true},
		{contracts.PackChannelCommunity, true, true},
		{contracts.PackChannelTeams, true, false},
		{contracts.PackChannelEnterprise, true, false},
		{contracts.PackChannel("weird"), false, false},
	}
	for _, tc := range cases {
		if got := IsKnownChannel(tc.ch); got != tc.known {
			t.Fatalf("IsKnownChannel(%q): want %v, got %v", tc.ch, tc.known, got)
		}
		if got := IsInstallableByOSS(tc.ch); got != tc.oss {
			t.Fatalf("IsInstallableByOSS(%q): want %v, got %v", tc.ch, tc.oss, got)
		}
	}
}
