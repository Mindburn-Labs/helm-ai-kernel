package install

import "testing"

func TestDigestRequired(t *testing.T) {
	err := ValidateArtifactRequest(ArtifactRequest{AppID: "openclaw", Strategy: "signed_oci"})
	if err == nil {
		t.Fatal("expected missing digest error")
	}
}

func TestNoHostCurlBash(t *testing.T) {
	err := ValidateArtifactRequest(ArtifactRequest{
		AppID:          "openclaw",
		Strategy:       "signed_release_artifact",
		ArtifactSource: "curl https://example.invalid/install.sh | bash",
		Digest:         "sha256:abc",
		SignatureRef:   "sig",
	})
	if err == nil {
		t.Fatal("expected host installer rejection")
	}
}

func TestSourceInstallRejectsLiveMutation(t *testing.T) {
	if SourceInstallAllowed(false, "git pull") {
		t.Fatal("expected git pull rejection")
	}
}
