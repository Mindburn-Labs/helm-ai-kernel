package evidence

import (
	"testing"
	"time"
)

func TestBuildEnvelopeManifestAllowsDSSEAndJWS(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	for _, envelope := range []EnvelopeExportType{EnvelopeDSSE, EnvelopeJWS} {
		manifest, err := BuildEnvelopeManifest(EnvelopeExportRequest{
			ManifestID:         "manifest-" + string(envelope),
			Envelope:           envelope,
			NativeEvidenceHash: "sha256:evidence",
			Subject:            "pack:123",
			Statement:          map[string]any{"pack_hash": "sha256:evidence"},
			CreatedAt:          now,
		})
		if err != nil {
			t.Fatalf("build %s manifest: %v", envelope, err)
		}
		if manifest.ManifestHash == "" {
			t.Fatalf("%s manifest hash missing", envelope)
		}
		if manifest.Experimental {
			t.Fatalf("%s should not be experimental", envelope)
		}
	}
}

func TestBuildEnvelopeManifestGatesExperimentalFormats(t *testing.T) {
	_, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		ManifestID:         "manifest-scitt",
		Envelope:           EnvelopeSCITT,
		NativeEvidenceHash: "sha256:evidence",
		CreatedAt:          time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected SCITT export to require explicit experimental enablement")
	}

	manifest, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		ManifestID:         "manifest-scitt",
		Envelope:           EnvelopeSCITT,
		NativeEvidenceHash: "sha256:evidence",
		AllowExperimental:  true,
		CreatedAt:          time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build experimental SCITT manifest: %v", err)
	}
	if !manifest.Experimental {
		t.Fatal("SCITT manifest should be marked experimental")
	}
}

func TestBuildEnvelopeManifestBindsStatementHash(t *testing.T) {
	now := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	base, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		ManifestID:         "manifest-dsse",
		Envelope:           EnvelopeDSSE,
		NativeEvidenceHash: "sha256:evidence",
		Statement:          map[string]any{"predicate": "a"},
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("base manifest: %v", err)
	}
	changed, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		ManifestID:         "manifest-dsse",
		Envelope:           EnvelopeDSSE,
		NativeEvidenceHash: "sha256:evidence",
		Statement:          map[string]any{"predicate": "b"},
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("changed manifest: %v", err)
	}
	if base.StatementHash == changed.StatementHash {
		t.Fatal("statement hash did not change")
	}
	if base.ManifestHash == changed.ManifestHash {
		t.Fatal("manifest hash did not bind statement hash")
	}
}
