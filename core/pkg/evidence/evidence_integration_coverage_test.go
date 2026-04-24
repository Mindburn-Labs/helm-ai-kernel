package evidence_test

import (
	"context"
	"testing"

	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/evidence"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/provenance"
	"github.com/stretchr/testify/assert"
)

// staticProber avoids external network calls in unit tests.
type staticProber struct{}

func (staticProber) Probe(ctx context.Context, url string) (lcp float64, a11y float64, err error) {
	switch url {
	case "http://good-ux.com":
		return 1.0, 100.0, nil
	case "http://bad-ux.com":
		// Trip LCP threshold while keeping A11y high to ensure deterministic failure reason.
		return 10.0, 100.0, nil
	default:
		return 0, 0, nil
	}
}

func TestEvidenceExporter(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("test-evidence-bundle")
	assert.NoError(t, err)
	exporter := evidence.NewExporter(signer, signer.KeyID)
	ctx := context.Background()

	// 1. Export SOC2
	// Build a dummy envelope
	b := provenance.NewBuilder()
	b.AddSystemPrompt("sys")
	env := b.Build()

	bundle, err := exporter.ExportSOC2(ctx, "trace-1", []*provenance.Envelope{env})
	assert.NoError(t, err)
	assert.Equal(t, evidence.BundleTypeSOC2, bundle.Type)
	assert.Len(t, bundle.Artifacts, 1)
	assert.Equal(t, "trace-1", bundle.TraceID)
	assert.NotEmpty(t, bundle.Signature)

	// 2. Export Incident
	bundle2, err := exporter.ExportIncidentReport(ctx, "trace-2", map[string]string{"error": "timeout"})
	assert.NoError(t, err)
	assert.Equal(t, evidence.BundleTypeIncident, bundle2.Type)
	assert.NotEmpty(t, bundle2.Signature)
}
