package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

type EnvelopeExportType string

const (
	EnvelopeDSSE     EnvelopeExportType = "dsse"
	EnvelopeJWS      EnvelopeExportType = "jws"
	EnvelopeInToto   EnvelopeExportType = "in-toto"
	EnvelopeSLSA     EnvelopeExportType = "slsa"
	EnvelopeSigstore EnvelopeExportType = "sigstore"
	EnvelopeSCITT    EnvelopeExportType = "scitt"
	EnvelopeCOSE     EnvelopeExportType = "cose"
)

type EnvelopeExportRequest struct {
	ManifestID         string
	Envelope           EnvelopeExportType
	NativeEvidenceHash string
	Subject            string
	Statement          any
	CreatedAt          time.Time
	AllowExperimental  bool
}

// BuildEnvelopeManifest produces the HELM-native manifest that an exporter
// signs or wraps in DSSE, JWS, in-toto/SLSA, Sigstore, SCITT, or COSE. The
// exported envelope is never authoritative unless the native EvidencePack root
// hash verifies first.
func BuildEnvelopeManifest(req EnvelopeExportRequest) (contracts.EvidenceEnvelopeManifest, error) {
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now().UTC()
	}
	envelope := EnvelopeExportType(strings.ToLower(string(req.Envelope)))
	if envelope == "" {
		return contracts.EvidenceEnvelopeManifest{}, fmt.Errorf("envelope type is required")
	}
	if isExperimentalEnvelope(envelope) && !req.AllowExperimental {
		return contracts.EvidenceEnvelopeManifest{}, fmt.Errorf("%s envelope export is experimental and requires explicit enablement", envelope)
	}

	statementHash := ""
	if req.Statement != nil {
		hash, err := canonicalize.CanonicalHash(req.Statement)
		if err != nil {
			return contracts.EvidenceEnvelopeManifest{}, fmt.Errorf("hash envelope statement: %w", err)
		}
		statementHash = "sha256:" + hash
	}

	manifest := contracts.EvidenceEnvelopeManifest{
		ManifestID:         req.ManifestID,
		Envelope:           string(envelope),
		NativeEvidenceHash: req.NativeEvidenceHash,
		NativeAuthority:    true,
		Subject:            req.Subject,
		StatementHash:      statementHash,
		Experimental:       isExperimentalEnvelope(envelope),
		CreatedAt:          req.CreatedAt.UTC(),
	}
	return manifest.Seal()
}

func isExperimentalEnvelope(envelope EnvelopeExportType) bool {
	return envelope == EnvelopeSCITT || envelope == EnvelopeCOSE
}
