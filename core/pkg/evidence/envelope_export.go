package evidence

// quantum_posture: envelope export builds unsigned wrapper payloads and
// compares SHA-256 canonical hashes. It signs and verifies no signature: the
// JWS wrapper names EdDSA in its header and carries an empty signature. No
// post-quantum primitives are used in this file.

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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

	payload, err := BuildEnvelopePayload(contracts.EvidenceEnvelopeManifest{
		ManifestID:         req.ManifestID,
		Envelope:           string(envelope),
		NativeEvidenceHash: req.NativeEvidenceHash,
		NativeAuthority:    true,
		Subject:            req.Subject,
		StatementHash:      statementHash,
		Experimental:       isExperimentalEnvelope(envelope),
		CreatedAt:          req.CreatedAt.UTC(),
	})
	if err != nil {
		return contracts.EvidenceEnvelopeManifest{}, err
	}

	manifest := contracts.EvidenceEnvelopeManifest{
		ManifestID:         req.ManifestID,
		Envelope:           string(envelope),
		NativeEvidenceHash: req.NativeEvidenceHash,
		NativeAuthority:    true,
		Subject:            req.Subject,
		StatementHash:      statementHash,
		PayloadType:        payload.PayloadType,
		PayloadHash:        payload.PayloadHash,
		Experimental:       isExperimentalEnvelope(envelope),
		CreatedAt:          req.CreatedAt.UTC(),
	}
	return manifest.Seal()
}

func isExperimentalEnvelope(envelope EnvelopeExportType) bool {
	return envelope == EnvelopeSCITT || envelope == EnvelopeCOSE
}

// BuildEnvelopePayload creates a concrete export payload over the HELM-native
// root. The payload is deterministic and non-authoritative; verification first
// checks the native EvidencePack/receipt root, then the wrapper hash.
func BuildEnvelopePayload(manifest contracts.EvidenceEnvelopeManifest) (contracts.EvidenceEnvelopePayload, error) {
	envelope := EnvelopeExportType(strings.ToLower(manifest.Envelope))
	if envelope == "" {
		return contracts.EvidenceEnvelopePayload{}, fmt.Errorf("envelope type is required")
	}
	if manifest.NativeEvidenceHash == "" {
		return contracts.EvidenceEnvelopePayload{}, fmt.Errorf("native evidence hash is required")
	}
	payloadType := payloadTypeForEnvelope(envelope)
	payload := payloadForEnvelope(envelope, manifest)
	payloadHash, err := canonicalize.CanonicalHash(payload)
	if err != nil {
		return contracts.EvidenceEnvelopePayload{}, fmt.Errorf("hash envelope payload: %w", err)
	}
	generatedAt := manifest.CreatedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	return contracts.EvidenceEnvelopePayload{
		ManifestID:    manifest.ManifestID,
		Envelope:      string(envelope),
		PayloadType:   payloadType,
		Payload:       payload,
		PayloadHash:   "sha256:" + payloadHash,
		GeneratedAt:   generatedAt.UTC(),
		Authoritative: false,
	}, nil
}

// Statuses in EvidenceEnvelopeVerification.Checks. A SKIPPED check did not run
// because it had nothing to compare; a result that holds one is not verified.
const (
	EnvelopeCheckPass    = "PASS"
	EnvelopeCheckFail    = "FAIL"
	EnvelopeCheckSkipped = "SKIPPED"
)

// envelopeManifestChecks runs the checks a manifest supports on its own.
func envelopeManifestChecks(manifest contracts.EvidenceEnvelopeManifest) (map[string]string, []string) {
	checks := map[string]string{
		"native_authority": EnvelopeCheckPass,
		"manifest_hash":    EnvelopeCheckPass,
	}
	var errs []string
	if !manifest.NativeAuthority || manifest.NativeEvidenceHash == "" {
		checks["native_authority"] = EnvelopeCheckFail
		errs = append(errs, "native EvidencePack authority is missing")
	}
	expectedManifest := manifest
	expectedManifest.ManifestHash = ""
	manifestHash, err := canonicalize.CanonicalHash(expectedManifest)
	if err != nil || "sha256:"+manifestHash != manifest.ManifestHash {
		checks["manifest_hash"] = EnvelopeCheckFail
		errs = append(errs, "manifest hash mismatch")
	}
	return checks, errs
}

// VerifyEnvelopeManifest reports what a manifest proves when no payload was
// recorded for it. The payload checks are SKIPPED and the result is never
// verified: a payload rebuilt from the manifest would only be compared with
// itself.
func VerifyEnvelopeManifest(manifest contracts.EvidenceEnvelopeManifest) contracts.EvidenceEnvelopeVerification {
	checks, errs := envelopeManifestChecks(manifest)
	checks["payload_hash"] = EnvelopeCheckSkipped
	checks["envelope_role"] = EnvelopeCheckSkipped
	errs = append(errs, "no payload is recorded for this manifest: payload_hash and envelope_role were not checked")
	return contracts.EvidenceEnvelopeVerification{
		ManifestID:   manifest.ManifestID,
		ManifestHash: manifest.ManifestHash,
		Envelope:     manifest.Envelope,
		NativeRoot:   manifest.NativeEvidenceHash,
		Checks:       checks,
		Errors:       errs,
		VerifiedAt:   time.Now().UTC(),
	}
}

func VerifyEnvelopePayload(manifest contracts.EvidenceEnvelopeManifest, payload contracts.EvidenceEnvelopePayload) contracts.EvidenceEnvelopeVerification {
	checks, errs := envelopeManifestChecks(manifest)
	checks["payload_hash"] = EnvelopeCheckPass
	checks["envelope_role"] = EnvelopeCheckPass
	expectedPayload, err := BuildEnvelopePayload(manifest)
	if err != nil || expectedPayload.PayloadHash != payload.PayloadHash {
		checks["payload_hash"] = EnvelopeCheckFail
		errs = append(errs, "payload hash mismatch")
	}
	actualPayloadHash, err := canonicalize.CanonicalHash(payload.Payload)
	if err != nil || "sha256:"+actualPayloadHash != payload.PayloadHash {
		checks["payload_hash"] = EnvelopeCheckFail
		errs = append(errs, "payload content hash mismatch")
	}
	if payload.Authoritative {
		checks["envelope_role"] = EnvelopeCheckFail
		errs = append(errs, "external envelope cannot be authoritative")
	}
	return contracts.EvidenceEnvelopeVerification{
		ManifestID:   manifest.ManifestID,
		ManifestHash: manifest.ManifestHash,
		Envelope:     manifest.Envelope,
		PayloadHash:  payload.PayloadHash,
		Verified:     len(errs) == 0,
		NativeRoot:   manifest.NativeEvidenceHash,
		Checks:       checks,
		Errors:       errs,
		VerifiedAt:   time.Now().UTC(),
	}
}

func payloadTypeForEnvelope(envelope EnvelopeExportType) string {
	switch envelope {
	case EnvelopeDSSE:
		return "application/vnd.dsse.envelope.v1+json"
	case EnvelopeJWS:
		return "application/jose+json"
	case EnvelopeInToto:
		return "application/vnd.in-toto+json"
	case EnvelopeSLSA:
		return "application/vnd.slsa.provenance+json"
	case EnvelopeSigstore:
		return "application/vnd.dev.sigstore.bundle+json"
	case EnvelopeSCITT:
		return "application/scitt+json"
	case EnvelopeCOSE:
		return "application/cose+json"
	default:
		return "application/json"
	}
}

func payloadForEnvelope(envelope EnvelopeExportType, manifest contracts.EvidenceEnvelopeManifest) map[string]any {
	root := map[string]any{
		"manifest_id":          manifest.ManifestID,
		"native_evidence_hash": manifest.NativeEvidenceHash,
		"native_authority":     true,
		"subject":              manifest.Subject,
		"statement_hash":       manifest.StatementHash,
	}
	switch envelope {
	case EnvelopeDSSE:
		return map[string]any{
			"payloadType": "application/vnd.helm.evidence-root.v1+json",
			"payload":     root,
			"signatures":  []any{},
		}
	case EnvelopeJWS:
		return map[string]any{
			"protected": map[string]any{"alg": "EdDSA", "typ": "JWT", "crit": []string{"helm-native-root"}},
			"payload":   root,
			"signature": "",
		}
	case EnvelopeInToto:
		return map[string]any{
			"_type":     "https://in-toto.io/Statement/v1",
			"subject":   []any{map[string]any{"name": manifest.Subject, "digest": map[string]any{"sha256": manifest.NativeEvidenceHash}}},
			"predicate": root,
		}
	case EnvelopeSLSA:
		return map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate":     map[string]any{"buildDefinition": root, "runDetails": map[string]any{"builder": map[string]any{"id": "helm-ai-kernel"}}},
		}
	case EnvelopeSigstore:
		return map[string]any{
			"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
			"content":   root,
			"verificationMaterial": map[string]any{
				"helmNativeRoot": manifest.NativeEvidenceHash,
			},
		}
	default:
		return root
	}
}
