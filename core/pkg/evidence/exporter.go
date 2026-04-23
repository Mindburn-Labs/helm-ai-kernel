package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/provenance"
	"github.com/google/uuid"
)

// BundleType defines the purpose of the evidence bundle.
type BundleType string

const (
	BundleTypeSOC2     BundleType = "SOC2_AUDIT"
	BundleTypeIncident BundleType = "INCIDENT_REPORT"
)

// Bundle is a sealed package of evidence.
type Bundle struct {
	ID                   string     `json:"id"`
	Type                 BundleType `json:"type"`
	TraceID              string     `json:"trace_id"`
	Timestamp            time.Time  `json:"timestamp"`
	Artifacts            []Artifact `json:"artifacts"`
	BundleHash           string     `json:"bundle_hash"`
	SignatureKeyID       string     `json:"signature_key_id"`
	SignaturePublicKey   string     `json:"signature_public_key"`
	Signature            string     `json:"signature"`
	SignatureMessageHash string     `json:"signature_message_hash"`
}

type Artifact struct {
	Name    string          `json:"name"`
	Content json.RawMessage `json:"content"`
	Hash    string          `json:"hash"`
}

type BundleSigner interface {
	Sign(data []byte) (string, error)
	PublicKey() string
}

// Exporter collects and packages evidence.
type Exporter interface {
	ExportSOC2(ctx context.Context, traceID string, envelopes []*provenance.Envelope) (*Bundle, error)
	ExportIncidentReport(ctx context.Context, traceID string, diagnostics map[string]string) (*Bundle, error)
}

type DefaultExporter struct {
	signer BundleSigner
	keyID  string
}

func NewExporter(signer BundleSigner, keyID string) *DefaultExporter {
	return &DefaultExporter{signer: signer, keyID: keyID}
}

func (e *DefaultExporter) ExportSOC2(ctx context.Context, traceID string, envelopes []*provenance.Envelope) (*Bundle, error) {
	if e.signer == nil || e.keyID == "" {
		return nil, errors.New("fail-closed: evidence exporter signing key not configured")
	}

	bundle := &Bundle{
		ID:                 uuid.New().String(),
		Type:               BundleTypeSOC2,
		TraceID:            traceID,
		Timestamp:          time.Now().UTC(),
		Artifacts:          make([]Artifact, 0),
		SignatureKeyID:     e.keyID,
		SignaturePublicKey: e.signer.PublicKey(),
	}

	for i, env := range envelopes {
		data, err := canonicalize.JCS(env)
		if err != nil {
			return nil, fmt.Errorf("evidence export: marshal envelope %d: %w", i, err)
		}
		bundle.Artifacts = append(bundle.Artifacts, Artifact{
			Name:    fmt.Sprintf("envelope_%d", i),
			Content: data,
			Hash:    computeHash(data),
		})
	}

	if err := sealBundle(bundle, e.signer); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (e *DefaultExporter) ExportIncidentReport(ctx context.Context, traceID string, diagnostics map[string]string) (*Bundle, error) {
	if e.signer == nil || e.keyID == "" {
		return nil, errors.New("fail-closed: evidence exporter signing key not configured")
	}

	bundle := &Bundle{
		ID:                 uuid.New().String(),
		Type:               BundleTypeIncident,
		TraceID:            traceID,
		Timestamp:          time.Now().UTC(),
		Artifacts:          make([]Artifact, 0),
		SignatureKeyID:     e.keyID,
		SignaturePublicKey: e.signer.PublicKey(),
	}

	data, err := canonicalize.JCS(diagnostics)
	if err != nil {
		return nil, fmt.Errorf("evidence export: marshal diagnostics: %w", err)
	}
	bundle.Artifacts = append(bundle.Artifacts, Artifact{
		Name:    "diagnostics",
		Content: data,
		Hash:    computeHash(data),
	})

	if err := sealBundle(bundle, e.signer); err != nil {
		return nil, err
	}
	return bundle, nil
}

func computeHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sealBundle(bundle *Bundle, signer BundleSigner) error {
	sort.Slice(bundle.Artifacts, func(i, j int) bool {
		return bundle.Artifacts[i].Name < bundle.Artifacts[j].Name
	})

	type artifactSig struct {
		Name string `json:"name"`
		Hash string `json:"hash"`
	}
	payload := struct {
		ID        string        `json:"id"`
		Type      BundleType    `json:"type"`
		TraceID   string        `json:"trace_id"`
		Timestamp time.Time     `json:"timestamp"`
		Artifacts []artifactSig `json:"artifacts"`
	}{
		ID:        bundle.ID,
		Type:      bundle.Type,
		TraceID:   bundle.TraceID,
		Timestamp: bundle.Timestamp,
		Artifacts: make([]artifactSig, 0, len(bundle.Artifacts)),
	}
	for _, a := range bundle.Artifacts {
		payload.Artifacts = append(payload.Artifacts, artifactSig{Name: a.Name, Hash: a.Hash})
	}

	msg, err := canonicalize.JCS(payload)
	if err != nil {
		return fmt.Errorf("evidence export: seal marshal failed: %w", err)
	}
	bundle.SignatureMessageHash = computeHash(msg)
	bundle.BundleHash = bundle.SignatureMessageHash

	sig, err := signer.Sign(msg)
	if err != nil {
		return fmt.Errorf("evidence export: sign failed: %w", err)
	}
	bundle.Signature = sig
	return nil
}
