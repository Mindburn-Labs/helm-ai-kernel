package evidence

// quantum_posture: local seal fixtures exercise classical Ed25519 verification;
// these tests establish no post-quantum or external-proof assurance.

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
)

// A matching imprint and a locally writable receipt are not independent trust.
// These expectations come from the external-proof requirement, not the fields
// that happen to be checked by the current parsers.
func TestExternalProofTruthProfilesCannotPromoteUnsignedClaims(t *testing.T) {
	root := strings.Repeat("a", 64)
	seal := EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:   "rfc3161",
			Request:   proofanchor.AnchorRequest{MerkleRoot: root},
			LogID:     "https://tsa.invalid",
			Signature: base64.StdEncoding.EncodeToString(rfc3161TokenForRoot(t, root)),
		}},
	}
	cfg := &EvidencePackTrustConfig{Anchor: EvidencePackSealAnchor{Type: "rfc3161", URL: "https://tsa.invalid"}}
	receiptPath := filepath.Join(t.TempDir(), "storage.json")
	if err := WriteStorageReceipt(receiptPath, unsignedStorageClaim(root)); err != nil {
		t.Fatal(err)
	}
	// Test the artifact-selected storage path as well as the explicit path used
	// by the CLI regression. Choosing a file cannot establish its authenticity.
	seal.Storage.Receipt = receiptPath
	for _, profile := range []EvidenceTrustProfile{EvidenceTrustProfileDevLocal, EvidenceTrustProfileTeam, EvidenceTrustProfileCustomer, EvidenceTrustProfileHighAssurance} {
		t.Run(string(profile), func(t *testing.T) {
			want, wantError := "not-checked", false
			if profile == EvidenceTrustProfileCustomer || profile == EvidenceTrustProfileHighAssurance {
				want, wantError = "unverifiable", true
			}
			status, errs := verifyEvidenceAnchorReceipts(context.Background(), seal, cfg, profile)
			if status != want || (len(errs) > 0) != wantError {
				t.Fatalf("anchor status=%s errors=%v, want %s error=%v", status, errs, want, wantError)
			}
			storage, path, storageErrs := VerifyStorageReceiptForSeal(seal, profile, "", "", fixedSealTime())
			if storage != want || path != receiptPath || (len(storageErrs) > 0) != wantError {
				t.Fatalf("storage status=%s path=%s errors=%v, want %s error=%v", storage, path, storageErrs, want, wantError)
			}
		})
	}
}

type externalProofRoundTripFunc func(*http.Request) (*http.Response, error)

func (f externalProofRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestExternalProofTruthVerifierOwnsBackend(t *testing.T) {
	// The vulnerable baseline can use the default public Rekor endpoint.
	// Keep the reproduction network-free while recording that attempted I/O.
	originalTransport := http.DefaultTransport
	var blockedRequests atomic.Int64
	http.DefaultTransport = externalProofRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		ip := net.ParseIP(req.URL.Hostname())
		if ip == nil || !ip.IsLoopback() {
			blockedRequests.Add(1)
			return nil, errors.New("external network request blocked by external-proof test")
		}
		return originalTransport.RoundTrip(req)
	})
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
		if attempts := blockedRequests.Load(); attempts != 0 {
			t.Errorf("untrusted artifact attempted %d external network requests (all blocked)", attempts)
		}
	})
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	root := strings.Repeat("b", 64)
	seal := EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:   "rfc3161",
			Request:   proofanchor.AnchorRequest{MerkleRoot: root},
			LogID:     server.URL,
			Signature: base64.StdEncoding.EncodeToString(rfc3161TokenForRoot(t, root)),
		}},
	}
	for _, tc := range []struct {
		name   string
		cfg    *EvidencePackTrustConfig
		status string
		reason string
	}{
		{"no configuration", nil, "unverifiable", "backend is not configured"},
		{"missing endpoint", &EvidencePackTrustConfig{Anchor: EvidencePackSealAnchor{Type: "rfc3161"}}, "unverifiable", "URL is not configured"},
		{"local configuration", &EvidencePackTrustConfig{Anchor: EvidencePackSealAnchor{Type: "local-dev", URL: server.URL}}, "unverifiable", "backend is not configured"},
		{"artifact changes backend", &EvidencePackTrustConfig{Anchor: EvidencePackSealAnchor{Type: "rekor", URL: server.URL}}, "invalid", "does not match configured backend"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, errs := verifyEvidenceAnchorReceipts(context.Background(), seal, tc.cfg, EvidenceTrustProfileCustomer)
			if status != tc.status || !strings.Contains(strings.Join(errs, "; "), tc.reason) {
				t.Fatalf("status=%s errors=%v, want %s / %s", status, errs, tc.status, tc.reason)
			}
		})
	}
	// A supported artifact backend must not contact either a default log or
	// its own endpoint when verifier configuration has not selected it.
	seal.AnchorReceipts[0].Backend = "rekor-v2"
	status, errs := verifyEvidenceAnchorReceipts(context.Background(), seal, nil, EvidenceTrustProfileCustomer)
	if status != "unverifiable" || !strings.Contains(strings.Join(errs, "; "), "backend is not configured") {
		t.Fatalf("unconfigured Rekor receipt: status=%s errors=%v", status, errs)
	}
	if requests.Load() != 0 {
		t.Fatalf("untrusted artifact caused %d network requests", requests.Load())
	}
}

func TestExternalProofTruthUnavailableCheckDoesNotHideMalformedReceipt(t *testing.T) {
	root := strings.Repeat("c", 64)
	good := proofanchor.AnchorReceipt{
		Backend:   "rfc3161",
		Request:   proofanchor.AnchorRequest{MerkleRoot: root},
		Signature: base64.StdEncoding.EncodeToString(rfc3161TokenForRoot(t, root)),
	}
	bad := good
	bad.Signature = "not-base64"
	seal := EvidencePackSeal{MerkleRoot: root, AnchorReceipts: []proofanchor.AnchorReceipt{good, bad}}
	cfg := &EvidencePackTrustConfig{Anchor: EvidencePackSealAnchor{Type: "rfc3161", URL: "https://tsa.invalid"}}
	status, errs := verifyEvidenceAnchorReceipts(context.Background(), seal, cfg, EvidenceTrustProfileCustomer)
	if status != "invalid" || !strings.Contains(strings.Join(errs, "; "), "decode timestamp token") {
		t.Fatalf("malformed later receipt hidden: status=%s errors=%v", status, errs)
	}
}

// This adapter supplies real Ed25519 signatures with an external-type label
// solely to isolate the external-proof gate; it does not simulate a KMS claim.
type externalProofTestSigner struct{ *FileDevEvidenceSigner }

func (externalProofTestSigner) SignerType() string { return "external-test" }

func TestExternalProofTruthSignedSealPreservesLocalSuccess(t *testing.T) {
	for _, profile := range []EvidenceTrustProfile{EvidenceTrustProfileTeam, EvidenceTrustProfileCustomer, EvidenceTrustProfileHighAssurance} {
		t.Run(string(profile), func(t *testing.T) {
			signer, err := NewFileDevEvidenceSigner(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			pack := writeSealTestPack(t, map[string][]byte{"01_SCORE.json": []byte(`{"pass":true}`)})
			roots, err := ComputeEvidencePackIndexRoots(pack)
			if err != nil {
				t.Fatal(err)
			}
			receiptPath := filepath.Join(t.TempDir(), "storage.json")
			if err := WriteStorageReceipt(receiptPath, unsignedStorageClaim(roots.MerkleRoot)); err != nil {
				t.Fatal(err)
			}
			cfg := &EvidencePackTrustConfig{
				ActiveProfile: profile,
				Anchor:        EvidencePackSealAnchor{Type: "rfc3161", URL: "https://tsa.invalid", Status: "verified-externally"},
				Storage:       EvidencePackSealStorage{Type: "s3-object-lock", Bucket: "audit", ObjectLock: true, Immutable: true, Receipt: receiptPath, Status: "immutable-off-host"},
				TrustedKeys:   map[string]string{signer.KeyID(): signer.PublicKeyHex()},
			}
			seal, err := SealEvidencePack(context.Background(), pack, SealEvidencePackOptions{
				Profile:     profile,
				TrustConfig: cfg,
				Signer:      externalProofTestSigner{signer},
				SignedAt:    fixedSealTime(),
				AnchorReceipts: []proofanchor.AnchorReceipt{{
					Backend:   "rfc3161",
					Request:   proofanchor.AnchorRequest{MerkleRoot: roots.MerkleRoot},
					LogID:     "https://tsa.invalid",
					Signature: base64.StdEncoding.EncodeToString(rfc3161TokenForRoot(t, roots.MerkleRoot)),
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if seal.Anchor.Status != "not-checked" || seal.Storage.Status == "immutable-off-host" {
				t.Fatalf("producer claimed checks it did not run: anchor=%s storage=%s", seal.Anchor.Status, seal.Storage.Status)
			}
			result := VerifyEvidencePackSeal(pack, VerifyEvidencePackSealOptions{Profile: profile, TrustConfig: cfg, Now: fixedSealTime()})
			if !result.SignatureValid {
				t.Fatalf("real trusted Ed25519 signature failed: %+v", result)
			}
			if profile == EvidenceTrustProfileTeam {
				if result.State != "valid" || result.AnchorStatus != "not-checked" || result.StorageStatus != "not-checked" || len(result.Errors) != 0 {
					t.Fatalf("trusted local seal must retain bounded success: %+v", result)
				}
			} else if result.State == "valid" || result.AnchorStatus != "unverifiable" || result.StorageStatus != "unverifiable" || len(result.Errors) != 2 {
				t.Fatalf("external proof requirements must reject only the two unchecked proofs: %+v", result)
			}
		})
	}
}

func unsignedStorageClaim(root string) EvidencePackStorageReceipt {
	return EvidencePackStorageReceipt{
		SchemaVersion: EvidencePackStorageReceiptSchemaS3,
		StorageType:   "s3-object-lock",
		SubjectRoot:   root,
		Bucket:        "audit",
		Key:           "pack.tar",
		VersionID:     "version-1",
		ObjectHash:    "sha256:" + strings.Repeat("d", 64),
		RetentionMode: "COMPLIANCE",
		RetainUntil:   fixedSealTime().Add(time.Hour),
		StoredAt:      fixedSealTime(),
	}
}
