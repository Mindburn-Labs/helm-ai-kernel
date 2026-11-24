package main

// quantum_posture: These route tests use classical Ed25519 receipt signatures.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

func TestEvidenceVerifyRejectsUnsafeArchivePaths(t *testing.T) {
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{})

	bundle, err := unsafeEvidenceBundle()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(bundle))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["outcome"] != "FAILED" {
		t.Fatalf("expected unsafe archive to fail verification, got %+v", result)
	}
	if statuses := evidenceCheckStatuses(t, result); len(statuses) != 1 || statuses["bundle_format"] != "FAILED" {
		t.Fatalf("an unreadable bundle runs no check past the format check: %+v", result)
	}
}

func TestExtractEvidenceBundleToDirRejectsUnsafeArchivePaths(t *testing.T) {
	for _, archiveName := range []string{"../receipt.json", `..\\receipt.json`} {
		t.Run(archiveName, func(t *testing.T) {
			root := t.TempDir()
			dstDir := filepath.Join(root, "extract")
			if err := os.Mkdir(dstDir, 0o700); err != nil {
				t.Fatalf("create extract dir: %v", err)
			}
			bundle, err := unsafeEvidenceBundleWithName(archiveName)
			if err != nil {
				t.Fatal(err)
			}
			err = extractEvidenceBundleToDir(bundle, dstDir)
			if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
				t.Fatalf("expected unsafe path rejection, got %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(root, "receipt.json")); !os.IsNotExist(statErr) {
				t.Fatalf("expected no escaped write, stat err=%v", statErr)
			}
		})
	}
}

func TestWriteEvidenceBundlePackFilesRejectsUnsafeDerivedNames(t *testing.T) {
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "../../escaped-artifact",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	files, err := buildEvidenceBundleFilesWithSurfaceArtifacts("session-unsafe", []*contracts.Receipt{{
		ReceiptID:    "../../escaped-receipt",
		DecisionID:   "dec-unsafe",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-unsafe",
		ScopeHash:    scope.ScopeHash,
		LamportClock: 1,
		ArgsHash:     "args-unsafe",
		Metadata: map[string]any{
			"risk_class":             "T2",
			"verification_scope_ref": scope.ScopeHash,
		},
	}}, registry)
	if err != nil {
		t.Fatalf("build unsafe bundle files: %v", err)
	}
	for _, name := range []string{
		"receipts/../../escaped-receipt.json",
		"verification_scopes/../../escaped-artifact.json",
	} {
		if _, ok := files[name]; !ok {
			t.Fatalf("expected derived file %q in bundle files: %v", name, files)
		}
	}

	root := t.TempDir()
	packDir := filepath.Join(root, "pack")
	if err := os.Mkdir(packDir, 0o700); err != nil {
		t.Fatalf("create pack dir: %v", err)
	}
	err = writeEvidenceBundlePackFiles(packDir, files)
	if err == nil || !strings.Contains(err.Error(), `unsafe archive path "receipts/../../escaped-receipt.json"`) && !strings.Contains(err.Error(), `unsafe archive path "verification_scopes/../../escaped-artifact.json"`) {
		t.Fatalf("expected unsafe path rejection, got %v", err)
	}
	for _, escaped := range []string{"escaped-receipt.json", "escaped-artifact.json"} {
		if _, statErr := os.Stat(filepath.Join(root, escaped)); !os.IsNotExist(statErr) {
			t.Fatalf("expected no escaped write for %q, stat err=%v", escaped, statErr)
		}
	}
}

func TestWriteEvidenceBundlePackFilesRejectsBackslashDerivedNames(t *testing.T) {
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: `..\..\escaped-artifact`,
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	files, err := buildEvidenceBundleFilesWithSurfaceArtifacts("session-unsafe", []*contracts.Receipt{{
		ReceiptID:    `..\..\escaped-receipt`,
		DecisionID:   "dec-unsafe",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-unsafe",
		ScopeHash:    scope.ScopeHash,
		LamportClock: 1,
		ArgsHash:     "args-unsafe",
		Metadata: map[string]any{
			"risk_class":             "T2",
			"verification_scope_ref": scope.ScopeHash,
		},
	}}, registry)
	if err != nil {
		t.Fatalf("build unsafe bundle files: %v", err)
	}
	for _, name := range []string{
		`receipts/..\..\escaped-receipt.json`,
		`verification_scopes/..\..\escaped-artifact.json`,
	} {
		if _, ok := files[name]; !ok {
			t.Fatalf("expected derived file %q in bundle files: %v", name, files)
		}
	}

	root := t.TempDir()
	packDir := filepath.Join(root, "pack")
	if err := os.Mkdir(packDir, 0o700); err != nil {
		t.Fatalf("create pack dir: %v", err)
	}
	err = writeEvidenceBundlePackFiles(packDir, files)
	if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("expected unsafe path rejection, got %v", err)
	}
	for _, escaped := range []string{"escaped-receipt.json", "escaped-artifact.json"} {
		if _, statErr := os.Stat(filepath.Join(root, escaped)); !os.IsNotExist(statErr) {
			t.Fatalf("expected no escaped write for %q, stat err=%v", escaped, statErr)
		}
	}
}

func TestBuildTrustedEvidenceBundleWithSurfaceArtifactsAllowsSafeNames(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("safe-export")
	if err != nil {
		t.Fatal(err)
	}
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "scope-safe",
		SubjectHash:         "sha256:subject",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	receipt := &contracts.Receipt{
		ReceiptID:    "rcpt-safe",
		DecisionID:   "dec-safe",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-safe",
		ScopeHash:    scope.ScopeHash,
		LamportClock: 1,
		ArgsHash:     "args-safe",
		Metadata: map[string]any{
			"risk_class":             "T2",
			"verification_scope_ref": scope.ScopeHash,
		},
	}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}

	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("session-safe", []*contracts.Receipt{receipt}, registry, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build trusted evidence bundle: %v", err)
	}
	parsed, err := readEvidenceBundle(bundle)
	if err != nil {
		t.Fatalf("read evidence bundle: %v", err)
	}
	for _, name := range []string{
		"receipts/rcpt-safe.json",
		"verification_scopes/scope-safe.json",
		evidenceBundleIndexPath,
		evidencepkg.EvidencePackSealPath,
	} {
		if _, ok := parsed.Files[name]; !ok {
			t.Fatalf("expected safe bundle file %q: %v", name, parsed.Files)
		}
	}
}

func unsafeEvidenceBundle() ([]byte, error) {
	return unsafeEvidenceBundleWithName("../receipt.json")
}

func unsafeEvidenceBundleWithName(name string) ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Size: 2, Mode: 0644}); err != nil {
		return nil, err
	}
	if _, err := tarWriter.Write([]byte("{}")); err != nil {
		return nil, err
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
