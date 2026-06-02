package pack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverageVerifierSignatureEdges(t *testing.T) {
	t.Run("VerifyPack rejects content hash mismatch", func(t *testing.T) {
		verifier := NewVerifier(nil)
		ok, err := verifier.VerifyPack(&Pack{
			PackID:      "pack-1",
			Manifest:    PackManifest{Name: "pack-1", Version: "1.0.0"},
			ContentHash: "not-the-computed-hash",
		})
		if ok || err == nil {
			t.Fatalf("VerifyPack ok=%v err=%v, want mismatch error", ok, err)
		}
	})

	t.Run("VerifyPack succeeds with trusted Ed25519 signature", func(t *testing.T) {
		p, anchor := coverageSignedVerifierPack(t)
		verifier := NewVerifier(nil)
		verifier.AddTrustAnchor(anchor)

		ok, err := verifier.VerifyPack(p)
		if err != nil {
			t.Fatalf("VerifyPack: %v", err)
		}
		if !ok {
			t.Fatal("VerifyPack returned false for valid signature")
		}
	})

	t.Run("signature check reports no trust anchors", func(t *testing.T) {
		check := NewVerifier(nil).verifySignature(ResolvedPack{
			Manifest: PackManifest{Name: "pack-1", Version: "1.0.0"},
		})
		if check.Passed || check.Message != "No trust anchors configured" {
			t.Fatalf("check = %+v", check)
		}
	})

	t.Run("signature check reports missing signatures", func(t *testing.T) {
		_, anchor := coverageSignedVerifierPack(t)
		verifier := NewVerifier(nil)
		verifier.AddTrustAnchor(anchor)

		check := verifier.verifySignature(ResolvedPack{
			Manifest: PackManifest{Name: "pack-1", Version: "1.0.0"},
		})
		if check.Passed || check.Message != "No signatures found on pack" {
			t.Fatalf("check = %+v", check)
		}
	})

	t.Run("signature check skips malformed anchor and signature encodings", func(t *testing.T) {
		manifest := PackManifest{
			Name:    "pack-1",
			Version: "1.0.0",
			Signatures: []Signature{{
				SignerID:  "bad-anchor",
				Signature: "00",
			}, {
				SignerID:  "good-anchor",
				Signature: "not-hex",
			}},
		}
		_, anchor := coverageSignedVerifierPack(t)
		anchor.AnchorID = "good-anchor"

		verifier := NewVerifier(nil)
		verifier.AddTrustAnchor(TrustAnchor{AnchorID: "bad-anchor", PublicKey: "not-hex"})
		verifier.AddTrustAnchor(anchor)

		check := verifier.verifySignature(ResolvedPack{Manifest: manifest})
		if check.Passed || check.Message != "No valid signature found from trusted anchors" {
			t.Fatalf("check = %+v", check)
		}
	})

	t.Run("signature check rejects wrong but well encoded signature", func(t *testing.T) {
		_, anchor := coverageSignedVerifierPack(t)
		manifest := PackManifest{
			Name:    "pack-1",
			Version: "1.0.0",
			Signatures: []Signature{{
				SignerID:  anchor.AnchorID,
				Signature: hex.EncodeToString([]byte("wrong")),
			}},
		}
		verifier := NewVerifier(nil)
		verifier.AddTrustAnchor(anchor)

		check := verifier.verifySignature(ResolvedPack{Manifest: manifest})
		if check.Passed || check.Message != "No valid signature found from trusted anchors" {
			t.Fatalf("check = %+v", check)
		}
	})
}

func TestCoverageTelemetryEdges(t *testing.T) {
	t.Run("trust score clamps severe SLO violations at zero", func(t *testing.T) {
		score := CalculateTrustScore(PackMetrics{
			FailureRate:         10,
			EvidenceSuccessRate: -1,
			IncidentRate:        10,
		}, &ServiceLevelObjectives{
			MaxFailureRate:  0.01,
			MinEvidenceRate: 0.99,
			MaxIncidentRate: 0.01,
		})
		if score != 0 {
			t.Fatalf("score = %f, want 0", score)
		}
	})

	t.Run("ledger append reports open and marshal failures", func(t *testing.T) {
		missingParent := filepath.Join(t.TempDir(), "missing", "ledger.jsonl")
		if err := NewLedgerTelemetryHook(missingParent).append(&TelemetryEntry{}); err == nil {
			t.Fatal("expected open failure for missing parent directory")
		}

		badDataPath := filepath.Join(t.TempDir(), "ledger.jsonl")
		if err := NewLedgerTelemetryHook(badDataPath).append(&TelemetryEntry{Data: func() {}}); err == nil {
			t.Fatal("expected initial marshal failure")
		}

		count := 0
		flakyPath := filepath.Join(t.TempDir(), "ledger.jsonl")
		if err := NewLedgerTelemetryHook(flakyPath).append(&TelemetryEntry{
			Data: flakyJSON{count: &count},
		}); err == nil {
			t.Fatal("expected final marshal failure")
		}
	})

	t.Run("ledger records evidence and returns metrics for missing and existing ledgers", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "ledger.jsonl")
		hook := NewLedgerTelemetryHook(path)
		hook.RecordEvidenceGeneration(ctx, "pack-1", "1.0.0", "SOC2", true)

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if len(content) == 0 {
			t.Fatal("expected evidence entry in ledger")
		}

		metrics, err := hook.GetMetrics(ctx, "pack-1", "1.0.0")
		if err != nil {
			t.Fatalf("GetMetrics existing: %v", err)
		}
		if metrics.PackID != "pack-1" || metrics.Version != "1.0.0" {
			t.Fatalf("metrics = %+v", metrics)
		}

		missingMetrics, err := NewLedgerTelemetryHook(filepath.Join(t.TempDir(), "missing.jsonl")).
			GetMetrics(ctx, "pack-2", "2.0.0")
		if err != nil {
			t.Fatalf("GetMetrics missing: %v", err)
		}
		if missingMetrics.PackID != "pack-2" || missingMetrics.Version != "2.0.0" {
			t.Fatalf("missing metrics = %+v", missingMetrics)
		}

		noReadPath := filepath.Join(t.TempDir(), "no-read.jsonl")
		if err := os.WriteFile(noReadPath, []byte("ledger"), 0600); err != nil {
			t.Fatalf("WriteFile no-read: %v", err)
		}
		if err := os.Chmod(noReadPath, 0000); err != nil {
			t.Fatalf("Chmod no-read: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(noReadPath, 0600) })
		if _, err := NewLedgerTelemetryHook(noReadPath).GetMetrics(ctx, "pack-3", "3.0.0"); err == nil {
			t.Fatal("expected unreadable ledger to fail")
		}
	})
}

func TestCoverageVerifierIntegrityEdges(t *testing.T) {
	verifier := NewVerifier(nil)

	empty, err := verifier.Verify(context.Background(), &VerificationRequest{
		RequestID: "empty",
		Packs:     []ResolvedPack{},
		Options:   DefaultVerificationOptions(),
	})
	if err != nil {
		t.Fatalf("Verify empty: %v", err)
	}
	if empty.Summary.AvgTrustScore != 0 {
		t.Fatalf("empty average trust score = %f, want 0", empty.Summary.AvgTrustScore)
	}

	missingSignature := ResolvedPack{
		PackID:      "missing-signature",
		Manifest:    PackManifest{Name: "missing-signature", Version: "1.0.0"},
		ContentHash: "sha256:abc123",
	}
	missingSignatureResult, err := verifier.Verify(context.Background(), &VerificationRequest{
		RequestID: "missing-signature",
		Packs:     []ResolvedPack{missingSignature},
		Options:   VerificationOptions{RequiredChecks: []string{"signature"}},
	})
	if err != nil {
		t.Fatalf("Verify missing signature: %v", err)
	}
	if missingSignatureResult.Status != VerificationFailed {
		t.Fatalf("missing signature status = %s, want %s", missingSignatureResult.Status, VerificationFailed)
	}

	withDrill := ResolvedPack{
		PackID: "pack-drill",
		Manifest: PackManifest{
			Name:    "pack-drill",
			Version: "1.0.0",
			Metadata: map[string]interface{}{
				"drill:network-partition": "PASS",
			},
		},
		ContentHash: "sha256:abc123",
	}
	result, err := verifier.Verify(context.Background(), &VerificationRequest{
		RequestID: "drill",
		Packs:     []ResolvedPack{withDrill},
		Options: VerificationOptions{
			RequiredChecks: []string{"integrity"},
			RequiredDrills: []string{"network-partition"},
		},
	})
	if err != nil {
		t.Fatalf("Verify drill: %v", err)
	}
	foundDrill := false
	for _, check := range result.PackResults[0].Checks {
		if check.CheckType == CheckType("drill_network-partition") && check.Passed {
			foundDrill = true
		}
	}
	if !foundDrill {
		t.Fatalf("drill check not verified: %+v", result.PackResults[0].Checks)
	}
}

func coverageSignedVerifierPack(t *testing.T) (*Pack, TrustAnchor) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	manifest := PackManifest{
		Name:         "pack-1",
		Version:      "1.0.0",
		Capabilities: []string{"capture"},
	}
	hash := ComputePackHash(&Pack{Manifest: manifest})
	signature := ed25519.Sign(priv, []byte(hash))
	manifest.Signatures = []Signature{{
		SignerID:  "anchor-1",
		Signature: hex.EncodeToString(signature),
		SignedAt:  time.Now().UTC(),
		Algorithm: "ed25519",
	}}

	return &Pack{
			PackID:      "pack-1",
			Manifest:    manifest,
			ContentHash: ComputePackHash(&Pack{Manifest: manifest}),
		}, TrustAnchor{
			AnchorID:   "anchor-1",
			Name:       "HELM Signing Key",
			PublicKey:  hex.EncodeToString(pub),
			ValidFrom:  time.Now().Add(-time.Hour),
			ValidUntil: time.Now().Add(time.Hour),
			TrustLevel: 5,
		}
}

type flakyJSON struct {
	count *int
}

func (f flakyJSON) MarshalJSON() ([]byte, error) {
	*f.count++
	if *f.count == 1 {
		return []byte(`"ok"`), nil
	}
	return nil, errors.New("flaky marshal failed")
}
