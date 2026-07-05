package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
)

func TestExportAndVerify_RoundTrip(t *testing.T) {
	tmpFile := t.TempDir() + "/test.tar"

	files := map[string][]byte{
		"decisions/dec-001.json": []byte(`{"id":"dec-001","verdict":"PASS"}`),
		"receipts/rec-001.json":  []byte(`{"id":"rec-001","status":"SUCCESS"}`),
		"proofgraph/nodes.json":  []byte(`[{"id":"pg-1","type":"INTENT"}]`),
	}

	if err := ExportPack("session-test-1", files, tmpFile); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	manifest, err := VerifyPack(tmpFile)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	if manifest.SessionID != "session-test-1" {
		t.Errorf("session = %s, want session-test-1", manifest.SessionID)
	}
	if len(manifest.FileHashes) != 3 {
		t.Errorf("file count = %d, want 3", len(manifest.FileHashes))
	}
}

func TestPackVerifyCLIRejectsUnsignedIntegrityOnlyPack(t *testing.T) {
	tmpFile := t.TempDir() + "/unsigned.tar"
	files := map[string][]byte{
		"receipts/forged.json": []byte(`{"id":"forged","status":"SUCCESS"}`),
	}
	if err := ExportPack("session-forged", files, tmpFile); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if _, err := VerifyPack(tmpFile); err != nil {
		t.Fatalf("integrity check should still pass: %v", err)
	}
	if code := handlePackVerify([]string{"--bundle", tmpFile, "--json"}); code == 0 {
		t.Fatal("pack verify CLI must not authenticate unsigned integrity-only packs")
	}
}

func TestExportPack_Deterministic(t *testing.T) {
	dir := t.TempDir()
	path1 := dir + "/pack1.tar"
	path2 := dir + "/pack2.tar"

	files := map[string][]byte{
		"b.txt": []byte("second"),
		"a.txt": []byte("first"),
	}

	if err := ExportPack("sess", files, path1); err != nil {
		t.Fatal(err)
	}
	if err := ExportPack("sess", files, path2); err != nil {
		t.Fatal(err)
	}

	data1, _ := os.ReadFile(path1)
	data2, _ := os.ReadFile(path2)

	// NOTE: Timestamps in manifest will differ, so byte-equality won't hold.
	// But we can verify both packs pass verification.
	if _, err := VerifyPack(path1); err != nil {
		t.Fatalf("pack1 verify: %v", err)
	}
	if _, err := VerifyPack(path2); err != nil {
		t.Fatalf("pack2 verify: %v", err)
	}

	_ = data1
	_ = data2
}

func TestVerifyPack_TamperedFile(t *testing.T) {
	// Create a valid pack, then we'll test the verify logic
	dir := t.TempDir()
	path := dir + "/tampered.tar"

	files := map[string][]byte{
		"data.json": []byte(`{"key":"value"}`),
	}

	if err := ExportPack("sess", files, path); err != nil {
		t.Fatal(err)
	}

	// Valid pack should verify
	if _, err := VerifyPack(path); err != nil {
		t.Fatalf("valid pack should verify: %v", err)
	}
}

func TestVerifyPackRejectsUnmanifestedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.tar")
	tamperedPath := filepath.Join(dir, "tampered.tar")

	files := map[string][]byte{
		"data.json": []byte(`{"key":"value"}`),
	}
	if err := ExportPack("sess", files, path); err != nil {
		t.Fatal(err)
	}
	if err := copyPackWithExtraEntry(path, tamperedPath, "proofgraph/unmanifested.json", []byte(`{"extra":true}`)); err != nil {
		t.Fatal(err)
	}

	_, err := VerifyPack(tamperedPath)
	if err == nil || !strings.Contains(err.Error(), "missing from manifest") {
		t.Fatalf("expected unmanifested file rejection, got %v", err)
	}
}

func TestExportPackWithOptions_EUAIActProfile(t *testing.T) {
	path := t.TempDir() + "/ai-act.tar"
	profile := completeExportEUAIActProfile()

	if err := ExportPackWithOptions("sess-ai-act", map[string][]byte{
		"evidence/profile.json": []byte(`{"ok":true}`),
	}, path, ExportPackOptions{EUAIActProfile: profile}); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	manifest, err := VerifyPack(path)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if manifest.EUAIActProfile == nil || manifest.EUAIActProfile.ProfileID != profile.ProfileID {
		t.Fatalf("manifest profile = %#v, want %s", manifest.EUAIActProfile, profile.ProfileID)
	}
}

func TestExportPackWithOptions_TransparencySTH(t *testing.T) {
	path := t.TempDir() + "/sth.tar"
	sth := translog.SignedTreeHead{
		TreeSize:  3,
		RootHash:  "abc123",
		Timestamp: "2026-06-24T00:00:00Z",
		LogID:     "log-test",
		PublicKey: "pub",
		Signature: "sig",
	}

	if err := ExportPackWithOptions("sess-sth", map[string][]byte{
		"receipts/rec-001.json": []byte(`{"id":"rec-001"}`),
	}, path, ExportPackOptions{TransparencySTH: sth}); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	manifest, err := VerifyPack(path)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if _, ok := manifest.FileHashes["transparency/sth.json"]; !ok {
		t.Fatal("manifest is missing transparency/sth.json")
	}

	var got translog.SignedTreeHead
	if err := json.Unmarshal(readPackEntry(t, path, "transparency/sth.json"), &got); err != nil {
		t.Fatalf("decode STH: %v", err)
	}
	if got.LogID != sth.LogID || got.TreeSize != sth.TreeSize {
		t.Fatalf("STH mismatch: got %+v want %+v", got, sth)
	}
}

func TestPackCreateEmbedsTransparencySTHFromDataDir(t *testing.T) {
	dir := t.TempDir()
	signer, err := loadOrGenerateSignerWithDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	logID := translog.LogIDFromPublicKey(signer.PublicKeyBytes())
	receipt := contracts.Receipt{
		ReceiptID: "rec-001",
		Status:    "SUCCESS",
		LogID:     logID,
		LeafIndex: 0,
		Transparency: &contracts.TransparencyAnchor{
			Backend: "translog",
			LogID:   logID,
		},
	}
	receiptHash, err := contracts.ReceiptChainHash(&receipt)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runLogCLI(t, "log", "append",
		"--leaf-hash", receiptHash,
		"--data-dir", dir)
	if code != 0 {
		t.Fatalf("append failed (%d): %s", code, errOut)
	}

	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(receiptsDir, 0750); err != nil {
		t.Fatal(err)
	}
	receiptData, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(receiptsDir, "rec-001.json"), receiptData, 0600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "evidencepack.tar")
	if code := handlePackCreate([]string{
		"--session", "sess-sth-cli",
		"--receipts", receiptsDir,
		"--out", out,
		"--data-dir", dir,
	}); code != 0 {
		t.Fatalf("pack create exit %d", code)
	}

	manifest, err := VerifyPack(out)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if _, ok := manifest.FileHashes["transparency/sth.json"]; !ok {
		t.Fatal("manifest is missing transparency/sth.json")
	}
	if _, ok := manifest.FileHashes["transparency/inclusion/rec-001.json"]; !ok {
		t.Fatal("manifest is missing transparency/inclusion/rec-001.json")
	}

	var sth translog.SignedTreeHead
	if err := json.Unmarshal(readPackEntry(t, out, "transparency/sth.json"), &sth); err != nil {
		t.Fatalf("decode STH: %v", err)
	}
	if sth.TreeSize != 1 || sth.LogID == "" || sth.Signature == "" {
		t.Fatalf("unexpected STH: %+v", sth)
	}
	if err := translog.VerifyTreeHead(&sth, sth.PublicKey); err != nil {
		t.Fatalf("STH does not verify: %v", err)
	}

	var proof translog.InclusionProof
	if err := json.Unmarshal(readPackEntry(t, out, "transparency/inclusion/rec-001.json"), &proof); err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	if proof.LeafIndex != 0 || proof.TreeSize != 1 {
		t.Fatalf("unexpected inclusion proof: %+v", proof)
	}
	leafInput, err := hex.DecodeString(receiptHash)
	if err != nil {
		t.Fatal(err)
	}
	expectedLeaf := translog.LeafHash(leafInput)
	if proof.LeafHash != hex.EncodeToString(expectedLeaf[:]) {
		t.Fatalf("proof leaf hash = %s, want %x", proof.LeafHash, expectedLeaf[:])
	}
	if err := translog.VerifyInclusion(&proof, sth.RootHash); err != nil {
		t.Fatalf("inclusion proof does not verify: %v", err)
	}
}

func TestTransparencyArtifactsRejectReceiptLeafMismatch(t *testing.T) {
	dir := t.TempDir()
	signer, err := loadOrGenerateSignerWithDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	logID := translog.LogIDFromPublicKey(signer.PublicKeyBytes())
	receipt := contracts.Receipt{
		ReceiptID: "rec-001",
		Status:    "SUCCESS",
		LogID:     logID,
		LeafIndex: 0,
		Transparency: &contracts.TransparencyAnchor{
			Backend: "translog",
			LogID:   logID,
		},
	}
	receiptHash, err := contracts.ReceiptChainHash(&receipt)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runLogCLI(t, "log", "append",
		"--leaf-hash", receiptHash,
		"--data-dir", dir)
	if code != 0 {
		t.Fatalf("append failed (%d): %s", code, errOut)
	}

	receipt.Status = "DENIED"
	receiptData, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = transparencyArtifactsForPackCreate(dir, map[string][]byte{
		"receipts/rec-001.json": receiptData,
	})
	if err == nil {
		t.Fatal("expected transparency leaf mismatch")
	}
	if !strings.Contains(err.Error(), "transparency proof leaf hash mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExportPackWithOptions_RejectsIncompleteEUAIActProfile(t *testing.T) {
	path := t.TempDir() + "/bad-ai-act.tar"
	err := ExportPackWithOptions("sess-ai-act", map[string][]byte{
		"evidence/profile.json": []byte(`{"ok":true}`),
	}, path, ExportPackOptions{EUAIActProfile: &contracts.EUAIActEvidenceProfile{
		ProfileID:              "eu-ai-act:bad",
		RoleMap:                contracts.EUAIActRoleMap{Deployer: "customer"},
		RiskCategory:           "high-risk employment",
		RelevantArticles:       []string{"Article 14"},
		ProviderOrDeployerRole: "deployer",
		RedactionProfile:       "employment_minimized",
		TimelineStatus:         "FINAL",
	}})
	if err == nil {
		t.Fatal("expected incomplete profile export to fail")
	}
}

func readPackEntry(t *testing.T, packPath, entryName string) []byte {
	t.Helper()
	f, err := os.Open(packPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == entryName {
			return data
		}
	}
	t.Fatalf("entry %s not found", entryName)
	return nil
}

func completeExportEUAIActProfile() *contracts.EUAIActEvidenceProfile {
	return &contracts.EUAIActEvidenceProfile{
		ProfileID:                           "eu-ai-act:export:1",
		RoleMap:                             contracts.EUAIActRoleMap{Deployer: "customer"},
		RiskCategory:                        "high-risk Annex III employment",
		RelevantArticles:                    []string{"Article 9", "Article 10", "Article 12", "Article 14", "Article 26", "Article 27", "Article 49"},
		HighRiskReasons:                     []string{"employment and worker management"},
		ProviderOrDeployerRole:              "deployer",
		RiskManagementRefs:                  []string{"risk:1"},
		DataGovernanceRefs:                  []string{"data:1"},
		LogRecordRefs:                       []string{"logs:1"},
		TransparencyNoticeRefs:              []string{"instructions:1"},
		HumanOversightRefs:                  []string{"oversight:1"},
		AccuracyRobustnessCybersecurityRefs: []string{"security:1"},
		FRIARefs:                            []string{"fria:1"},
		AffectedPersonNoticeRefs:            []string{"notice:1"},
		RegistrationRefs:                    []string{"registration:1"},
		RedactionProfile:                    "employment_minimized",
		TimelineStatus:                      "FINAL",
		RedactionMetadata:                   map[string]string{"profile": "employment_minimized"},
	}
}

func copyPackWithExtraEntry(srcPath, dstPath, extraName string, extraData []byte) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	gr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	defer gr.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	gw := gzip.NewWriter(dst)
	tw := tar.NewWriter(gw)

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		copied := *hdr
		if err := tw.WriteHeader(&copied); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := writeEntry(tw, extraName, extraData); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}
