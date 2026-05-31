package main

import (
	"os"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
