// quantum_posture: these tests cover classical Ed25519 receipt signatures
// only and do not claim post-quantum protection.
package workstation

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeAuditReportForTest(t *testing.T) ScopeAuditReport {
	t.Helper()
	dir := t.TempDir()
	decision, err := Decide(DefaultObserveDraftProfile(), decisionRequest("secret", "secret://prod/api"), workstationTestDecisionOptions())
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFixture(t, filepath.Join(dir, "secret-deny.json"), decision)
	report, err := BuildScopeAudit(TrustAnchor{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// The scope audit and its pack are written into a directory of their own,
// through the opened directory and only as new files.
func TestWriteScopeAuditArtifactsRefusesADirectoryThatIsNotEmpty(t *testing.T) {
	report := scopeAuditReportForTest(t)
	out := filepath.Join(t.TempDir(), "audit")
	if _, err := WriteScopeAuditArtifacts(report, out, true); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteScopeAuditArtifacts(report, out, true); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("a second export into the same directory = %v, want a refusal", err)
	}

	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.MkdirAll(linked, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(linked, "scope-audit.md")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, err := WriteScopeAuditArtifacts(report, linked, false); err == nil {
		t.Fatal("export into a directory holding a hard link succeeded")
	}
	if data, _ := os.ReadFile(outside); string(data) != "keep" {
		t.Fatalf("the hard-linked file was written through: %q", data)
	}
}

// The evidence pack is exported only into a new or empty directory, so a file
// left there by an earlier export cannot pass for part of this one.
func TestWriteScopeAuditArtifactsRefusesAStalePackSubdirectory(t *testing.T) {
	report := scopeAuditReportForTest(t)
	out := filepath.Join(t.TempDir(), "audit")
	pack := filepath.Join(out, "scope-audit-evidencepack")
	if err := os.MkdirAll(pack, 0o750); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(pack, "stale.txt")
	if err := os.WriteFile(stale, []byte("earlier"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteScopeAuditArtifacts(report, out, true); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("export into a directory that is not empty = %v, want a refusal", err)
	}
	if _, err := os.Stat(filepath.Join(out, "scope-audit.json")); !os.IsNotExist(err) {
		t.Fatalf("the refused export created a report: %v", err)
	}
	if entries, _ := os.ReadDir(pack); len(entries) != 1 {
		t.Fatalf("the refused export wrote into the directory: %v", entries)
	}
}

// A pack directory that holds a link to a directory elsewhere is refused, and
// nothing is written there.
func TestWriteScopeAuditArtifactsRefusesALinkedPackSubdirectory(t *testing.T) {
	report := scopeAuditReportForTest(t)
	elsewhere := t.TempDir()
	out := filepath.Join(t.TempDir(), "audit")
	pack := filepath.Join(out, "scope-audit-evidencepack")
	if err := os.MkdirAll(pack, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(pack, "99_EXT")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := WriteScopeAuditArtifacts(report, out, true); err == nil {
		t.Fatal("export into a pack directory with a linked subdirectory succeeded")
	}
	entries, err := os.ReadDir(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("files were written through the linked subdirectory: %v", entries)
	}
}

// Receipts of another signer are counted apart with every action they claim,
// not one per receipt.
func TestScopeAuditCountsEveryActionOfAnotherSigner(t *testing.T) {
	other := []byte(strings.Repeat("o", ed25519.SeedSize))
	imported, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "scope-audit-all-boundaries"), ImportOptions{SigningSeed: other})
	if err != nil {
		t.Fatal(err)
	}
	alone := t.TempDir()
	writeJSONFixture(t, filepath.Join(alone, "other.json"), imported.Receipt)
	claimed, err := BuildScopeAudit(TrustAnchor{}, alone)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Summary.TotalActions < 2 {
		t.Fatalf("the fixture claims %d actions; the test needs a receipt with several", claimed.Summary.TotalActions)
	}

	dir := t.TempDir()
	writeJSONFixture(t, filepath.Join(dir, "other.json"), imported.Receipt)
	decision, err := Decide(DefaultObserveDraftProfile(), decisionRequest("network", "https://trusted.example"), workstationTestDecisionOptions())
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFixture(t, filepath.Join(dir, "trusted.json"), decision)
	report, err := BuildScopeAudit(TrustAnchor{PublicKey: workstationTestPublicKey(), Source: "test-anchor.pub"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.UntrustedSignerReceipts != 1 || report.Summary.UntrustedSignerActions != claimed.Summary.TotalActions || report.Summary.TotalActions != 1 {
		t.Fatalf("summary = %+v, want one receipt of another signer with its %d actions apart from the one trusted action", report.Summary, claimed.Summary.TotalActions)
	}
}
