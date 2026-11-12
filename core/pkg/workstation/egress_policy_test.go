package workstation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func egressProfile(destinations ...contracts.WorkstationEgressDestination) contracts.WorkstationPolicyProfile {
	profile := DefaultObserveDraftProfile()
	profile.Operate.Permissions = []string{contracts.WorkstationPermissionNetworkEgress}
	profile.Egress.Allowlist = destinations
	return profile
}

func evaluateEgress(profile contracts.WorkstationPolicyProfile, target string) (string, string) {
	verdict, reasonCode, _ := EvaluateEvent(profile, ToolEvent{
		Type:       "network_egress",
		EffectType: contracts.EffectTypeWorkstationNetworkEgress,
		EffectMode: contracts.WorkstationEffectModeOperate,
		Target:     target,
	})
	return verdict, reasonCode
}

// The allowlist is compared against the host a client would connect to, so
// spellings of one host agree and text that merely contains an allowed name
// does not.
func TestEgressAllowlistComparesTheRealHost(t *testing.T) {
	profile := egressProfile(
		contracts.WorkstationEgressDestination{Host: "allowed.example", Protocol: "https"},
		contracts.WorkstationEgressDestination{Host: "any-protocol.example"},
		contracts.WorkstationEgressDestination{Host: "2001:db8::1", Protocol: "https"},
		contracts.WorkstationEgressDestination{Host: "[2001:DB8::2]", Protocol: "https"},
		contracts.WorkstationEgressDestination{Host: "bücher.example", Protocol: "https"},
		contracts.WorkstationEgressDestination{Host: "xn--mnchen-3ya.example", Protocol: "https"},
		contracts.WorkstationEgressDestination{Host: "Dotted.Example.", Protocol: "https"},
		contracts.WorkstationEgressDestination{Host: "192.0.2.10", Protocol: "https"},
	)
	cases := []struct {
		target string
		reason string // "" = ALLOW
	}{
		{"https://allowed.example/path?q=1", ""},
		{"https://ALLOWED.example", ""},
		{"https://allowed.example.", ""},
		{"https://allowed.example:443", ""},
		{"https://allowed.example:8443/x", ""},
		{"https://user:pw@allowed.example/", ""},
		{"allowed.example", ""},
		{"allowed.example:443", ""},
		{"ssh://any-protocol.example", ""},
		{"https://[2001:db8::1]/", ""},
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443/", ""},
		{"https://[2001:db8::2]/", ""},
		{"https://xn--bcher-kva.example/", ""},
		{"https://bücher.example/", ""},
		{"https://BÜCHER.example/", ""},
		{"https://münchen.example/", ""},
		{"https://dotted.example/", ""},
		{"https://192.0.2.10/", ""},
		{"https://[::ffff:192.0.2.10]/", ""},

		{"https://allowed.example@other.example/", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://allowed.example:443@other.example/", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://other.example/allowed.example", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://other.example/?h=allowed.example", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://allowed.example.other.example/", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://notallowed.example/", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"http://allowed.example/", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"ssh://allowed.example", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://[2001:db8::3]/", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://192.0.2.11/", "EGRESS_DESTINATION_NOT_ALLOWED"},

		{"", "EGRESS_DESTINATION_UNDETERMINED"},
		{"<undetermined>", "EGRESS_DESTINATION_UNDETERMINED"},
		{"curl", "EGRESS_DESTINATION_NOT_ALLOWED"},
		{"https://", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https:///allowed.example/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://allowed.example other.example/", "EGRESS_DESTINATION_UNDETERMINED"},
		{`https://allowed.example\@other.example/`, "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://other.example#@allowed.example/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://allowed%2eexample/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://{allowed,other}.example/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://$HOST/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://allowed.example:99999/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://allowed.example:abc/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://[fe80::1%25en0]/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"http://2130706433/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"http://0x7f.0.0.1/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"https://faß.example/", "EGRESS_DESTINATION_UNDETERMINED"},
		{"file:///etc/passwd", "EGRESS_DESTINATION_UNDETERMINED"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			verdict, reasonCode := evaluateEgress(profile, tc.target)
			if tc.reason == "" {
				if verdict != contracts.WorkstationVerdictAllow {
					t.Fatalf("egress to %q = %s/%s, want ALLOW", tc.target, verdict, reasonCode)
				}
				return
			}
			if verdict != contracts.WorkstationVerdictDeny || reasonCode != tc.reason {
				t.Fatalf("egress to %q = %s/%s, want DENY/%s", tc.target, verdict, reasonCode, tc.reason)
			}
		})
	}
}

// An allowlist entry that names the sentinel cannot make an unresolved
// destination allowable: the refusal happens before the comparison.
func TestUndeterminedEgressCannotBeAllowlisted(t *testing.T) {
	profile := egressProfile(
		contracts.WorkstationEgressDestination{Host: "<undetermined>"},
		contracts.WorkstationEgressDestination{Host: ""},
		contracts.WorkstationEgressDestination{Host: "*"},
	)
	for _, target := range []string{"<undetermined>", "", "*", "https://*/"} {
		verdict, reasonCode := evaluateEgress(profile, target)
		if verdict != contracts.WorkstationVerdictDeny || reasonCode != "EGRESS_DESTINATION_UNDETERMINED" {
			t.Errorf("egress to %q = %s/%s, want DENY/EGRESS_DESTINATION_UNDETERMINED", target, verdict, reasonCode)
		}
	}
}

// The default profile keeps its own reason: with nothing on the allowlist the
// destination is never inspected.
func TestEmptyAllowlistStillDeniesBeforeParsing(t *testing.T) {
	for _, target := range []string{"https://allowed.example/", "<undetermined>", ""} {
		verdict, reasonCode := evaluateEgress(DefaultObserveDraftProfile(), target)
		if verdict != contracts.WorkstationVerdictDeny || reasonCode != "EGRESS_ALLOWLIST_EMPTY" {
			t.Errorf("egress to %q under the default profile = %s/%s, want DENY/EGRESS_ALLOWLIST_EMPTY", target, verdict, reasonCode)
		}
	}
}

func TestExportEvidencePackRejectsReceiptIDsThatAreNotIdentifiers(t *testing.T) {
	root := repoRoot(t)
	for _, receiptID := range []string{
		"../../../escaped",
		"..",
		"a/b",
		`a\b`,
		"/abs",
		"arr_ok/../../x",
		"",
		"with space",
		"dot.dot",
		strings.Repeat("a", 200),
		"arr_ok\x00",
	} {
		t.Run(receiptID, func(t *testing.T) {
			imported, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", "denied-memory"), workstationTestImportOptions())
			if err != nil {
				t.Fatal(err)
			}
			imported.Receipt.ReceiptID = receiptID
			parent := t.TempDir()
			outDir := filepath.Join(parent, "nested", "deeper", "pack")
			if _, err := ExportEvidencePack(imported, outDir); err == nil {
				t.Fatalf("ExportEvidencePack accepted receipt_id %q", receiptID)
			}
			var outside []string
			_ = filepath.Walk(parent, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				if rel, relErr := filepath.Rel(outDir, path); relErr != nil || strings.HasPrefix(rel, "..") {
					outside = append(outside, path)
				}
				return nil
			})
			if len(outside) != 0 {
				t.Fatalf("receipt_id %q wrote outside the pack directory: %v", receiptID, outside)
			}
		})
	}
}

// A pack directory that already holds a link out of the tree must not be
// written through.
func TestExportEvidencePackRefusesToWriteThroughSymlinks(t *testing.T) {
	root := repoRoot(t)
	imported, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", "denied-memory"), workstationTestImportOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("linked directory", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "pack")
		elsewhere := t.TempDir()
		if err := os.MkdirAll(filepath.Join(outDir, "02_PROOFGRAPH"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(outDir, "02_PROOFGRAPH", "receipts")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := ExportEvidencePack(imported, outDir); err == nil {
			t.Fatal("ExportEvidencePack wrote through a linked directory")
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Fatalf("files written outside the pack: %v", entries)
		}
	})
	t.Run("linked file", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "pack")
		victim := filepath.Join(t.TempDir(), "victim.json")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(outDir, "00_INDEX.json")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := ExportEvidencePack(imported, outDir); err == nil {
			t.Fatal("ExportEvidencePack wrote through a linked file")
		}
		if data, _ := os.ReadFile(victim); string(data) != "keep" {
			t.Fatalf("linked file was overwritten: %q", data)
		}
	})
}

func TestExportEvidencePackStillWritesGeneratedReceiptIDs(t *testing.T) {
	root := repoRoot(t)
	imported, err := ImportArtifactDir(filepath.Join(root, "fixtures", "workstation", "denied-memory"), workstationTestImportOptions())
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "pack")
	export, err := ExportEvidencePack(imported, outDir)
	if err != nil {
		t.Fatalf("ExportEvidencePack() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "02_PROOFGRAPH", "receipts", imported.Receipt.ReceiptID+".json"))
	if err != nil {
		t.Fatalf("receipt file missing: %v", err)
	}
	var receipt contracts.AgentRunReceipt
	if err := json.Unmarshal(data, &receipt); err != nil || receipt.ReceiptID != export.ReceiptID {
		t.Fatalf("exported receipt = %q err=%v, want %q", receipt.ReceiptID, err, export.ReceiptID)
	}
}
