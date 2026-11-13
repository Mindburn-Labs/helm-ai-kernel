package spendproxy

// quantum_posture: these offline compatibility tests verify historical
// classical Ed25519 signatures and SHA-256 hashes; the fixed seed belongs to
// generated test fixtures only. No provider or spending authority is used.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureSeed = "0101010101010101010101010101010101010101010101010101010101010101"

func legacyCapture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{ReceiptLogName, TrustedKeyFileName, "config.json", CaptureTaskSplitFile, CaptureResultsFile, CaptureParityFile} {
		raw, err := os.ReadFile(filepath.Join("testdata", "legacy-capture", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func fixtureIssuer(t *testing.T) *Issuer {
	t.Helper()
	issuer, _, err := NewIssuer(fixtureSeed)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func rewriteRecords(t *testing.T, dir string, records []*ReceiptRecord) {
	t.Helper()
	var lines []string
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(raw))
	}
	if err := os.WriteFile(filepath.Join(dir, ReceiptLogName), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacySpendEvidenceStillExportsOffline(t *testing.T) {
	dir := legacyCapture(t)
	results, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: dir, OutDir: t.TempDir(), PublicKeys: []ed25519.PublicKey{fixtureIssuer(t).PublicKey()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 9 {
		t.Fatalf("exported %d historical intents, want 9", len(results))
	}
	for _, result := range results {
		if !result.OfflineVerified || !result.SignatureVerified {
			t.Fatalf("unverified historical receipt: %+v", result)
		}
	}
}

func TestLegacySpendExportRefusesForgedRecords(t *testing.T) {
	for _, edit := range []string{"payload", "metadata", "kind", "release", "intent", "settlement intent"} {
		t.Run(edit, func(t *testing.T) {
			dir := legacyCapture(t)
			records, err := LoadRecords(filepath.Join(dir, ReceiptLogName))
			if err != nil {
				t.Fatal(err)
			}
			r := records[0]
			if r.RouteQuote == nil {
				t.Fatal("fixture must begin with a signed quote")
			}
			switch edit {
			case "payload":
				r.RouteQuote.MaxAmountCents++
			case "metadata":
				r.RouteQuote.Metadata["test_note"] = "not signed"
			case "kind":
				r.Kind = RecordUsage
			case "release":
				copy := *r
				copy.Kind = RecordDispatchReleased
				records = append(records, &copy)
			case "intent":
				r.SpendIntentID = "another-intent"
			case "settlement intent":
				for _, record := range records {
					if record.Settlement != nil {
						r = record
						break
					}
				}
				r.SpendIntentID = "another-intent"
			}
			rewriteRecords(t, dir, records)
			results, err := ExportEvidencePacks(ExportOptions{ReceiptsDir: dir, OutDir: t.TempDir(), PublicKeys: []ed25519.PublicKey{fixtureIssuer(t).PublicKey()}})
			if err == nil {
				for _, result := range results {
					if result.SpendIntentID == r.SpendIntentID && result.OfflineVerified && result.SignatureVerified {
						t.Fatalf("forged record exported as verified: %+v", result)
					}
				}
			}
		})
	}
}

func savingsOptions(t *testing.T, dir string) SavingsExportOptions {
	t.Helper()
	return SavingsExportOptions{ReceiptsDir: dir, CaptureDir: dir, ConfigPath: filepath.Join(dir, "config.json"), OutDir: t.TempDir(), SigningSecret: fixtureSeed}
}

func TestLegacySavingsStillExportsAndVerifiesOffline(t *testing.T) {
	dir := legacyCapture(t)
	result, err := ExportSavingsEvidencePack(savingsOptions(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if !result.OfflineVerified || result.PreWindowUnattributedCalls != 1 {
		t.Fatalf("historical capture was not verified with its disclosed warmup: %+v", result)
	}
	issuer := fixtureIssuer(t)
	pinned := map[string]string{issuer.KeyID(): "ed25519:" + hex.EncodeToString(issuer.PublicKey())}
	verified, err := VerifySavingsPackDirWithIssuer(result.OutputDir, pinned)
	if err != nil || !verified.OK {
		t.Fatalf("offline verification: %+v, %v", verified, err)
	}
	path := filepath.Join(result.OutputDir, "views", "savings_view.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tampered, err := VerifySavingsPackDirWithIssuer(result.OutputDir, pinned); err == nil && tampered.OK {
		t.Fatal("tampered savings view verified")
	}
}

func TestLegacySavingsRefusesIncompleteOrUnboundCapture(t *testing.T) {
	for _, edit := range []string{"missing artifact", "different config", "different key", "missing signature", "unattributed spend"} {
		t.Run(edit, func(t *testing.T) {
			dir := legacyCapture(t)
			opts := savingsOptions(t, dir)
			switch edit {
			case "missing artifact":
				if err := os.Remove(filepath.Join(dir, CaptureParityFile)); err != nil {
					t.Fatal(err)
				}
			case "different config":
				if err := os.WriteFile(opts.ConfigPath, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "different key":
				opts.SigningSecret = strings.Repeat("02", 32)
			case "missing signature":
				records, err := LoadRecords(filepath.Join(dir, ReceiptLogName))
				if err != nil {
					t.Fatal(err)
				}
				for _, record := range records {
					if record.BudgetVerdict != nil {
						record.BudgetVerdict.Signature = ""
					}
				}
				rewriteRecords(t, dir, records)
			case "unattributed spend":
				path := filepath.Join(dir, CaptureResultsFile)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				// Remove the recorded holdout intent from the capture without
				// changing its signed receipt; unattributed spend must not vanish.
				var document map[string]any
				if err := json.Unmarshal(raw, &document); err != nil {
					t.Fatal(err)
				}
				results := document["results"].([]any)
				document["results"] = results[:len(results)-1]
				raw, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ExportSavingsEvidencePack(opts); err == nil {
				t.Fatal("incomplete or unbound capture was accepted")
			}
		})
	}
}
