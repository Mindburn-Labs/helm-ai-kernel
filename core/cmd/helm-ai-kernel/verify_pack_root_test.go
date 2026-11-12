package main

// quantum_posture: these tests pin where pack files are read from and make no
// post-quantum or classical signature assurance.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// linkFromOutside writes value as JSON outside the pack and links rel inside
// the pack to it.
func linkFromOutside(t *testing.T, pack, outside, rel string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, strings.ReplaceAll(rel, "/", "_"))
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(pack, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func packBesideOutside(t *testing.T) (pack, outside string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	root := t.TempDir()
	pack, outside = filepath.Join(root, "pack"), filepath.Join(root, "outside")
	for _, dir := range []string{pack, outside} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return pack, outside
}

// F6: the checks `verify` adds for --require-eidas and --require-tee read
// anchors and receipts by path and followed a symbolic link out of the pack,
// so metadata the pack does not hold passed them. They read through an
// os.Root on the pack directory now.
func TestVerifyFlagChecksReadOnlyFromInsideThePack(t *testing.T) {
	t.Run("eidas anchor", func(t *testing.T) {
		pack, outside := packBesideOutside(t)
		linkFromOutside(t, pack, outside, "02_PROOFGRAPH/anchors/a.json", map[string]any{
			"backend":         "eidas-qtsp",
			"integrated_time": time.Now().UTC().Format(time.RFC3339),
		})
		results := checkEIDASAnchorMetadata(pack, 24*time.Hour)
		refused := false
		for _, result := range results {
			if result.Pass {
				t.Fatalf("%s passed on an anchor outside the pack: %s", result.Name, result.Detail)
			}
			if strings.Contains(result.Reason, "outside the pack") {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("no result says the anchor is outside the pack: %+v", results)
		}
	})
	t.Run("eidas anchor directory", func(t *testing.T) {
		// A refused anchors directory or index is named, not taken for an
		// empty one: here the index anchor alone would have passed.
		pack, outside := packBesideOutside(t)
		if err := os.MkdirAll(filepath.Join(pack, "02_PROOFGRAPH"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(pack, "02_PROOFGRAPH", "anchors")); err != nil {
			t.Fatal(err)
		}
		writeEIDASMetadataFixture(t, filepath.Join(pack, "00_INDEX.json"), map[string]any{"anchor": map[string]any{
			"backend":         "eidas-qtsp",
			"integrated_time": time.Now().UTC().Format(time.RFC3339),
		}})
		results := checkEIDASAnchorMetadata(pack, 24*time.Hour)
		refused := false
		for _, result := range results {
			if !result.Pass && strings.Contains(result.Reason, "02_PROOFGRAPH/anchors") && strings.Contains(result.Reason, "outside the pack") {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("no failed result refuses 02_PROOFGRAPH/anchors as outside the pack: %+v", results)
		}
	})
	t.Run("eidas index", func(t *testing.T) {
		pack, outside := packBesideOutside(t)
		linkFromOutside(t, pack, outside, "00_INDEX.json", map[string]any{"anchor": map[string]any{
			"backend":         "eidas-qtsp",
			"integrated_time": time.Now().UTC().Format(time.RFC3339),
		}})
		results := checkEIDASAnchorMetadata(pack, 24*time.Hour)
		refused := false
		for _, result := range results {
			if result.Pass {
				t.Fatalf("%s passed on an index outside the pack: %s", result.Name, result.Detail)
			}
			if strings.Contains(result.Reason, "00_INDEX.json") && strings.Contains(result.Reason, "outside the pack") {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("no result refuses 00_INDEX.json as outside the pack: %+v", results)
		}
	})
	t.Run("tee receipts directory", func(t *testing.T) {
		pack, outside := packBesideOutside(t)
		if err := os.Symlink(outside, filepath.Join(pack, "receipts")); err != nil {
			t.Fatal(err)
		}
		results := checkTEEAttestations(pack, "any")
		refused := false
		for _, result := range results {
			if result.Pass {
				t.Fatalf("%s passed on a receipts directory outside the pack: %s", result.Name, result.Detail)
			}
			if result.Name == "tee:read_receipt" && strings.Contains(result.Reason, "outside the pack") {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("no tee:read_receipt result refuses receipts as outside the pack: %+v", results)
		}
	})
	t.Run("tee receipt", func(t *testing.T) {
		pack, outside := packBesideOutside(t)
		linkFromOutside(t, pack, outside, "receipts/r.json", map[string]any{
			"receipt_id":      "r-1",
			"tee_attestation": map[string]any{"platform": "sevsnp"},
		})
		results := checkTEEAttestations(pack, "any")
		refused := false
		for _, result := range results {
			if result.Pass {
				t.Fatalf("%s passed on a receipt outside the pack: %s", result.Name, result.Detail)
			}
			if strings.Contains(result.Reason, "outside the pack") {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("no result says the receipt is outside the pack: %+v", results)
		}
	})
}

// `evidence inspect` prints the launch id, file hashes and evidence graph
// root the pack's launchpad files state. Linked from outside the pack, they
// were printed as the pack's own.
func TestEvidenceInspectMetadataIsReadOnlyFromInsideThePack(t *testing.T) {
	pack, outside := packBesideOutside(t)
	linkFromOutside(t, pack, outside, "04_EXPORTS/launchpad_manifest.json", map[string]any{"launch_id": "outside-launch"})
	linkFromOutside(t, pack, outside, "04_EXPORTS/launchpad_evidence_graph.json", map[string]any{"root_hash": "outside-root"})
	linkFromOutside(t, pack, outside, "00_INDEX.json", map[string]any{"entries": []any{map[string]any{"path": "a", "sha256": "b"}}})

	if manifest, err := readLaunchpadManifest(pack); err == nil || !strings.Contains(err.Error(), "outside the pack") {
		t.Fatalf("readLaunchpadManifest = %+v, %v; want an error saying the file is outside the pack", manifest, err)
	}
	if graph, err := readEvidenceGraph(pack); err == nil || !strings.Contains(err.Error(), "outside the pack") {
		t.Fatalf("readEvidenceGraph = %+v, %v; want an error saying the file is outside the pack", graph, err)
	}
	if index, err := readEvidenceIndex(pack); err == nil || !strings.Contains(err.Error(), "outside the pack") {
		t.Fatalf("readEvidenceIndex = %v, %v; want an error saying the file is outside the pack", index, err)
	}
}
