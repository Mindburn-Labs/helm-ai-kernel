package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// runExportCmd implements `helm export` per §2.1.
//
// Exports selected EvidencePack sections for audit or incident response.
//
// Exit codes:
//
//	0 = export completed
//	2 = runtime error
func runExportCmd(args []string, stdout, stderr io.Writer) int {
	// Support `helm export pack` subcommand (Gap #21 DoD)
	if len(args) > 0 && args[0] == "pack" {
		return handlePackCreate(args[1:])
	}

	cmd := flag.NewFlagSet("export", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		evidenceDir string
		outDir      string
		audit       bool
		incident    string
		jsonOutput  bool
		tarOutput   bool
	)

	cmd.StringVar(&evidenceDir, "evidence", "", "Path to EvidencePack directory (REQUIRED)")
	cmd.StringVar(&outDir, "out", "", "Output directory or archive path (REQUIRED)")
	cmd.BoolVar(&audit, "audit", false, "Export full audit bundle")
	cmd.StringVar(&incident, "incident", "", "Export incident-related evidence for given incident ID")
	cmd.BoolVar(&jsonOutput, "json", false, "Output manifest as JSON")
	cmd.BoolVar(&tarOutput, "tar", false, "Export as deterministic .tar (sorted, epoch mtime, root uid)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if evidenceDir == "" || outDir == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --evidence and --out are required")
		return 2
	}

	if !audit && incident == "" {
		audit = true
	}

	// Determine which subdirs to export
	var exportDirs []string
	if audit {
		// Full audit export
		exportDirs = []string{
			"00_INDEX.json",
			"01_SCORE.json",
			"02_PROOFGRAPH",
			"03_TELEMETRY",
			"05_DIFFS",
			"06_LOGS",
			"07_ATTESTATIONS",
			"08_TAPES",
			"09_SCHEMAS",
			"12_REPORTS",
		}
	} else if incident != "" {
		// Incident-focused export
		exportDirs = []string{
			"00_INDEX.json",
			"01_SCORE.json",
			"02_PROOFGRAPH",
			"06_LOGS",
			"07_ATTESTATIONS",
		}
	}

	exportPath := outDir
	exportRoot := outDir
	cleanupRoot := ""
	if isArchivePath(outDir) {
		tarOutput = true
		tempDir, err := os.MkdirTemp("", "helm-export-*")
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: cannot create staging directory: %v\n", err)
			return 2
		}
		exportRoot = tempDir
		cleanupRoot = tempDir
		defer os.RemoveAll(cleanupRoot)
	}

	// Create output directory
	if err := os.MkdirAll(exportRoot, 0750); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot create output directory: %v\n", err)
		return 2
	}

	// Copy selected items
	var exported []string
	for _, item := range exportDirs {
		src := filepath.Join(evidenceDir, item)
		dst := filepath.Join(exportRoot, item)

		info, err := os.Stat(src)
		if err != nil {
			continue // skip non-existent items
		}

		if info.IsDir() {
			if err := copyDir(src, dst); err != nil {
				_, _ = fmt.Fprintf(stderr, "Warning: failed to copy %s: %v\n", item, err)
				continue
			}
		} else {
			if err := copyFile(src, dst); err != nil {
				_, _ = fmt.Fprintf(stderr, "Warning: failed to copy %s: %v\n", item, err)
				continue
			}
		}
		exported = append(exported, item)
	}

	if len(exported) == 0 {
		fallback, err := copyAllEvidence(evidenceDir, exportRoot)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error copying evidence contents: %v\n", err)
			return 2
		}
		exported = fallback
	}

	result := map[string]any{
		"evidence_dir": evidenceDir,
		"exported":     exported,
		"count":        len(exported),
	}
	if incident != "" {
		result["incident_id"] = incident
	}

	// Deterministic .tar export (Phase 9: identical hashes for identical content)
	if tarOutput {
		tarPath := exportPath
		if !isArchivePath(tarPath) {
			tarPath = exportPath + ".tar"
		}
		if err := deterministicTarArchive(exportRoot, tarPath); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error creating .tar: %v\n", err)
			return 2
		}
		result["output_path"] = tarPath
		result["tar_path"] = tarPath
	} else {
		result["output_path"] = exportRoot
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		_, _ = fmt.Fprintf(stdout, "Exported %d items to %s\n", len(exported), result["output_path"])
		for _, item := range exported {
			_, _ = fmt.Fprintf(stdout, "  ✅ %s\n", item)
		}
		if tarPath, ok := result["tar_path"].(string); ok {
			_, _ = fmt.Fprintf(stdout, "  📦 Deterministic archive: %s\n", tarPath)
		}
	}

	return 0
}

func copyAllEvidence(srcRoot, dstRoot string) ([]string, error) {
	var exported []string
	err := filepath.Walk(srcRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == srcRoot {
			return nil
		}

		relPath, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dstRoot, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, 0750)
		}

		if err := copyFile(path, dstPath); err != nil {
			return err
		}
		exported = append(exported, relPath)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(exported)
	return exported, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0750); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(src, path)
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, 0750)
		}
		return copyFile(path, dstPath)
	})
}

func isArchivePath(path string) bool {
	return strings.HasSuffix(path, ".tar") || strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz")
}

// deterministicTarArchive creates a byte-identical tar archive from a directory.
// Invariants:
//   - Paths sorted lexicographically
//   - Mtime fixed to Unix epoch (1970-01-01T00:00:00Z)
//   - Uid/Gid = 0/0, Uname/Gname = "root"/"root"
//   - Files: 0644, Dirs: 0755
//
// Two exports of identical content produce identical SHA-256.
func deterministicTarArchive(srcDir, dstPath string) error {
	// 1. Collect all paths, sorted
	var paths []string
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(srcDir, path)
		if relPath == "." {
			return nil
		}
		paths = append(paths, relPath)
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk failed: %w", err)
	}
	sort.Strings(paths)

	// 2. Create .tar archive
	f, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create .tar failed: %w", err)
	}
	defer f.Close()

	var writer io.Writer = f
	var gw *gzip.Writer
	if strings.HasSuffix(dstPath, ".tar.gz") || strings.HasSuffix(dstPath, ".tgz") {
		gw = gzip.NewWriter(f)
		gw.ModTime = time.Unix(0, 0) // Deterministic gzip header
		defer gw.Close()
		writer = gw
	}

	tw := tar.NewWriter(writer)
	defer tw.Close()

	epoch := time.Unix(0, 0)

	for _, relPath := range paths {
		fullPath := filepath.Join(srcDir, relPath)
		info, err := os.Stat(fullPath)
		if err != nil {
			return err
		}

		hdr := &tar.Header{
			Name:    relPath,
			ModTime: epoch,
			Uname:   "root",
			Gname:   "root",
			Uid:     0,
			Gid:     0,
		}

		if info.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0755
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = 0644
			hdr.Size = info.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			data, err := os.ReadFile(fullPath)
			if err != nil {
				return err
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}
	}

	return nil
}

func init() {
	Register(Subcommand{Name: "export", Aliases: []string{}, Usage: "Export EvidencePack (--evidence, --out)", RunFn: runExportCmd})
}
