// Command skill_pack packages a skill directory into a signed bundle.
//
// Usage: skill_pack <skill-dir> [-o output.tar.gz]
//
// Reads manifest.json from the skill directory, validates it, computes a
// SHA-256 bundle hash over all files, and creates a .tar.gz archive.
// Exits 0 on success, 1 on pack/validation failure, 2 on usage error.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry/skills"
)

// bundleInfo is the structured JSON output printed on success.
type bundleInfo struct {
	Output     string    `json:"output"`
	BundleHash string    `json:"bundle_hash"`
	Files      []string  `json:"files"`
	ManifestID string    `json:"manifest_id"`
	Version    string    `json:"version"`
	PackedAt   time.Time `json:"packed_at"`
}

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("skill_pack", flag.ContinueOnError)
	outputPath := flags.String("o", "", "output .tar.gz path (default: <skill-dir>.tar.gz)")
	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: skill_pack <skill-dir> [-o output.tar.gz]\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if flags.NArg() < 1 {
		flags.Usage()
		return 2
	}

	skillDir := flags.Arg(0)

	// Resolve output path.
	out := *outputPath
	if out == "" {
		out = strings.TrimSuffix(filepath.Base(skillDir), string(filepath.Separator)) + ".tar.gz"
	}

	// Read and validate the manifest.
	manifestPath := filepath.Join(skillDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read manifest.json from %q: %v\n", skillDir, err)
		return 1
	}

	var manifest skills.SkillManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		fmt.Fprintf(os.Stderr, "error: manifest.json is not valid JSON: %v\n", err)
		return 1
	}

	// Collect all files in the skill directory (sorted for determinism).
	var filePaths []string
	if err := filepath.Walk(skillDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			filePaths = append(filePaths, path)
		}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: walking skill directory: %v\n", err)
		return 1
	}
	sort.Strings(filePaths)

	// Compute bundle hash: SHA-256 over the concatenated contents of all files.
	hasher := sha256.New()
	for _, fp := range filePaths {
		content, err := os.ReadFile(fp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading %q: %v\n", fp, err)
			return 1
		}
		hasher.Write(content)
	}
	bundleHash := hex.EncodeToString(hasher.Sum(nil))

	// Create the .tar.gz bundle.
	outFile, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: creating output file %q: %v\n", out, err)
		return 1
	}
	defer outFile.Close()

	gw := gzip.NewWriter(outFile)
	tw := tar.NewWriter(gw)

	for _, fp := range filePaths {
		info, err := os.Stat(fp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: stat %q: %v\n", fp, err)
			return 1
		}

		// Use a path relative to the skill directory inside the archive.
		relPath, err := filepath.Rel(skillDir, fp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: computing relative path for %q: %v\n", fp, err)
			return 1
		}

		header := &tar.Header{
			Name:    relPath,
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime(),
		}
		if err := tw.WriteHeader(header); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing tar header for %q: %v\n", relPath, err)
			return 1
		}

		f, err := os.Open(fp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: opening %q: %v\n", fp, err)
			return 1
		}
		if _, err := io.Copy(tw, f); err != nil {
			f.Close()
			fmt.Fprintf(os.Stderr, "error: copying %q into archive: %v\n", relPath, err)
			return 1
		}
		f.Close()
	}

	if err := tw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error: closing tar writer: %v\n", err)
		return 1
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error: closing gzip writer: %v\n", err)
		return 1
	}

	// Build relative file list for output.
	relFiles := make([]string, 0, len(filePaths))
	for _, fp := range filePaths {
		rel, _ := filepath.Rel(skillDir, fp)
		relFiles = append(relFiles, rel)
	}

	info := bundleInfo{
		Output:     out,
		BundleHash: bundleHash,
		Files:      relFiles,
		ManifestID: manifest.ID,
		Version:    manifest.Version,
		PackedAt:   time.Now().UTC(),
	}
	out2, _ := json.MarshalIndent(info, "", "  ")
	fmt.Println(string(out2))
	return 0
}
