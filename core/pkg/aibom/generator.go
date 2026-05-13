package aibom

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// GenerateConfig configures BOM generation.
type GenerateConfig struct {
	Component string            // component name
	GoModPath string            // path to go.mod (optional)
	Models    []ModelProvenance // explicit model entries
	Datasets  []DatasetLineage  // explicit dataset entries
}

// Generate creates a new AI-BOM from the given configuration.
// It parses go.mod for dependencies when GoModPath is set and computes a
// JCS-canonicalized SHA-256 content hash over the resulting BOM.
func Generate(config GenerateConfig) (*AIBOM, error) {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(config.Component+time.Now().String())))
	if len(id) > 16 {
		id = id[:16]
	}

	bom := &AIBOM{
		BomID:         "bom-" + id,
		FormatVersion: "1.0.0",
		Component:     config.Component,
		CreatedAt:     time.Now(),
		Models:        config.Models,
		Datasets:      config.Datasets,
	}

	// Parse go.mod for dependencies.
	if config.GoModPath != "" {
		deps, err := FromGoMod(config.GoModPath)
		if err != nil {
			return nil, fmt.Errorf("parse go.mod: %w", err)
		}
		bom.Dependencies = deps
	}

	// Ensure non-nil slices for deterministic JSON output.
	if bom.Models == nil {
		bom.Models = []ModelProvenance{}
	}
	if bom.Dependencies == nil {
		bom.Dependencies = []DependencyEntry{}
	}

	// Compute content hash via JCS canonicalization.
	if err := computeContentHash(bom); err != nil {
		return nil, fmt.Errorf("compute content hash: %w", err)
	}

	return bom, nil
}

// FromGoMod parses a go.mod file and extracts dependency entries.
// Both single-line require directives and block require are supported.
// Indirect dependencies are tagged with SPDXID "indirect".
func FromGoMod(modPath string) ([]DependencyEntry, error) {
	f, err := os.Open(modPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []DependencyEntry
	inRequire := false
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		// Single-line require (e.g. `require foo v1.0.0`).
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				deps = append(deps, DependencyEntry{
					Name:    parts[0],
					Version: parts[1],
					Type:    "go-module",
				})
			}
			continue
		}
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 && !strings.HasPrefix(parts[0], "//") {
				dep := DependencyEntry{
					Name:    parts[0],
					Version: parts[1],
					Type:    "go-module",
				}
				// Check for // indirect comment.
				if strings.Contains(line, "// indirect") {
					dep.SPDXID = "indirect"
				}
				deps = append(deps, dep)
			}
		}
	}

	return deps, scanner.Err()
}

// computeContentHash sets the ContentHash field to a JCS-canonicalized
// SHA-256 digest of the BOM (with ContentHash and Signature temporarily
// cleared to avoid circular hashing).
func computeContentHash(bom *AIBOM) error {
	// Temporarily clear hash and signature for deterministic hashing.
	savedHash := bom.ContentHash
	savedSig := bom.Signature
	bom.ContentHash = ""
	bom.Signature = ""
	defer func() {
		if bom.ContentHash == "" {
			bom.ContentHash = savedHash
		}
		bom.Signature = savedSig
	}()

	data, err := canonicalize.JCS(bom)
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	bom.ContentHash = "sha256:" + hex.EncodeToString(h[:])
	return nil
}
