package conform

import (
	"fmt"
	"os"
	"path/filepath"
)

// EvidencePackSubdirs lists the §3.1 mandatory top-level directories.
var EvidencePackSubdirs = []string{
	"02_PROOFGRAPH",
	"03_TELEMETRY",
	"04_EXPORTS",
	"05_DIFFS",
	"06_LOGS",
	"07_ATTESTATIONS",
	"08_TAPES",
	"09_SCHEMAS",
	"12_REPORTS",
}

// ExtensionDirPrefix is the reserved prefix for vendor extensions.
// Extensions are allowed ONLY under 99_EXT/<vendor_or_pack>/... and
// ONLY if declared in 00_INDEX.json extensions[] with hashes and schemas.
const ExtensionDirPrefix = "99_EXT"

// CreateEvidencePackDirs creates the full §3.1 directory structure.
func CreateEvidencePackDirs(root string) error {
	if err := os.MkdirAll(root, 0750); err != nil {
		return fmt.Errorf("create evidence root: %w", err)
	}
	for _, sub := range EvidencePackSubdirs {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create %s: %w", sub, err)
		}
	}
	return nil
}

// ValidateEvidencePackStructure checks that the directory matches §3.1.
// Supports declared extensions under 99_EXT/ if listed in declaredExtensions.
func ValidateEvidencePackStructure(root string, declaredExtensions ...string) []string {
	var issues []string

	// Check 00_INDEX.json exists
	if _, err := os.Stat(filepath.Join(root, "00_INDEX.json")); err != nil {
		issues = append(issues, "missing 00_INDEX.json")
	}

	// Check 01_SCORE.json exists
	if _, err := os.Stat(filepath.Join(root, "01_SCORE.json")); err != nil {
		issues = append(issues, "missing 01_SCORE.json")
	}

	// Check all mandatory subdirs
	for _, sub := range EvidencePackSubdirs {
		if _, err := os.Stat(filepath.Join(root, sub)); err != nil {
			issues = append(issues, fmt.Sprintf("missing %s/", sub))
		}
	}

	// Build allowed set
	allowed := map[string]bool{
		"00_INDEX.json": true,
		"01_SCORE.json": true,
	}
	for _, sub := range EvidencePackSubdirs {
		allowed[sub] = true
	}
	// Allow declared extension directories under 99_EXT/
	if len(declaredExtensions) > 0 {
		allowed[ExtensionDirPrefix] = true
	}

	// Check no extra top-level entries
	entries, err := os.ReadDir(root)
	if err != nil {
		issues = append(issues, fmt.Sprintf("cannot read directory: %v", err))
		return issues
	}

	for _, entry := range entries {
		name := entry.Name()
		if !allowed[name] {
			issues = append(issues, fmt.Sprintf("unexpected top-level entry: %s", name))
		}
	}

	// If 99_EXT/ exists, validate only declared extensions are present
	extDir := filepath.Join(root, ExtensionDirPrefix)
	if _, err := os.Stat(extDir); err == nil {
		declaredSet := make(map[string]bool)
		for _, ext := range declaredExtensions {
			declaredSet[ext] = true
		}

		extEntries, _ := os.ReadDir(extDir)
		for _, e := range extEntries {
			if !declaredSet[e.Name()] {
				issues = append(issues, fmt.Sprintf("undeclared extension: %s/%s", ExtensionDirPrefix, e.Name()))
			}
		}
	}

	return issues
}
