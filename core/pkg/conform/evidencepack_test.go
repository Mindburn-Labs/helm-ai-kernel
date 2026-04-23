package conform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateEvidencePackDirs(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pack")
	require.NoError(t, CreateEvidencePackDirs(root))

	for _, sub := range EvidencePackSubdirs {
		info, err := os.Stat(filepath.Join(root, sub))
		require.NoError(t, err, "directory %s must exist", sub)
		require.True(t, info.IsDir())
	}
}

func TestValidateEvidencePackStructure_Valid(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pack")
	require.NoError(t, CreateEvidencePackDirs(root))

	// Write required files
	require.NoError(t, os.WriteFile(filepath.Join(root, "00_INDEX.json"), []byte("{}"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "01_SCORE.json"), []byte("{}"), 0600))

	issues := ValidateEvidencePackStructure(root)
	require.Empty(t, issues, "valid pack should have no issues")
}

func TestValidateEvidencePackStructure_MissingIndex(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pack")
	require.NoError(t, CreateEvidencePackDirs(root))
	require.NoError(t, os.WriteFile(filepath.Join(root, "01_SCORE.json"), []byte("{}"), 0600))

	issues := ValidateEvidencePackStructure(root)
	require.Contains(t, issues, "missing 00_INDEX.json")
}

func TestValidateEvidencePackStructure_ExtraDir(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pack")
	require.NoError(t, CreateEvidencePackDirs(root))
	require.NoError(t, os.WriteFile(filepath.Join(root, "00_INDEX.json"), []byte("{}"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "01_SCORE.json"), []byte("{}"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "ROGUE_DIR"), 0750))

	issues := ValidateEvidencePackStructure(root)
	require.NotEmpty(t, issues)
	require.Contains(t, issues[0], "unexpected top-level entry")
}

func TestValidateEvidencePackStructure_MissingSubdir(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "pack")
	require.NoError(t, os.MkdirAll(root, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "00_INDEX.json"), []byte("{}"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "01_SCORE.json"), []byte("{}"), 0600))
	// Don't create mandatory subdirs

	issues := ValidateEvidencePackStructure(root)
	require.Len(t, issues, len(EvidencePackSubdirs), "should report all missing subdirs")
}
