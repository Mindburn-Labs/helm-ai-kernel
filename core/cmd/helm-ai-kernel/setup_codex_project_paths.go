package main

import (
	"fmt"
	"path/filepath"
)

const setupCodexProjectStateLayout = "v1"

// setupCodexProjectPaths separates project-scoped native-client state from
// the shared local authority (root keys, receipt DB, and evidence). A single
// data-dir may intentionally serve multiple Codex projects; their install
// bindings, recovery journals, and generated discovery artifacts must never
// overwrite one another.
type setupCodexProjectPaths struct {
	WorkspacePathHash string
	StateRoot         string
	BindingPath       string
	RecoveryRoot      string
	ArtifactsDir      string
}

func newSetupCodexProjectPaths(opts setupOptions) (setupCodexProjectPaths, error) {
	if opts.Target != "codex" || opts.Scope != "project" {
		return setupCodexProjectPaths{}, fmt.Errorf("Codex project state paths require target codex with project scope")
	}
	workspacePathHash, err := setupRecoveryWorkspacePathHash()
	if err != nil {
		return setupCodexProjectPaths{}, fmt.Errorf("resolve Codex project workspace identity: %w", err)
	}
	if !isSetupSHA256(workspacePathHash) {
		return setupCodexProjectPaths{}, fmt.Errorf("invalid Codex project workspace identity")
	}
	stateRoot := filepath.Join(opts.DataDir, "native-client", "codex-projects", setupCodexProjectStateLayout, workspacePathHash)
	return setupCodexProjectPaths{
		WorkspacePathHash: workspacePathHash,
		StateRoot:         stateRoot,
		BindingPath:       filepath.Join(stateRoot, setupCodexProjectBindingFile),
		RecoveryRoot:      filepath.Join(stateRoot, setupRecoveryDirectory),
		ArtifactsDir:      filepath.Join(stateRoot, "autoconfigure"),
	}, nil
}

// currentCodexProjectPaths is deliberately a convenience only for helpers
// whose existing signature predates project namespaces. All external command
// paths validate through buildSetupSummary/newSetupCodexProjectPaths before a
// mutation; the sentinel makes an unexpected getwd failure non-colliding in
// direct test/helper calls rather than falling back to a shared root.
func currentCodexProjectPaths(dataDir string) setupCodexProjectPaths {
	paths, err := newSetupCodexProjectPaths(setupOptions{Target: "codex", Scope: "project", DataDir: dataDir})
	if err == nil {
		return paths
	}
	stateRoot := filepath.Join(dataDir, "native-client", "codex-projects", setupCodexProjectStateLayout, "workspace-unavailable")
	return setupCodexProjectPaths{
		StateRoot:    stateRoot,
		BindingPath:  filepath.Join(stateRoot, setupCodexProjectBindingFile),
		RecoveryRoot: filepath.Join(stateRoot, setupRecoveryDirectory),
		ArtifactsDir: filepath.Join(stateRoot, "autoconfigure"),
	}
}

func setupCodexProjectArtifactsDir(dataDir string) string {
	return currentCodexProjectPaths(dataDir).ArtifactsDir
}

// setupCodexProjectStateAuthorityRelativePath derives the entire
// project-scoped state tree below dataDir. Keeping the relative path explicit
// makes it possible to validate every existing native-client ancestor before
// a binding, recovery journal, or generated artifact is trusted.
func setupCodexProjectStateAuthorityRelativePath(dataDir string) (string, error) {
	normalized, err := normalizeSetupDataDir(dataDir)
	if err != nil {
		return "", err
	}
	paths, err := newSetupCodexProjectPaths(setupOptions{Target: "codex", Scope: "project", DataDir: normalized})
	if err != nil {
		return "", err
	}
	relativePath, err := filepath.Rel(normalized, paths.StateRoot)
	if err != nil || relativePath == "." || filepath.IsAbs(relativePath) || relativePath == ".." {
		return "", fmt.Errorf("resolve Codex project state authority path")
	}
	return relativePath, nil
}

func ensureCodexProjectStateAuthority(dataDir string) error {
	relativePath, err := setupCodexProjectStateAuthorityRelativePath(dataDir)
	if err != nil {
		return err
	}
	return ensureSetupAuthoritySubdirectory(dataDir, relativePath)
}

func inspectCodexProjectStateAuthority(dataDir string) (bool, error) {
	relativePath, err := setupCodexProjectStateAuthorityRelativePath(dataDir)
	if err != nil {
		return false, err
	}
	return inspectSetupAuthoritySubdirectory(dataDir, relativePath)
}

func requireCodexProjectStateAuthority(dataDir string) error {
	relativePath, err := setupCodexProjectStateAuthorityRelativePath(dataDir)
	if err != nil {
		return err
	}
	_, err = requireSetupAuthoritySubdirectory(dataDir, relativePath)
	return err
}

// legacyCodexProjectBindingPath and legacyCodexProjectArtifactsDir name the
// pre-v1 locations that existed before project namespacing. They are only
// used by the explicit migration/recovery path; normal runtime admission must
// never silently fall back to them because one shared data-dir could contain
// state from a different project.
func legacyCodexProjectBindingPath(dataDir string) string {
	return filepath.Join(dataDir, "native-client", setupCodexProjectBindingFile)
}

func legacyCodexProjectArtifactsDir(dataDir string) string {
	return filepath.Join(dataDir, "autoconfigure")
}

// legacySetupRecoveryRoot names the pre-v1 unscoped recovery location. It is
// never used to mutate current project state; detecting it is fail-closed so a
// pre-upgrade pending transaction cannot be made invisible by namespacing.
func legacySetupRecoveryRoot(dataDir string) string {
	return filepath.Join(dataDir, setupRecoveryDirectory)
}
