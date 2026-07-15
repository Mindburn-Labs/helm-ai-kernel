package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// normalizeSetupDataDir rejects a final data-dir symlink and symlinks below a
// caller-local trusted root before setup writes. It deliberately preserves the
// user's lexical path: macOS commonly exposes TMPDIR through /var, so silently
// canonicalizing that platform alias would change the path stored in config.
func normalizeSetupDataDir(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	root := trustedSetupDataDirRoot(absPath)
	rel, err := filepath.Rel(root, absPath)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("--data-dir must be below its trusted root: %s", absPath)
	}
	current := root
	if rel == "." {
		return absPath, rejectSetupDataDirSymlink(current)
	}
	for _, component := range splitSetupPath(rel) {
		current = filepath.Join(current, component)
		if err := rejectSetupDataDirSymlink(current); err != nil {
			return "", err
		}
	}
	return absPath, nil
}

// ensureSetupAuthorityDataDir creates (when necessary) and validates the root
// of the local authority state. A private root.key is not sufficient when the
// directory holding it is writable by another local principal: that principal
// can replace the key, database, binding, or evidence between ordinary path
// checks. We deliberately keep this separate from normalizeSetupDataDir so
// dry-run/status parsing remains non-mutating.
func ensureSetupAuthorityDataDir(path string) (string, error) {
	normalized, err := normalizeSetupDataDir(path)
	if err != nil {
		return "", err
	}
	if err := ensureSetupAuthorityDirectory(normalized); err != nil {
		return "", fmt.Errorf("secure local authority data dir: %w", err)
	}
	return normalized, nil
}

// requireSetupAuthorityDataDir validates an already-existing authority root
// without creating it. Runtime admission uses this form so a missing or
// unsafe state directory never becomes a fresh authority implicitly.
func requireSetupAuthorityDataDir(path string) (string, error) {
	normalized, err := normalizeSetupDataDir(path)
	if err != nil {
		return "", err
	}
	if err := requireSetupAuthorityDirectory(normalized); err != nil {
		return "", fmt.Errorf("secure local authority data dir: %w", err)
	}
	return normalized, nil
}

// validateSetupAuthorityDataDirIfPresent preserves setup's preflight
// no-side-effect contract. A fresh install may have no local authority state
// yet, but an existing root must already meet the same ownership and mode
// requirements as runtime authority. Callers that are about to write state
// must still use ensureSetupAuthorityDataDir after all user-owned config
// preflight checks have passed.
func validateSetupAuthorityDataDirIfPresent(path string) (string, error) {
	normalized, err := normalizeSetupDataDir(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(normalized); os.IsNotExist(err) {
		return normalized, nil
	} else if err != nil {
		return "", err
	}
	if err := requireSetupAuthorityDirectory(normalized); err != nil {
		return "", fmt.Errorf("secure local authority data dir: %w", err)
	}
	return normalized, nil
}

// inspectSetupAuthoritySubdirectory validates each existing setup-owned
// component without creating one. A missing root or descendant is reported as
// absent so preflight/status paths remain non-mutating; an unsafe existing
// ancestor is never treated as absent state.
func inspectSetupAuthoritySubdirectory(dataDir, relativePath string) (bool, error) {
	normalized, err := normalizeSetupDataDir(dataDir)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(normalized); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := requireSetupAuthorityDirectory(normalized); err != nil {
		return false, fmt.Errorf("secure local authority data dir: %w", err)
	}
	clean := filepath.Clean(relativePath)
	if clean == "." {
		return true, nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false, fmt.Errorf("authority subdirectory must be relative to data dir: %s", relativePath)
	}
	current := normalized
	for _, component := range splitSetupPath(clean) {
		current = filepath.Join(current, component)
		if _, err := os.Lstat(current); os.IsNotExist(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		if err := requireSetupAuthorityDirectory(current); err != nil {
			return false, err
		}
	}
	return true, nil
}

// ensureSetupAuthoritySubdirectory creates a setup-owned directory beneath a
// validated authority root. Every component is re-checked: an old
// world-writable native-client/ or lifecycle-evidence/ directory would
// otherwise let another local principal replace a binding or proof even if
// dataDir itself is private.
func ensureSetupAuthoritySubdirectory(dataDir, relativePath string) error {
	normalized, err := ensureSetupAuthorityDataDir(dataDir)
	if err != nil {
		return err
	}
	clean := filepath.Clean(relativePath)
	if clean == "." {
		return nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("authority subdirectory must be relative to data dir: %s", relativePath)
	}
	current := normalized
	for _, component := range splitSetupPath(clean) {
		current = filepath.Join(current, component)
		if err := ensureSetupAuthorityDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

// requireSetupAuthoritySubdirectory validates a previously-created
// setup-owned directory without creating it. Evidence and bindings are proof
// inputs during runtime admission, so a missing directory is handled by its
// caller as absent state while an unsafe existing directory is never read as
// authority.
func requireSetupAuthoritySubdirectory(dataDir, relativePath string) (string, error) {
	normalized, err := requireSetupAuthorityDataDir(dataDir)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(relativePath)
	if clean == "." {
		return normalized, nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("authority subdirectory must be relative to data dir: %s", relativePath)
	}
	current := normalized
	for _, component := range splitSetupPath(clean) {
		current = filepath.Join(current, component)
		if err := requireSetupAuthorityDirectory(current); err != nil {
			return "", err
		}
	}
	return current, nil
}

func ensureSetupAuthorityDirectory(path string) error {
	if err := ensureSetupDirectory(path, 0o700); err != nil {
		return err
	}
	return requireSetupAuthorityDirectory(path)
}

func requireSetupAuthorityDirectory(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("authority state is not a real directory: %s", absPath)
	}
	if info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("authority state directory must not be group/world-writable or special: %s", absPath)
	}
	if err := requireSetupAuthorityDirectoryOwner(absPath, info); err != nil {
		return err
	}
	return nil
}

func trustedSetupDataDirRoot(path string) string {
	candidates := []string{os.TempDir(), homeDirOrDot()}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	// These are platform roots rather than user-controlled intermediate links.
	// They avoid treating macOS's /var and /tmp aliases as a setup escape.
	candidates = append(candidates, string(filepath.Separator), "/tmp", "/var", "/private/var")
	best := string(filepath.Separator)
	for _, candidate := range candidates {
		absCandidate, err := filepath.Abs(candidate)
		if err != nil || !safeSetupDataDirAnchor(absCandidate) || !pathWithinSetupRoot(absCandidate, path) {
			continue
		}
		if len(absCandidate) > len(best) {
			best = absCandidate
		}
	}
	return best
}

func safeSetupDataDirAnchor(path string) bool {
	// The filesystem root is the final fallback. Every other caller or
	// environment-derived candidate must itself be a real directory before we
	// use it as an unchecked traversal boundary.
	if path == string(filepath.Separator) {
		return true
	}
	if isAcceptedPlatformSetupAlias(path) {
		return true
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && resolved == canonicalPlatformSetupPath(path)
}

func isAcceptedPlatformSetupAlias(path string) bool {
	canonical := canonicalPlatformSetupPath(path)
	if canonical == path {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && resolved == canonical
}

func canonicalPlatformSetupPath(path string) string {
	// macOS exposes /var and /tmp as stable public aliases of /private/var and
	// /private/tmp. These are the only aliases accepted for an anchor; every
	// other resolved difference denotes a user-controlled symlink traversal.
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, alias := range []struct{ from, to string }{
		{from: "/var", to: "/private/var"},
		{from: "/tmp", to: "/private/tmp"},
	} {
		if path == alias.from {
			return alias.to
		}
		if strings.HasPrefix(path, alias.from+string(filepath.Separator)) {
			return alias.to + strings.TrimPrefix(path, alias.from)
		}
	}
	return path
}

func pathWithinSetupRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && (len(rel) < 3 || rel[:3] != ".."+string(filepath.Separator))
}

func splitSetupPath(rel string) []string {
	if rel == "." || rel == "" {
		return nil
	}
	parts := make([]string, 0)
	for current := rel; current != "." && current != ""; {
		parent := filepath.Dir(current)
		parts = append(parts, filepath.Base(current))
		if parent == current {
			break
		}
		current = parent
	}
	for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
		parts[left], parts[right] = parts[right], parts[left]
	}
	return parts
}

func rejectSetupDataDirSymlink(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if isAcceptedPlatformSetupAlias(path) {
			return nil
		}
		return fmt.Errorf("--data-dir must not traverse a symlink: %s", path)
	}
	return nil
}
