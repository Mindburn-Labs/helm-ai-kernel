// quantum_posture: local Console integrity uses classical SHA-256/HMAC and
// Sigstore-verified release evidence; it makes no post-quantum assurance.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

func loadLocalConsoleBundle(root, target string) (localConsoleBundle, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("resolve local Console bundle: %w", err)
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return localConsoleBundle{}, fmt.Errorf("matching console bundle is missing for %s", target)
	}
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("inspect local Console bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return localConsoleBundle{}, fmt.Errorf("invalid local Console bundle root")
	}

	provenanceBytes, err := readLocalConsoleBundleFile(root, localConsoleProvenanceFile, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("read local Console provenance: %w", err)
	}
	var provenance localConsoleProvenance
	if err := decodeLocalConsoleJSON(provenanceBytes, &provenance); err != nil {
		return localConsoleBundle{}, fmt.Errorf("decode local Console provenance: %w", err)
	}
	if err := validateLocalConsoleProvenance(provenance, target); err != nil {
		return localConsoleBundle{}, err
	}

	inventoryBytes, err := readLocalConsoleBundleFile(root, localConsoleInventoryFile, localConsoleInventoryMaxBytes)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("read local Console inventory: %w", err)
	}
	if actual := sha256Hex(inventoryBytes); !hmac.Equal([]byte(actual), []byte(provenance.BundleSHA256)) {
		return localConsoleBundle{}, fmt.Errorf("local Console inventory hash does not match provenance")
	}
	entries, err := parseLocalConsoleInventory(inventoryBytes)
	if err != nil {
		return localConsoleBundle{}, err
	}
	nodePath, err := validateLocalConsoleBundledRuntime(root, entries)
	if err != nil {
		return localConsoleBundle{}, err
	}
	if err := validateLocalConsoleInventoryFiles(root, entries); err != nil {
		return localConsoleBundle{}, err
	}
	if err := validateLocalConsoleBundleTree(root, entries); err != nil {
		return localConsoleBundle{}, err
	}
	serverPath, err := localConsoleBundlePath(root, localConsoleServerFile)
	if err != nil {
		return localConsoleBundle{}, fmt.Errorf("local Console server is invalid: %w", err)
	}
	if _, ok := entries[localConsoleServerFile]; !ok {
		return localConsoleBundle{}, fmt.Errorf("local Console inventory is missing %s", localConsoleServerFile)
	}
	return localConsoleBundle{
		Root:       root,
		AppRoot:    filepath.Join(root, "app"),
		ServerPath: serverPath,
		NodePath:   nodePath,
		Target:     target,
	}, nil
}

func validateLocalConsoleProvenance(provenance localConsoleProvenance, target string) error {
	if provenance.Schema != localConsoleProvenanceSchema {
		return fmt.Errorf("local Console provenance schema is invalid")
	}
	parts := strings.Split(target, "-")
	if len(parts) != 2 || provenance.Target.OS != parts[0] || provenance.Target.Arch != parts[1] {
		return fmt.Errorf("local Console provenance target does not match %s", target)
	}
	if provenance.Build.APIMode != "kernel" || provenance.Build.Closure != localConsoleBuildClosure {
		return fmt.Errorf("local Console provenance does not describe the kernel sidecar closure")
	}
	if provenance.Build.SourceSnapshot != localConsoleBuildSourceSnapshot || provenance.Build.Environment != localConsoleBuildEnvironment {
		return fmt.Errorf("local Console provenance does not describe an isolated build")
	}
	if provenance.Inventory != localConsoleInventoryFile {
		return fmt.Errorf("local Console provenance inventory path is invalid")
	}
	if provenance.Signature != localConsoleUnsignedSignature {
		return fmt.Errorf("local Console provenance signature state is invalid")
	}
	if provenance.Runtime.BundledNode != (localConsoleBundledNode{Executable: localConsoleNodeFile, LicenseNotice: localConsoleNodeLicenseFile}) ||
		provenance.Runtime.Platform.OS != parts[0] || provenance.Runtime.Platform.Arch != parts[1] || provenance.Runtime.Platform.Target != target ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.Node) || !strings.HasPrefix(provenance.Runtime.Node, "v") ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.NPM) || !validLocalConsoleRuntimeValue(provenance.Runtime.Next) ||
		!validLocalConsoleRuntimeValue(provenance.Runtime.Libc.Version) ||
		(provenance.Runtime.Libc.Family != "glibc" && provenance.Runtime.Libc.Family != "libSystem") {
		return fmt.Errorf("local Console provenance runtime is incomplete")
	}
	if (parts[0] == "darwin" && provenance.Runtime.Libc.Family != "libSystem") ||
		(parts[0] == "linux" && provenance.Runtime.Libc.Family != "glibc") ||
		(parts[0] == "darwin" && provenance.Runtime.Libc.Version != "host-reported-unavailable") {
		return fmt.Errorf("local Console provenance runtime does not match %s", target)
	}
	if provenance.BundleHashScope != localConsoleBundleHashScope || !validLowerHex(provenance.BundleSHA256, sha256.Size) || !validLocalConsoleSource(provenance.Source) {
		return fmt.Errorf("local Console provenance is incomplete")
	}
	return nil
}

func validLocalConsoleRuntimeValue(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func parseLocalConsoleInventory(contents []byte) (map[string]localConsoleInventoryEntry, error) {
	if len(contents) == 0 || len(contents) > localConsoleInventoryMaxBytes || contents[len(contents)-1] != '\n' {
		return nil, fmt.Errorf("local Console inventory is invalid")
	}
	entries := make(map[string]localConsoleInventoryEntry)
	lastPath := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || !validLowerHex(parts[0], sha256.Size) {
			return nil, fmt.Errorf("local Console inventory record is invalid")
		}
		relativePath, err := canonicalLocalConsoleRelativePath(parts[1])
		if err != nil || !validLocalConsoleInventoryPath(relativePath) || relativePath <= lastPath {
			return nil, fmt.Errorf("local Console inventory path is invalid")
		}
		if _, duplicate := entries[relativePath]; duplicate {
			return nil, fmt.Errorf("local Console inventory path is duplicated")
		}
		entries[relativePath] = localConsoleInventoryEntry{Path: relativePath, SHA256: parts[0]}
		lastPath = relativePath
	}
	return entries, nil
}

func validLocalConsoleInventoryPath(relativePath string) bool {
	return strings.HasPrefix(relativePath, "app/") ||
		relativePath == localConsoleNodeFile ||
		relativePath == localConsoleNodeLicenseFile
}

func validateLocalConsoleBundledRuntime(root string, entries map[string]localConsoleInventoryEntry) (string, error) {
	nodePath, nodeInfo, err := localConsoleRequiredRuntimeFile(root, entries, localConsoleNodeFile)
	if err != nil {
		return "", err
	}
	if nodeInfo.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("local Console bundled Node is not executable")
	}
	if _, _, err := localConsoleRequiredRuntimeFile(root, entries, localConsoleNodeLicenseFile); err != nil {
		return "", err
	}
	return nodePath, nil
}

func localConsoleRequiredRuntimeFile(root string, entries map[string]localConsoleInventoryEntry, relativePath string) (string, fs.FileInfo, error) {
	if _, ok := entries[relativePath]; !ok {
		return "", nil, fmt.Errorf("local Console inventory is missing %s", relativePath)
	}
	filePath, err := localConsoleBundlePath(root, relativePath)
	if err != nil {
		return "", nil, fmt.Errorf("local Console required runtime file is invalid: %s", relativePath)
	}
	info, err := os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("local Console required runtime file is invalid: %s", relativePath)
	}
	return filePath, info, nil
}

func validateLocalConsoleInventoryFiles(root string, entries map[string]localConsoleInventoryEntry) error {
	var total int64
	for _, entry := range entries {
		filePath, err := localConsoleBundlePath(root, entry.Path)
		if err != nil {
			return fmt.Errorf("local Console inventory path is invalid: %w", err)
		}
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("local Console inventory file is invalid")
		}
		total += info.Size()
		if total < 0 || total > localConsoleBundleMaxBytes {
			return fmt.Errorf("local Console bundle exceeds the validation limit")
		}
		actual, err := sha256LocalConsoleFile(filePath)
		if err != nil || !hmac.Equal([]byte(actual), []byte(entry.SHA256)) {
			return fmt.Errorf("local Console inventory file hash does not match")
		}
	}
	return nil
}

func validateLocalConsoleBundleTree(root string, entries map[string]localConsoleInventoryEntry) error {
	return filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("local Console bundle contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("local Console bundle contains an unsupported entry")
		}
		relativePath, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		relativePath = filepath.ToSlash(relativePath)
		if relativePath == localConsoleProvenanceFile || relativePath == localConsoleInventoryFile {
			return nil
		}
		if _, ok := entries[relativePath]; !ok {
			return fmt.Errorf("local Console bundle contains an unverified file")
		}
		return nil
	})
}

func readLocalConsoleBundleFile(root, relativePath string, maxBytes int) ([]byte, error) {
	filePath, err := localConsoleBundlePath(root, relativePath)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("invalid local Console file")
	}
	return os.ReadFile(filePath)
}

func localConsoleBundlePath(root, relativePath string) (string, error) {
	relativePath, err := canonicalLocalConsoleRelativePath(relativePath)
	if err != nil {
		return "", err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", err
	}
	current := root
	for _, component := range strings.Split(relativePath, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("local Console bundle path contains a symlink")
		}
	}
	rel, err := filepath.Rel(root, current)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("local Console bundle path escapes root")
	}
	return current, nil
}

func canonicalLocalConsoleRelativePath(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") || path.IsAbs(value) || filepath.IsAbs(value) {
		return "", fmt.Errorf("path must be a relative slash path")
	}
	clean := path.Clean(value)
	if clean == "." || clean != value || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes root")
	}
	return clean, nil
}

func sha256LocalConsoleFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
