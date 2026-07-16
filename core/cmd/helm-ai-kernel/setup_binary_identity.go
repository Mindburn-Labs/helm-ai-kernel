package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// setupKernelBinaryIdentity pins a native-client configuration to a concrete
// executable rather than a basename-shaped path. It intentionally refuses a
// symlink at this boundary so a later target swap cannot silently change the
// program that Codex or the hook will launch.
type setupKernelBinaryIdentity struct {
	Path        string
	ContentHash string
}

func inspectSetupKernelBinary(path string) (setupKernelBinaryIdentity, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return setupKernelBinaryIdentity{}, fmt.Errorf("Kernel binary path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return setupKernelBinaryIdentity{}, fmt.Errorf("resolve Kernel binary %s: %w", path, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return setupKernelBinaryIdentity{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return setupKernelBinaryIdentity{}, fmt.Errorf("inspect Kernel binary %s: %w", resolved, err)
	}
	if !info.Mode().IsRegular() {
		return setupKernelBinaryIdentity{}, fmt.Errorf("Kernel binary is not a regular file: %s", resolved)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return setupKernelBinaryIdentity{}, fmt.Errorf("Kernel binary is not executable: %s", resolved)
	}
	if !isHELMKernelExecutable(resolved) {
		return setupKernelBinaryIdentity{}, fmt.Errorf("Kernel binary does not have a HELM executable name: %s", resolved)
	}
	contents, err := os.ReadFile(resolved)
	if err != nil {
		return setupKernelBinaryIdentity{}, fmt.Errorf("read Kernel binary %s: %w", resolved, err)
	}
	return setupKernelBinaryIdentity{Path: resolved, ContentHash: canonicalize.HashBytes(contents)}, nil
}
