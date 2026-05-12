package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// BranchFS provides speculative containment via a copy-on-write filesystem.
// It allows agentic execution to perform speculative modifications isolated
// from the main workspace until cryptographically authorized and committed
// to the ProofGraph.
type BranchFS struct {
	BaseDir   string
	BranchDir string
}

// NewBranchFS initializes a speculative BranchFS.
func NewBranchFS(baseDir, branchID string) (*BranchFS, error) {
	// Note: In a production environment with proper CAP_SYS_ADMIN capabilities,
	// this would utilize FUSE or overlayfs. We simulate this by creating an
	// isolated branch directory.
	branchDir := filepath.Join(os.TempDir(), "helm-branchfs", branchID)
	if err := os.MkdirAll(branchDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create BranchFS directory: %w", err)
	}

	return &BranchFS{
		BaseDir:   baseDir,
		BranchDir: branchDir,
	}, nil
}

// Mount performs the actual overlayfs or FUSE mount attaching the BranchFS.
func (b *BranchFS) Mount(ctx context.Context) error {
	// Future implementation: host-level overlayfs mount logic.
	// Example: syscall.Mount("overlay", target, "overlay", 0, options)
	return nil
}

// Unmount detaches the speculative filesystem cleanly.
func (b *BranchFS) Unmount(ctx context.Context) error {
	// Future implementation: syscall.Unmount integration.
	return nil
}

// Commit finalized the speculative changes. It calculates a Merkle root of the
// diff against the BaseDir, which is then recorded in the ProofGraph as part
// of the execution receipt.
func (b *BranchFS) Commit(ctx context.Context) (string, error) {
	// Future implementation: traverse BranchDir and generate an RFC 8785 canonical hash
	// representing the total side-effect state.
	return "sha256:branchfs_commit_hash_placeholder", nil
}

// Cleanup destroys the speculative branch completely, functioning as a rollback.
func (b *BranchFS) Cleanup() error {
	return os.RemoveAll(b.BranchDir)
}
