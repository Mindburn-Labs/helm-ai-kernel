// shellapproval.go — binding between a shell gate escalation and the approval
// ceremony that authorizes it, plus the local single-use consumption ledger.
//
// An approval ceremony created for a blocked shell command carries a binding
// token derived from the exact command line (args included): the ceremony
// authorizes that command line and nothing else. When the gate re-checks a
// pending command, it consumes a matching approved ceremony exactly once; a
// ceremony approved for a different command never satisfies the gate
// (wrong-command reuse is rejected), and an already-consumed ceremony leaves
// the command pending.
package workstation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ShellGateApprovalSubject and ShellGateApprovalAction identify approval
// ceremonies created by the shell gate.
const (
	ShellGateApprovalSubject = "shell_command"
	ShellGateApprovalAction  = "shell_operate"
)

// shellGateBindingPrefix prefixes the binding token embedded in the approval
// reason so it is greppable by operators and parseable by the gate.
const shellGateBindingPrefix = "shellgate-binding=sha256:"

// ShellCommandBindingHash returns the hex SHA-256 of the exact command line.
// The hash covers the full line, arguments included, so an approval for
// `rm /tmp/a` never authorizes `rm /etc/b`.
func ShellCommandBindingHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// ShellCommandBinding returns the binding token to embed in an approval
// ceremony for command.
func ShellCommandBinding(command string) string {
	return shellGateBindingPrefix + ShellCommandBindingHash(command)
}

// ApprovalBindsToCommand reports whether an approval ceremony reason carries
// the binding token for exactly this command line.
func ApprovalBindsToCommand(approvalReason, command string) bool {
	return strings.Contains(approvalReason, ShellCommandBinding(command))
}

// ConsumedApprovalDirectory is the single-use marker directory under the
// workstation data directory.
const ConsumedApprovalDirectory = "consumed-approvals"

// DefaultConsumedApprovalPath returns the default ledger path inside the
// given data directory.
func DefaultConsumedApprovalPath(dataDir string) string {
	return filepath.Join(dataDir, "workstation", ConsumedApprovalDirectory)
}

// ConsumedApprovalStore is a local ledger of approval IDs already consumed by
// the shell gate. It enforces the single-use property of an approval: once
// consumed, the same approval can never authorize the command again. The
// ledger uses one 0600 marker file per approval. O_CREATE|O_EXCL makes
// consumption atomic across processes without a read-modify-write race.
type ConsumedApprovalStore struct {
	path string
}

// NewConsumedApprovalStore creates a ledger rooted at path.
func NewConsumedApprovalStore(path string) *ConsumedApprovalStore {
	return &ConsumedApprovalStore{path: path}
}

// Path returns the ledger file path.
func (s *ConsumedApprovalStore) Path() string {
	return s.path
}

func (s *ConsumedApprovalStore) markerPath(approvalID string) string {
	sum := sha256.Sum256([]byte(approvalID))
	return filepath.Join(s.path, hex.EncodeToString(sum[:]))
}

// IsConsumed reports whether the approval ID was already consumed. A ledger
// error returns an error so callers can fail closed.
func (s *ConsumedApprovalStore) IsConsumed(approvalID string) (bool, error) {
	if strings.TrimSpace(approvalID) == "" {
		return false, fmt.Errorf("approval ID is required")
	}
	_, err := os.Stat(s.markerPath(approvalID))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat consumed approval marker: %w", err)
	}
	return true, nil
}

// MarkConsumed atomically records the approval ID as consumed.
func (s *ConsumedApprovalStore) MarkConsumed(approvalID string) error {
	if strings.TrimSpace(approvalID) == "" {
		return fmt.Errorf("approval ID is required")
	}
	if err := os.MkdirAll(s.path, 0o700); err != nil {
		return fmt.Errorf("create consumed approval ledger directory: %w", err)
	}
	file, err := os.OpenFile(s.markerPath(approvalID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("approval %s was already consumed", approvalID)
		}
		return fmt.Errorf("create consumed approval marker: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close consumed approval marker: %w", err)
	}
	return nil
}
