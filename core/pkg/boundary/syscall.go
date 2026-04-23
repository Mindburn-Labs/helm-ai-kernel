package boundary

import (
	"fmt"
)

// SyscallOp defines allowed semantic operations.
type SyscallOp string

// SyscallOp constants for type-safe system call operations.
const (
	OpFilesystemRead  SyscallOp = "FS_READ"
	OpFilesystemWrite SyscallOp = "FS_WRITE"
	OpNetworkGet      SyscallOp = "NET_GET"
	OpExecRun         SyscallOp = "EXEC_RUN"
)

// TypedSyscall represents a request from the heuristic layer to cross the semantic boundary.
type TypedSyscall struct {
	Operation SyscallOp `json:"operation"`
	Payload   any       `json:"payload"`
}

// ValidateSyscall checks if the operation is valid and the payload matches basic expectations.
// In a full implementation, this would use JSON Schema validation.
//
//nolint:gocognit // payload validation requires comprehensive type checks
func ValidateSyscall(op SyscallOp, payload any) error {
	switch op {
	case OpFilesystemRead:
		// Expect Payload to be a string (path) or map with "path"
		if _, ok := payload.(string); !ok {
			// Check map
			if m, ok := payload.(map[string]any); ok {
				if _, hasPath := m["path"]; !hasPath {
					return fmt.Errorf("invalid payload for %s: missing 'path'", op)
				}
			} else {
				return fmt.Errorf("invalid payload for %s: expected string or map with path", op)
			}
		}
	case OpFilesystemWrite:
		// Expect map with path and content
		m, ok := payload.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid payload for %s: expected map", op)
		}
		if _, hasPath := m["path"]; !hasPath {
			return fmt.Errorf("invalid payload for %s: missing 'path'", op)
		}
		if _, hasContent := m["content"]; !hasContent {
			return fmt.Errorf("invalid payload for %s: missing 'content'", op)
		}
	case OpNetworkGet:
		// Expect string (URL)
		if _, ok := payload.(string); !ok {
			return fmt.Errorf("invalid payload for %s: expected string URL", op)
		}
	case OpExecRun:
		// Expect map with cmd (string) and args ([]string)
		m, ok := payload.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid payload for %s: expected map", op)
		}
		if _, hasCmd := m["cmd"]; !hasCmd {
			return fmt.Errorf("invalid payload for %s: missing 'cmd'", op)
		}
	default:
		return fmt.Errorf("unknown or unauthorized syscall operation: %s", op)
	}
	return nil
}
