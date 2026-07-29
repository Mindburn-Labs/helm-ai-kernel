// shellallowlist.go — user-editable shell allowlist file with stable reads.
//
// Attribution: the file format tolerance (bare array / {"allowedCommands"} /
// truthy map) are adapted from Rowboat (Apache-2.0),
// apps/cli/src/config/security.ts. This is an original Go implementation; no
// Rowboat code is copied verbatim.
//
// Fail-closed deviations from Rowboat:
//   - A corrupt or unreadable allowlist file is an error, not a silent fallback
//     to the defaults. Callers must treat the error as "everything blocked".
//   - Each read verifies the opened file against the path and reads identical
//     bytes twice, so replacement or in-place mutation fails closed.
package workstation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// DefaultShellAllowlist is the minimal read-only set seeded on first use.
// curl and echo are deliberately NOT in the shipped defaults: `curl -o file
// URL` and `echo x > file` are arbitrary writes, and an allowlisted writer
// defeats the gate. Operators who need them add them explicitly.
var DefaultShellAllowlist = []string{
	"cat",
	"date",
	"grep",
	"jq",
	"ls",
	"pwd",
	"whoami",
}

// ShellAllowlistFilename is the allowlist file name under the workstation
// data directory.
const ShellAllowlistFilename = "shell-allowlist.json"

// DefaultShellAllowlistPath returns the default allowlist path inside the
// given data directory (e.g. defaultSetupDataDir()).
func DefaultShellAllowlistPath(dataDir string) string {
	return filepath.Join(dataDir, "workstation", ShellAllowlistFilename)
}

// ShellAllowlistStore reads a user-editable JSON allowlist file. It is safe
// for concurrent use.
type ShellAllowlistStore struct {
	path string
	mu   sync.Mutex
}

// NewShellAllowlistStore creates a store rooted at path.
func NewShellAllowlistStore(path string) *ShellAllowlistStore {
	return &ShellAllowlistStore{path: path}
}

// Path returns the allowlist file path.
func (s *ShellAllowlistStore) Path() string {
	return s.path
}

// Allowlist returns the current allowlist. A missing file is seeded with
// DefaultShellAllowlist. Parse and I/O failures return an error — callers must
// fail closed. The allowlist file must be a regular file (never a symlink or
// special file) and must not be writable by group or others.
func (s *ShellAllowlistStore) Allowlist() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := os.Lstat(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat shell allowlist %s: %w", s.path, err)
		}
		if err := s.seedLocked(); err != nil {
			return nil, err
		}
	}
	allowlist, err := readStableShellAllowlistFile(s.path)
	if err != nil {
		return nil, err
	}
	return allowlist, nil
}

// validateShellAllowlistInfo enforces the file-safety invariants of the
// allowlist: regular file, no symlink, not writable by group/others.
func validateShellAllowlistInfo(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("shell allowlist %s must be a regular file, not a symlink or special file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("shell allowlist %s must not be writable by group or others (chmod 0600)", path)
	}
	return nil
}

// Reset remains for API compatibility. Allowlist always performs a stable
// read, so there is no cache to clear.
func (s *ShellAllowlistStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
}

// seedLocked writes the default allowlist to a missing file with restrictive
// permissions (directory 0700, file 0600).
func (s *ShellAllowlistStore) seedLocked() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create shell allowlist directory %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(DefaultShellAllowlist, "", "  ")
	if err != nil {
		return fmt.Errorf("encode default shell allowlist: %w", err)
	}
	if err := os.WriteFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("seed shell allowlist %s: %w", s.path, err)
	}
	return nil
}

// readShellAllowlistFile parses the allowlist file. Accepted forms mirror the
// Rowboat security config:
//   - a bare JSON array: ["ls", "cat"]
//   - an object with an allowedCommands array: {"allowedCommands": ["ls"]}
//   - a truthy map: {"ls": true, "rm": false} → ["ls"]
func parseShellAllowlist(path string, data []byte) ([]string, error) {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse shell allowlist %s: %w", path, err)
	}
	switch value := payload.(type) {
	case []any:
		return normalizeShellAllowlist(value), nil
	case map[string]any:
		if raw, ok := value["allowedCommands"]; ok {
			entries, ok := raw.([]any)
			if !ok {
				return nil, fmt.Errorf("parse shell allowlist %s: allowedCommands must be an array", path)
			}
			return normalizeShellAllowlist(entries), nil
		}
		var truthy []any
		for key, entry := range value {
			if jsonTruthy(entry) {
				truthy = append(truthy, key)
			}
		}
		return normalizeShellAllowlist(truthy), nil
	default:
		return nil, fmt.Errorf("parse shell allowlist %s: expected array or object", path)
	}
}

func readStableShellAllowlistFile(path string) ([]string, error) {
	const attempts = 3
	for attempt := 0; attempt < attempts; attempt++ {
		first, err := readShellAllowlistBytes(path)
		if err != nil {
			return nil, err
		}
		second, err := readShellAllowlistBytes(path)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(first, second) {
			return parseShellAllowlist(path, first)
		}
	}
	return nil, fmt.Errorf("read shell allowlist %s: file changed during stable read", path)
}

func readShellAllowlistBytes(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat shell allowlist %s: %w", path, err)
	}
	if err := validateShellAllowlistInfo(path, pathInfo); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open shell allowlist %s: %w", path, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened shell allowlist %s: %w", path, err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("read shell allowlist %s: path changed before open", path)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read shell allowlist %s: %w", path, err)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("re-stat shell allowlist %s: %w", path, err)
	}
	if !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("read shell allowlist %s: path changed during read", path)
	}
	return data, nil
}

// jsonTruthy mirrors JavaScript truthiness for decoded JSON values.
func jsonTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != ""
	default:
		return true
	}
}

// normalizeShellAllowlist keeps string entries only, trims, lowercases,
// de-duplicates, and sorts.
func normalizeShellAllowlist(entries []any) []string {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		text, ok := entry.(string)
		if !ok {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(text))
		if normalized == "" {
			continue
		}
		seen[normalized] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
