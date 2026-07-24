// shellallowlist.go — user-editable shell allowlist file with an mtime cache.
//
// Attribution: the file format tolerance (bare array / {"allowedCommands"} /
// truthy map) and the mtime-cached read are adapted from Rowboat (Apache-2.0),
// apps/cli/src/config/security.ts. This is an original Go implementation; no
// Rowboat code is copied verbatim.
//
// Fail-closed deviations from Rowboat:
//   - A corrupt or unreadable allowlist file is an error, not a silent fallback
//     to the defaults. Callers must treat the error as "everything blocked".
//   - The cache also compares file size alongside mtime, so a rewrite that
//     preserves mtime but changes length still reloads.
package workstation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultShellAllowlist mirrors the Rowboat default: a minimal read-only set
// seeded on first use.
var DefaultShellAllowlist = []string{
	"cat",
	"curl",
	"date",
	"echo",
	"grep",
	"jq",
	"ls",
	"pwd",
	"yq",
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

// ShellAllowlistStore reads a user-editable JSON allowlist file and caches it
// by modification time (and size). It is safe for concurrent use.
type ShellAllowlistStore struct {
	path string

	mu           sync.Mutex
	cached       []string
	cachedMtime  time.Time
	cachedSize   int64
	cachePresent bool
}

// NewShellAllowlistStore creates a store rooted at path.
func NewShellAllowlistStore(path string) *ShellAllowlistStore {
	return &ShellAllowlistStore{path: path}
}

// Path returns the allowlist file path.
func (s *ShellAllowlistStore) Path() string {
	return s.path
}

// Allowlist returns the current allowlist, reloading the file when its mtime
// or size changed since the last successful read. A missing file is seeded
// with DefaultShellAllowlist. Parse and I/O failures return an error — callers
// must fail closed.
func (s *ShellAllowlistStore) Allowlist() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Stat(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat shell allowlist %s: %w", s.path, err)
		}
		if err := s.seedLocked(); err != nil {
			return nil, err
		}
		info, err = os.Stat(s.path)
		if err != nil {
			return nil, fmt.Errorf("stat seeded shell allowlist %s: %w", s.path, err)
		}
	}

	if s.cachePresent && info.ModTime().Equal(s.cachedMtime) && info.Size() == s.cachedSize {
		return append([]string(nil), s.cached...), nil
	}

	allowlist, err := readShellAllowlistFile(s.path)
	if err != nil {
		return nil, err
	}
	s.cached = allowlist
	s.cachedMtime = info.ModTime()
	s.cachedSize = info.Size()
	s.cachePresent = true
	return append([]string(nil), s.cached...), nil
}

// Reset drops the cached allowlist so the next Allowlist call re-reads the
// file. Primarily for tests.
func (s *ShellAllowlistStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = nil
	s.cachedMtime = time.Time{}
	s.cachedSize = 0
	s.cachePresent = false
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
func readShellAllowlistFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read shell allowlist %s: %w", path, err)
	}
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
