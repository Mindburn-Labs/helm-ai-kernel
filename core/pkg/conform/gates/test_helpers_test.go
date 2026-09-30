package gates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedClock = func() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func writeGateFile(t *testing.T, path string, data []byte) {
	t.Helper()
	mkdirGate(t, filepath.Dir(path))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mkdirGate(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func reasonContains(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want || strings.Contains(reason, want) {
			return true
		}
	}
	return false
}
