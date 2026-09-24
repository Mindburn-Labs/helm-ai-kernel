// Package secrettest is a test harness for §10.4: a known secret value must
// never reach a child process's argv or the process's logs (17-04).
package secrettest

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Recorder is a fake executable that records each invocation's argv and
// environment.
type Recorder struct {
	Dir  string // directory holding the executable; prepend it to PATH
	Path string // the executable itself
	log  string
}

// FakeExecutable writes an executable called name that appends its argv and
// its environment to a log, prints stdout and exits 0.
func FakeExecutable(t *testing.T, name, stdout string) *Recorder {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("secrettest.FakeExecutable needs a POSIX shell")
	}
	dir := t.TempDir()
	rec := &Recorder{Dir: dir, Path: filepath.Join(dir, name), log: filepath.Join(dir, name+".calls")}
	script := "#!/bin/sh\n" +
		"{ printf 'argv:'; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\n'; env | sed 's/^/env: /'; } >> '" + rec.log + "'\n" +
		"printf '%s' '" + strings.ReplaceAll(stdout, "'", "'\\''") + "'\n"
	if err := os.WriteFile(rec.Path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return rec
}

func (r *Recorder) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(r.log)
	if err != nil {
		t.Fatalf("%s was never invoked: %v", filepath.Base(r.Path), err)
	}
	return strings.Split(string(data), "\n")
}

// Argv returns every recorded argv line.
func (r *Recorder) Argv(t *testing.T) string {
	t.Helper()
	var out []string
	for _, line := range r.calls(t) {
		if strings.HasPrefix(line, "argv:") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// Env returns every recorded environment line.
func (r *Recorder) Env(t *testing.T) string {
	t.Helper()
	var out []string
	for _, line := range r.calls(t) {
		if strings.HasPrefix(line, "env: ") {
			out = append(out, strings.TrimPrefix(line, "env: "))
		}
	}
	return strings.Join(out, "\n")
}

// CaptureLogs sends slog's default logger and the standard log package to a
// buffer until the test ends.
func CaptureLogs(t *testing.T) *SyncBuffer {
	t.Helper()
	buf := &SyncBuffer{}
	prevSlog, prevLog, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(buf)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
		log.SetFlags(prevFlags)
	})
	return buf
}

// AssertAbsent fails the test for every named text that contains secret.
func AssertAbsent(t *testing.T, secret string, texts map[string]string) {
	t.Helper()
	if len(secret) < 8 {
		t.Fatalf("secrettest: canary %q is too short to search for", secret)
	}
	for where, text := range texts {
		if strings.Contains(text, secret) {
			t.Errorf("secret leaked into %s", where)
		}
	}
}

// SyncBuffer is a bytes.Buffer safe for concurrent writers.
type SyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *SyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *SyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
