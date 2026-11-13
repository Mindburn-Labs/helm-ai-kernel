//go:build unix

package skillpacks

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

func TestLoadDirRefusesNamedPipesBeforeScanning(t *testing.T) {
	for _, name := range []string{"SKILL.md", "skillpack.json"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTestSkill(t, testManifest("test/pipe"), "safe skill")
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan error, 1)
			go func() { _, err := LoadDir(dir); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, packfs.ErrNotRegular) {
					t.Fatalf("pipe input: got %v, want non-regular-file error", err)
				}
			case <-time.After(2 * time.Second):
				// Release and join an unsafe reader so a regression cannot
				// leave a blocked goroutine behind the test.
				if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = syscall.Close(fd)
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("could not join blocked pack loader")
				}
				t.Fatal("pack loader blocked on named pipe before the scan")
			}
		})
	}
}
