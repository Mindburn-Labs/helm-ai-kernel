//go:build unix

package packfs

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A named pipe is refused without being opened, so a read cannot wait for a
// writer that never comes.
func TestANamedPipeIsRefusedWithoutBlocking(t *testing.T) {
	dir, _ := pack(t)
	fifo := filepath.Join(dir, "pipe.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	symlink(t, "pipe.json", filepath.Join(dir, "link-to-pipe.json"))
	p := open(t, dir)
	for _, name := range []string{"pipe.json", "link-to-pipe.json"} {
		done := make(chan error, 1)
		go func() {
			_, err := p.ReadFile(name)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "named pipe") {
				t.Fatalf("ReadFile(%s) = %v, want ErrNotRegular naming the pipe", name, err)
			}
		case <-time.After(5 * time.Second):
			if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = syscall.Close(fd)
			}
			t.Fatalf("ReadFile(%s) blocked on the named pipe", name)
		}
		if _, err := p.Open(name); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("Open(%s) = %v, want ErrNotRegular", name, err)
		}
	}
}
