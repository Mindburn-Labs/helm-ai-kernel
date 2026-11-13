//go:build unix

package packfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestADirectorySwappedToAPipeNeverBlocks(t *testing.T) {
	for method, run := range directoryOperations() {
		t.Run(method, func(t *testing.T) {
			dir, _ := pack(t)
			fifo := filepath.Join(dir, "pipe")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			p := open(t, dir)
			root := &statReplacingRoot{rootHandle: p.root, name: "sub", replace: func() error {
				if err := os.Rename(filepath.Join(dir, "sub"), filepath.Join(dir, "original")); err != nil {
					return err
				}
				return os.Rename(fifo, filepath.Join(dir, "sub"))
			}}
			p.root = root
			done := make(chan error, 1)
			go func() { done <- run(p, "sub") }()
			select {
			case err := <-done:
				if !root.replaced {
					t.Fatalf("directory replacement failed: %v", err)
				}
				if err == nil {
					t.Fatalf("%s accepted a pipe swapped in after Stat", method)
				}
			case <-time.After(2 * time.Second):
				// Release and join a blocking mutant before failing the test.
				if fd, err := syscall.Open(filepath.Join(dir, "sub"), syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = syscall.Close(fd)
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("could not join the blocked directory reader")
				}
				t.Fatalf("%s blocked on a pipe swapped in after Stat", method)
			}
		})
	}
}

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

// A named pipe where a directory is expected is refused without being
// opened, so a listing cannot wait for a writer (#308 r4 B1).
func TestANamedPipeIsNeverListedAsADirectory(t *testing.T) {
	dir, _ := pack(t)
	fifo := filepath.Join(dir, "99_EXT")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	p := open(t, dir)
	done := make(chan error, 1)
	go func() {
		_, err := p.ReadDir("99_EXT")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("ReadDir(99_EXT) = %v, want ErrNotRegular saying it is not a directory", err)
		}
	case <-time.After(5 * time.Second):
		if fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = syscall.Close(fd)
		}
		t.Fatal("ReadDir blocked on a named pipe in place of a directory")
	}
}
