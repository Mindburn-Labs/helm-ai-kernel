//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestEvidenceCheckpointReadReplacement(t *testing.T) {
	for _, scenario := range []string{"fifo", "symlink_fifo", "symlink_original", "regular", "ancestor_fifo", "ancestor_regular"} {
		t.Run(scenario, func(t *testing.T) {
			// A regression to blocking open must fail this test without leaving a
			// blocked goroutine, FIFO peer or process in the owning test binary.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEvidenceCheckpointReadReplacementProcess$")
			cmd.Env = append(os.Environ(), "HELM_CHECKPOINT_IO_SCENARIO="+scenario, "HELM_CHECKPOINT_IO_DIR="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("checkpoint open blocked on a replaced local input")
			}
			if err != nil {
				t.Fatalf("replacement refusal failed: %s", out)
			}
		})
	}
}

func TestEvidenceCheckpointReadReplacementProcess(t *testing.T) {
	scenario := os.Getenv("HELM_CHECKPOINT_IO_SCENARIO")
	if scenario == "" {
		return
	}
	dir := os.Getenv("HELM_CHECKPOINT_IO_DIR")
	parent := filepath.Join(dir, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "input")
	if err := os.WriteFile(path, []byte("public original bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	observed, err := checkpointCLIPathInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	// Swap deterministically at the real inspect/open boundary. No production
	// global hook or probabilistic racing loop is needed.
	if scenario == "ancestor_fifo" || scenario == "ancestor_regular" {
		if err := os.Rename(parent, filepath.Join(dir, "saved-parent")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Rename(path, filepath.Join(parent, "saved-input")); err != nil {
		t.Fatal(err)
	}
	switch scenario {
	case "fifo", "ancestor_fifo":
		err = unix.Mkfifo(path, 0o600)
	case "symlink_fifo":
		target := filepath.Join(parent, "fifo-target")
		if err = unix.Mkfifo(target, 0o600); err == nil {
			err = os.Symlink(target, path)
		}
	case "symlink_original":
		// SameFile alone would accept following this link to the original.
		err = os.Symlink(filepath.Join(parent, "saved-input"), path)
	case "regular", "ancestor_regular":
		err = os.WriteFile(path, []byte("public foreign bytes"), 0o600)
	default:
		t.Fatal("unknown test scenario")
	}
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := checkpointCLIReadChecked(path, observed, 1024); err == nil || raw != nil {
		t.Fatal("replaced input was read instead of refused")
	}
}
