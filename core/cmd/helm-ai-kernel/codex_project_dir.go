package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

var errCodexProjectDirNotFound = errors.New("Codex project config directory does not exist")

// codexProjectDir keeps all project-scoped Codex configuration operations
// rooted in the opened .codex directory. os.Root keeps the directory binding
// stable across renames and refuses symlink traversal outside that root.
type codexProjectDir struct {
	root *os.Root
}

func openCodexProjectDir(workspace string, create bool) (*codexProjectDir, error) {
	workspaceRoot, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, fmt.Errorf("open project workspace %q: %w", workspace, err)
	}
	defer func() { _ = workspaceRoot.Close() }()

	for {
		info, err := workspaceRoot.Lstat(".codex")
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if !create {
				return nil, errCodexProjectDirNotFound
			}
			if err := workspaceRoot.Mkdir(".codex", 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, fmt.Errorf("create project .codex directory: %w", err)
			}
			continue
		case err != nil:
			return nil, fmt.Errorf("inspect project .codex directory: %w", err)
		case info.Mode()&os.ModeSymlink != 0:
			return nil, fmt.Errorf("refuse symlinked project .codex directory")
		case !info.IsDir():
			return nil, fmt.Errorf("project .codex path is not a directory")
		}

		root, err := workspaceRoot.OpenRoot(".codex")
		if err != nil {
			return nil, fmt.Errorf("open project .codex directory: %w", err)
		}
		return &codexProjectDir{root: root}, nil
	}
}

func (d *codexProjectDir) Close() error {
	if d == nil || d.root == nil {
		return nil
	}
	return d.root.Close()
}

func (d *codexProjectDir) readRegularFile(name string) ([]byte, error) {
	if err := validateCodexProjectFileName(name); err != nil {
		return nil, err
	}
	info, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refuse symlinked project .codex/%s", name)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("project .codex/%s is not a regular file", name)
	}
	return d.root.ReadFile(name)
}

func (d *codexProjectDir) writePrivateFileAtomic(name string, data []byte) error {
	if err := validateCodexProjectFileName(name); err != nil {
		return err
	}
	if info, err := d.root.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse symlinked project .codex/%s", name)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("project .codex/%s is not a regular file", name)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	file, tempName, err := d.createPrivateTemp()
	if err != nil {
		return err
	}
	defer func() { _ = d.root.Remove(tempName) }()
	if n, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	} else if n != len(data) {
		_ = file.Close()
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return d.root.Rename(tempName, name)
}

func (d *codexProjectDir) createPrivateTemp() (*os.File, string, error) {
	for range 100 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("generate project config temp name: %w", err)
		}
		name := fmt.Sprintf(".helm-tmp-%x", suffix[:])
		file, err := d.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("create project config temp file: exhausted unique names")
}

func validateCodexProjectFileName(name string) error {
	switch name {
	case "config.toml", "hooks.json":
		return nil
	default:
		return fmt.Errorf("unsupported project .codex file %q", name)
	}
}

var _ io.Closer = (*codexProjectDir)(nil)
