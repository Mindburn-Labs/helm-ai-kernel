package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func setupPrivateFileRoot(opts setupOptions) string {
	if opts.Scope == "project" {
		return opts.Workspace
	}
	return ""
}

func readJSONObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if root == nil {
		root = map[string]any{}
	}
	return root, nil
}

func writeJSONObject(path string, root map[string]any, allowedRoot string) error {
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, append(data, '\n'), allowedRoot)
}

func writePrivateFileAtomic(path string, data []byte, allowedRoot string) error {
	return writePrivateFileAtomicWithMutationHook(path, data, allowedRoot, nil)
}

func writePrivateFileAtomicWithMutationHook(path string, data []byte, allowedRoot string, beforeMutation func()) error {
	if allowedRoot != "" {
		root, err := os.OpenRoot(allowedRoot)
		if err != nil {
			return fmt.Errorf("open project workspace root %q: %w", allowedRoot, err)
		}
		defer func() { _ = root.Close() }()

		canonicalRoot, err := canonicalPrivateFileRoot(allowedRoot)
		if err != nil {
			return err
		}
		writePath, err := privateFileWritePath(path, canonicalRoot)
		if err != nil {
			return err
		}
		if !privateFilePathWithinRoot(canonicalRoot, writePath) || !privateFilePathWithinRoot(canonicalRoot, filepath.Dir(writePath)) {
			return fmt.Errorf("private config path %q resolves outside opened project workspace %q", path, canonicalRoot)
		}
		relPath, err := filepath.Rel(canonicalRoot, writePath)
		if err != nil {
			return fmt.Errorf("make private config path relative to project workspace: %w", err)
		}
		if beforeMutation != nil {
			beforeMutation()
		}
		return writePrivateFileAtomicInRoot(root, relPath, data)
	}

	writePath, err := privateFileWritePath(path, allowedRoot)
	if err != nil {
		return err
	}
	if beforeMutation != nil {
		beforeMutation()
	}
	return writePrivateFileAtomicAtPath(writePath, data)
}

func writePrivateFileAtomicAtPath(writePath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(writePath), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(writePath), ".helm-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, writePath)
}

func writePrivateFileAtomicInRoot(root *os.Root, writePath string, data []byte) error {
	parent := filepath.Dir(writePath)
	if err := root.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	tmp, tmpPath, err := createPrivateRootTemp(root, parent)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return root.Rename(tmpPath, writePath)
}

func createPrivateRootTemp(root *os.Root, parent string) (*os.File, string, error) {
	for range 100 {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate private config temp name: %w", err)
		}
		path := filepath.Join(parent, fmt.Sprintf(".helm-tmp-%x", random[:]))
		file, err := root.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, path, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("create private config temp file: exhausted unique names")
}

func privateFileWritePath(path, allowedRoot string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve private config path %q: %w", path, err)
	}

	var writePath string
	_, err = os.Lstat(absPath)
	switch {
	case err == nil:
		resolved, resolveErr := filepath.EvalSymlinks(absPath)
		if resolveErr != nil {
			return "", fmt.Errorf("resolve private config path %q: %w", path, resolveErr)
		}
		targetInfo, statErr := os.Stat(resolved)
		if statErr != nil {
			return "", fmt.Errorf("stat private config target %q: %w", path, statErr)
		}
		if !targetInfo.Mode().IsRegular() {
			return "", fmt.Errorf("private config path %q targets a non-regular file", path)
		}
		writePath = resolved
	case os.IsNotExist(err):
		resolvedParent, resolveErr := resolvePrivateFileParent(filepath.Dir(absPath))
		if resolveErr != nil {
			return "", fmt.Errorf("resolve private config parent for %q: %w", path, resolveErr)
		}
		writePath = filepath.Join(resolvedParent, filepath.Base(absPath))
	default:
		return "", err
	}

	if allowedRoot == "" {
		return writePath, nil
	}
	root, err := canonicalPrivateFileRoot(allowedRoot)
	if err != nil {
		return "", err
	}
	if !privateFilePathWithinRoot(root, writePath) || !privateFilePathWithinRoot(root, filepath.Dir(writePath)) {
		return "", fmt.Errorf("private config path %q resolves outside project workspace %q", path, root)
	}
	return writePath, nil
}

func resolvePrivateFileParent(parent string) (string, error) {
	missing := make([]string, 0, 2)
	for current := parent; ; current = filepath.Dir(current) {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			info, statErr := os.Stat(resolved)
			if statErr != nil {
				return "", statErr
			}
			if !info.IsDir() {
				return "", fmt.Errorf("private config parent %q is not a directory", current)
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}

		if info, lstatErr := os.Lstat(current); lstatErr == nil {
			return "", fmt.Errorf("resolve private config parent %q: %w (mode %v)", current, err, info.Mode())
		} else if !os.IsNotExist(lstatErr) {
			return "", lstatErr
		}
		next := filepath.Dir(current)
		if next == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
	}
}

func canonicalPrivateFileRoot(root string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project workspace %q: %w", root, err)
	}
	resolved, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", fmt.Errorf("resolve project workspace %q: %w", root, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat project workspace %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project workspace %q is not a directory", root)
	}
	return resolved, nil
}

func privateFilePathWithinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(rel) || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
