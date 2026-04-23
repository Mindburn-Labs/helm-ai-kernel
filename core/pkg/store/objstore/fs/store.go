// Package fs implements the ObjectStore interface using the local filesystem.
// Objects are stored in a content-addressed layout: hash[:2]/hash[2:4]/hash
package fs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/objstore"
)

// Store implements ObjectStore using the local filesystem.
type Store struct {
	root string
}

// New creates a new filesystem-backed object store at the given root directory.
func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("create object store root: %w", err)
	}
	return &Store{root: root}, nil
}

func (s *Store) objectPath(hash string) string {
	clean := strings.TrimPrefix(hash, "sha256:")
	if len(clean) < 4 {
		return filepath.Join(s.root, clean)
	}
	return filepath.Join(s.root, clean[:2], clean[2:4], clean)
}

func (s *Store) Put(_ context.Context, hash string, data io.Reader) error {
	path := s.objectPath(hash)

	// Check if already exists (idempotent)
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	// Create directory structure
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	// Write to temp file then rename (atomic)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := io.Copy(tmp, data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write object: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename to final path: %w", err)
	}

	return nil
}

func (s *Store) Get(_ context.Context, hash string) (io.ReadCloser, error) {
	path := s.objectPath(hash)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &objstore.ErrNotFound{Hash: hash}
		}
		return nil, fmt.Errorf("open object: %w", err)
	}
	return f, nil
}

func (s *Store) Exists(_ context.Context, hash string) (bool, error) {
	path := s.objectPath(hash)
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat object: %w", err)
	}
	return true, nil
}

func (s *Store) Delete(_ context.Context, hash string) error {
	path := s.objectPath(hash)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete object: %w", err)
	}
	return nil
}

func (s *Store) List(_ context.Context, prefix string) ([]string, error) {
	var hashes []string
	return hashes, filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || strings.HasPrefix(info.Name(), ".tmp-") {
			return nil
		}
		name := info.Name()
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			return nil
		}
		hashes = append(hashes, name)
		return nil
	})
}
