package skillpacks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// atomicWrite replaces rel under rootDir. os.Root confines every operation to
// rootDir, symlinked path components and a symlinked target are refused, and
// the bytes are staged in a freshly created O_EXCL file with a random name, so
// a planted "<name>.tmp" link or a symlinked directory cannot redirect them.
func atomicWrite(rootDir, rel string, data []byte) error {
	root, err := openManagedRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return atomicReplaceManagedAt(root, rel, data)
}

func sanitizePathSegment(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "://", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "\\", "_")
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = filepath.Clean(value)
	value = strings.Trim(value, ".")
	if value == "" || value == string(filepath.Separator) {
		return "skill"
	}
	return value
}

func observeManagedFile(root *os.Root, rel string, maxBytes int64) (bool, string, error) {
	data, err := readManagedFileAt(root, rel, maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, HashBytes(data), nil
}

func validateManagedRelative(rel string) error {
	if rel == "" || filepath.IsAbs(rel) {
		return ErrProjectionPathUnsafe
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return ErrProjectionPathUnsafe
	}
	return nil
}

func readManagedFileAt(root *os.Root, rel string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, ErrProjectionPathUnsafe
	}
	if err := validateManagedPathAt(root, rel, false); err != nil {
		return nil, err
	}
	lstat, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, ErrProjectionPathUnsafe
	}
	file, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	fstat, err := file.Stat()
	if err != nil || !os.SameFile(lstat, fstat) || !fstat.Mode().IsRegular() {
		return nil, ErrProjectionPathUnsafe
	}
	if fstat.Size() < 0 || fstat.Size() > maxBytes {
		return nil, ErrProjectionFileTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrProjectionFileTooLarge
	}
	return data, nil
}

func atomicReplaceManagedAt(root *os.Root, rel string, data []byte) error {
	if err := validateManagedRelative(rel); err != nil {
		return err
	}
	dirRel := filepath.Dir(rel)
	if err := ensureManagedDirAt(root, dirRel); err != nil {
		return err
	}
	if info, statErr := root.Lstat(rel); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrProjectionPathUnsafe
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	tmpName, err := projectionRandomName(".projection-write-")
	if err != nil {
		return err
	}
	tmpRel := filepath.Join(dirRel, tmpName)
	tmp, err := root.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmpRel) }()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpRel, rel); err != nil {
		return fmt.Errorf("skillpacks: atomic projection replace: %w", err)
	}
	if err := syncManagedDirectoryAt(root, dirRel); err != nil {
		return fmt.Errorf("skillpacks: sync projection parent after replace: %w", err)
	}
	if err := validateManagedPathAt(root, rel, false); err != nil {
		return err
	}
	return nil
}

func openManagedRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("skillpacks: open managed projection root: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() {
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrProjectionPathUnsafe
	}
	return root, nil
}

func validateManagedPathAt(root *os.Root, rel string, allowMissing bool) error {
	if root == nil {
		return ErrProjectionPathUnsafe
	}
	if err := validateManagedRelative(rel); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.Clean(rel), string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrProjectionPathUnsafe
		}
	}
	return nil
}

func ensureManagedDirAt(root *os.Root, rel string) error {
	if rel == "." {
		return nil
	}
	if err := validateManagedRelative(rel); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(filepath.Clean(rel), string(os.PathSeparator)) {
		parent := current
		if parent == "" {
			parent = "."
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		created := false
		if errors.Is(err, os.ErrNotExist) {
			mkdirErr := root.Mkdir(current, 0o755)
			if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			created = mkdirErr == nil
			info, err = root.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrProjectionPathUnsafe
		}
		if created {
			if err := syncManagedDirectoryAt(root, parent); err != nil {
				return fmt.Errorf("skillpacks: sync managed directory parent: %w", err)
			}
		}
	}
	return nil
}

func syncManagedDirectoryAt(root *os.Root, rel string) error {
	dir, err := root.Open(rel)
	if err != nil {
		return err
	}
	info, statErr := dir.Stat()
	if statErr != nil || !info.IsDir() {
		_ = dir.Close()
		if statErr != nil {
			return statErr
		}
		return ErrProjectionPathUnsafe
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func removeManagedFileAt(root *os.Root, rel string) error {
	if root == nil {
		return ErrProjectionPathUnsafe
	}
	if err := validateManagedPathAt(root, rel, false); err != nil {
		return err
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrProjectionPathUnsafe
	}
	if err := root.Remove(rel); err != nil {
		return fmt.Errorf("skillpacks: remove managed projection file: %w", err)
	}
	return syncManagedDirectoryAt(root, filepath.Dir(rel))
}

func projectionRandomName(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random[:]), nil
}

func writeExclusiveManagedFileAt(root *os.Root, rel string, data []byte) error {
	file, err := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func cleanupManagedStage(root *os.Root, rel string) {
	_ = root.Remove(filepath.Join(rel, "skillpack.json"))
	_ = root.Remove(filepath.Join(rel, "SKILL.md"))
	_ = root.Remove(rel)
}
