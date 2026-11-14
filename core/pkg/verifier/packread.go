package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

// packFiles is how a check reads the pack: through one packfs.FS, an os.Root
// opened on the pack directory. A name or a symbolic link cannot reach a file
// outside the pack, and only regular files are read (see package packfs). A
// pack directory that cannot be opened leaves every read failing with the
// reason, and a missing one reads as a pack that holds nothing.
type packFiles struct {
	fs  *packfs.FS
	err error
}

func openPack(bundlePath string) *packFiles {
	fsys, err := packfs.Open(bundlePath)
	return &packFiles{fs: fsys, err: err}
}

func (p *packFiles) close() {
	if p.fs != nil {
		_ = p.fs.Close()
	}
}

// absent reports whether err means the pack does not hold the name.
func absent(err error) bool { return errors.Is(err, fs.ErrNotExist) }

func (p *packFiles) stat(name string) (fs.FileInfo, error) {
	if p.fs == nil {
		return nil, p.err
	}
	return p.fs.Stat(name)
}

// hasFile reports whether the pack holds name as a regular file. A name that
// is absent or a directory returns false. A name that is there but cannot be
// read (a symbolic link out of the pack, a named pipe, a device) returns the
// error, so the caller fails on it instead of treating the file as absent.
func (p *packFiles) hasFile(name string) (bool, error) {
	info, err := p.stat(name)
	switch {
	case absent(err):
		return false, nil
	case err != nil:
		return false, err
	case info.IsDir():
		return false, nil
	case !info.Mode().IsRegular():
		_, _, err := p.fs.OpenRegular(name)
		return false, err
	}
	return true, nil
}

// hasDir reports whether the pack holds name as a directory. A name that is
// absent or a file returns false; one that leaves the pack returns the error.
func (p *packFiles) hasDir(name string) (bool, error) {
	info, err := p.stat(name)
	switch {
	case absent(err):
		return false, nil
	case err != nil:
		return false, err
	}
	return info.IsDir(), nil
}

// readFile reads the regular file name whole, up to packfs.MaxFileBytes.
func (p *packFiles) readFile(name string) ([]byte, error) {
	if p.fs == nil {
		return nil, p.err
	}
	return p.fs.ReadFile(name)
}

func (p *packFiles) openRegular(name string) (*os.File, fs.FileInfo, error) {
	if p.fs == nil {
		return nil, nil, p.err
	}
	return p.fs.OpenRegular(name)
}

func (p *packFiles) readDir(name string) ([]fs.DirEntry, error) {
	if p.fs == nil {
		return nil, p.err
	}
	return p.fs.ReadDir(name)
}

// walk walks the tree under name in lexical order. Symbolic links are
// reported as themselves and never descended into.
func (p *packFiles) walk(name string, fn fs.WalkDirFunc) error {
	if p.fs == nil {
		if absent(p.err) {
			return nil
		}
		return p.err
	}
	return p.fs.Walk(name, fn)
}

// hashNamed returns the SHA-256 of a file a pack file names (an 00_INDEX.json
// entry or a manifest.json file_hashes key). The name must stay inside the
// pack under packfs.CleanName and be spelled as the pack directory lists it.
// The file is hashed as it streams, so its size is not limited.
func (p *packFiles) hashNamed(name string) (string, error) {
	clean, err := packfs.CleanName(name)
	if err != nil {
		return "", err
	}
	if p.fs == nil {
		return "", p.err
	}
	if err := p.fs.CheckCase(clean); err != nil {
		return "", err
	}
	file, _, err := p.fs.OpenRegular(clean)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
