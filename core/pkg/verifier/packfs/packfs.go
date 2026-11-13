// Package packfs reads the files of one EvidencePack directory for the
// offline verifier, the conformance report check (core/pkg/conform) and the
// `verify`, `evidence inspect` and `replay` commands.
//
// Every read goes through one os.Root opened on the pack directory. A name
// cannot leave the pack: a ".." segment, an absolute name and a symbolic link
// whose target is outside the pack are refused, and so is a symbolic link
// with an absolute target, even one that points back into the pack. Whether
// the pack directory was named by a relative or an absolute path makes no
// difference. A symbolic link that stays inside the pack is followed.
//
// Only regular files are read. A named pipe, a device, a socket, or a
// directory where a file is read is refused before it is opened, and the
// opened file is checked again, so a read can neither block on a pipe nor
// touch a device. Whole-file reads stop at MaxFileBytes.
// Directory opens require a directory handle and validate its identity, so
// replacing a checked child directory with a pipe cannot block a listing.
package packfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// MaxFileBytes is the most ReadFile reads from one file: 64 MiB. The
// verifier parses the files it reads whole, so a larger one is refused with
// ErrTooLarge instead of read into memory.
const MaxFileBytes int64 = 64 << 20

var (
	// ErrOutside marks a name that leaves the pack directory.
	ErrOutside = errors.New("outside the pack")
	// ErrNotRegular marks a name that is in the pack but is not a regular
	// file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge marks a file larger than the read limit.
	ErrTooLarge = errors.New("larger than the read limit")
)

// FS reads one pack directory. It implements fs.FS, fs.StatFS,
// fs.ReadFileFS and fs.ReadDirFS with the rules in the package documentation,
// and Lstat. It is safe for concurrent use.
type FS struct {
	root rootHandle
	// escape is the error os.Root returns for a name that leaves the root.
	// os does not export it, so it is taken from the root at Open.
	escape error

	mu       sync.Mutex
	listings map[string]*listing
}

// rootHandle is the set of operations used on the opened pack root. Tests
// wrap Stat to schedule a filesystem change before the subsequent open.
type rootHandle interface {
	Stat(string) (fs.FileInfo, error)
	Lstat(string) (fs.FileInfo, error)
	OpenFile(string, int, fs.FileMode) (*os.File, error)
	Close() error
}

// listing is what one directory lists: its names, and each name under its
// case-folded key (foldKey) mapped to the first listed name with that key.
type listing struct {
	names  map[string]bool
	folded map[string]string
}

// Open opens the pack directory dir.
func Open(dir string) (*FS, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	p := &FS{root: root}
	var pathErr *fs.PathError
	if _, err := root.Lstat(".."); errors.As(err, &pathErr) {
		p.escape = pathErr.Err
	}
	return p, nil
}

// Close releases the pack directory.
func (p *FS) Close() error { return p.root.Close() }

// CleanName turns a path a pack file states (an 00_INDEX.json entry, a
// manifest.json file_hashes key) into a name for this package. A path that is
// absolute, starts with a slash or a backslash, or has a ".." segment between
// either separator is refused with ErrOutside, so a pack cannot name a file
// above its directory even when the path would come back into it. "." and
// empty segments are dropped.
func CleanName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: the path is empty", ErrOutside)
	}
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", fmt.Errorf("%w: %q is absolute, and a pack names its files relative to its own directory", ErrOutside, name)
	}
	for _, segment := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return "", fmt.Errorf("%w: %q contains a \"..\" segment", ErrOutside, name)
		}
	}
	clean := path.Clean(name)
	if !fs.ValidPath(clean) || clean == "." {
		return "", fmt.Errorf("%w: %q does not name a file in the pack", ErrOutside, name)
	}
	return clean, nil
}

// checkName holds a name passed to a method to the fs.FS rules and to the
// backslash rule of CleanName.
func checkName(op, name string) error {
	if !fs.ValidPath(name) {
		return &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: %q is not a slash-separated path inside the pack", ErrOutside, name)}
	}
	if strings.HasPrefix(name, `\`) {
		return &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: %q starts with a backslash", ErrOutside, name)}
	}
	for _, segment := range strings.Split(name, `\`) {
		if segment == ".." {
			return &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: %q contains a \"..\" segment", ErrOutside, name)}
		}
	}
	return nil
}

// wrap turns the error os.Root gives for a name that leaves the root into
// one that wraps ErrOutside.
func (p *FS) wrap(op, name string, err error) error {
	if err == nil {
		return nil
	}
	if p.escape != nil && errors.Is(err, p.escape) {
		return &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: a symbolic link on the path leaves the pack directory or has an absolute target", ErrOutside)}
	}
	return err
}

func osName(name string) string { return filepath.FromSlash(name) }

// Stat describes name, following symbolic links that stay inside the pack.
func (p *FS) Stat(name string) (fs.FileInfo, error) {
	if err := checkName("stat", name); err != nil {
		return nil, err
	}
	info, err := p.root.Stat(osName(name))
	return info, p.wrap("stat", name, err)
}

// Lstat describes name without following a symbolic link at its end.
func (p *FS) Lstat(name string) (fs.FileInfo, error) {
	if err := checkName("lstat", name); err != nil {
		return nil, err
	}
	info, err := p.root.Lstat(osName(name))
	return info, p.wrap("lstat", name, err)
}

// ReadDir lists the directory name, sorted by file name.
func (p *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := checkName("readdir", name); err != nil {
		return nil, err
	}
	// A name that is not a directory is never opened: opening a named pipe
	// for a listing would wait for a writer that never comes (#308 r4 B1).
	info, err := p.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fmt.Errorf("%w: it is not a directory, which is never listed", ErrNotRegular)}
	}
	file, err := p.openDirectory(name, info)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	slices.SortFunc(entries, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return entries, p.wrap("readdir", name, err)
}

// Open opens a regular file with OpenRegular, or a directory for listing.
// Anything else is refused with ErrNotRegular.
func (p *FS) Open(name string) (fs.File, error) {
	info, err := p.Stat(name)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return p.openDirectory(name, info)
	}
	file, _, err := p.OpenRegular(name)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// openDirectory acquires a directory-only handle inside the pack root.
// The trailing separator preserves directory semantics, including Windows;
// Unix sets O_DIRECTORY and O_NONBLOCK explicitly. The opened object must still
// be the directory described by the preliminary stat.
func (p *FS) openDirectory(name string, before fs.FileInfo) (*os.File, error) {
	file, err := p.root.OpenFile(osName(name)+string(filepath.Separator), os.O_RDONLY|openDirectoryFlags, 0)
	if err != nil {
		return nil, p.wrap("open", name, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.IsDir() || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, &fs.PathError{Op: "open", Path: name, Err: fmt.Errorf("%w: the directory changed while it was opened", ErrNotRegular)}
	}
	return file, nil
}

// OpenRegular opens name for reading if it is a regular file, and returns
// what the opened file is. A name that is not a regular file is refused
// without being opened; the file is opened without blocking and checked again,
// so a swap to a named pipe between the two looks is refused too.
func (p *FS) OpenRegular(name string) (*os.File, fs.FileInfo, error) {
	before, err := p.Stat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, notRegular(name, before.Mode())
	}
	file, err := p.root.OpenFile(osName(name), os.O_RDONLY|openNonBlocking, 0)
	if err != nil {
		return nil, nil, p.wrap("open", name, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, nil, notRegular(name, info.Mode())
	}
	return file, info, nil
}

func notRegular(name string, mode fs.FileMode) error {
	kind := "an irregular file"
	switch {
	case mode.IsDir():
		kind = "a directory"
	case mode&fs.ModeNamedPipe != 0:
		kind = "a named pipe"
	case mode&fs.ModeSocket != 0:
		kind = "a socket"
	case mode&fs.ModeDevice != 0:
		kind = "a device"
	case mode&fs.ModeSymlink != 0:
		kind = "a symbolic link"
	}
	return &fs.PathError{Op: "open", Path: name, Err: fmt.Errorf("%w: it is %s, which is never read", ErrNotRegular, kind)}
}

// ReadFile reads the regular file name whole, up to MaxFileBytes.
func (p *FS) ReadFile(name string) ([]byte, error) {
	return p.ReadFileLimit(name, MaxFileBytes)
}

// ReadFileLimit reads the regular file name whole, up to limit bytes. A
// larger file is refused with ErrTooLarge.
func (p *FS) ReadFileLimit(name string, limit int64) ([]byte, error) {
	file, info, err := p.OpenRegular(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > limit {
		return nil, tooLarge(name, info.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	if int64(len(data)) > limit {
		return nil, tooLarge(name, int64(len(data)), limit)
	}
	return data, nil
}

func tooLarge(name string, size, limit int64) error {
	return &fs.PathError{Op: "read", Path: name, Err: fmt.Errorf("%w: it holds %d bytes or more, and the limit is %d (%s)", ErrTooLarge, size, limit, Bytes(limit))}
}

// Bytes formats a byte count the way limits are stated.
func Bytes(n int64) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

// CheckCase reports whether every segment of name is spelled exactly as the
// pack directory lists it. On a file system that ignores letter case,
// "01_score.JSON" opens 01_SCORE.json; a pack that names it so must fail the
// way it fails where case is kept. A segment the directory does not list
// returns an error wrapping fs.ErrNotExist.
func (p *FS) CheckCase(name string) error {
	if err := checkName("open", name); err != nil {
		return err
	}
	dir := "."
	for _, segment := range strings.Split(name, "/") {
		list, err := p.listing(dir)
		if err != nil {
			return err
		}
		if !list.names[segment] {
			if listed, ok := list.folded[foldKey(segment)]; ok {
				return &fs.PathError{Op: "open", Path: name, Err: fmt.Errorf("%w: the pack holds %q, which is spelled in another letter case", fs.ErrNotExist, path.Join(dir, listed))}
			}
			return &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		dir = path.Join(dir, segment)
	}
	return nil
}

func (p *FS) listing(dir string) (*listing, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if list, ok := p.listings[dir]; ok {
		return list, nil
	}
	entries, err := p.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	list := &listing{names: make(map[string]bool, len(entries)), folded: make(map[string]string, len(entries))}
	for _, entry := range entries {
		list.names[entry.Name()] = true
		key := foldKey(entry.Name())
		if _, ok := list.folded[key]; !ok {
			list.folded[key] = entry.Name()
		}
	}
	if p.listings == nil {
		p.listings = map[string]*listing{}
	}
	p.listings[dir] = list
	return list, nil
}

// foldKey maps every rune of s to the smallest rune of its Unicode simple
// case-folding orbit, so foldKey(a) == foldKey(b) exactly when
// strings.EqualFold(a, b).
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			smallest = min(smallest, next)
		}
		b.WriteRune(smallest)
	}
	return b.String()
}

// Walk walks the tree under dir in lexical order, as fs.WalkDir does. A
// symbolic link is reported as itself and never descended into.
func (p *FS) Walk(dir string, fn fs.WalkDirFunc) error {
	return fs.WalkDir(p, dir, fn)
}
