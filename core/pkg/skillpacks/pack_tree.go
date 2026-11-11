package skillpacks

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile/updatebundle"
)

const (
	// maxPackFileBytes is the lifecycle's per-file bound, so a pack the scan
	// accepts is one the projection lifecycle could carry.
	maxPackFileBytes = maxProjectionArtifactBytes
	// A pack is instructions and a few supporting files. The caps keep one
	// scan bounded; a pack past them is refused, never partly inspected.
	maxPackFiles      = 1024
	maxPackTotalBytes = 16 << 20
)

// packFile is one regular file of a pack as it was read.
type packFile struct {
	path string // relative to the pack root, forward slashes
	data []byte
}

// packTree is one pass over a pack directory. The file checks, the content
// digest and the comparison with the loaded pack all use this single read, so
// they cannot disagree about which bytes were judged.
type packTree struct {
	files []packFile // path-sorted
	// hazard is the first entry the scan refuses outright. The walk stops
	// there, so the tree is incomplete and has no digest.
	hazard *Finding
	// unhashed says why the tree has no digest although the scan may go on:
	// a symlink that stays inside the pack has no bytes of its own to hash.
	unhashed string
}

var errPackWalkStopped = errors.New("skillpacks: pack walk stopped at a hazard")

// readPackTree reads every file under dir through an os.Root, so no path,
// symlink or swapped directory can take a read outside the pack. An error is
// an I/O failure; anything the scan must refuse is reported as tree.hazard.
func readPackTree(dir string) (packTree, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return packTree{}, fmt.Errorf("open pack directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	var tree packTree
	total := 0
	refuse := func(code, severity, message, path string) error {
		tree.hazard = &Finding{Code: code, Severity: severity, Message: message, Path: path}
		return errPackWalkStopped
	}
	err = fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		rel := filepath.FromSlash(path)
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, err := root.Readlink(rel)
			if err != nil {
				return err
			}
			if symlinkLeavesPack(dir, rel, target) {
				return refuse("ERR_SKILL_PATH_ESCAPE", "HIGH", "symlink escapes skill root", path)
			}
			if tree.unhashed == "" {
				tree.unhashed = fmt.Sprintf("%s is a symlink, and the content digest covers regular files only", path)
			}
			return nil
		case entry.IsDir():
			return nil
		case !entry.Type().IsRegular():
			return refuse("ERR_SKILL_OPAQUE_BINARY", "MEDIUM", "not a regular file; it cannot be inspected", path)
		}
		if len(tree.files) == maxPackFiles {
			return refuse("ERR_SKILL_OPAQUE_BINARY", "MEDIUM", fmt.Sprintf("pack holds more than %d files; it was not inspected", maxPackFiles), path)
		}
		data, err := readManagedFileAt(root, rel, maxPackFileBytes)
		switch {
		case errors.Is(err, ErrProjectionFileTooLarge):
			return refuse("ERR_SKILL_OPAQUE_BINARY", "MEDIUM", fmt.Sprintf("file exceeds %d bytes; it was not inspected", maxPackFileBytes), path)
		case errors.Is(err, ErrProjectionPathUnsafe):
			// The entry was a regular file when it was listed and is not one
			// now: something is rewriting the pack under the scan.
			return refuse("ERR_SKILL_PATH_ESCAPE", "HIGH", "file changed into a link or special file while the pack was read", path)
		case err != nil:
			return err
		}
		total += len(data)
		if total > maxPackTotalBytes {
			return refuse("ERR_SKILL_OPAQUE_BINARY", "MEDIUM", fmt.Sprintf("pack exceeds %d bytes; it was not inspected", maxPackTotalBytes), path)
		}
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return refuse("ERR_SKILL_OPAQUE_BINARY", "MEDIUM", "opaque binary payload requires provenance review", path)
		}
		tree.files = append(tree.files, packFile{path: path, data: data})
		return nil
	})
	if err != nil && !errors.Is(err, errPackWalkStopped) {
		return packTree{}, fmt.Errorf("read pack directory: %w", err)
	}
	// WalkDir orders names within a directory; the digest needs whole paths
	// in byte order ("a.txt" sorts before "a/b").
	sort.Slice(tree.files, func(i, j int) bool { return tree.files[i].path < tree.files[j].path })
	return tree, nil
}

// symlinkLeavesPack reports whether a link's target, read lexically, lies
// outside the pack directory.
func symlinkLeavesPack(dir, rel, target string) bool {
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, filepath.Dir(rel), target)
	}
	resolved = filepath.Clean(resolved)
	packRoot := filepath.Clean(dir)
	return resolved != packRoot && !strings.HasPrefix(resolved, packRoot+string(filepath.Separator))
}

func (t packTree) file(path string) ([]byte, bool) {
	for _, file := range t.files {
		if file.path == path {
			return file.data, true
		}
	}
	return nil, false
}

func (t packTree) entries() []updatebundle.BundleEntry {
	entries := make([]updatebundle.BundleEntry, 0, len(t.files))
	for _, file := range t.files {
		entries = append(entries, updatebundle.BundleEntry{Path: file.path, SHA256: HashBytes(file.data), Size: int64(len(file.data))})
	}
	return entries
}

// contentDigest is the artifact set hash over every file of the pack: the
// path, SHA-256 and size of each one, path-sorted and JCS-canonical. It is the
// derivation update bundles already use (updatebundle.EntrySetHash), which also
// refuses a path that is not clean and relative.
func (t packTree) contentDigest() (string, error) {
	if t.hazard != nil {
		return "", fmt.Errorf("%s: %s", t.hazard.Path, t.hazard.Message)
	}
	if t.unhashed != "" {
		return "", errors.New(t.unhashed)
	}
	digest, err := updatebundle.EntrySetHash(t.entries())
	if err != nil {
		return "", fmt.Errorf("pack file set cannot be hashed: %w", err)
	}
	return digest, nil
}

// holds reports whether pack still carries exactly what the tree read. The
// pack was loaded earlier and its SkillMD is what an install writes, so a
// digest over files that have since changed would vouch for different bytes.
func (t packTree) holds(pack SkillPack) error {
	skill, ok := t.file("SKILL.md")
	if !ok || string(skill) != pack.SkillMD {
		return errors.New("SKILL.md on disk is not the SKILL.md that was loaded")
	}
	raw, ok := t.file("skillpack.json")
	if !ok {
		return errors.New("skillpack.json is missing")
	}
	manifest, err := decodeManifest(pack.Root, raw, skill)
	if err != nil || hashCanonical(manifest) != hashCanonical(pack.Manifest) {
		return errors.New("skillpack.json on disk is not the manifest that was loaded")
	}
	return nil
}
