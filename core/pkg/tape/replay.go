package tape

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Tape is a recorded tape as an EvidencePack holds it: tape_manifest.json and
// one entry_<n>.json file per entry, in one directory (08_TAPES).
type Tape struct {
	Manifest *Manifest
	Entries  []Entry
	// Files names the entry file each entry was read from, in the order the
	// entries were read.
	Files []string
}

// recordedEntryTypes are the entry types a Recorder writes.
var recordedEntryTypes = []EntryType{
	EntryTypeTime, EntryTypeRNGSeed, EntryTypeNetwork, EntryTypeToolOutput,
	EntryTypeDBRead, EntryTypeEnvVar, EntryTypeFileRead,
}

// ParseManifest decodes tape_manifest.json.
func ParseManifest(data []byte) (*Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse tape manifest: %w", err)
	}
	return &manifest, nil
}

// LstatFS is a file system that can describe a symbolic link as itself.
type LstatFS interface {
	fs.FS
	Lstat(name string) (fs.FileInfo, error)
}

// LoadTape reads the tape in directory dir of fsys: tape_manifest.json and
// every entry_*.json file beside it.
//
// The directory, the manifest and every entry file must be what the layout
// puts there, and not symbolic links: a link points at bytes the pack does
// not hold. Entry files are read in the order of
// the number in their name, so entry_2.json comes before entry_12.json, and
// a name without a number comes after every numbered one.
func LoadTape(fsys LstatFS, dir string) (*Tape, error) {
	if err := requireKind(fsys, dir, true); err != nil {
		return nil, err
	}
	manifestName := path.Join(dir, "tape_manifest.json")
	if err := requireKind(fsys, manifestName, false); err != nil {
		return nil, fmt.Errorf("cannot read tape manifest: %w", err)
	}
	data, err := fs.ReadFile(fsys, manifestName)
	if err != nil {
		return nil, fmt.Errorf("cannot read tape manifest: %w", err)
	}
	manifest, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("cannot read tape manifest: %w", err)
	}

	files, err := EntryFileNames(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("cannot load tape entries: %w", err)
	}
	tape := &Tape{Manifest: manifest, Files: files}
	for _, file := range files {
		name := path.Join(dir, file)
		if err := requireKind(fsys, name, false); err != nil {
			return nil, fmt.Errorf("cannot load tape entries: %w", err)
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("cannot load tape entries: read %s: %w", file, err)
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("cannot load tape entries: parse %s: %w", file, err)
		}
		tape.Entries = append(tape.Entries, entry)
	}
	return tape, nil
}

// EntryFileNames lists the entry_*.json names in dir, ordered by the number
// in the name. Two names with the same number, and names without one, are
// ordered by name.
func EntryFileNames(fsys fs.FS, dir string) ([]string, error) {
	listing, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range listing {
		if matched, _ := path.Match("entry_*.json", entry.Name()); matched {
			names = append(names, entry.Name())
		}
	}
	sort.SliceStable(names, func(i, j int) bool {
		ni, okI := entryFileNumber(names[i])
		nj, okJ := entryFileNumber(names[j])
		switch {
		case okI && okJ && ni != nj:
			return ni < nj
		case okI != okJ:
			return okI
		default:
			return names[i] < names[j]
		}
	})
	return names, nil
}

func entryFileNumber(name string) (uint64, bool) {
	digits := strings.TrimSuffix(strings.TrimPrefix(name, "entry_"), ".json")
	n, err := strconv.ParseUint(digits, 10, 64)
	return n, err == nil
}

// requireKind refuses a name that is a symbolic link, or that is not the
// kind of file the tape layout puts there: a directory when wantDir is set, a
// regular file otherwise. It looks at the name itself and does not follow it.
func requireKind(fsys LstatFS, name string, wantDir bool) error {
	base := path.Base(name)
	info, err := fsys.Lstat(name)
	if err != nil {
		if wantDir {
			return fmt.Errorf("tapes directory not found: %s: %w", name, err)
		}
		return fmt.Errorf("%s: %w", base, err)
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("refusing to read %s: it is a symbolic link, and a tape is replayed only from files the pack holds", base)
	case wantDir && !info.IsDir():
		return fmt.Errorf("refusing to read %s: it is not a directory", base)
	case !wantDir && !info.Mode().IsRegular():
		return fmt.Errorf("refusing to read %s: it is not a regular file", base)
	}
	return nil
}

// Replay serves the tape back through a Replayer the way a replayed run
// consumes it, front to back, and returns how many entries were served with
// their recorded value intact, and everything that did not hold:
//
//   - the entry files are not in sequence order, or two share a sequence
//     number;
//   - an entry was missed while serving from seq 1, or its served value does
//     not match the value_hash recorded on it;
//   - an entry has a type the Recorder never writes, or none;
//   - an entry is not listed in the manifest, or the manifest and the tape
//     disagree (VerifyManifestIntegrity).
//
// `helm-ai-kernel replay` and the verifier's replay_determinism check both
// judge a tape with it.
func (t *Tape) Replay() (int, []string) {
	entries, files := t.Entries, t.Files
	var issues []string

	// The replayer keys entries by seq, so the order of the files does not
	// change what it serves. A tape whose files are out of sequence order was
	// still not written by a recorder, which numbers entries as it appends.
	for i := 1; i < len(entries); i++ {
		if entries[i].Seq <= entries[i-1].Seq {
			issues = append(issues, fmt.Sprintf("entry files are not in sequence order: %s holds seq=%d after seq=%d in %s",
				fileName(files, i), entries[i].Seq, entries[i-1].Seq, fileName(files, i-1)))
		}
	}
	for _, entry := range entries {
		if !slices.Contains(recordedEntryTypes, entry.Type) {
			issues = append(issues, fmt.Sprintf("seq=%d has entry type %q, which is not one the recorder writes (%s)", entry.Seq, entry.Type, entryTypeList()))
		}
	}

	replayer := NewReplayer(entries)
	if replayer.Count() != len(entries) {
		// The replayer keys entries by seq, so a repeated seq leaves one entry
		// that can never be served.
		issues = append(issues, fmt.Sprintf("%d entry files hold %d distinct sequence numbers: entries share a sequence number", len(entries), replayer.Count()))
	}

	replayed := 0
	served := make(map[uint64]bool, replayer.Count())
	for range replayer.Count() {
		entry, err := replayer.Next()
		if err != nil {
			issues = append(issues, err.Error())
			continue
		}
		served[entry.Seq] = true
		sum := sha256.Sum256(entry.Value)
		if computed := hex.EncodeToString(sum[:]); computed != entry.ValueHash {
			issues = append(issues, fmt.Sprintf("seq=%d served value does not match its recorded value_hash: recorded %s, got %s", entry.Seq, entry.ValueHash, computed))
			continue
		}
		replayed++
	}

	// A hole stops the walk short of the entries behind it.
	listed := make(map[uint64]bool, len(t.Manifest.Entries))
	for _, item := range t.Manifest.Entries {
		listed[item.Seq] = true
	}
	var unreached, unlisted []uint64
	seen := make(map[uint64]bool, len(entries))
	for _, entry := range entries {
		if seen[entry.Seq] {
			continue
		}
		seen[entry.Seq] = true
		if !served[entry.Seq] {
			unreached = append(unreached, entry.Seq)
		}
		if !listed[entry.Seq] {
			unlisted = append(unlisted, entry.Seq)
		}
	}
	slices.Sort(unreached)
	slices.Sort(unlisted)
	for _, seq := range unreached {
		issues = append(issues, fmt.Sprintf("seq=%d is on the tape but was never served: the sequence is not contiguous from 1", seq))
	}
	for _, seq := range unlisted {
		issues = append(issues, fmt.Sprintf("seq=%d is on the tape but not listed in tape_manifest.json", seq))
	}

	// The manifest is what the run says it recorded; the tape must hold each
	// of those entries, and every field a manifest row carries must equal the
	// entry it names.
	issues = append(issues, VerifyManifestIntegrity(entries, t.Manifest)...)
	return replayed, issues
}

func fileName(files []string, i int) string {
	if i < len(files) {
		return files[i]
	}
	return fmt.Sprintf("entry %d", i)
}

func entryTypeList() string {
	names := make([]string, len(recordedEntryTypes))
	for i, entryType := range recordedEntryTypes {
		names[i] = string(entryType)
	}
	return strings.Join(names, ", ")
}
