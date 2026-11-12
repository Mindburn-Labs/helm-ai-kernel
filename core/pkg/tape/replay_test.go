package tape

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeTapeDir writes entries and their manifest the way a pack holds them,
// naming each entry file with name(seq).
func writeTapeDir(t *testing.T, entries []Entry, manifest *Manifest, name func(seq uint64) string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, WriteManifest(dir, manifest))
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name(entry.Seq)), data, 0o600))
	}
	return dir
}

func recordedTape(n int) *Recorder {
	r := NewRecorder("run-1")
	for i := 0; i < n; i++ {
		r.RecordToolOutput("executor", fmt.Sprintf("tool-%d", i), []byte(fmt.Sprintf(`{"n":%d}`, i)))
	}
	return r
}

func load(t *testing.T, dir string) *Tape {
	t.Helper()
	tape, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
	require.NoError(t, err)
	return tape
}

// N1: entry files are read in the order of the number in their name.
func TestLoadTape_OrdersEntryFilesByTheirNumber(t *testing.T) {
	r := recordedTape(12)
	dir := writeTapeDir(t, r.Entries(), r.BuildManifest(), func(seq uint64) string { return fmt.Sprintf("entry_%d.json", seq) })
	tape := load(t, dir)
	require.Equal(t, "entry_1.json", tape.Files[0])
	require.Equal(t, "entry_2.json", tape.Files[1])
	require.Equal(t, "entry_12.json", tape.Files[11])
	replayed, issues := tape.Replay()
	require.Empty(t, issues)
	require.Equal(t, 12, replayed)

	// A name without a number comes after every numbered one.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "entry_extra.json"), []byte(`{"seq":13,"type":"TIME","key":"time"}`), 0o600))
	require.Equal(t, "entry_extra.json", load(t, dir).Files[12])
}

// N7: an entry type the recorder never writes is an issue.
func TestReplay_RefusesEntryTypesTheRecorderDoesNotWrite(t *testing.T) {
	r := recordedTape(2)
	entries := r.Entries()
	manifest := r.BuildManifest()
	entries[1].Type = "BOGUS_TYPE"
	manifest.Entries[1].Type = "BOGUS_TYPE"
	tape := &Tape{Manifest: manifest, Entries: entries, Files: []string{"entry_1.json", "entry_2.json"}}
	_, issues := tape.Replay()
	require.Len(t, issues, 1)
	require.Contains(t, issues[0], `seq=2 has entry type "BOGUS_TYPE", which is not one the recorder writes`)

	entries[1].Type = ""
	manifest.Entries[1].Type = ""
	_, issues = tape.Replay()
	require.Len(t, issues, 1)
	require.Contains(t, issues[0], `seq=2 has entry type ""`)
}

// The replay findings the command reports: order, holes, a tampered value,
// a shared sequence number and an unlisted entry.
func TestReplay_ReportsWhatDoesNotHold(t *testing.T) {
	r := recordedTape(3)
	entries := r.Entries()
	manifest := r.BuildManifest()

	tape := &Tape{Manifest: manifest, Entries: []Entry{entries[1], entries[0], entries[2]}}
	_, issues := tape.Replay()
	require.Contains(t, strings.Join(issues, "\n"), "entry files are not in sequence order: entry 1 holds seq=1 after seq=2 in entry 0")

	tampered := append([]Entry(nil), entries...)
	tampered[1].Value = []byte("tampered")
	replayed, issues := (&Tape{Manifest: manifest, Entries: tampered}).Replay()
	require.Equal(t, 2, replayed)
	require.Contains(t, strings.Join(issues, "\n"), "seq=2 served value does not match its recorded value_hash")

	replayed, issues = (&Tape{Manifest: manifest, Entries: []Entry{entries[0], entries[2]}}).Replay()
	require.Equal(t, 1, replayed)
	joined := strings.Join(issues, "\n")
	require.Contains(t, joined, "REPLAY_TAPE_MISS: seq=2")
	require.Contains(t, joined, "seq=3 is on the tape but was never served")

	_, issues = (&Tape{Manifest: manifest, Entries: append(append([]Entry(nil), entries...), entries[0])}).Replay()
	require.Contains(t, strings.Join(issues, "\n"), "entries share a sequence number")

	short := &Manifest{RunID: manifest.RunID, Entries: manifest.Entries[:2]}
	_, issues = (&Tape{Manifest: short, Entries: entries}).Replay()
	require.Equal(t, []string{"seq=3 is on the tape but not listed in tape_manifest.json"}, issues)
}

func TestLoadTape_RefusesWhatTheLayoutDoesNotPutThere(t *testing.T) {
	r := recordedTape(1)
	name := func(seq uint64) string { return fmt.Sprintf("entry_%04d.json", seq) }

	t.Run("missing directory", func(t *testing.T) {
		_, err := LoadTape(os.DirFS(t.TempDir()).(LstatFS), "08_TAPES")
		require.ErrorContains(t, err, "tapes directory not found")
	})
	t.Run("a file where the directory goes", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "08_TAPES"), nil, 0o600))
		_, err := LoadTape(os.DirFS(dir).(LstatFS), "08_TAPES")
		require.ErrorContains(t, err, "refusing to read 08_TAPES: it is not a directory")
	})
	t.Run("missing manifest", func(t *testing.T) {
		dir := writeTapeDir(t, r.Entries(), r.BuildManifest(), name)
		require.NoError(t, os.Remove(filepath.Join(dir, "tape_manifest.json")))
		_, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
		require.ErrorContains(t, err, "cannot read tape manifest: tape_manifest.json")
	})
	t.Run("manifest that does not parse", func(t *testing.T) {
		dir := writeTapeDir(t, r.Entries(), r.BuildManifest(), name)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tape_manifest.json"), []byte("{"), 0o600))
		_, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
		require.ErrorContains(t, err, "cannot read tape manifest: parse tape manifest")
	})
	t.Run("entry that does not parse", func(t *testing.T) {
		dir := writeTapeDir(t, r.Entries(), r.BuildManifest(), name)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "entry_0001.json"), []byte("{"), 0o600))
		_, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
		require.ErrorContains(t, err, "cannot load tape entries: parse entry_0001.json")
	})
	t.Run("entry that is a directory", func(t *testing.T) {
		dir := writeTapeDir(t, nil, r.BuildManifest(), name)
		require.NoError(t, os.Mkdir(filepath.Join(dir, "entry_0001.json"), 0o755))
		_, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
		require.ErrorContains(t, err, "refusing to read entry_0001.json: it is not a regular file")
	})
	t.Run("symbolic links", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symbolic links need privileges on Windows")
		}
		for _, linked := range []string{"tape_manifest.json", "entry_0001.json"} {
			dir := writeTapeDir(t, r.Entries(), r.BuildManifest(), name)
			moved := filepath.Join(t.TempDir(), linked)
			require.NoError(t, os.Rename(filepath.Join(dir, linked), moved))
			require.NoError(t, os.Symlink(moved, filepath.Join(dir, linked)))
			_, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
			require.ErrorContains(t, err, "refusing to read "+linked+": it is a symbolic link")
		}
	})
}
