package tape

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRecorder_CaptureTime(t *testing.T) {
	fixed := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	r := NewRecorder("run-1").WithClock(func() time.Time { return fixed })

	entry := r.RecordTime("kernel")
	require.Equal(t, EntryTypeTime, entry.Type)
	require.Equal(t, "kernel", entry.ComponentID)
	require.NotEmpty(t, entry.ValueHash)
	require.Equal(t, uint64(1), entry.Seq)
}

func TestRecorder_CaptureRNG(t *testing.T) {
	r := NewRecorder("run-1")
	entry := r.RecordRNGSeed("component-a", []byte("seed-bytes-123"))
	require.Equal(t, EntryTypeRNGSeed, entry.Type)
	require.NotEmpty(t, entry.ValueHash)
}

func TestRecorder_CaptureNetwork(t *testing.T) {
	r := NewRecorder("run-1")
	entry := r.RecordNetwork("connector-1", "https://api.example.com/data", []byte(`{"result":42}`))
	require.Equal(t, EntryTypeNetwork, entry.Type)
	require.Equal(t, "https://api.example.com/data", entry.Key)
}

func TestRecorder_CaptureToolOutput(t *testing.T) {
	r := NewRecorder("run-1")
	entry := r.RecordToolOutput("executor", "tool-search", []byte(`["result1","result2"]`))
	require.Equal(t, EntryTypeToolOutput, entry.Type)
	require.Equal(t, "tool-search", entry.Key)
}

func TestReplayer_ServeFromTape(t *testing.T) {
	r := NewRecorder("run-1")
	r.RecordToolOutput("exec", "tool-1", []byte("output-data"))

	replayer := NewReplayer(r.Entries())
	val, err := replayer.Lookup(1)
	require.NoError(t, err)
	require.Equal(t, []byte("output-data"), val)
}

func TestReplayer_BlockNetwork(t *testing.T) {
	replayer := NewReplayer(nil)
	err := replayer.BlockNetwork("https://api.example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "REPLAY_TAPE_MISS")
}

func TestReplayer_VirtualClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRecorder("run-1").WithClock(func() time.Time { return fixed })
	r.RecordTime("kernel")

	replayer := NewReplayer(r.Entries())
	val, err := replayer.LookupByKey(EntryTypeTime, "time")
	require.NoError(t, err)
	require.Equal(t, fixed.Format(time.RFC3339Nano), string(val))
}

func TestReplayer_TapeMiss(t *testing.T) {
	replayer := NewReplayer(nil)
	_, err := replayer.Lookup(999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "REPLAY_TAPE_MISS")
}

func TestManifest_WriteRead(t *testing.T) {
	dir := t.TempDir()
	r := NewRecorder("run-1")
	r.Record(EntryTypeTime, "k", "t", []byte("now"))
	r.Record(EntryTypeRNGSeed, "k", "s", []byte("seed"))

	manifest := r.BuildManifest()
	require.NoError(t, WriteManifest(dir, manifest))

	loaded, err := ReadManifest(dir)
	require.NoError(t, err)
	require.Equal(t, "run-1", loaded.RunID)
	require.Len(t, loaded.Entries, 2)
}

func TestManifest_HashIntegrity(t *testing.T) {
	r := NewRecorder("run-1")
	r.Record(EntryTypeNetwork, "c", "url", []byte("response"))
	entries := r.Entries()
	manifest := r.BuildManifest()

	issues := VerifyManifestIntegrity(entries, manifest)
	require.Empty(t, issues)
}

func TestManifest_CorruptedHash(t *testing.T) {
	r := NewRecorder("run-1")
	r.Record(EntryTypeNetwork, "c", "url", []byte("response"))
	entries := r.Entries()
	manifest := r.BuildManifest()
	manifest.Entries[0].SHA256 = "tampered"

	issues := VerifyManifestIntegrity(entries, manifest)
	require.NotEmpty(t, issues)
}

func TestRecorder_Count(t *testing.T) {
	r := NewRecorder("run-1")
	require.Equal(t, 0, r.Count())
	r.Record(EntryTypeTime, "k", "t", []byte("x"))
	require.Equal(t, 1, r.Count())
}

func TestManifest_FileOnDisk(t *testing.T) {
	dir := t.TempDir()
	m := &Manifest{RunID: "r1", Entries: []ManifestItem{{Seq: 1, Type: EntryTypeTime, Key: "t", SHA256: "abc", SizeBytes: 3}}}
	require.NoError(t, WriteManifest(dir, m))

	_, err := os.Stat(filepath.Join(dir, "tape_manifest.json"))
	require.NoError(t, err)
}
