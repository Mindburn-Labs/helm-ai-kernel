package tape

import (
	"encoding/json"
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

	data, err := os.ReadFile(filepath.Join(dir, "tape_manifest.json"))
	require.NoError(t, err)
	loaded, err := ParseManifest(data)
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

// A manifest row built in memory is compared on every field it marshals to,
// not on sha256 alone: a wrong type, key or size used to pass.
func TestManifest_EveryTypedFieldIsCompared(t *testing.T) {
	r := NewRecorder("run-1")
	r.Record(EntryTypeNetwork, "connector", "https://example.test", []byte("response"))
	entries := r.Entries()

	for name, tc := range map[string]struct {
		mutate func(item *ManifestItem)
		want   string
	}{
		"type":       {func(item *ManifestItem) { item.Type = EntryTypeTime }, `seq=1 manifest field "type" is "TIME", tape entry has "NETWORK"`},
		"key":        {func(item *ManifestItem) { item.Key = "other" }, `seq=1 manifest field "key" is "other", tape entry has "https://example.test"`},
		"size_bytes": {func(item *ManifestItem) { item.SizeBytes = 99 }, `seq=1 manifest field "size_bytes" is 99, tape entry value is 8 bytes`},
		"sha256":     {func(item *ManifestItem) { item.SHA256 = "tampered" }, "seq=1 hash mismatch: expected tampered"},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := r.BuildManifest()
			tc.mutate(&manifest.Entries[0])
			issues := VerifyManifestIntegrity(entries, manifest)
			require.Len(t, issues, 1)
			require.Contains(t, issues[0], tc.want)
		})
	}
}

// A row read from tape_manifest.json keeps the fields this package does not
// declare, and they are compared with the entry too.
func TestManifest_FieldsOutsideTheStructAreCompared(t *testing.T) {
	r := NewRecorder("run-1")
	r.Record(EntryTypeToolOutput, "executor", "tool", []byte("out"))
	entries := r.Entries()
	entries[0].DataClass = "PUBLIC"
	sum := entries[0].ValueHash

	read := func(t *testing.T, row string) *Manifest {
		t.Helper()
		dir := t.TempDir()
		doc := `{"run_id":"run-1","entries":[` + row + `]}`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "tape_manifest.json"), []byte(doc), 0o600))
		tape, err := LoadTape(os.DirFS(dir).(LstatFS), ".")
		require.NoError(t, err)
		return tape.Manifest
	}
	base := `"seq":1,"type":"TOOL_OUTPUT","key":"tool","sha256":"` + sum + `","size_bytes":3`

	require.Empty(t, VerifyManifestIntegrity(entries, read(t, `{`+base+`}`)))
	require.Empty(t, VerifyManifestIntegrity(entries, read(t, `{`+base+`,"component_id":"executor","data_class":"PUBLIC"}`)))

	issues := VerifyManifestIntegrity(entries, read(t, `{`+base+`,"component_id":"someone-else"}`))
	require.Equal(t, []string{`seq=1 manifest field "component_id" is "someone-else", tape entry has "executor"`}, issues)

	issues = VerifyManifestIntegrity(entries, read(t, `{`+base+`,"approved_by":"nobody"}`))
	require.Equal(t, []string{`seq=1 manifest field "approved_by" has no counterpart on the tape entry, so it cannot be compared`}, issues)

	// A row that leaves out a field the recorder always writes is not a row
	// the recorder wrote, and the field it leaves out is compared with
	// nothing. It used to make no statement about it and pass.
	require.Equal(t, []string{
		`seq=1 manifest row lacks "key", "size_bytes", "type": the recorder writes seq, type, key, sha256 and size_bytes on every row`,
	}, VerifyManifestIntegrity(entries, read(t, `{"seq":1,"sha256":"`+sum+`"}`)))
}

// F3: rows that carried only seq replayed as COMPLETE, because only the fields
// a row carries were compared. Every row must carry the fields the recorder
// writes, and a missing one is an issue.
func TestManifest_RowsMustCarryEveryFieldTheRecorderWrites(t *testing.T) {
	r := NewRecorder("run-1")
	r.Record(EntryTypeToolOutput, "executor", "tool", []byte("out"))
	r.Record(EntryTypeTime, "kernel", "time", []byte("now"))
	entries := r.Entries()

	var manifest Manifest
	require.NoError(t, json.Unmarshal([]byte(`{"run_id":"run-1","entries":[{"seq":1},{"seq":2,"type":null,"key":"time","sha256":"`+entries[1].ValueHash+`","size_bytes":3}]}`), &manifest))
	issues := VerifyManifestIntegrity(entries, &manifest)
	require.Contains(t, issues, `seq=1 manifest row lacks "key", "sha256", "size_bytes", "type": the recorder writes seq, type, key, sha256 and size_bytes on every row`)
	// A field written as null is carried, and compared.
	require.Contains(t, issues, `seq=2 manifest field "type" is null, tape entry has "TIME"`)

	// A row without seq cannot be matched to an entry at all.
	manifest = Manifest{}
	require.NoError(t, json.Unmarshal([]byte(`{"run_id":"run-1","entries":[{"type":"TOOL_OUTPUT","key":"tool","sha256":"`+entries[0].ValueHash+`","size_bytes":3}]}`), &manifest))
	issues = VerifyManifestIntegrity(entries, &manifest)
	require.Contains(t, issues, `seq=0 manifest row lacks "seq": the recorder writes seq, type, key, sha256 and size_bytes on every row`)

	// The rows the recorder builds carry every field.
	require.Empty(t, VerifyManifestIntegrity(entries, r.BuildManifest()))
}

func TestManifest_RowListedTwiceAndRowWithoutEntry(t *testing.T) {
	r := NewRecorder("run-1")
	r.Record(EntryTypeTime, "k", "t", []byte("now"))
	entries := r.Entries()
	manifest := r.BuildManifest()
	manifest.Entries = append(manifest.Entries, manifest.Entries[0], ManifestItem{Seq: 7})

	issues := VerifyManifestIntegrity(entries, manifest)
	require.Equal(t, []string{
		"seq=1 is listed 2 times in tape_manifest.json",
		"seq=7 referenced in manifest but not in entries",
	}, issues)
}
