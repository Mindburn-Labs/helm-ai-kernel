package conform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stubGate is a test gate for engine tests.
type stubGate struct {
	id     string
	name   string
	pass   bool
	reason string
}

func (g *stubGate) ID() string   { return g.id }
func (g *stubGate) Name() string { return g.name }
func (g *stubGate) Run(_ *RunContext) *GateResult {
	r := &GateResult{
		GateID:  g.id,
		Pass:    g.pass,
		Reasons: []string{},
	}
	if !g.pass && g.reason != "" {
		r.Reasons = append(r.Reasons, g.reason)
	}
	return r
}

func TestEngine_RegisterAndRun(t *testing.T) {
	e := NewEngine()
	e.RegisterGate(&stubGate{id: "G0", name: "Build Identity", pass: true})
	e.RegisterGate(&stubGate{id: "G1", name: "Proof Receipts", pass: true})

	dir := t.TempDir()
	report, err := e.Run(&RunOptions{
		Profile:     ProfileCore,
		ProjectRoot: dir,
		OutputDir:   filepath.Join(dir, "evidence"),
	})
	require.NoError(t, err)
	require.NotNil(t, report)
	require.Equal(t, ProfileCore, report.Profile)

	// Only G0 and G1 registered; CORE requires more,
	// so only those two should run
	found := 0
	for _, r := range report.GateResults {
		if r.GateID == "G0" || r.GateID == "G1" {
			require.True(t, r.Pass)
			found++
		}
	}
	require.Equal(t, 2, found)
}

func TestEngine_FailingGate(t *testing.T) {
	e := NewEngine()
	e.RegisterGate(&stubGate{id: "G0", name: "Build", pass: true})
	e.RegisterGate(&stubGate{id: "G1", name: "Proof", pass: false, reason: ReasonReceiptChainBroken})

	dir := t.TempDir()
	report, err := e.Run(&RunOptions{
		Profile:     ProfileCore,
		ProjectRoot: dir,
		OutputDir:   filepath.Join(dir, "evidence"),
	})
	require.NoError(t, err)
	require.False(t, report.Pass, "report must fail when any gate fails")

	for _, r := range report.GateResults {
		if r.GateID == "G1" {
			require.False(t, r.Pass)
			require.Contains(t, r.Reasons, ReasonReceiptChainBroken)
		}
	}
}

func TestEngine_MissingGate(t *testing.T) {
	e := NewEngine()
	// Register only G0, but filter asks for G0 and G1
	e.RegisterGate(&stubGate{id: "G0", name: "Build", pass: true})

	dir := t.TempDir()
	report, err := e.Run(&RunOptions{
		Profile:     ProfileCore,
		ProjectRoot: dir,
		OutputDir:   filepath.Join(dir, "evidence"),
		GateFilter:  []string{"G0", "G1"},
	})
	require.NoError(t, err)
	require.False(t, report.Pass, "missing gate must fail")
}

func TestEngine_ScoreFileWritten(t *testing.T) {
	e := NewEngine()
	e.RegisterGate(&stubGate{id: "G0", name: "Build", pass: true})

	dir := t.TempDir()
	report, err := e.Run(&RunOptions{
		Profile:     ProfileCore,
		ProjectRoot: dir,
		OutputDir:   filepath.Join(dir, "evidence"),
		GateFilter:  []string{"G0"},
	})
	require.NoError(t, err)

	// Find the evidence directory
	scorePath := filepath.Join(dir, "evidence", report.Timestamp.Format("2006-01-02"), report.RunID, "01_SCORE.json")
	data, err := os.ReadFile(scorePath)
	require.NoError(t, err)

	var decoded ConformanceReport
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.True(t, decoded.Pass)
}

func TestEngine_IndexFileWritten(t *testing.T) {
	e := NewEngine()
	e.RegisterGate(&stubGate{id: "G0", name: "Build", pass: true})

	dir := t.TempDir()
	report, err := e.Run(&RunOptions{
		Profile:     ProfileCore,
		ProjectRoot: dir,
		OutputDir:   filepath.Join(dir, "evidence"),
		GateFilter:  []string{"G0"},
	})
	require.NoError(t, err)

	indexPath := filepath.Join(dir, "evidence", report.Timestamp.Format("2006-01-02"), report.RunID, "00_INDEX.json")
	data, err := os.ReadFile(indexPath)
	require.NoError(t, err)

	var manifest IndexManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, report.RunID, manifest.RunID)
	require.NotEmpty(t, manifest.Entries)
}

func TestEngine_DeterministicClock(t *testing.T) {
	fixed := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	e := NewEngine().WithClock(func() time.Time { return fixed })
	e.RegisterGate(&stubGate{id: "G0", name: "Build", pass: true})

	dir := t.TempDir()
	report, err := e.Run(&RunOptions{
		Profile:     ProfileCore,
		ProjectRoot: dir,
		OutputDir:   filepath.Join(dir, "evidence"),
		GateFilter:  []string{"G0"},
	})
	require.NoError(t, err)
	require.Equal(t, fixed, report.Timestamp)
}
