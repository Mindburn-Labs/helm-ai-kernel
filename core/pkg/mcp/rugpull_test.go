package mcp

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestRugPullDetector_FirstRegistrationReturnsNil(t *testing.T) {
	d := NewRugPullDetector()

	finding, err := d.RegisterTool("server-a", "file_read", "Read a file", json.RawMessage(`{"type":"object"}`))
	require.NoError(t, err)
	assert.Nil(t, finding, "first registration should return nil (trust-on-first-use)")
}

func TestRugPullDetector_SameToolReregisteredReturnsNil(t *testing.T) {
	d := NewRugPullDetector()

	schema := json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)

	_, err := d.RegisterTool("server-a", "file_read", "Read a file", schema)
	require.NoError(t, err)

	finding, err := d.RegisterTool("server-a", "file_read", "Read a file", schema)
	require.NoError(t, err)
	assert.Nil(t, finding, "unchanged re-registration should return nil")
}

func TestRugPullDetector_DescriptionChangeDetected(t *testing.T) {
	now := time.Date(2026, 4, 13, 10, 0, 0, 0, time.UTC)
	d := NewRugPullDetector(WithDetectorClock(fixedClock(now)))

	schema := json.RawMessage(`{"type":"object"}`)
	_, err := d.RegisterTool("server-a", "file_read", "Read a file", schema)
	require.NoError(t, err)

	finding, err := d.RegisterTool("server-a", "file_read", "Read a file from disk with extra powers", schema)
	require.NoError(t, err)
	require.NotNil(t, finding)

	assert.Equal(t, RugPullSeverityMedium, finding.Severity)
	assert.Equal(t, RugPullChangeDescription, finding.ChangeType)
	assert.Equal(t, "server-a", finding.ServerID)
	assert.Equal(t, "file_read", finding.ToolName)
	assert.Equal(t, 1, finding.PreviousVersion)
	assert.Equal(t, 2, finding.CurrentVersion)
	assert.Equal(t, now, finding.DetectedAt)
	assert.NotEmpty(t, finding.PreviousHash)
	assert.NotEmpty(t, finding.CurrentHash)
	assert.NotEqual(t, finding.PreviousHash, finding.CurrentHash)
	assert.Contains(t, finding.Description, "DESCRIPTION_CHANGED")
}

func TestRugPullDetector_SchemaChangeDetected(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "file_read", "Read a file",
		json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`))
	require.NoError(t, err)

	finding, err := d.RegisterTool("server-a", "file_read", "Read a file",
		json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"exec":{"type":"string"}}}`))
	require.NoError(t, err)
	require.NotNil(t, finding)

	assert.Equal(t, RugPullSeverityHigh, finding.Severity)
	assert.Equal(t, RugPullChangeSchema, finding.ChangeType)
}

func TestRugPullDetector_BothChangedDetected(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "file_read", "Read a file",
		json.RawMessage(`{"type":"object"}`))
	require.NoError(t, err)

	finding, err := d.RegisterTool("server-a", "file_read", "Execute arbitrary code",
		json.RawMessage(`{"type":"object","properties":{"cmd":{"type":"string"}}}`))
	require.NoError(t, err)
	require.NotNil(t, finding)

	assert.Equal(t, RugPullSeverityCritical, finding.Severity)
	assert.Equal(t, RugPullChangeBoth, finding.ChangeType)
	assert.Equal(t, 2, finding.CurrentVersion)
}

func TestRugPullDetector_ToolRemovedDetection(t *testing.T) {
	d := NewRugPullDetector()

	// Register two tools on the same server.
	_, err := d.RegisterTool("server-a", "file_read", "Read", nil)
	require.NoError(t, err)
	_, err = d.RegisterTool("server-a", "file_write", "Write", nil)
	require.NoError(t, err)

	// Check with only one tool present — the other should be flagged as removed.
	findings := d.CheckServer("server-a", []ToolDefinition{
		{Name: "file_read", Description: "Read"},
	})

	require.Len(t, findings, 1)
	assert.Equal(t, "file_write", findings[0].ToolName)
	assert.Equal(t, RugPullChangeRemoved, findings[0].ChangeType)
	assert.Equal(t, RugPullSeverityHigh, findings[0].Severity)
	assert.Empty(t, findings[0].CurrentHash)
	assert.NotEmpty(t, findings[0].PreviousHash)
	assert.Contains(t, findings[0].Description, "no longer present")
}

func TestRugPullDetector_NewToolAddedToExistingServer(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "file_read", "Read", nil)
	require.NoError(t, err)

	// Check with original tool plus a new one.
	findings := d.CheckServer("server-a", []ToolDefinition{
		{Name: "file_read", Description: "Read"},
		{Name: "exec_cmd", Description: "Execute a command", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	// No findings — new tools are trust-on-first-use, existing is unchanged.
	assert.Empty(t, findings)

	// Verify the new tool was registered.
	fp, ok := d.GetFingerprint("server-a", "exec_cmd")
	require.True(t, ok)
	assert.Equal(t, 1, fp.Version)
}

func TestRugPullDetector_VersionIncrementedOnEachChange(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "tool", "v1 desc", nil)
	require.NoError(t, err)

	for i := 2; i <= 5; i++ {
		finding, err := d.RegisterTool("server-a", "tool", fmt.Sprintf("v%d desc", i), nil)
		require.NoError(t, err)
		require.NotNil(t, finding, "change %d should produce finding", i)
		assert.Equal(t, i-1, finding.PreviousVersion)
		assert.Equal(t, i, finding.CurrentVersion)
	}

	fp, ok := d.GetFingerprint("server-a", "tool")
	require.True(t, ok)
	assert.Equal(t, 5, fp.Version)
}

func TestRugPullDetector_ConcurrentRegistrations(t *testing.T) {
	d := NewRugPullDetector()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			serverID := fmt.Sprintf("server-%d", n%5)
			toolName := fmt.Sprintf("tool-%d", n%10)
			_, _ = d.RegisterTool(serverID, toolName, "description", json.RawMessage(`{"type":"object"}`))
		}(i)
	}
	wg.Wait()

	// Verify no panic and state is consistent.
	all := d.AllFingerprints()
	assert.NotEmpty(t, all)

	for _, fp := range all {
		assert.NotEmpty(t, fp.ServerID)
		assert.NotEmpty(t, fp.ToolName)
		assert.NotEmpty(t, fp.CombinedHash)
		assert.True(t, fp.Version >= 1)
	}
}

func TestRugPullDetector_ClockInjection(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	current := t1
	d := NewRugPullDetector(WithDetectorClock(func() time.Time { return current }))

	_, err := d.RegisterTool("server-a", "tool", "desc", nil)
	require.NoError(t, err)

	fp, ok := d.GetFingerprint("server-a", "tool")
	require.True(t, ok)
	assert.Equal(t, t1, fp.FirstSeen)
	assert.Equal(t, t1, fp.LastSeen)
	assert.True(t, fp.LastChanged.IsZero())

	// Advance clock and trigger a change.
	current = t2
	finding, err := d.RegisterTool("server-a", "tool", "changed desc", nil)
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, t2, finding.DetectedAt)

	fp, ok = d.GetFingerprint("server-a", "tool")
	require.True(t, ok)
	assert.Equal(t, t1, fp.FirstSeen, "first-seen should not change")
	assert.Equal(t, t2, fp.LastSeen)
	assert.Equal(t, t2, fp.LastChanged)
}

func TestRugPullDetector_MultipleServersIndependentTracking(t *testing.T) {
	d := NewRugPullDetector()

	// Same tool name on different servers — independent fingerprints.
	_, err := d.RegisterTool("server-a", "file_read", "Read from server A", nil)
	require.NoError(t, err)
	_, err = d.RegisterTool("server-b", "file_read", "Read from server B", nil)
	require.NoError(t, err)

	fpA, ok := d.GetFingerprint("server-a", "file_read")
	require.True(t, ok)
	fpB, ok := d.GetFingerprint("server-b", "file_read")
	require.True(t, ok)

	// Different descriptions → different hashes.
	assert.NotEqual(t, fpA.CombinedHash, fpB.CombinedHash)

	// Changing one server's tool should not affect the other.
	finding, err := d.RegisterTool("server-a", "file_read", "MUTATED description", nil)
	require.NoError(t, err)
	require.NotNil(t, finding)
	assert.Equal(t, "server-a", finding.ServerID)

	// Server B unchanged.
	fpB2, ok := d.GetFingerprint("server-b", "file_read")
	require.True(t, ok)
	assert.Equal(t, fpB.CombinedHash, fpB2.CombinedHash)
}

func TestRugPullDetector_EmptyDescriptionAndSchema(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "tool", "", nil)
	require.NoError(t, err)

	fp, ok := d.GetFingerprint("server-a", "tool")
	require.True(t, ok)
	assert.NotEmpty(t, fp.DescriptionHash, "empty description should still hash to a value")
	assert.NotEmpty(t, fp.SchemaHash, "nil schema should still hash to a value")
	assert.NotEmpty(t, fp.CombinedHash)
	assert.Equal(t, 1, fp.Version)
}

func TestRugPullDetector_LargeSchemaHandling(t *testing.T) {
	d := NewRugPullDetector()

	// Build a large schema with many properties.
	props := make(map[string]any, 100)
	for i := 0; i < 100; i++ {
		props[fmt.Sprintf("field_%d", i)] = map[string]any{"type": "string"}
	}
	largeSchema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	schemaBytes, err := json.Marshal(largeSchema)
	require.NoError(t, err)

	finding, regErr := d.RegisterTool("server-a", "big_tool", "A tool with many fields", schemaBytes)
	require.NoError(t, regErr)
	assert.Nil(t, finding)

	fp, ok := d.GetFingerprint("server-a", "big_tool")
	require.True(t, ok)
	assert.NotEmpty(t, fp.SchemaHash)

	// Re-register with same schema — should produce no finding.
	finding, regErr = d.RegisterTool("server-a", "big_tool", "A tool with many fields", schemaBytes)
	require.NoError(t, regErr)
	assert.Nil(t, finding)
}

func TestRugPullDetector_CheckServerBatchOperation(t *testing.T) {
	d := NewRugPullDetector()

	// Initial registration via CheckServer.
	findings := d.CheckServer("server-a", []ToolDefinition{
		{Name: "tool_a", Description: "Alpha"},
		{Name: "tool_b", Description: "Beta"},
		{Name: "tool_c", Description: "Gamma"},
	})
	assert.Empty(t, findings, "first check should produce no findings")

	// Check again with one changed, one removed, one new.
	findings = d.CheckServer("server-a", []ToolDefinition{
		{Name: "tool_a", Description: "Alpha"},        // unchanged
		{Name: "tool_b", Description: "Beta MUTATED"}, // changed
		{Name: "tool_d", Description: "Delta"},        // new
		// tool_c is missing → should be detected as removed
	})

	require.Len(t, findings, 2)

	// Collect findings by type for assertion.
	findingsByChange := make(map[RugPullChange]RugPullFinding)
	for _, f := range findings {
		findingsByChange[f.ChangeType] = f
	}

	changed, ok := findingsByChange[RugPullChangeDescription]
	require.True(t, ok, "should detect description change")
	assert.Equal(t, "tool_b", changed.ToolName)

	removed, ok := findingsByChange[RugPullChangeRemoved]
	require.True(t, ok, "should detect tool removal")
	assert.Equal(t, "tool_c", removed.ToolName)
}

func TestRugPullDetector_FingerprintSnapshotIsolation(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "tool", "original", nil)
	require.NoError(t, err)

	// Take a snapshot.
	snapshot := d.AllFingerprints()
	require.Len(t, snapshot, 1)

	originalHash := snapshot["server-a:tool"].CombinedHash

	// Modify the tool after snapshot.
	_, err = d.RegisterTool("server-a", "tool", "mutated", nil)
	require.NoError(t, err)

	// Snapshot should be unaffected.
	assert.Equal(t, originalHash, snapshot["server-a:tool"].CombinedHash,
		"snapshot should be isolated from subsequent mutations")

	// New snapshot should reflect the change.
	newSnapshot := d.AllFingerprints()
	assert.NotEqual(t, originalHash, newSnapshot["server-a:tool"].CombinedHash)
}

func TestRugPullDetector_GetFingerprintReturnsCopy(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "tool", "desc", nil)
	require.NoError(t, err)

	fp1, ok := d.GetFingerprint("server-a", "tool")
	require.True(t, ok)

	// Mutate the returned copy.
	fp1.Version = 999
	fp1.CombinedHash = "tampered"

	// Original should be unaffected.
	fp2, ok := d.GetFingerprint("server-a", "tool")
	require.True(t, ok)
	assert.Equal(t, 1, fp2.Version)
	assert.NotEqual(t, "tampered", fp2.CombinedHash)
}

func TestRugPullDetector_Reset(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "tool1", "desc", nil)
	require.NoError(t, err)
	_, err = d.RegisterTool("server-b", "tool2", "desc", nil)
	require.NoError(t, err)

	all := d.AllFingerprints()
	assert.Len(t, all, 2)

	d.Reset()

	all = d.AllFingerprints()
	assert.Empty(t, all)

	// After reset, registrations are first-seen again.
	finding, err := d.RegisterTool("server-a", "tool1", "completely different", nil)
	require.NoError(t, err)
	assert.Nil(t, finding, "after reset, should be trust-on-first-use")
}

func TestRugPullDetector_ValidationErrors(t *testing.T) {
	d := NewRugPullDetector()

	t.Run("empty server ID", func(t *testing.T) {
		_, err := d.RegisterTool("", "tool", "desc", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server ID is required")
	})

	t.Run("empty tool name", func(t *testing.T) {
		_, err := d.RegisterTool("server-a", "", "desc", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tool name is required")
	})
}

func TestRugPullDetector_GetFingerprintNotFound(t *testing.T) {
	d := NewRugPullDetector()

	fp, ok := d.GetFingerprint("nonexistent", "tool")
	assert.False(t, ok)
	assert.Nil(t, fp)
}

func TestRugPullDetector_SchemaKeyOrderInsensitive(t *testing.T) {
	d := NewRugPullDetector()

	// Register with one key order.
	_, err := d.RegisterTool("server-a", "tool", "desc",
		json.RawMessage(`{"type":"object","properties":{"b":"2","a":"1"}}`))
	require.NoError(t, err)

	// Re-register with a different key order — should produce no finding
	// because canonical JSON re-encoding sorts keys.
	finding, err := d.RegisterTool("server-a", "tool", "desc",
		json.RawMessage(`{"properties":{"a":"1","b":"2"},"type":"object"}`))
	require.NoError(t, err)
	assert.Nil(t, finding, "different JSON key order should produce the same canonical hash")
}

func TestRugPullDetector_InvalidJSONSchemaHashedAsIs(t *testing.T) {
	d := NewRugPullDetector()

	// Invalid JSON as schema — should not panic, just hash raw bytes.
	_, err := d.RegisterTool("server-a", "tool", "desc", json.RawMessage(`{not valid json!!!`))
	require.NoError(t, err)

	fp, ok := d.GetFingerprint("server-a", "tool")
	require.True(t, ok)
	assert.NotEmpty(t, fp.SchemaHash)
}

func TestRugPullDetector_CheckServerEmptyToolList(t *testing.T) {
	d := NewRugPullDetector()

	// Register a tool first.
	_, err := d.RegisterTool("server-a", "tool", "desc", nil)
	require.NoError(t, err)

	// Check with empty tool list — the registered tool should be flagged as removed.
	findings := d.CheckServer("server-a", nil)
	require.Len(t, findings, 1)
	assert.Equal(t, RugPullChangeRemoved, findings[0].ChangeType)
	assert.Equal(t, "tool", findings[0].ToolName)
}

func TestRugPullDetector_CheckServerDoesNotAffectOtherServers(t *testing.T) {
	d := NewRugPullDetector()

	_, err := d.RegisterTool("server-a", "tool", "desc A", nil)
	require.NoError(t, err)
	_, err = d.RegisterTool("server-b", "tool", "desc B", nil)
	require.NoError(t, err)

	// Check server-a with empty list — only server-a's tool should be removed.
	findings := d.CheckServer("server-a", nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "server-a", findings[0].ServerID)

	// Server-b's fingerprint should be untouched.
	fp, ok := d.GetFingerprint("server-b", "tool")
	require.True(t, ok)
	assert.Equal(t, 1, fp.Version)
}

func TestHashContent(t *testing.T) {
	h := hashContent([]byte("hello"))
	assert.True(t, len(h) > 10)
	assert.Contains(t, h, "sha256:")

	// Deterministic.
	assert.Equal(t, h, hashContent([]byte("hello")))

	// Different input → different hash.
	assert.NotEqual(t, h, hashContent([]byte("world")))
}

func TestCombineHashes(t *testing.T) {
	h1 := hashContent([]byte("a"))
	h2 := hashContent([]byte("b"))

	combined := combineHashes(h1, h2)
	assert.Contains(t, combined, "sha256:")

	// Deterministic.
	assert.Equal(t, combined, combineHashes(h1, h2))

	// Order matters.
	assert.NotEqual(t, combined, combineHashes(h2, h1))
}

func TestCanonicalSchemaHash(t *testing.T) {
	t.Run("nil schema", func(t *testing.T) {
		h := canonicalSchemaHash(nil)
		assert.Contains(t, h, "sha256:")
	})

	t.Run("empty schema", func(t *testing.T) {
		h := canonicalSchemaHash(json.RawMessage{})
		assert.Contains(t, h, "sha256:")
	})

	t.Run("deterministic for same content", func(t *testing.T) {
		schema := json.RawMessage(`{"type":"object","properties":{"a":"1"}}`)
		assert.Equal(t, canonicalSchemaHash(schema), canonicalSchemaHash(schema))
	})

	t.Run("key order insensitive", func(t *testing.T) {
		s1 := json.RawMessage(`{"b":"2","a":"1"}`)
		s2 := json.RawMessage(`{"a":"1","b":"2"}`)
		assert.Equal(t, canonicalSchemaHash(s1), canonicalSchemaHash(s2))
	})
}
