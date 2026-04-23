package mcp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTyposquatDetector_ExactMatchDifferentServer(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "github")

	// Identical name on a different server is NOT typosquatting (distance 0).
	findings := d.Check("server-b", "github")
	assert.Empty(t, findings, "identical tool name on different server should not be flagged")
}

func TestTyposquatDetector_Distance1(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	d := NewTyposquatDetector(WithTyposquatClock(fixedClock(now)))
	d.Register("server-a", "github")

	findings := d.Check("server-b", "g1thub")
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "g1thub", f.ToolName)
	assert.Equal(t, "server-b", f.ServerID)
	assert.Equal(t, "github", f.SimilarTool)
	assert.Equal(t, "server-a", f.SimilarServer)
	assert.Equal(t, 1, f.Distance)
	assert.Equal(t, now, f.DetectedAt)
}

func TestTyposquatDetector_Distance2(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "github")

	// "g1thib" differs in 2 positions from "github" (i→1, u→i).
	findings := d.Check("server-b", "g1thib")
	require.Len(t, findings, 1)
	assert.Equal(t, 2, findings[0].Distance)
}

func TestTyposquatDetector_DistanceAboveThreshold(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "github")

	// "completely_different" has high Levenshtein distance from "github" (beyond default threshold 2).
	findings := d.Check("server-b", "completely_different")
	assert.Empty(t, findings, "distance > threshold should not produce a finding")
}

func TestTyposquatDetector_SameServerNeverFlags(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "github")

	// "g1thub" is distance 1 but on the same server — should not flag.
	findings := d.Check("server-a", "g1thub")
	assert.Empty(t, findings, "same-server comparison should never produce a finding")
}

func TestTyposquatDetector_MultipleTools(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "file_read")
	d.Register("server-b", "file_write")

	// "file_reed" is distance 1 from "file_read" (server-a) and
	// distance 2 from "file_write" (server-b, but checking from server-c).
	// Actually: file_reed vs file_write is distance 4, so only file_read should match.
	findings := d.Check("server-c", "file_reed")
	require.Len(t, findings, 1)
	assert.Equal(t, "file_read", findings[0].SimilarTool)
	assert.Equal(t, "server-a", findings[0].SimilarServer)
	assert.Equal(t, 1, findings[0].Distance)
}

func TestTyposquatDetector_MultipleFindings(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "read")
	d.Register("server-b", "reed")

	// "resd" is distance 1 from "read" and distance 1 from "reed".
	findings := d.Check("server-c", "resd")
	require.Len(t, findings, 2, "should match both similar tools")
}

func TestTyposquatDetector_ConcurrentAccess(t *testing.T) {
	d := NewTyposquatDetector()

	var wg sync.WaitGroup
	const goroutines = 50

	// Register tools concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			serverID := "server-a"
			if idx%2 == 0 {
				serverID = "server-b"
			}
			d.Register(serverID, toolName(idx))
		}(i)
	}
	wg.Wait()

	// Check tools concurrently.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Just verify it doesn't panic or race.
			_ = d.Check("server-c", toolName(idx))
		}(i)
	}
	wg.Wait()
}

func TestTyposquatDetector_CustomThreshold(t *testing.T) {
	d := NewTyposquatDetector(WithTyposquatThreshold(1))
	d.Register("server-a", "github")

	// Distance 1: should be flagged.
	findings := d.Check("server-b", "g1thub")
	require.Len(t, findings, 1)

	// Distance 2: should NOT be flagged with threshold=1.
	findings = d.Check("server-b", "g1thib")
	assert.Empty(t, findings, "distance 2 should not be flagged with threshold 1")
}

func TestTyposquatDetector_RegisterOverwrites(t *testing.T) {
	d := NewTyposquatDetector()
	d.Register("server-a", "github")
	d.Register("server-b", "github") // Overwrite with new server.

	// Now "g1thub" on server-a should match "github" on server-b (not server-a).
	findings := d.Check("server-a", "g1thub")
	require.Len(t, findings, 1)
	assert.Equal(t, "server-b", findings[0].SimilarServer)
}

func TestTyposquatDetector_EmptyRegistry(t *testing.T) {
	d := NewTyposquatDetector()

	findings := d.Check("server-a", "github")
	assert.Empty(t, findings, "empty registry should produce no findings")
}

func TestTyposquatDetector_CheckDoesNotRegister(t *testing.T) {
	d := NewTyposquatDetector()

	_ = d.Check("server-a", "github")

	// Verify the tool was not added by Check.
	d.mu.RLock()
	_, exists := d.tools["github"]
	d.mu.RUnlock()
	assert.False(t, exists, "Check should not register the tool")
}

func TestLevenshtein_BasicCases(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"kitten", "sitting", 3},
		{"github", "g1thub", 1},
		{"github", "gitlab", 2},
		{"a", "b", 1},
		{"ab", "ba", 2},
		{"flaw", "lawn", 2},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := levenshtein(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

// toolName generates a unique tool name for concurrency tests.
func toolName(idx int) string {
	names := []string{
		"file_read", "file_write", "github_push", "github_pull",
		"slack_send", "slack_recv", "db_query", "db_insert",
	}
	return names[idx%len(names)]
}
