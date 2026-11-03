package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFederatedReport_ReportFields(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 30, 0, 0, time.UTC)

	report := FederatedTrustReport{
		PeerID:     "peer-alpha",
		ServerID:   "mcp-server-1",
		ToolName:   "file_read",
		Score:      750,
		ReportedAt: now,
	}

	assert.Equal(t, "peer-alpha", report.PeerID)
	assert.Equal(t, "mcp-server-1", report.ServerID)
	assert.Equal(t, "file_read", report.ToolName)
	assert.Equal(t, 750, report.Score)
	assert.Equal(t, now, report.ReportedAt)
}
