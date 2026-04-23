package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/audit"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_Record_WritesStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWithWriter(&buf)

	err := logger.Record(context.Background(), audit.EventAccess, "login", "/api/v1/auth", nil)
	require.NoError(t, err)

	output := buf.String()
	assert.True(t, strings.HasPrefix(output, "AUDIT: "))

	// Parse the JSON part
	jsonPart := strings.TrimPrefix(output, "AUDIT: ")
	jsonPart = strings.TrimSpace(jsonPart)

	var event audit.Event
	err = json.Unmarshal([]byte(jsonPart), &event)
	require.NoError(t, err)

	assert.Equal(t, audit.EventAccess, event.Type)
	assert.Equal(t, "login", event.Action)
	assert.Equal(t, "/api/v1/auth", event.Resource)
	assert.Equal(t, "system", event.TenantID)
	assert.NotEmpty(t, event.ID)
	// UUID format: 8-4-4-4-12
	assert.Len(t, event.ID, 36)
}

func TestLogger_Record_WithMetadata(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLoggerWithWriter(&buf)

	meta := map[string]interface{}{"ip": "10.0.0.1", "user_agent": "test"}
	err := logger.Record(context.Background(), audit.EventMutation, "deploy", "/clusters/prod", meta)
	require.NoError(t, err)

	jsonPart := strings.TrimPrefix(buf.String(), "AUDIT: ")
	var event audit.Event
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(jsonPart)), &event))

	assert.Equal(t, "10.0.0.1", event.Metadata["ip"])
}

func TestExporter_GeneratePack_Success(t *testing.T) {
	audStore := store.NewAuditStore()
	exporter := audit.NewExporter(audStore)
	req := audit.ExportRequest{
		TenantID:  "tenant-123",
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	}

	zipBytes, checksum, err := exporter.GeneratePack(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, zipBytes)
	assert.Len(t, checksum, 64) // sha256 hex
}

func TestExporter_GeneratePack_EmptyTenantID(t *testing.T) {
	audStore := store.NewAuditStore()
	exporter := audit.NewExporter(audStore)
	req := audit.ExportRequest{TenantID: ""}

	_, _, err := exporter.GeneratePack(context.Background(), req)
	assert.ErrorIs(t, err, audit.ErrEmptyTenantID)
}

func TestExporter_GeneratePack_InvalidTimeRange(t *testing.T) {
	audStore := store.NewAuditStore()
	exporter := audit.NewExporter(audStore)
	req := audit.ExportRequest{
		TenantID:  "tenant-123",
		StartTime: time.Now(),
		EndTime:   time.Now().Add(-1 * time.Hour),
	}

	_, _, err := exporter.GeneratePack(context.Background(), req)
	assert.ErrorIs(t, err, audit.ErrInvalidTimeRange)
}

func TestExporter_GeneratePack_FailClosedWithoutStore(t *testing.T) {
	exporter := audit.NewExporter(nil)
	req := audit.ExportRequest{
		TenantID: "tenant-123",
	}

	_, _, err := exporter.GeneratePack(context.Background(), req)
	assert.ErrorIs(t, err, audit.ErrStoreNotConfigured)
}
