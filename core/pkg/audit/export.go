package audit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
)

var (
	// ErrEmptyTenantID is returned when tenant ID is empty.
	ErrEmptyTenantID = errors.New("audit: tenant_id must not be empty")
	// ErrInvalidTimeRange is returned when start time is after end time.
	ErrInvalidTimeRange = errors.New("audit: start_time must be before end_time")
	// ErrStoreNotConfigured is returned when audit export is invoked without a backing store.
	ErrStoreNotConfigured = errors.New("audit: store not configured (fail-closed)")
)

// ExportRequest defines what to export.
type ExportRequest struct {
	TenantID  string    `json:"tenant_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// AuditEvidencePack represents the exported bundle.
type AuditEvidencePack struct {
	TenantID    string    `json:"tenant_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Checksum    string    `json:"checksum"`
	DownloadURL string    `json:"download_url,omitempty"` // If stored in bucket
	Events      []Event   `json:"events"`
}

// Exporter handles the creation of evidence packs.
type Exporter struct {
	store *store.AuditStore
}

func NewExporter(s *store.AuditStore) *Exporter {
	return &Exporter{store: s}
}

// GeneratePack creates a zip file containing the audit logs and a manifest with checksums.
func (e *Exporter) GeneratePack(ctx context.Context, req ExportRequest) ([]byte, string, error) {
	if req.TenantID == "" {
		return nil, "", ErrEmptyTenantID
	}
	if !req.StartTime.IsZero() && !req.EndTime.IsZero() && req.StartTime.After(req.EndTime) {
		return nil, "", ErrInvalidTimeRange
	}
	if e.store == nil {
		return nil, "", ErrStoreNotConfigured
	}

	filter := store.QueryFilter{
		EntryType: store.EntryTypeAudit,
		Subject:   "tenant:" + req.TenantID,
	}
	if !req.StartTime.IsZero() {
		filter.StartTime = &req.StartTime
	}
	if !req.EndTime.IsZero() {
		filter.EndTime = &req.EndTime
	}
	entries := e.store.Query(filter)

	// 2. Serialize Events
	eventsJSON, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, "", err
	}

	// 3. Create Manifest
	manifest := map[string]interface{}{
		"tenant_id":    req.TenantID,
		"generated_at": time.Now(),
		"event_count":  len(entries),
		"chain_head":   e.store.GetChainHead(),
		"period": map[string]interface{}{
			"start": req.StartTime,
			"end":   req.EndTime,
		},
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("audit: failed to marshal manifest: %w", err)
	}

	// 4. Create Zip
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	// Add events.json
	f, err := w.Create("events.json")
	if err != nil {
		return nil, "", err
	}
	_, _ = f.Write(eventsJSON)

	// Add manifest.json
	f, err = w.Create("manifest.json")
	if err != nil {
		return nil, "", err
	}
	_, _ = f.Write(manifestJSON)

	// Add README
	f, err = w.Create("README.txt")
	if err != nil {
		return nil, "", err
	}
	_, _ = fmt.Fprintf(f, "Evidence Pack for Tenant %s\nGenerated at %s\n", req.TenantID, time.Now())

	if err := w.Close(); err != nil {
		return nil, "", err
	}

	// 5. Calculate Checksum of the Zip
	zipBytes := buf.Bytes()
	hash := sha256.Sum256(zipBytes)
	checksum := hex.EncodeToString(hash[:])

	return zipBytes, checksum, nil
}
