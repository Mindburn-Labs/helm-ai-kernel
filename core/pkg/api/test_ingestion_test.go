package api_test

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
)

func TestIngestionEndToEnd(t *testing.T) {
	// 1. Setup — NewMemoryService is a kernel stub (no pipeline in OSS mode)
	svc := api.NewMemoryService()

	// 2. Create Request — IngestRequest only has TenantID + SourceID in kernel mode
	req := api.IngestRequest{
		TenantID: "tenant-1",
		SourceID: "gmail-adapter",
	}

	// 3. Execute — expect stub error since kernel mode doesn't have real ingestion
	resp, err := svc.Ingest(context.Background(), req)
	if err == nil {
		t.Fatal("Expected ingestion to fail in kernel mode, but got nil error")
	}

	// 4. Verify — in kernel mode, response should be nil
	if resp != nil {
		t.Errorf("Expected nil response in kernel mode, got %+v", resp)
	}
}
