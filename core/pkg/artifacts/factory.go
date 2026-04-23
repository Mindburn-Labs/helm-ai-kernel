package artifacts

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// StoreType represents the type of artifact storage backend.
type StoreType string

const (
	StoreTypeFS  StoreType = "fs"
	StoreTypeS3  StoreType = "s3"
	StoreTypeGCS StoreType = "gcs"
)

// NewStoreFromEnv creates an artifact store based on environment variables.
//
// Environment variables:
//   - ARTIFACT_STORAGE_TYPE: "fs" (default), "s3", or "gcs"
//   - DATA_DIR: Base directory for filesystem store (default: "data")
//
// For S3:
//   - AWS_REGION or ARTIFACT_S3_REGION
//   - ARTIFACT_S3_BUCKET (required)
//   - ARTIFACT_S3_ENDPOINT (optional, for MinIO/LocalStack)
//   - ARTIFACT_S3_PREFIX (optional)
//
// For GCS:
//   - ARTIFACT_GCS_BUCKET (required)
//   - ARTIFACT_GCS_PREFIX (optional)
func NewStoreFromEnv(ctx context.Context) (Store, error) {
	storeType := StoreType(os.Getenv("ARTIFACT_STORAGE_TYPE"))
	if storeType == "" {
		storeType = StoreTypeFS
	}

	switch storeType {
	case StoreTypeFS:
		return newFileStoreFromEnv()
	case StoreTypeS3:
		return newS3StoreFromEnv(ctx)
	case StoreTypeGCS:
		return newGCSStoreFromEnv(ctx)
	default:
		return nil, fmt.Errorf("unsupported artifact storage type: %s", storeType)
	}
}

func newFileStoreFromEnv() (Store, error) {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}
	return NewFileStore(filepath.Join(dataDir, "artifacts"))
}

func newS3StoreFromEnv(ctx context.Context) (Store, error) {
	bucket := os.Getenv("ARTIFACT_S3_BUCKET")
	if bucket == "" {
		return nil, fmt.Errorf("ARTIFACT_S3_BUCKET is required for S3 storage")
	}

	region := os.Getenv("ARTIFACT_S3_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	cfg := S3StoreConfig{
		Bucket:   bucket,
		Region:   region,
		Endpoint: os.Getenv("ARTIFACT_S3_ENDPOINT"),
		Prefix:   os.Getenv("ARTIFACT_S3_PREFIX"),
	}

	return NewS3Store(ctx, cfg)
}
