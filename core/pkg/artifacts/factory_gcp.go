//go:build gcp

package artifacts

import (
	"context"
	"fmt"
	"os"
)

func newGCSStoreFromEnv(ctx context.Context) (Store, error) {
	bucket := os.Getenv("ARTIFACT_GCS_BUCKET")
	if bucket == "" {
		return nil, fmt.Errorf("ARTIFACT_GCS_BUCKET is required for GCS storage")
	}

	cfg := GCSStoreConfig{
		Bucket: bucket,
		Prefix: os.Getenv("ARTIFACT_GCS_PREFIX"),
	}

	return NewGCSStore(ctx, cfg)
}
