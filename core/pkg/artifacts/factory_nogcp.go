//go:build !gcp

package artifacts

import (
	"context"
	"fmt"
)

func newGCSStoreFromEnv(ctx context.Context) (Store, error) {
	return nil, fmt.Errorf("GCS storage is not enabled in this build (use -tags gcp)")
}
