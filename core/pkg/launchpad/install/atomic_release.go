package install

import (
	"os"
	"path/filepath"
	"strings"
)

func ReleasePath(root, appID, digest string) string {
	cleanDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(root, "apps", appID, "releases", "sha256-"+cleanDigest)
}

func EnsureImmutableLayout(root, appID, digest string) (string, error) {
	releasePath := ReleasePath(root, appID, digest)
	for _, dir := range []string{
		releasePath,
		filepath.Join(root, "apps", appID, "state"),
		filepath.Join(root, "apps", appID, "logs"),
		filepath.Join(root, "apps", appID, "receipts"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	current := filepath.Join(root, "apps", appID, "current")
	_ = os.Remove(current)
	if err := os.Symlink(releasePath, current); err != nil {
		return "", err
	}
	return releasePath, nil
}
