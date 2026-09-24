package skillpacks

import (
	"path/filepath"
	"strings"
)

// atomicWrite replaces rel under rootDir. os.Root confines every operation to
// rootDir, symlinked path components and a symlinked target are refused, and
// the bytes are staged in a freshly created O_EXCL file with a random name, so
// a planted "<name>.tmp" link or a symlinked directory cannot redirect them.
func atomicWrite(rootDir, rel string, data []byte) error {
	root, err := openManagedRoot(rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return atomicReplaceManagedAt(root, rel, data)
}

func sanitizePathSegment(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "://", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "\\", "_")
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = filepath.Clean(value)
	value = strings.Trim(value, ".")
	if value == "" || value == string(filepath.Separator) {
		return "skill"
	}
	return value
}
