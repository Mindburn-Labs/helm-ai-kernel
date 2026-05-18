package skillpacks

import (
	"os"
	"path/filepath"
	"strings"
)

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
