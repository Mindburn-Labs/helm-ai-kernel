package main

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

func safeArchiveEntryPath(dstDir, entryName string) (string, error) {
	normalized := path.Clean(strings.ReplaceAll(entryName, "\\", "/"))
	if normalized == "." || normalized == ".." || path.IsAbs(normalized) || strings.HasPrefix(normalized, "../") || hasWindowsDrivePrefix(normalized) {
		return "", fmt.Errorf("archive entry escapes destination: %s", entryName)
	}

	localName := filepath.FromSlash(normalized)
	baseName := filepath.Clean(localName)
	if !filepath.IsLocal(baseName) {
		return "", fmt.Errorf("archive entry escapes destination: %s", entryName)
	}
	return filepath.Join(dstDir, baseName), nil
}

func hasWindowsDrivePrefix(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	first := name[0]
	return ('a' <= first && first <= 'z') || ('A' <= first && first <= 'Z')
}
