package gates

import (
	"os"
)

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func firstExistingFile(paths ...string) string {
	for _, path := range paths {
		if fileExists(path) {
			return path
		}
	}
	return ""
}
