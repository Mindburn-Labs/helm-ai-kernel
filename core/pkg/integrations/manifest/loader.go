package manifest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LoadFromDir loads all .json manifest files from a directory.
// Each file must contain a single IntegrationManifest. Files that fail
// validation are collected in the returned error.
func LoadFromDir(dir string) ([]IntegrationManifest, error) {
	var manifests []IntegrationManifest
	var loadErrors []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		m, err := LoadFromFile(path)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", path, err))
			return nil // Continue loading other files.
		}
		manifests = append(manifests, *m)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk manifest directory %s: %w", dir, err)
	}
	if len(loadErrors) > 0 {
		return manifests, fmt.Errorf("errors loading manifests:\n  - %s", strings.Join(loadErrors, "\n  - "))
	}
	return manifests, nil
}

// LoadFromFile loads and validates a single manifest from a JSON file.
func LoadFromFile(path string) (*IntegrationManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest file: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates an IntegrationManifest from raw JSON bytes.
func Parse(data []byte) (*IntegrationManifest, error) {
	var m IntegrationManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	if err := Validate(&m); err != nil {
		return nil, err
	}
	return &m, nil
}
