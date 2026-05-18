package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Catalog struct {
	Root       string          `json:"root"`
	Apps       []AppSpec       `json:"apps"`
	Substrates []SubstrateSpec `json:"substrates"`
}

func LoadCatalog(root string) (*Catalog, error) {
	if root == "" {
		discovered, err := DiscoverRoot()
		if err != nil {
			return nil, err
		}
		root = discovered
	}
	apps, err := loadYAMLDir[AppSpec](filepath.Join(root, "registry", "launchpad", "apps"))
	if err != nil {
		return nil, err
	}
	substrates, err := loadYAMLDir[SubstrateSpec](filepath.Join(root, "registry", "launchpad", "substrates"))
	if err != nil {
		return nil, err
	}
	return &Catalog{Root: root, Apps: apps, Substrates: substrates}, nil
}

func DiscoverRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if exists(filepath.Join(dir, "registry", "launchpad")) && exists(filepath.Join(dir, "core", "go.mod")) {
			return dir, nil
		}
		if filepath.Base(dir) == "core" && exists(filepath.Join(filepath.Dir(dir), "registry", "launchpad")) {
			return filepath.Dir(dir), nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
	}
	return "", fmt.Errorf("launchpad registry root not found from %s", wd)
}

func loadYAMLDir[T any](dir string) ([]T, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []T
	for _, entry := range entries {
		if entry.IsDir() || !(strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var item T
		if err := yaml.Unmarshal(data, &item); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sortKey(out[i]) < sortKey(out[j])
	})
	return out, nil
}

func sortKey(v any) string {
	switch item := v.(type) {
	case AppSpec:
		return item.ID
	case SubstrateSpec:
		return item.ID
	default:
		return fmt.Sprintf("%v", v)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
