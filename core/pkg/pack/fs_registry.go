package pack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
)

// FSRegistry implements PackRegistry using a file system directory.
// Structure: <root>/<pack_id>/<version>/manifest.json
type FSRegistry struct {
	rootDir string
	mu      sync.RWMutex
}

// NewFSRegistry creates a new file system registry.
func NewFSRegistry(rootDir string) *FSRegistry {
	return &FSRegistry{
		rootDir: rootDir,
	}
}

// GetPack retrieves the latest version for a pack ID.
func (r *FSRegistry) GetPack(ctx context.Context, id string) (*Pack, error) {
	versions, err := r.ListVersions(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("pack not found: %s", id)
	}

	latest := versions[len(versions)-1]
	return r.loadPack(id, latest.Version)
}

// FindByCapability finds all packs with a given capability.
func (r *FSRegistry) FindByCapability(ctx context.Context, capability string) ([]Pack, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Pack

	// Walk the directory structure
	entries, err := os.ReadDir(r.rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Pack{}, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		packName := entry.Name()
		versions, err := r.ListVersions(ctx, packName)
		if err != nil {
			continue
		}
		if len(versions) == 0 {
			continue
		}

		// Check latest version only for capabilities
		latest := versions[len(versions)-1]
		p, err := r.loadPack(packName, latest.Version)
		if err != nil {
			continue
		}

		for _, cap := range p.Manifest.Capabilities {
			if cap == capability {
				result = append(result, *p)
				break
			}
		}
	}

	return result, nil
}

// ListVersions lists all available versions of a pack.
func (r *FSRegistry) ListVersions(ctx context.Context, packName string) ([]PackVersion, error) {
	packDir := filepath.Join(r.rootDir, packName)
	entries, err := os.ReadDir(packDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PackVersion{}, nil
		}
		return nil, err
	}

	var versions []PackVersion
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		version := entry.Name()
		p, err := r.loadPack(packName, version)
		if err != nil {
			// Skip invalid packs
			continue
		}
		versions = append(versions, PackVersion{
			PackName:    p.Manifest.Name,
			Version:     p.Manifest.Version,
			ContentHash: p.ContentHash,
			ReleasedAt:  p.CreatedAt,
		})
	}

	// Sort versions semantically
	sort.Slice(versions, func(i, j int) bool {
		vA, errA := semver.NewVersion(versions[i].Version)
		vB, errB := semver.NewVersion(versions[j].Version)
		if errA != nil || errB != nil {
			return versions[i].Version < versions[j].Version
		}
		return vA.LessThan(vB)
	})

	return versions, nil
}

func (r *FSRegistry) loadPack(name, version string) (*Pack, error) {
	manifestPath := filepath.Join(r.rootDir, name, version, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}

	var manifest PackManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest for %s@%s: %w", name, version, err)
	}

	contentHash, err := r.computeContentHash(filepath.Join(r.rootDir, name, version))
	if err != nil {
		return nil, fmt.Errorf("failed to compute content hash: %w", err)
	}

	return &Pack{
		PackID:      manifest.PackID,
		Manifest:    manifest,
		ContentHash: contentHash,
		CreatedAt:   time.Now(), // approximate
	}, nil
}

// computeContentHash recursively hashes the directory content.
func (r *FSRegistry) computeContentHash(path string) (string, error) {
	var files []string
	hashes := make(map[string]string)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(filePath, ".DS_Store") {
			return nil
		}

		relPath, err := filepath.Rel(path, filePath)
		if err != nil {
			return err
		}

		// Normalize path separators
		relPath = filepath.ToSlash(relPath)

		// Read file content
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}

		files = append(files, relPath)
		hashes[relPath] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	if err != nil {
		return "", err
	}

	// Deterministic order
	sort.Strings(files)

	// Hash the list of (path, hash)
	h := sha256.New()
	for _, file := range files {
		// Format: "path:hash\n"
		line := fmt.Sprintf("%s:%s\n", file, hashes[file])
		h.Write([]byte(line))
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
