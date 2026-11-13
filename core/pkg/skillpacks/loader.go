package skillpacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/packfs"
)

func Load(ref string) (SkillPack, error) {
	if ref == "" {
		return SkillPack{}, errors.New("skill ref is required")
	}
	if st, err := os.Stat(ref); err == nil && st.IsDir() {
		return LoadDir(ref)
	}
	if strings.HasPrefix(ref, "github:") {
		return LoadGitHub(ref)
	}
	root, err := findRepoRoot("")
	if err != nil {
		return SkillPack{}, err
	}
	if strings.Contains(ref, "/") {
		path := filepath.Join(root, "registry", "skills", filepath.FromSlash(ref))
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			return LoadDir(path)
		}
	}
	return SkillPack{}, fmt.Errorf("skill %q not found", ref)
}

func LoadDir(dir string) (SkillPack, error) {
	root, err := packfs.Open(dir)
	if err != nil {
		return SkillPack{}, fmt.Errorf("open pack directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFileLimit("SKILL.md", maxPackFileBytes)
	if err != nil {
		return SkillPack{}, fmt.Errorf("read SKILL.md: %w", err)
	}
	manifestBytes, err := root.ReadFileLimit("skillpack.json", maxPackFileBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return SkillPack{}, fmt.Errorf("read skillpack.json: %w", err)
	}
	manifest, err := decodeManifest(dir, manifestBytes, data)
	if err != nil {
		return SkillPack{}, err
	}
	if err := ValidateManifest(manifest, data); err != nil {
		return SkillPack{}, err
	}
	return SkillPack{Manifest: manifest, SkillMD: string(data), Root: dir}, nil
}

// decodeManifest applies skillpack.json (raw, nil when the pack has none) over
// the loader's defaults. The scan decodes the bytes it hashed the same way, to
// tell whether they are still the manifest that was loaded.
func decodeManifest(dir string, raw, skillMD []byte) (Manifest, error) {
	manifest := Manifest{
		SchemaVersion:              "helm.skillpack.v1",
		ID:                         filepath.Base(dir),
		Name:                       filepath.Base(dir),
		Version:                    "0.0.0",
		Status:                     StatusExperimental,
		ScopeDefault:               ScopeRepo,
		Risk:                       "LOW",
		AgentTargets:               []string{"codex", "generic"},
		PermissionsDoNotGrantTools: true,
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return Manifest{}, fmt.Errorf("parse skillpack.json: %w", err)
		}
	}
	if manifest.ContentHash == "" {
		manifest.ContentHash = HashBytes(skillMD)
	}
	return manifest, nil
}

// ListCatalog lists the packs in the registry of the repository the working
// directory is in. That registry is whatever the checkout holds, so each entry
// carries the publisher state computed for it; a manifest's own status is only
// what the pack declares.
func ListCatalog(query string) ([]CatalogEntry, error) {
	root, err := findRepoRoot("")
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, "registry", "skills")
	var out []CatalogEntry
	_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "skillpack.json" {
			return nil
		}
		pack, err := LoadDir(filepath.Dir(path))
		if err != nil {
			return nil
		}
		if query == "" || strings.Contains(strings.ToLower(pack.Manifest.ID+" "+pack.Manifest.Name+" "+pack.Manifest.Description), strings.ToLower(query)) {
			out = append(out, CatalogEntry{Manifest: pack.Manifest, PublisherVerification: CheckPublisher(pack)})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out, nil
}

func findRepoRoot(start string) (string, error) {
	wd := start
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "registry", "skills")); err == nil {
			return wd, nil
		}
		if _, err := os.Stat(filepath.Join(wd, "core", "go.mod")); err == nil {
			return wd, nil
		}
		next := filepath.Dir(wd)
		if next == wd {
			break
		}
		wd = next
	}
	return "", errors.New("HELM repo root not found")
}
