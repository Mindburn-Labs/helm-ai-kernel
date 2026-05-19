package skillpacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	manifestPath := filepath.Join(dir, "skillpack.json")
	skillPath := filepath.Join(dir, "SKILL.md")
	data, err := os.ReadFile(skillPath)
	if err != nil {
		return SkillPack{}, fmt.Errorf("read SKILL.md: %w", err)
	}
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
	if raw, err := os.ReadFile(manifestPath); err == nil {
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return SkillPack{}, fmt.Errorf("parse skillpack.json: %w", err)
		}
	}
	if manifest.ContentHash == "" {
		manifest.ContentHash = HashBytes(data)
	}
	if err := ValidateManifest(manifest, data); err != nil {
		return SkillPack{}, err
	}
	return SkillPack{Manifest: manifest, SkillMD: string(data), Root: dir}, nil
}

func ListCatalog(query string) ([]Manifest, error) {
	root, err := findRepoRoot("")
	if err != nil {
		return nil, err
	}
	base := filepath.Join(root, "registry", "skills")
	var out []Manifest
	_ = filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "skillpack.json" {
			return nil
		}
		pack, err := LoadDir(filepath.Dir(path))
		if err != nil {
			return nil
		}
		if query == "" || strings.Contains(strings.ToLower(pack.Manifest.ID+" "+pack.Manifest.Name+" "+pack.Manifest.Description), strings.ToLower(query)) {
			out = append(out, pack.Manifest)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
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
