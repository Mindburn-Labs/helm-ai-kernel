package skillpacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Install(pack SkillPack, req InstallRequest) (InstallResult, error) {
	if req.Scope == "" {
		req.Scope = ScopeRepo
	}
	if req.Agent == "" {
		req.Agent = "codex"
	}
	scan, err := Scan(pack)
	if err != nil {
		return InstallResult{}, err
	}
	result := InstallResult{SkillID: pack.Manifest.ID, Verdict: scan.Verdict, Scan: scan}
	if req.Scope != ScopeRepo {
		result.Status = "approval_required"
		result.Verdict = VerdictEscalate
		result.ReasonCode = "ERR_GLOBAL_SKILL_INSTALL_DENIED"
		result.Message = "repo-scoped install is the default; broader scope requires approval receipt"
		return result, nil
	}
	if scan.Verdict != VerdictAllow {
		result.Status = "blocked"
		result.ReasonCode = scan.ReasonCode
		return result, nil
	}
	root := req.RepoRoot
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return InstallResult{}, err
		}
	}
	projections, err := ProjectionPaths(root, pack.Manifest.ID, req.Agent)
	if err != nil {
		return InstallResult{}, err
	}
	for _, projection := range projections {
		if err := os.MkdirAll(filepath.Dir(projection.Path), 0o755); err != nil {
			return InstallResult{}, err
		}
		if err := atomicWrite(projection.Path, []byte(pack.SkillMD)); err != nil {
			return InstallResult{}, err
		}
	}
	installReceipt := NewReceipt("SKILL_INSTALL_RECEIPT", pack.Manifest.ID, VerdictAllow, "", scan.SkillContentHash, pack.Manifest.PolicyRef, projections)
	projectionReceipt := NewReceipt("SKILL_PROJECTION_RECEIPT", pack.Manifest.ID, VerdictAllow, "", scan.SkillContentHash, pack.Manifest.PolicyRef, projections)
	if _, err := WriteReceipt(root, installReceipt); err != nil {
		return InstallResult{}, err
	}
	if _, err := WriteReceipt(root, projectionReceipt); err != nil {
		return InstallResult{}, err
	}
	if err := updateInstallStore(root, pack.Manifest, req, projections, installReceipt.ID, projectionReceipt.ID); err != nil {
		return InstallResult{}, err
	}
	result.Status = "active"
	result.Verdict = VerdictAllow
	result.ProjectionPaths = projections
	result.InstallReceipt = installReceipt
	result.ProjectionReceipt = projectionReceipt
	return result, nil
}

func ProjectionPaths(root, skillID, agent string) ([]Projection, error) {
	safeParts := strings.Split(filepath.ToSlash(skillID), "/")
	if len(safeParts) != 2 || safeParts[0] == "" || safeParts[1] == "" {
		return nil, fmt.Errorf("skill id must be namespaced publisher/name: %s", skillID)
	}
	switch strings.ToLower(agent) {
	case "codex", "generic":
		return []Projection{{Agent: agent, Path: filepath.Join(root, ".agents", "skills", safeParts[0], safeParts[1], "SKILL.md")}}, nil
	case "claude", "claude-code":
		return []Projection{{Agent: "claude-code", Path: filepath.Join(root, ".claude", "skills", safeParts[0], safeParts[1], "SKILL.md")}}, nil
	case "cursor":
		return []Projection{{Agent: "cursor", Path: filepath.Join(root, ".cursor", "rules", safeParts[0]+"-"+safeParts[1]+".md")}}, nil
	case "opencode":
		return []Projection{{Agent: "opencode", Path: filepath.Join(root, ".opencode", "skills", safeParts[0], safeParts[1], "SKILL.md")}}, nil
	default:
		return nil, fmt.Errorf("unsupported agent projection: %s", agent)
	}
}

func Disable(repoRoot, skillID string) (Receipt, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return Receipt{}, err
		}
	}
	receipt := NewReceipt("SKILL_DISABLE_RECEIPT", skillID, VerdictAllow, "", "", "", nil)
	if err := markInstallStatus(repoRoot, skillID, "disabled"); err != nil {
		return Receipt{}, err
	}
	_, err := WriteReceipt(repoRoot, receipt)
	return receipt, err
}

func Revoke(repoRoot, skillID string) (Receipt, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return Receipt{}, err
		}
	}
	store, err := readInstallStore(repoRoot)
	if err != nil {
		return Receipt{}, err
	}
	paths := []Projection{}
	for i := range store.Installs {
		if store.Installs[i].SkillID == skillID {
			paths = append(paths, store.Installs[i].ProjectionPaths...)
			store.Installs[i].Status = "revoked"
			store.Installs[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	for _, p := range paths {
		if err := os.Remove(p.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Receipt{}, err
		}
	}
	if err := writeInstallStore(repoRoot, store); err != nil {
		return Receipt{}, err
	}
	receipt := NewReceipt("SKILL_REVOKE_RECEIPT", skillID, VerdictAllow, "", "", "", paths)
	_, err = WriteReceipt(repoRoot, receipt)
	return receipt, err
}

func ListInstalled(repoRoot string) (any, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	return readInstallStore(repoRoot)
}

type installStore struct {
	SchemaVersion string           `json:"schema_version"`
	Installs      []installedSkill `json:"installs"`
}

type installedSkill struct {
	SkillID             string       `json:"skill_id"`
	Agent               string       `json:"agent"`
	Scope               string       `json:"scope"`
	Status              string       `json:"status"`
	ContentHash         string       `json:"content_hash"`
	InstallReceiptID    string       `json:"install_receipt_id"`
	ProjectionReceiptID string       `json:"projection_receipt_id"`
	ProjectionPaths     []Projection `json:"projection_paths"`
	UpdatedAt           string       `json:"updated_at"`
	Manifest            Manifest     `json:"manifest"`
}

func updateInstallStore(root string, manifest Manifest, req InstallRequest, paths []Projection, installReceipt, projectionReceipt string) error {
	store, err := readInstallStore(root)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range store.Installs {
		if store.Installs[i].SkillID == manifest.ID && store.Installs[i].Agent == req.Agent && store.Installs[i].Scope == req.Scope {
			store.Installs[i].Status = "active"
			store.Installs[i].ContentHash = manifest.ContentHash
			store.Installs[i].InstallReceiptID = installReceipt
			store.Installs[i].ProjectionReceiptID = projectionReceipt
			store.Installs[i].ProjectionPaths = paths
			store.Installs[i].UpdatedAt = now
			store.Installs[i].Manifest = manifest
			return writeInstallStore(root, store)
		}
	}
	store.Installs = append(store.Installs, installedSkill{
		SkillID: manifest.ID, Agent: req.Agent, Scope: req.Scope, Status: "active",
		ContentHash: manifest.ContentHash, InstallReceiptID: installReceipt,
		ProjectionReceiptID: projectionReceipt, ProjectionPaths: paths, UpdatedAt: now, Manifest: manifest,
	})
	return writeInstallStore(root, store)
}

func markInstallStatus(root, skillID, status string) error {
	store, err := readInstallStore(root)
	if err != nil {
		return err
	}
	found := false
	for i := range store.Installs {
		if store.Installs[i].SkillID == skillID {
			store.Installs[i].Status = status
			store.Installs[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			found = true
		}
	}
	if !found {
		return fmt.Errorf("skill %s is not managed by HELM", skillID)
	}
	return writeInstallStore(root, store)
}

func readInstallStore(root string) (installStore, error) {
	path := filepath.Join(root, ".helm", "skillpacks", "installed.json")
	store := installStore{SchemaVersion: "helm.skillpack.installs.v1", Installs: []installedSkill{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return store, err
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return store, err
	}
	return store, nil
}

func writeInstallStore(root string, store installStore) error {
	path := filepath.Join(root, ".helm", "skillpacks", "installed.json")
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicWrite(path, data)
}
