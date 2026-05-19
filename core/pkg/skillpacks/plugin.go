package skillpacks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Export(pack SkillPack, format, output string) (map[string]any, error) {
	if output == "" {
		return nil, fmt.Errorf("output path is required")
	}
	scan, err := Scan(pack)
	if err != nil {
		return nil, err
	}
	if scan.Verdict == VerdictDeny {
		return nil, fmt.Errorf("skill scan denied export: %s", scan.ReasonCode)
	}
	switch format {
	case "codex-skill":
		path := filepath.Join(output, "skills", filepath.FromSlash(pack.Manifest.ID), "SKILL.md")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := atomicWrite(path, []byte(pack.SkillMD)); err != nil {
			return nil, err
		}
	case "codex-plugin":
		if err := exportCodexPlugin(pack, output, scan); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported skill export format: %s", format)
	}
	receipt := NewReceipt("SKILL_PLUGIN_EXPORT_RECEIPT", pack.Manifest.ID, VerdictAllow, "", scan.SkillContentHash, pack.Manifest.PolicyRef, nil)
	return map[string]any{"skill_id": pack.Manifest.ID, "format": format, "output": output, "scan": scan, "receipt": receipt}, nil
}

func exportCodexPlugin(pack SkillPack, output string, scan ScanResult) error {
	if err := os.MkdirAll(filepath.Join(output, ".codex-plugin"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(output, "skills", filepath.FromSlash(pack.Manifest.ID)), 0o755); err != nil {
		return err
	}
	plugin := map[string]any{
		"schema_version":           "codex.plugin.v1",
		"name":                     sanitizePathSegment(pack.Manifest.ID),
		"display_name":             pack.Manifest.Name,
		"description":              pack.Manifest.Description,
		"version":                  pack.Manifest.Version,
		"helm_skill_hash":          scan.SkillContentHash,
		"helm_policy_hash":         hashCanonical(pack.Manifest.PolicyRef),
		"helm_export_receipt_kind": "SKILL_PLUGIN_EXPORT_RECEIPT",
		"skills": []map[string]string{{
			"id":   pack.Manifest.ID,
			"path": "skills/" + filepath.ToSlash(filepath.Join(filepath.FromSlash(pack.Manifest.ID), "SKILL.md")),
		}},
		"mcp": map[string]any{
			"status":  "pending_quarantined",
			"servers": pack.Manifest.RequestedMCPServers,
			"tools":   pack.Manifest.RequestedMCPTools,
		},
		"hooks": map[string]any{
			"status": "off_by_default",
			"items":  pack.Manifest.Hooks,
		},
	}
	data, err := json.MarshalIndent(plugin, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(output, ".codex-plugin", "plugin.json"), data); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(output, "skills", filepath.FromSlash(pack.Manifest.ID), "SKILL.md"), []byte(pack.SkillMD))
}

func MarketplaceInit(repoRoot string) (string, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	marketplace := Marketplace{SchemaVersion: "helm.codex.marketplace.v1", Plugins: []MarketplacePlugin{}}
	path := filepath.Join(repoRoot, ".agents", "plugins", "marketplace.json")
	data, _ := json.MarshalIndent(marketplace, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, atomicWrite(path, data)
}

func MarketplaceAdd(repoRoot, pluginPath string) (MarketplacePlugin, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return MarketplacePlugin{}, err
		}
	}
	absRoot, _ := filepath.Abs(repoRoot)
	absPlugin, _ := filepath.Abs(pluginPath)
	if !strings.HasPrefix(absPlugin, absRoot+string(filepath.Separator)) {
		return MarketplacePlugin{}, fmt.Errorf("marketplace plugin path must stay inside repo")
	}
	manifestPath := filepath.Join(pluginPath, ".codex-plugin", "plugin.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return MarketplacePlugin{}, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return MarketplacePlugin{}, err
	}
	id, _ := raw["name"].(string)
	if id == "" {
		id = sanitizePathSegment(filepath.Base(pluginPath))
	}
	entry := MarketplacePlugin{
		ID:         id,
		Path:       strings.TrimPrefix(absPlugin, absRoot+string(filepath.Separator)),
		PolicyHash: hashCanonical(raw["helm_policy_hash"]),
		SourceHash: HashBytes(data),
		Status:     "scanned",
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	path := filepath.Join(repoRoot, ".agents", "plugins", "marketplace.json")
	marketplace := Marketplace{SchemaVersion: "helm.codex.marketplace.v1", Plugins: []MarketplacePlugin{}}
	if existing, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(existing, &marketplace)
	}
	replaced := false
	for i := range marketplace.Plugins {
		if marketplace.Plugins[i].ID == entry.ID {
			marketplace.Plugins[i] = entry
			replaced = true
		}
	}
	if !replaced {
		marketplace.Plugins = append(marketplace.Plugins, entry)
	}
	out, _ := json.MarshalIndent(marketplace, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return MarketplacePlugin{}, err
	}
	return entry, atomicWrite(path, out)
}
