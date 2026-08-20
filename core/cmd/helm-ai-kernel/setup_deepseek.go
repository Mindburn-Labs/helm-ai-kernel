package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	deepseekClaudeBridgePlugin = "@deepseek-ai/dsh-hooks-claude-code"
	deepseekCodexBridgePlugin  = "@deepseek-ai/dsh-hooks-codex"
	deepseekClaudeBridgeID     = "helm-ai-kernel-hooks"
	deepseekCodexBridgeID      = "helm-ai-kernel-hooks-codex"
	deepseekHookFileName       = "helm-ai-kernel-hooks.json"
	deepseekPatchFileName      = "cordis.patch.yml"
)

// deepseekHomeDir is DSH_HOME when set to an absolute path, otherwise ~/.dsh.
// Stock DSH loads $DSH_HOME/cordis.patch.yml for every profile.
func deepseekHomeDir() string {
	if home := strings.TrimSpace(os.Getenv("DSH_HOME")); home != "" {
		if filepath.IsAbs(home) {
			return home
		}
		return ""
	}
	return setupUserPath(".dsh")
}

func deepseekProfilePath() string {
	home := deepseekHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, deepseekPatchFileName)
}

func deepseekHookFilePath() string {
	home := deepseekHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, deepseekHookFileName)
}

func installDeepseekHop(opts setupOptions, bin string) error {
	hookPath, profilePath, err := deepseekRequiredPaths()
	if err != nil {
		return err
	}
	if err := upsertHookConfig(hookPath, setupHookMatcher(opts.Target), setupHookCommand(opts, bin), setupPrivateFileRoot(opts)); err != nil {
		return err
	}
	return upsertDeepseekProfileConfigPath(profilePath, hookPath, setupPrivateFileRoot(opts))
}

func removeDeepseekHop(opts setupOptions, bin string) error {
	hookPath, profilePath, err := deepseekRequiredPaths()
	if err != nil {
		return err
	}
	if err := removeHookConfig(hookPath, setupHookCommand(opts, bin), setupPrivateFileRoot(opts)); err != nil {
		return err
	}
	return removeDeepseekProfileConfigPath(profilePath, hookPath, setupPrivateFileRoot(opts))
}

func deepseekRequiredPaths() (hookPath, profilePath string, err error) {
	hookPath = deepseekHookFilePath()
	profilePath = deepseekProfilePath()
	if hookPath == "" || profilePath == "" {
		return "", "", fmt.Errorf("DSH home is unavailable; set DSH_HOME to an absolute path or ensure HOME is absolute")
	}
	return hookPath, profilePath, nil
}

func upsertDeepseekProfileConfigPath(path, hookPath, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	ops, err := readYAMLList(path)
	if err != nil {
		return fmt.Errorf("parse existing DSH cordis.patch.yml: %w", err)
	}
	hookPath = deepseekCleanHookPath(hookPath)
	// Insert the stock Claude-code bridge row. Inserting @deepseek-ai/dsh-hooks-codex
	// on a blank profile would fail DSH boot when that package is not a dependency,
	// so Codex is upserted only when a matching row already exists.
	ops = upsertDeepseekBridgeInsert(ops, deepseekClaudeBridgeID, deepseekClaudeBridgePlugin, hookPath, true)
	ops = upsertDeepseekBridgeInsert(ops, deepseekCodexBridgeID, deepseekCodexBridgePlugin, hookPath, false)
	return writeYAMLList(path, ops, allowedRoot)
}

func removeDeepseekProfileConfigPath(path, hookPath, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	ops, err := readYAMLList(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse existing DSH cordis.patch.yml: %w", err)
	}
	hookPath = deepseekCleanHookPath(hookPath)
	filtered := make([]any, 0, len(ops))
	for _, op := range ops {
		obj, ok := op.(map[string]any)
		if !ok {
			filtered = append(filtered, op)
			continue
		}
		insert := arrayValue(obj, "insert")
		if len(insert) == 0 {
			filtered = append(filtered, obj)
			continue
		}
		kept := make([]any, 0, len(insert))
		for _, item := range insert {
			row, ok := item.(map[string]any)
			if !ok {
				kept = append(kept, item)
				continue
			}
			if isDeepseekOwnedBridgeRow(row, hookPath) {
				continue
			}
			kept = append(kept, row)
		}
		if len(kept) == 0 {
			delete(obj, "insert")
			if len(obj) == 0 {
				continue
			}
			filtered = append(filtered, obj)
			continue
		}
		obj["insert"] = kept
		filtered = append(filtered, obj)
	}
	if len(filtered) == 0 {
		resolved, err := privateFileWritePath(path, allowedRoot)
		if err != nil {
			return err
		}
		if err := os.Remove(resolved); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeYAMLList(path, filtered, allowedRoot)
}

func upsertDeepseekBridgeInsert(ops []any, id, plugin, hookPath string, insertIfMissing bool) []any {
	updated := false
	for _, op := range ops {
		obj, ok := op.(map[string]any)
		if !ok {
			continue
		}
		insert := arrayValue(obj, "insert")
		if len(insert) == 0 {
			continue
		}
		for _, item := range insert {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if yamlString(row["id"]) != id && !sameDeepseekBridgePlugin(yamlString(row["name"]), plugin) {
				continue
			}
			row["id"] = id
			row["name"] = plugin
			cfg := objectValue(row, "config")
			cfg["configPath"] = hookPath
			row["config"] = cfg
			updated = true
		}
		obj["insert"] = insert
	}
	if updated || !insertIfMissing {
		return ops
	}
	row := map[string]any{
		"id":   id,
		"name": plugin,
		"config": map[string]any{
			"configPath": hookPath,
		},
	}
	for _, op := range ops {
		obj, ok := op.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := obj["insert"]; ok {
			obj["insert"] = append(arrayValue(obj, "insert"), row)
			return ops
		}
	}
	return append(ops, map[string]any{"insert": []any{row}})
}

func deepseekProfileConfigPathInstalled(path, hookPath string) bool {
	ops, err := readYAMLList(path)
	if err != nil {
		return false
	}
	hookPath = deepseekCleanHookPath(hookPath)
	for _, op := range ops {
		obj, ok := op.(map[string]any)
		if !ok {
			continue
		}
		for _, item := range arrayValue(obj, "insert") {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			cfg, _ := row["config"].(map[string]any)
			if cfg == nil {
				continue
			}
			if deepseekCleanHookPath(yamlString(cfg["configPath"])) != hookPath {
				continue
			}
			if sameDeepseekBridgePlugin(yamlString(row["name"]), deepseekClaudeBridgePlugin) {
				return true
			}
		}
	}
	return false
}

func deepseekHookFileInstalled(path, command string) bool {
	root, err := readJSONObject(path)
	if err != nil {
		return false
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return false
	}
	return hookCommandConfigPresent(arrayValue(hooks, "PreToolUse"), command)
}

func deepseekHopInstalled(opts setupOptions, bin string) bool {
	hookPath, profilePath, err := deepseekRequiredPaths()
	if err != nil {
		return false
	}
	return deepseekHookFileInstalled(hookPath, setupHookCommand(opts, bin)) &&
		deepseekProfileConfigPathInstalled(profilePath, hookPath)
}

func deepseekCleanHookPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(abs)
}

func isDeepseekOwnedBridgeRow(row map[string]any, hookPath string) bool {
	id := yamlString(row["id"])
	if id == deepseekClaudeBridgeID || id == deepseekCodexBridgeID {
		return true
	}
	cfg, _ := row["config"].(map[string]any)
	if cfg == nil {
		return false
	}
	if deepseekCleanHookPath(yamlString(cfg["configPath"])) != deepseekCleanHookPath(hookPath) {
		return false
	}
	name := yamlString(row["name"])
	return sameDeepseekBridgePlugin(name, deepseekClaudeBridgePlugin) ||
		sameDeepseekBridgePlugin(name, deepseekCodexBridgePlugin)
}

func sameDeepseekBridgePlugin(name, want string) bool {
	n := strings.TrimSpace(name)
	switch want {
	case deepseekClaudeBridgePlugin:
		return n == deepseekClaudeBridgePlugin || n == "dsh-hooks-claude-code" || n == "hooks-claude-code"
	case deepseekCodexBridgePlugin:
		return n == deepseekCodexBridgePlugin || n == "dsh-hooks-codex" || n == "hooks-codex"
	default:
		return n == want
	}
}

func readYAMLList(path string) ([]any, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return []any{}, nil
	}
	var root any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	switch v := root.(type) {
	case []any:
		return v, nil
	case nil:
		return []any{}, nil
	default:
		return nil, fmt.Errorf("expected a YAML list of patch operations")
	}
}

func writeYAMLList(path string, ops []any, allowedRoot string) error {
	data, err := yaml.Marshal(ops)
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, data, allowedRoot)
}
