package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	deepseekHookEvent          = "PreToolUse"
	deepseekHookTimeoutSeconds = 30
	deepseekHooksPluginID      = "hooks-claude-code"
	deepseekHooksPluginName    = "@deepseek-ai/dsh-hooks-claude-code"
	deepseekHooksPluginShort   = "dsh-hooks-claude-code"
	deepseekProfileFilename    = "cordis.patch.yml"
	deepseekHookFilename       = "hooks.json"
)

func deepseekHomeDir() string {
	if home := strings.TrimSpace(os.Getenv("DSH_HOME")); home != "" && filepath.IsAbs(home) {
		return filepath.Clean(home)
	}
	return setupUserPath(".dsh")
}

func deepseekDir(opts setupOptions) string {
	if opts.Scope == "project" {
		return filepath.Join(opts.Workspace, ".dsh")
	}
	return deepseekHomeDir()
}

func deepseekHookPath(opts setupOptions) string {
	dir := deepseekDir(opts)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, deepseekHookFilename)
}

func deepseekProfilePath(opts setupOptions) string {
	dir := deepseekDir(opts)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, deepseekProfileFilename)
}

func upsertDeepSeekHookConfig(path, matcher, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readJSONObject(path)
	if err != nil {
		return fmt.Errorf("parse existing DeepSeek hook config: %w", err)
	}
	hooks := objectValue(root, "hooks")
	pre := arrayValue(hooks, deepseekHookEvent)
	key := hookCommandKey(command)
	updated := false
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hookItems, ok := obj["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range hookItems {
			hookObj, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if hookCommandKey(hookCommandFromAny(h)) != key {
				continue
			}
			hookObj["type"] = "command"
			hookObj["command"] = command
			hookObj["timeout"] = deepseekHookTimeoutSeconds
			hookObj["fail_closed"] = true
			obj["matcher"] = matcher
			updated = true
		}
	}
	if !updated {
		pre = append(pre, map[string]any{
			"matcher": matcher,
			"hooks": []any{
				map[string]any{
					"type":        "command",
					"command":     command,
					"timeout":     deepseekHookTimeoutSeconds,
					"fail_closed": true,
				},
			},
		})
	}
	hooks[deepseekHookEvent] = pre
	root["hooks"] = hooks
	return writeJSONObject(path, root, allowedRoot)
}

func removeDeepSeekHookConfig(path, command, allowedRoot string) error {
	return removeHookConfig(path, command, allowedRoot)
}

func deepseekHookInstalled(path, command string) bool {
	root, err := readJSONObject(path)
	if err != nil {
		return false
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return false
	}
	key := hookCommandConfigKey(command)
	for _, item := range arrayValue(hooks, deepseekHookEvent) {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hookItems, ok := obj["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range hookItems {
			hookObj, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if hookCommandConfigKey(hookCommandFromAny(h)) != key {
				continue
			}
			return deepseekFailClosed(hookObj) && deepseekTimeoutOK(hookObj)
		}
	}
	return false
}

func deepseekFailClosed(entry map[string]any) bool {
	return yamlBool(entry["fail_closed"]) || yamlBool(entry["failClosed"])
}

func deepseekTimeoutOK(entry map[string]any) bool {
	return yamlInt(entry["timeout"]) == deepseekHookTimeoutSeconds
}

func deepseekInstalledHookCommands(path string) []string {
	root, err := readJSONObject(path)
	if err != nil {
		return nil
	}
	hooks, ok := root["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	var commands []string
	for _, item := range arrayValue(hooks, deepseekHookEvent) {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, h := range arrayValue(obj, "hooks") {
			if command := hookCommandFromAny(h); command != "" {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func upsertDeepSeekProfile(path, hookPath, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	entries, err := readYAMLList(path)
	if err != nil {
		return fmt.Errorf("parse existing DeepSeek profile: %w", err)
	}
	absHook, err := filepath.Abs(hookPath)
	if err != nil {
		absHook = hookPath
	}
	updated := false
	for i, item := range entries {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if !deepseekProfileEntryOwned(obj) {
			continue
		}
		entries[i] = deepseekProfileEntry(absHook)
		updated = true
	}
	if !updated {
		entries = append(entries, deepseekProfileEntry(absHook))
	}
	return writeYAMLList(path, entries, allowedRoot)
}

func removeDeepSeekProfile(path, hookPath, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	entries, err := readYAMLList(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse existing DeepSeek profile: %w", err)
	}
	absHook := deepseekAbsPath(hookPath)
	filtered := make([]any, 0, len(entries))
	for _, item := range entries {
		obj, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		if deepseekProfileEntryOwned(obj) && deepseekProfileConfigPath(obj) == absHook {
			continue
		}
		if deepseekProfileEntryOwned(obj) && absHook == "" {
			continue
		}
		filtered = append(filtered, obj)
	}
	if len(filtered) == 0 {
		return writeYAMLList(path, []any{}, allowedRoot)
	}
	return writeYAMLList(path, filtered, allowedRoot)
}

func deepseekProfileInstalled(path, hookPath string) bool {
	entries, err := readYAMLList(path)
	if err != nil {
		return false
	}
	absHook := deepseekAbsPath(hookPath)
	if absHook == "" {
		return false
	}
	for _, item := range entries {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if deepseekProfileEntryOwned(obj) && deepseekProfileConfigPath(obj) == absHook {
			return true
		}
	}
	return false
}

func deepseekProfileEntryOwned(obj map[string]any) bool {
	if cfg, ok := obj[deepseekHooksPluginShort].(map[string]any); ok && cfg != nil {
		return true
	}
	id := yamlString(obj["id"])
	name := yamlString(obj["name"])
	return id == deepseekHooksPluginID ||
		id == deepseekHooksPluginShort ||
		name == deepseekHooksPluginName ||
		name == deepseekHooksPluginShort
}

func deepseekProfileConfigPath(obj map[string]any) string {
	if cfg, ok := obj[deepseekHooksPluginShort].(map[string]any); ok {
		return deepseekAbsPath(yamlString(cfg["configPath"]))
	}
	if cfg, ok := obj["config"].(map[string]any); ok {
		return deepseekAbsPath(yamlString(cfg["configPath"]))
	}
	return deepseekAbsPath(yamlString(obj["configPath"]))
}

func deepseekProfileEntry(hookPath string) map[string]any {
	return map[string]any{
		deepseekHooksPluginShort: map[string]any{
			"configPath": hookPath,
		},
	}
}

func deepseekAbsPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

func readYAMLList(path string) ([]any, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return []any{}, nil
	}
	var entries []any
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		entries = []any{}
	}
	return entries, nil
}

func writeYAMLList(path string, entries []any, allowedRoot string) error {
	data, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, data, allowedRoot)
}
