package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	hermesHookEvent          = "pre_tool_call"
	hermesHookTimeoutSeconds = 30
)

func hermesConfigPath(opts setupOptions) string {
	if opts.Scope == "project" {
		return filepath.Join(opts.Workspace, ".hermes", "config.yaml")
	}
	return setupUserPath(".hermes", "config.yaml")
}

func upsertHermesMCP(path, bin, dataDir, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readYAMLObject(path)
	if err != nil {
		return fmt.Errorf("parse existing Hermes config: %w", err)
	}
	servers := objectValue(root, "mcp_servers")
	servers[setupMCPServerName] = map[string]any{
		"command": bin,
		"args":    setupMCPArgs(dataDir),
	}
	root["mcp_servers"] = servers
	return writeYAMLObject(path, root, allowedRoot)
}

func removeHermesMCP(path, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readYAMLObject(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse existing Hermes config: %w", err)
	}
	servers := objectValue(root, "mcp_servers")
	delete(servers, setupMCPServerName)
	if len(servers) == 0 {
		delete(root, "mcp_servers")
	} else {
		root["mcp_servers"] = servers
	}
	return writeYAMLObject(path, root, allowedRoot)
}

func hermesMCPInstalled(path, bin, dataDir string) bool {
	root, err := readYAMLObject(path)
	if err != nil {
		return false
	}
	servers, ok := root["mcp_servers"].(map[string]any)
	if !ok {
		return false
	}
	raw, ok := servers[setupMCPServerName]
	if !ok {
		return false
	}
	server, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	command, _ := server["command"].(string)
	return command == bin && equalSetupStrings(yamlStringSlice(server["args"]), setupMCPArgs(dataDir))
}

func upsertHermesHookConfig(path, matcher, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readYAMLObject(path)
	if err != nil {
		return fmt.Errorf("parse existing Hermes config: %w", err)
	}
	hooks := hermesHooksMap(root)
	pre := hermesPreToolCallEntries(hooks)
	key := hookCommandKey(command)
	updated := false
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if hookCommandKey(yamlString(obj["command"])) != key {
			continue
		}
		obj["command"] = command
		obj["matcher"] = matcher
		obj["fail_closed"] = true
		obj["timeout"] = hermesHookTimeoutSeconds
		updated = true
	}
	if !updated {
		pre = append(pre, map[string]any{
			"matcher":     matcher,
			"command":     command,
			"fail_closed": true,
			"timeout":     hermesHookTimeoutSeconds,
		})
	}
	hooks[hermesHookEvent] = pre
	root["hooks"] = hooks
	return writeYAMLObject(path, root, allowedRoot)
}

func removeHermesHookConfig(path, command, allowedRoot string) error {
	if _, err := privateFileWritePath(path, allowedRoot); err != nil {
		return err
	}
	root, err := readYAMLObject(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse existing Hermes config: %w", err)
	}
	hooks := hermesHooksMap(root)
	pre := hermesPreToolCallEntries(hooks)
	filtered := make([]any, 0, len(pre))
	key := hookCommandKey(command)
	for _, item := range pre {
		obj, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		if hookCommandKey(yamlString(obj["command"])) == key {
			continue
		}
		filtered = append(filtered, obj)
	}
	if len(filtered) == 0 {
		delete(hooks, hermesHookEvent)
	} else {
		hooks[hermesHookEvent] = filtered
	}
	if len(hooks) == 0 {
		delete(root, "hooks")
	} else {
		root["hooks"] = hooks
	}
	return writeYAMLObject(path, root, allowedRoot)
}

func hermesHookInstalled(path, command string) bool {
	root, err := readYAMLObject(path)
	if err != nil {
		return false
	}
	hooks := hermesHooksMap(root)
	key := hookCommandConfigKey(command)
	for _, item := range hermesPreToolCallEntries(hooks) {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if hookCommandConfigKey(yamlString(obj["command"])) != key {
			continue
		}
		return hermesFailClosed(obj) && hermesTimeoutOK(obj)
	}
	return false
}

func hermesFailClosed(entry map[string]any) bool {
	return yamlBool(entry["fail_closed"]) || yamlBool(entry["failClosed"])
}

func hermesTimeoutOK(entry map[string]any) bool {
	return yamlInt(entry["timeout"]) == hermesHookTimeoutSeconds
}

func hermesInstalledHookCommands(path string) []string {
	root, err := readYAMLObject(path)
	if err != nil {
		return nil
	}
	hooks := hermesHooksMap(root)
	var commands []string
	for _, item := range hermesPreToolCallEntries(hooks) {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if command := yamlString(obj["command"]); command != "" {
			commands = append(commands, command)
		}
	}
	return commands
}

func hermesHooksMap(root map[string]any) map[string]any {
	switch hooks := root["hooks"].(type) {
	case map[string]any:
		return hooks
	case []any:
		converted := map[string]any{}
		var pre []any
		for _, item := range hooks {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if yamlString(obj["event"]) == hermesHookEvent {
				pre = append(pre, obj)
			}
		}
		if len(pre) > 0 {
			converted[hermesHookEvent] = pre
		}
		return converted
	default:
		return objectValue(root, "hooks")
	}
}

func hermesPreToolCallEntries(hooks map[string]any) []any {
	return arrayValue(hooks, hermesHookEvent)
}

func readYAMLObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	if root == nil {
		root = map[string]any{}
	}
	return root, nil
}

func writeYAMLObject(path string, root map[string]any, allowedRoot string) error {
	data, err := yaml.Marshal(root)
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(path, data, allowedRoot)
}

func yamlString(v any) string {
	s, _ := v.(string)
	return s
}

func yamlBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func yamlInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int8:
		return int(n)
	case int16:
		return int(n)
	case int32:
		return int(n)
	case int64:
		return int(n)
	case uint:
		return int(n)
	case uint8:
		return int(n)
	case uint16:
		return int(n)
	case uint32:
		return int(n)
	case uint64:
		return int(n)
	case float32:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func yamlStringSlice(v any) []string {
	switch items := v.(type) {
	case []string:
		return items
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}
