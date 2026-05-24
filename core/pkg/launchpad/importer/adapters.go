package importer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"gopkg.in/yaml.v3"
)

func LoadAdapters(root string) ([]FrameworkAdapter, error) {
	if root == "" {
		discovered, err := registry.DiscoverRoot()
		if err != nil {
			return DefaultAdapters(), nil
		}
		root = discovered
	}
	dir := filepath.Join(root, "registry", "launchpad", "adapters")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return DefaultAdapters(), nil
	}
	var adapters []FrameworkAdapter
	for _, entry := range entries {
		if entry.IsDir() || !(strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var adapter FrameworkAdapter
		if err := yaml.Unmarshal(data, &adapter); err != nil {
			return nil, err
		}
		if adapter.Metadata.ID != "" {
			adapters = append(adapters, adapter)
		}
	}
	if len(adapters) == 0 {
		return DefaultAdapters(), nil
	}
	sort.SliceStable(adapters, func(i, j int) bool {
		if adapters[i].Metadata.Priority == adapters[j].Metadata.Priority {
			return adapters[i].Metadata.ID < adapters[j].Metadata.ID
		}
		return adapters[i].Metadata.Priority > adapters[j].Metadata.Priority
	})
	return adapters, nil
}

func DefaultAdapters() []FrameworkAdapter {
	return []FrameworkAdapter{
		adapter("langgraph-python", 100, []string{"langgraph.json"}, nil, []string{"agentFramework", "apiServer", "telemetry"}, "native", [][]string{{"langgraph", "dev"}}, []string{"LANGSMITH_API_KEY"}, []int{2024}),
		adapter("crewai-python", 90, []string{"pyproject.toml"}, []string{"crewai", "crew", "flow"}, []string{"agentFramework", "worker", "python"}, "native", [][]string{{"crewai", "run"}}, nil, nil),
		adapter("openhands", 95, []string{"openhands"}, []string{"openhands serve"}, []string{"agentFramework", "apiServer", "sandbox", "container"}, "compose", [][]string{{"openhands", "serve"}}, nil, []int{3000}),
		adapter("openai-agents-sdk", 80, []string{"pyproject.toml", "requirements.txt", "package.json"}, []string{"openai-agents", "agents sdk"}, []string{"agentFramework", "libraryFramework", "tracing"}, "native", nil, []string{"OPENAI_API_KEY"}, nil),
		adapter("semantic-kernel", 78, []string{"pyproject.toml", "requirements.txt", "pom.xml", "build.gradle", "package.json"}, []string{"semantic-kernel", "semantic kernel"}, []string{"agentFramework", "libraryFramework"}, "native", nil, nil, nil),
		adapter("pydantic-ai", 82, []string{"pyproject.toml", "requirements.txt"}, []string{"pydantic-ai", "pydantic ai"}, []string{"agentFramework", "mcpTools", "python"}, "native", nil, nil, nil),
		adapter("autogen", 72, []string{"pyproject.toml", "requirements.txt"}, []string{"autogen", "autogenstudio"}, []string{"agentFramework", "libraryFramework", "python"}, "native", nil, nil, nil),
		adapter("generic-docker-compose", 70, []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}, nil, []string{"compose", "localRuntime", "container"}, "compose", [][]string{{"docker", "compose", "up", "--build"}}, nil, nil),
		adapter("generic-tauri-electron", 68, []string{"package.json", "tauri.conf.json", "Cargo.toml"}, []string{"tauri", "electron"}, []string{"desktopUI", "node", "rust"}, "native", [][]string{{"npm", "run", "dev"}}, nil, nil),
		adapter("generic-node", 55, []string{"package.json"}, nil, []string{"node"}, "buildpacks", nil, nil, nil),
		adapter("generic-python", 55, []string{"pyproject.toml", "requirements.txt"}, nil, []string{"python"}, "buildpacks", nil, nil, nil),
		adapter("generic-rust", 50, []string{"Cargo.toml"}, nil, []string{"rust"}, "native", [][]string{{"cargo", "run"}}, nil, nil),
	}
}

func adapter(id string, priority int, filesAny, readme []string, capabilities []string, strategy string, commands [][]string, secrets []string, ports []int) FrameworkAdapter {
	localCommands := make([]AdapterCommand, 0, len(commands))
	for i, command := range commands {
		localCommands = append(localCommands, AdapterCommand{Name: "entrypoint-" + id + "-" + string(rune('a'+i)), Command: command})
	}
	return FrameworkAdapter{
		APIVersion:   "helm.platform/v1alpha1",
		Kind:         "FrameworkAdapter",
		Metadata:     AdapterMetadata{ID: id, Version: "1.0.0", Priority: priority},
		Match:        AdapterMatchSpec{FilesAny: filesAny, ReadmeRegex: readme, ConfidenceThreshold: 0.70},
		Capabilities: capabilities,
		Entrypoints:  AdapterEntrypoints{Local: localCommands},
		Build:        AdapterBuildSpec{Strategy: strategy},
		Dependencies: AdapterDeps{Files: filesAny},
		Secrets:      AdapterSecrets{Required: secrets},
		Network:      AdapterNetwork{Ports: ports},
		Tests:        AdapterTests{Smoke: [][]string{{"helm-ai-kernel", "launchpad", "import", "preflight"}}},
		Rollback:     AdapterRollback{Strategy: "teardown"},
	}
}
