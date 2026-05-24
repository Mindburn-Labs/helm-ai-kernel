package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

func TestFrameworkAdapterManifestsValidateAgainstSchema(t *testing.T) {
	root, err := registry.DiscoverRoot()
	if err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(root, "schemas", "launchpad", "framework_adapter.schema.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	schemaURL := "file:///" + strings.ReplaceAll(schemaPath, string(filepath.Separator), "/")
	if err := compiler.AddResource(schemaURL, strings.NewReader(string(schemaData))); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "registry", "launchpad", "adapters")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !(strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		count++
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var yamlValue any
		if err := yaml.Unmarshal(data, &yamlValue); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		jsonData, err := json.Marshal(yamlValue)
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		var jsonValue any
		if err := json.Unmarshal(jsonData, &jsonValue); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		if err := schema.Validate(jsonValue); err != nil {
			t.Fatalf("%s failed schema validation: %v", entry.Name(), err)
		}
	}
	if count < 12 {
		t.Fatalf("expected adapter manifest coverage for requested framework set, found %d", count)
	}
}
