package scenarios

import (
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/threatscan"
)

//go:embed antigravity_payloads/manifest.json
var antigravityPayloadManifest []byte

type antigravityManifest struct {
	SchemaVersion string                 `json:"schema_version"`
	PayloadClass  string                 `json:"payload_class"`
	TargetSurface string                 `json:"target_surface"`
	Payloads      []antigravityPayload   `json:"payloads"`
	Source        map[string]interface{} `json:"source"`
}

type antigravityPayload struct {
	ID                  string   `json:"id"`
	Tool                string   `json:"tool"`
	Parameter           string   `json:"parameter"`
	Pattern             string   `json:"pattern"`
	Input               string   `json:"input"`
	SourceChannel       string   `json:"source_channel"`
	TrustLevel          string   `json:"trust_level"`
	ExpectedClasses     []string `json:"expected_classes"`
	ExpectedMinSeverity string   `json:"expected_min_severity"`
}

type antigravityFakeDispatcher struct {
	called bool
}

func (d *antigravityFakeDispatcher) Dispatch(context.Context, string, map[string]any) (any, error) {
	d.called = true
	return "executed", nil
}

func TestAntigravityPayloadManifestValid(t *testing.T) {
	manifest := loadAntigravityManifest(t)
	if manifest.SchemaVersion != "1.0.0" {
		t.Fatalf("schema_version = %q, want 1.0.0", manifest.SchemaVersion)
	}
	if manifest.PayloadClass != "native_tool_parameter_flag_injection" {
		t.Fatalf("payload_class = %q", manifest.PayloadClass)
	}
	if manifest.TargetSurface != "find_by_name Pattern parameter" {
		t.Fatalf("target_surface = %q", manifest.TargetSurface)
	}
	if len(manifest.Payloads) < 3 {
		t.Fatalf("payload count = %d, want at least 3 variants", len(manifest.Payloads))
	}
	if url, ok := manifest.Source["url"].(string); !ok || url == "" {
		t.Fatal("manifest source URL is required")
	}
}

func TestAntigravityPayloadsThreatScannerFlagsNativeToolExecution(t *testing.T) {
	manifest := loadAntigravityManifest(t)
	scanner := threatscan.New()

	for _, payload := range manifest.Payloads {
		t.Run(payload.ID, func(t *testing.T) {
			result := scanner.ScanInput(
				payload.Input,
				contracts.SourceChannel(payload.SourceChannel),
				contracts.InputTrustLevel(payload.TrustLevel),
			)

			if result.FindingCount == 0 {
				t.Fatalf("expected threat findings for payload %s", payload.ID)
			}
			for _, expectedClass := range payload.ExpectedClasses {
				if !hasThreatClass(result, contracts.ThreatClass(expectedClass)) {
					t.Fatalf("expected class %s, findings=%v", expectedClass, result.Findings)
				}
			}
			if !contracts.SeverityAtLeast(result.MaxSeverity, contracts.ThreatSeverity(payload.ExpectedMinSeverity)) {
				t.Fatalf("max severity = %s, want at least %s", result.MaxSeverity, payload.ExpectedMinSeverity)
			}
		})
	}
}

func TestAntigravityFindByNameSchemaBlocksExecFlagsBeforeDispatch(t *testing.T) {
	manifest := loadAntigravityManifest(t)
	dispatcher := &antigravityFakeDispatcher{}
	fw := firewall.NewPolicyFirewall(dispatcher)
	if err := fw.AllowTool("find_by_name", findByNameSchema()); err != nil {
		t.Fatalf("schema registration failed: %v", err)
	}

	bundle := firewall.PolicyInputBundle{
		ActorID:   "agentic-ide-regression",
		Role:      "sandboxed-agent",
		SessionID: "antigravity-regression",
	}

	for _, payload := range manifest.Payloads {
		t.Run(payload.ID, func(t *testing.T) {
			dispatcher.called = false
			_, err := fw.CallTool(context.Background(), bundle, payload.Tool, map[string]any{
				payload.Parameter: payload.Pattern,
			})
			if err == nil {
				t.Fatalf("payload %s should be rejected before dispatch", payload.ID)
			}
			if !strings.Contains(err.Error(), "schema validation failed") {
				t.Fatalf("expected schema validation failure, got: %v", err)
			}
			if dispatcher.called {
				t.Fatal("dispatcher was invoked for rejected sandbox-escape payload")
			}
		})
	}

	_, err := fw.CallTool(context.Background(), bundle, "find_by_name", map[string]any{
		"pattern": "*.go",
	})
	if err != nil {
		t.Fatalf("benign find_by_name pattern should dispatch: %v", err)
	}
	if !dispatcher.called {
		t.Fatal("benign pattern should reach dispatcher")
	}
}

func loadAntigravityManifest(t *testing.T) antigravityManifest {
	t.Helper()
	var manifest antigravityManifest
	if err := json.Unmarshal(antigravityPayloadManifest, &manifest); err != nil {
		t.Fatalf("manifest parse failed: %v", err)
	}
	return manifest
}

func hasThreatClass(result *contracts.ThreatScanResult, class contracts.ThreatClass) bool {
	for _, finding := range result.Findings {
		if finding.Class == class {
			return true
		}
	}
	return false
}

func findByNameSchema() string {
	return `{
		"type": "object",
		"required": ["pattern"],
		"properties": {
			"pattern": {
				"type": "string",
				"not": {
					"pattern": "(^|[\\s\\\"'])-[xX]([\\s=;]|$)|--exec(-batch)?"
				}
			}
		},
		"additionalProperties": false
	}`
}
