package riskscan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
)

var testSalt = bytes.Repeat([]byte{0x08}, riskenvelope.SaltBytes)

func TestScanProjectionPreviewsAndPackOmitRawInputs(t *testing.T) {
	root := fixtureRoot(t)
	envelope, err := Scan(root, BuildOptions{
		Salt:   testSalt,
		Cohort: riskenvelope.CohortRepos1To10,
		Now:    time.Date(2026, 6, 30, 16, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if envelope.Posture.StaticConfigFilesRead != 2 {
		t.Fatalf("static config files read = %d, want 2", envelope.Posture.StaticConfigFilesRead)
	}
	if envelope.Posture.MCPServerCount != 1 {
		t.Fatalf("mcp server count = %d, want 1", envelope.Posture.MCPServerCount)
	}

	body, err := EnvelopeJSON(envelope)
	if err != nil {
		t.Fatalf("envelope json: %v", err)
	}
	md, err := RenderMarkdown(envelope)
	if err != nil {
		t.Fatalf("markdown: %v", err)
	}
	html, err := RenderHTML(envelope)
	if err != nil {
		t.Fatalf("html: %v", err)
	}
	pack := filepath.Join(t.TempDir(), "pack.tar")
	if err := WriteEvidencePack(pack, envelope, map[string][]byte{
		"preview/report.md":   md,
		"preview/report.html": html,
	}); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	packBytes, err := os.ReadFile(pack)
	if err != nil {
		t.Fatalf("read pack: %v", err)
	}

	for _, raw := range []string{
		"customer/private-game",
		"private-game-prod",
		"deploy-production",
		"sk-12345678901234567890123456789012",
	} {
		for name, payload := range map[string][]byte{
			"envelope": body,
			"markdown": md,
			"html":     html,
			"pack":     packBytes,
		} {
			if bytes.Contains(payload, []byte(raw)) {
				t.Fatalf("%s leaked raw input %q", name, raw)
			}
		}
	}
}

func TestEvidencePackTarIsDeterministicAndLimited(t *testing.T) {
	envelope, err := Scan(fixtureRoot(t), BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	md, _ := RenderMarkdown(envelope)
	html, _ := RenderHTML(envelope)
	previews := map[string][]byte{"preview/report.html": html, "preview/report.md": md}

	first := filepath.Join(t.TempDir(), "a.tar")
	second := filepath.Join(t.TempDir(), "b.tar")
	if err := WriteEvidencePack(first, envelope, previews); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := WriteEvidencePack(second, envelope, previews); err != nil {
		t.Fatalf("write second: %v", err)
	}
	firstBytes, _ := os.ReadFile(first)
	secondBytes, _ := os.ReadFile(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("evidence pack tar should be deterministic")
	}

	names := tarNames(t, firstBytes)
	want := []string{
		"preview/report.html",
		"preview/report.md",
		"privacy-manifest.json",
		"risk-envelope.json",
		"schema-validation.json",
		"source-pack-hash.json",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("pack names mismatch\ngot:  %#v\nwant: %#v", names, want)
	}
	if bytes.Contains(firstBytes, []byte("scan_salt")) || bytes.Contains(firstBytes, []byte("customer/private-game")) {
		t.Fatal("pack contains local salt metadata or raw source identity")
	}
}

func TestUploadEnvelopeSendsExactBody(t *testing.T) {
	envelope, err := Scan(fixtureRoot(t), BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	body, err := EnvelopeJSON(envelope)
	if err != nil {
		t.Fatalf("envelope json: %v", err)
	}
	var got []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type = %q", r.Header.Get("Content-Type"))
		}
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	if err := UploadEnvelope(context.Background(), server.URL, body); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("upload body did not match printed envelope body")
	}
	if err := UploadEnvelope(context.Background(), "", body); err == nil {
		t.Fatal("empty upload url should be rejected")
	}
}

func TestScanReceiptsProjectsObservedTrafficWithoutRawLeakage(t *testing.T) {
	root := receiptFixtureRoot(t)
	envelope, err := ScanReceipts(root, BuildOptions{
		Salt:   testSalt,
		Cohort: riskenvelope.CohortRepos11To50,
		Now:    fixedTime(),
	})
	if err != nil {
		t.Fatalf("scan receipts: %v", err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if envelope.Posture.StaticConfigFilesRead != 0 {
		t.Fatalf("static config files read = %d, want 0", envelope.Posture.StaticConfigFilesRead)
	}
	if envelope.Posture.AgentSurface != riskenvelope.AgentSurfaceClaudeCode {
		t.Fatalf("agent surface = %s, want claude_code", envelope.Posture.AgentSurface)
	}
	if envelope.Posture.PermissionMode != riskenvelope.PermissionModeUnknown {
		t.Fatalf("permission mode = %s, want unknown", envelope.Posture.PermissionMode)
	}
	wantRisks := map[riskenvelope.RiskCode]bool{
		riskenvelope.RiskBroadShellAllow:              false,
		riskenvelope.RiskMCPWriteScopeWithoutApproval: false,
		riskenvelope.RiskSecretClassAgentReadable:     false,
	}
	for _, finding := range envelope.Findings {
		if finding.Evidence.PermissionMode != riskenvelope.PermissionModeUnknown {
			t.Fatalf("finding permission mode = %s, want unknown", finding.Evidence.PermissionMode)
		}
		if _, ok := wantRisks[finding.RiskCode]; ok {
			wantRisks[finding.RiskCode] = true
		}
	}
	for risk, seen := range wantRisks {
		if !seen {
			t.Fatalf("missing receipt risk %s in %#v", risk, envelope.Findings)
		}
	}

	body, err := EnvelopeJSON(envelope)
	if err != nil {
		t.Fatalf("envelope json: %v", err)
	}
	md, err := RenderMarkdown(envelope)
	if err != nil {
		t.Fatalf("markdown: %v", err)
	}
	html, err := RenderHTML(envelope)
	if err != nil {
		t.Fatalf("html: %v", err)
	}
	for _, raw := range []string{
		"/Users/customer/private-game",
		"customer/private-game",
		"kubectl apply -f prod.yaml",
		"prod-cluster-token",
		"sk-12345678901234567890123456789012",
	} {
		for name, payload := range map[string][]byte{
			"envelope": body,
			"markdown": md,
			"html":     html,
		} {
			if bytes.Contains(payload, []byte(raw)) {
				t.Fatalf("%s leaked raw receipt input %q", name, raw)
			}
		}
	}
}

func TestScanReceiptsFailsClosedOnInvalidDeclaredInput(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "receipt.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ScanReceipts(root, BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
	if !errors.Is(err, ErrScanCoverageIncomplete) {
		t.Fatalf("ScanReceipts() error = %v, want coverage error", err)
	}
	if strings.Contains(err.Error(), root) {
		t.Fatalf("ScanReceipts() leaked local path: %v", err)
	}

	_, err = ScanReceipts(filepath.Join(root, "missing"), BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
	if !errors.Is(err, ErrScanCoverageIncomplete) {
		t.Fatalf("ScanReceipts() missing-root error = %v, want coverage error", err)
	}
}

func TestScanFailsClosedOnInvalidRecognizedConfig(t *testing.T) {
	for name, writeInvalid := range map[string]func(t *testing.T, root string){
		"mcp json": func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte("{not-json"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"mcp json missing server map": func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"metadata":{}}`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"mcp json malformed server map": func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":[]}`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"codex toml": func(t *testing.T, root string) {
			t.Helper()
			dir := filepath.Join(root, ".codex")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("approval_policy = ["), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeInvalid(t, root)
			_, err := Scan(root, BuildOptions{Salt: testSalt, Cohort: riskenvelope.CohortUnknown, Now: fixedTime()})
			if !errors.Is(err, ErrScanCoverageIncomplete) {
				t.Fatalf("Scan() error = %v, want coverage error", err)
			}
			if strings.Contains(err.Error(), root) {
				t.Fatalf("Scan() leaked local path: %v", err)
			}
		})
	}
}

func TestCollectConfigObservationReadsDirectClaudePluginManifest(t *testing.T) {
	root := t.TempDir()
	pluginDir := filepath.Join(root, ".claude-plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(pluginDir, "plugin.json"), map[string]any{"name": "context7"})
	writeJSON(t, filepath.Join(root, ".mcp.json"), map[string]any{
		"context7": map[string]any{"command": "context7"},
	})

	obs, err := collectConfigObservation(root, true, false)
	if err != nil {
		t.Fatalf("collect plugin config: %v", err)
	}
	if obs.MCPServerCount != 1 {
		t.Fatalf("mcp server count = %d, want 1", obs.MCPServerCount)
	}
	if obs.StaticConfigFilesRead != 1 {
		t.Fatalf("static config files read = %d, want 1", obs.StaticConfigFilesRead)
	}
}

func TestCollectConfigObservationAllowsDesktopConfigWithoutMCPServers(t *testing.T) {
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "claude_desktop_config.json"), map[string]any{
		"globalShortcut": "CommandOrControl+Shift+Space",
	})

	obs, err := collectConfigObservation(root, true, false)
	if err != nil {
		t.Fatalf("collect desktop config: %v", err)
	}
	if obs.MCPServerCount != 0 {
		t.Fatalf("mcp server count = %d, want 0", obs.MCPServerCount)
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "agent.py"), []byte("import anthropic\nOPENAI_API_KEY='sk-12345678901234567890123456789012'\n"), 0o644); err != nil {
		t.Fatalf("write agent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"private-game-prod":{"command":"deploy-production --token sk-12345678901234567890123456789012"}}}`), 0o644); err != nil {
		t.Fatalf("write mcp: %v", err)
	}
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"permissionMode":"acceptEdits","project":"customer/private-game"}`), 0o644); err != nil {
		t.Fatalf("write claude settings: %v", err)
	}
	return root
}

func receiptFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	created := time.Date(2026, 6, 30, 15, 0, 0, 0, time.UTC)
	receipt := contracts.AgentRunReceipt{
		ReceiptVersion: contracts.AgentRunReceiptVersion,
		ReceiptID:      "receipt-private-game",
		RunID:          "run-private-game",
		Goal:           "deploy customer/private-game to prod with prod-cluster-token",
		Workspace: contracts.AgentRunWorkspace{
			WorkspaceID: "workspace-private-game",
			Path:        "/Users/customer/private-game",
			Repository:  "customer/private-game",
		},
		AgentSurface: "claude-code",
		ToolActions: []contracts.AgentToolAction{
			{
				ActionID:   "shell-1",
				ToolID:     "bash",
				Action:     "kubectl apply -f prod.yaml",
				EffectType: contracts.EffectTypeWorkstationShellCommand,
				EffectMode: contracts.WorkstationEffectModeOperate,
				Status:     "ok",
				Verdict:    contracts.WorkstationVerdictAllow,
				Target:     "prod-cluster-token",
				OccurredAt: created,
				Metadata:   map[string]string{"command": "kubectl apply -f prod.yaml"},
			},
			{
				ActionID:   "mcp-1",
				ToolID:     "private-mcp",
				Action:     "write",
				EffectType: contracts.EffectTypeWorkstationMCPToolCall,
				EffectMode: contracts.WorkstationEffectModeObserve,
				Status:     "ok",
				Verdict:    contracts.WorkstationVerdictAllow,
				Target:     "customer/private-game",
				OccurredAt: created,
			},
		},
		CreatedAt: created,
	}
	writeJSON(t, filepath.Join(root, "agent.json"), receipt)

	decision := contracts.WorkstationPolicyDecisionReceipt{
		ReceiptVersion: "workstation_policy_decision.v1",
		DecisionID:     "decision-secret",
		Request: contracts.WorkstationDecisionRequest{
			RequestID:    "secret-1",
			RunID:        "run-private-game",
			AgentSurface: "claude-code",
			ToolID:       "env",
			Action:       "read",
			EffectType:   contracts.EffectTypeWorkstationSecretRead,
			EffectMode:   contracts.WorkstationEffectModeObserve,
			Target:       "sk-12345678901234567890123456789012",
			OccurredAt:   created,
		},
		Verdict:      contracts.WorkstationVerdictAllow,
		ObservedOnly: true,
		CreatedAt:    created,
	}
	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("marshal decision: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "decisions.ndjson"), append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write ndjson: %v", err)
	}
	return root
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

func fixedTime() time.Time {
	return time.Date(2026, 6, 30, 16, 0, 0, 0, time.UTC)
}

func tarNames(t *testing.T, data []byte) []string {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if strings.TrimSpace(header.Name) != "" {
			names = append(names, header.Name)
		}
	}
}

func TestCollectConfigObservationReadsUserAgentConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"a":{},"b":{}},"projects":{"/p":{"mcpServers":{"c":{}}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	claudeDir := filepath.Join(home, ".claude")
	codexDir := filepath.Join(home, ".codex")
	pluginDir := filepath.Join(claudeDir, "plugins", "cache", "official", "context7", "1.0.0")
	projectPluginDir := filepath.Join(claudeDir, "plugins", "cache", "official", "project", "1.0.0")
	disabledPluginDir := filepath.Join(claudeDir, "plugins", "cache", "official", "disabled", "1.0.0")
	for _, dir := range []string{claudeDir, codexDir, pluginDir, projectPluginDir, disabledPluginDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(t, filepath.Join(claudeDir, "settings.json"), map[string]any{
		"enabledPlugins": map[string]bool{
			"context7@official": true,
			"project@official":  false,
			"disabled@official": false,
		},
	})
	writeJSON(t, filepath.Join(claudeDir, "plugins", "installed_plugins.json"), map[string]any{
		"plugins": map[string]any{
			"context7@official": []map[string]any{{"installPath": pluginDir}},
			"project@official":  []map[string]any{{"installPath": projectPluginDir}},
			"disabled@official": []map[string]any{{"installPath": disabledPluginDir}},
		},
	})
	writeJSON(t, filepath.Join(pluginDir, ".mcp.json"), map[string]any{"context7": map[string]any{}})
	writeJSON(t, filepath.Join(projectPluginDir, ".mcp.json"), map[string]any{"project-plugin": map[string]any{}})
	writeJSON(t, filepath.Join(disabledPluginDir, ".mcp.json"), map[string]any{"must-not-count": map[string]any{}})
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`
[mcp_servers.codex]
command = "codex"

[plugins."browser@openai-bundled"]
enabled = true

[plugins."browser@openai-bundled".mcp_servers.browser]
command = "browser"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	projectClaudeDir := filepath.Join(project, ".claude")
	if err := os.MkdirAll(projectClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(projectClaudeDir, "settings.json"), map[string]any{
		"enabledPlugins": map[string]bool{"project@official": true},
	})
	obs, err := collectConfigObservation(project, false, false)
	if err != nil {
		t.Fatalf("without user config: %v", err)
	}
	if obs.MCPServerCount != 0 {
		t.Errorf("opt-out should ignore user config, got %d servers", obs.MCPServerCount)
	}

	obs, err = collectConfigObservation(project, false, true)
	if err != nil {
		t.Fatalf("with user config: %v", err)
	}
	if obs.MCPServerCount != 7 {
		t.Errorf("mcp server count = %d, want 7 (Claude, Codex, and user/project-enabled plugin servers)", obs.MCPServerCount)
	}
	if obs.StaticConfigFilesRead != 7 {
		t.Errorf("static config files read = %d, want 7", obs.StaticConfigFilesRead)
	}
	if obs.ManagedSettingsPresent {
		t.Error("ordinary Claude user config must not report managed settings")
	}
}

func TestCollectConfigObservationAppliesProjectLocalPluginOverrideLast(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	project := t.TempDir()
	claudeDir := filepath.Join(project, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(claudeDir, "Settings.local.json"), map[string]any{
		"enabledPlugins": map[string]bool{"project@official": false},
	})
	writeJSON(t, filepath.Join(claudeDir, "settings.json"), map[string]any{
		"enabledPlugins": map[string]bool{"project@official": true},
	})

	obs, err := collectConfigObservation(project, true, true)
	if err != nil {
		t.Fatalf("project-local plugin override: %v", err)
	}
	if obs.MCPServerCount != 0 {
		t.Fatalf("mcp server count = %d, want 0", obs.MCPServerCount)
	}
}

func TestCollectConfigObservationUsesLatestEnabledPluginInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	claudeDir := filepath.Join(home, ".claude")
	oldPluginDir := filepath.Join(claudeDir, "plugins", "cache", "official", "context7", "1.0.0")
	currentPluginDir := filepath.Join(claudeDir, "plugins", "cache", "official", "context7", "2.0.0")
	for _, dir := range []string{claudeDir, oldPluginDir, currentPluginDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(t, filepath.Join(claudeDir, "settings.json"), map[string]any{
		"enabledPlugins": map[string]bool{"context7@official": true},
	})
	writeJSON(t, filepath.Join(claudeDir, "plugins", "installed_plugins.json"), map[string]any{
		"plugins": map[string]any{
			"context7@official": []map[string]any{
				{"installPath": oldPluginDir, "lastUpdated": "2026-07-29T00:30:00+01:00"},
				{"installPath": currentPluginDir, "lastUpdated": "2026-07-28T23:45:00Z"},
			},
		},
	})
	writeJSON(t, filepath.Join(oldPluginDir, ".mcp.json"), map[string]any{
		"stale-a": map[string]any{},
		"stale-b": map[string]any{},
	})
	writeJSON(t, filepath.Join(currentPluginDir, ".mcp.json"), map[string]any{
		"current": map[string]any{},
	})

	obs, err := collectConfigObservation(t.TempDir(), true, true)
	if err != nil {
		t.Fatalf("latest enabled plugin install: %v", err)
	}
	if obs.MCPServerCount != 1 {
		t.Fatalf("mcp server count = %d, want 1", obs.MCPServerCount)
	}
}

func TestCollectConfigObservationSkipsUninstalledProjectPlugin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	project := t.TempDir()
	claudeDir := filepath.Join(project, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(claudeDir, "settings.json"), map[string]any{
		"enabledPlugins": map[string]bool{"project@official": true},
	})

	obs, err := collectConfigObservation(project, true, true)
	if err != nil {
		t.Fatalf("uninstalled project plugin: %v", err)
	}
	if obs.MCPServerCount != 0 {
		t.Fatalf("mcp server count = %d, want 0", obs.MCPServerCount)
	}
}

func TestCollectConfigObservationAllowsOnlyDisabledPluginsWithoutRegistry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(claudeDir, "settings.json"), map[string]any{
		"enabledPlugins": map[string]bool{"disabled@official": false},
	})

	obs, err := collectConfigObservation(t.TempDir(), true, true)
	if err != nil {
		t.Fatalf("disabled plugins: %v", err)
	}
	if obs.MCPServerCount != 0 {
		t.Fatalf("mcp server count = %d, want 0", obs.MCPServerCount)
	}
}

func TestCollectConfigObservationRejectsInvalidUserAgentConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{not-json`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := collectConfigObservation(t.TempDir(), true, true)
	if !errors.Is(err, ErrScanCoverageIncomplete) {
		t.Fatalf("error = %v, want coverage error", err)
	}
}

func TestCollectConfigObservationRejectsMalformedNestedClaudeMCPServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"projects":{"/srv":{"mcpServers":[]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := collectConfigObservation(t.TempDir(), true, true)
	if !errors.Is(err, ErrScanCoverageIncomplete) {
		t.Fatalf("error = %v, want coverage error", err)
	}
}
