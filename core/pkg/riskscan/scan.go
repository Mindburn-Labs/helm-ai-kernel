package riskscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/riskenvelope"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shadow"
)

type BuildOptions struct {
	Root              string
	Salt              []byte
	Cohort            riskenvelope.CohortBucket
	Now               time.Time
	IncludeUserConfig bool
}

type ConfigObservation struct {
	AgentSurface           riskenvelope.AgentSurface
	PermissionMode         riskenvelope.PermissionMode
	ManagedSettingsPresent bool
	MCPServerCount         int
	StaticConfigFilesRead  int

	permissionModeScope configScope
	permissionModeSet   bool
}

type configScope uint8

const (
	configScopeUser configScope = iota
	configScopeProject
)

// ErrScanCoverageIncomplete means the CLI-only static scan could not inspect
// its declared candidate/config scope. Callers must not export a partial
// RiskEnvelope or scan artifact.
var ErrScanCoverageIncomplete = errors.New("risk scan coverage incomplete")

func Scan(root string, opts BuildOptions) (riskenvelope.RiskEnvelope, error) {
	scanner := shadow.NewScanner()
	scanner.RequireComplete = true
	report, err := scanner.Scan(root)
	if err != nil {
		if errors.Is(err, shadow.ErrScanCoverageIncomplete) {
			return riskenvelope.RiskEnvelope{}, scanCoverageError("static candidate coverage could not be completed")
		}
		return riskenvelope.RiskEnvelope{}, err
	}
	obs, err := collectConfigObservation(root, true, opts.IncludeUserConfig)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	opts.Root = root
	return BuildEnvelope(report, obs, opts)
}

func CollectConfigObservation(root string) (ConfigObservation, error) {
	return collectConfigObservation(root, false, false)
}

func collectConfigObservation(root string, requireComplete, includeUserConfig bool) (ConfigObservation, error) {
	obs := ConfigObservation{
		AgentSurface:   riskenvelope.AgentSurfaceUnknown,
		PermissionMode: riskenvelope.PermissionModeUnknown,
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return obs, err
	}
	userConfigPaths := map[string]struct{}{}
	userEnabledPlugins := map[string]bool{}
	projectEnabledPlugins := map[string]bool{}
	userHome := ""
	if includeUserConfig {
		var err error
		userHome, err = os.UserHomeDir()
		if err != nil {
			if requireComplete {
				return obs, scanCoverageError("user configuration coverage could not be completed")
			}
			return obs, err
		}
		paths := knownUserConfigPaths(userHome)
		for _, path := range paths {
			path = filepath.Clean(path)
			userConfigPaths[path] = struct{}{}
			if pathWithinRoot(path, absRoot) {
				continue
			}
			if err := observeConfigFile(&obs, path, configScopeUser, requireComplete, userEnabledPlugins); err != nil {
				return obs, err
			}
		}
	}
	err = filepath.WalkDir(absRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if requireComplete && !shouldSkipPath(path) {
				return scanCoverageError("static configuration coverage could not be completed")
			}
			return nil
		}
		if entry == nil {
			if requireComplete {
				return scanCoverageError("static configuration coverage could not be completed")
			}
			return nil
		}
		if entry.IsDir() {
			if shouldSkipDir(entry.Name()) && path != absRoot {
				return filepath.SkipDir
			}
			return nil
		}
		scope := configScopeProject
		if _, ok := userConfigPaths[filepath.Clean(path)]; ok {
			scope = configScopeUser
		}
		enabledPlugins := projectEnabledPlugins
		if scope == configScopeUser {
			enabledPlugins = userEnabledPlugins
		}
		return observeConfigFile(&obs, path, scope, requireComplete, enabledPlugins)
	})
	if err != nil {
		if requireComplete && !errors.Is(err, ErrScanCoverageIncomplete) {
			return obs, scanCoverageError("static configuration coverage could not be completed")
		}
		return obs, err
	}
	if includeUserConfig {
		enabledPlugins := make(map[string]bool, len(userEnabledPlugins)+len(projectEnabledPlugins))
		for pluginID, enabled := range userEnabledPlugins {
			enabledPlugins[pluginID] = enabled
		}
		for pluginID, enabled := range projectEnabledPlugins {
			enabledPlugins[pluginID] = enabled
		}
		if err := applyClaudePluginConfigs(&obs, userHome, absRoot, enabledPlugins, requireComplete); err != nil {
			return obs, err
		}
	}
	return obs, nil
}

func knownUserConfigPaths(home string) []string {
	return []string{
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(home, ".codex", "config.toml"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
	}
}

func pathWithinRoot(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func observeConfigFile(obs *ConfigObservation, path string, scope configScope, requireComplete bool, enabledPlugins map[string]bool) error {
	kind, ok := configKind(path)
	if !ok {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.IsDir() {
		if requireComplete {
			return scanCoverageError("recognized configuration could not be read")
		}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if requireComplete {
			return scanCoverageError("recognized configuration could not be read")
		}
		return nil
	}
	obs.StaticConfigFilesRead++
	if err := applyConfigObservation(obs, kind, data, scope); err != nil && requireComplete {
		return scanCoverageError("recognized configuration is invalid")
	}
	if enabledPlugins != nil && isClaudeSettingsConfig(path) {
		if err := mergeClaudeEnabledPlugins(enabledPlugins, data); err != nil && requireComplete {
			return scanCoverageError("recognized configuration is invalid")
		}
	}
	return nil
}

func isClaudeSettingsConfig(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	parent := strings.ToLower(filepath.Base(filepath.Dir(path)))
	return parent == ".claude" && strings.HasPrefix(base, "settings") && strings.HasSuffix(base, ".json")
}

func mergeClaudeEnabledPlugins(dst map[string]bool, data []byte) error {
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}
	for pluginID, enabled := range settings.EnabledPlugins {
		dst[pluginID] = enabled
	}
	return nil
}

type claudePluginInstall struct {
	InstallPath string `json:"installPath"`
	LastUpdated string `json:"lastUpdated"`
}

func applyClaudePluginConfigs(obs *ConfigObservation, home, absRoot string, enabledPlugins map[string]bool, requireComplete bool) error {
	hasEnabledPlugin := false
	for _, enabled := range enabledPlugins {
		if enabled {
			hasEnabledPlugin = true
			break
		}
	}
	if !hasEnabledPlugin {
		return nil
	}

	registryPath := filepath.Join(home, ".claude", "plugins", "installed_plugins.json")
	data, err := os.ReadFile(registryPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		if requireComplete {
			return scanCoverageError("enabled plugin inventory could not be read")
		}
		return nil
	}
	obs.StaticConfigFilesRead++
	var registry struct {
		Plugins map[string][]claudePluginInstall `json:"plugins"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		if requireComplete {
			return scanCoverageError("enabled plugin inventory is invalid")
		}
		return nil
	}

	seen := map[string]bool{}
	for pluginID, enabled := range enabledPlugins {
		if !enabled {
			continue
		}
		installs := registry.Plugins[pluginID]
		if len(installs) == 0 {
			continue
		}
		install, err := latestClaudePluginInstall(installs)
		if err != nil {
			if requireComplete {
				return scanCoverageError("enabled plugin inventory is invalid")
			}
			return nil
		}
		if strings.TrimSpace(install.InstallPath) == "" || !filepath.IsAbs(install.InstallPath) {
			if requireComplete {
				return scanCoverageError("enabled plugin inventory is invalid")
			}
			return nil
		}
		manifestPath := filepath.Clean(filepath.Join(install.InstallPath, ".mcp.json"))
		if seen[manifestPath] || pathWithinRoot(manifestPath, absRoot) {
			continue
		}
		seen[manifestPath] = true
		if err := observeConfigFile(obs, manifestPath, configScopeUser, requireComplete, nil); err != nil {
			return err
		}
	}
	return nil
}

func latestClaudePluginInstall(installs []claudePluginInstall) (claudePluginInstall, error) {
	latest := installs[0]
	if len(installs) == 1 {
		return latest, nil
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, latest.LastUpdated)
	if err != nil {
		return claudePluginInstall{}, err
	}
	for _, candidate := range installs[1:] {
		candidateUpdatedAt, err := time.Parse(time.RFC3339Nano, candidate.LastUpdated)
		if err != nil {
			return claudePluginInstall{}, err
		}
		if candidateUpdatedAt.After(updatedAt) {
			latest = candidate
			updatedAt = candidateUpdatedAt
		}
	}
	return latest, nil
}

func scanCoverageError(reason string) error {
	return fmt.Errorf("%w: %s", ErrScanCoverageIncomplete, reason)
}

func BuildEnvelope(report *shadow.Report, obs ConfigObservation, opts BuildOptions) (riskenvelope.RiskEnvelope, error) {
	if report == nil {
		return riskenvelope.RiskEnvelope{}, fmt.Errorf("shadow report is required")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	sourceHash, err := riskenvelope.CanonicalSHA256Ref(sourceSummary{
		FilesScanned:          report.FilesScanned,
		FilesSkipped:          report.FilesSkipped,
		SummaryByVendor:       report.SummaryByVendor,
		SummaryBySeverity:     report.SummaryBySeverity,
		BoundaryGrade:         report.Grade.Letter,
		HelmPresent:           report.HelmCoverage.Present,
		MCPServerCount:        obs.MCPServerCount,
		StaticConfigFilesRead: obs.StaticConfigFilesRead,
	})
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	envelopeID, err := riskenvelope.EnvelopeID(opts.Salt, sourceHash)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	findings, err := projectFindings(report.Findings, obs, opts.Salt)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].RiskCode != findings[j].RiskCode {
			return findings[i].RiskCode < findings[j].RiskCode
		}
		return findings[i].ResourceID < findings[j].ResourceID
	})
	envelope := riskenvelope.RiskEnvelope{
		SchemaVersion:  riskenvelope.SchemaVersion,
		EnvelopeID:     envelopeID,
		CohortBucket:   opts.Cohort,
		SourcePackHash: sourceHash,
		Findings:       findings,
		Posture: riskenvelope.PostureProbe{
			AgentSurface:           resolveAgentSurface(report, obs),
			PermissionMode:         obs.PermissionMode,
			ManagedSettingsPresent: obs.ManagedSettingsPresent,
			MCPServerCount:         obs.MCPServerCount,
			OAuthScopeBuckets:      []riskenvelope.OAuthScopeBucketCount{},
			IAMGrantBuckets:        []riskenvelope.IAMGrantBucketCount{},
			StaticConfigFilesRead:  obs.StaticConfigFilesRead,
			MetadataAPICalls:       0,
			SuppressedFindingCount: 0,
			KAnonymityFloor:        0,
		},
		Privacy:     riskenvelope.PrivacyNonCollection{},
		GeneratedAt: opts.Now.UTC(),
	}
	sealed, err := riskenvelope.Seal(envelope)
	if err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	if err := sealed.Validate(); err != nil {
		return riskenvelope.RiskEnvelope{}, err
	}
	return sealed, nil
}

func EnvelopeJSON(envelope riskenvelope.RiskEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func RenderMarkdown(envelope riskenvelope.RiskEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	view := newPreviewView(envelope)
	var b strings.Builder
	fmt.Fprintf(&b, "# HELM AI Agent Risk Surface\n\n")
	fmt.Fprintf(&b, "- Envelope: `%s`\n", view.EnvelopeID)
	fmt.Fprintf(&b, "- Content hash: `%s`\n", view.ContentHash)
	fmt.Fprintf(&b, "- Generated: `%s`\n", view.GeneratedAt)
	fmt.Fprintf(&b, "- Agent surface: `%s`\n", view.AgentSurface)
	fmt.Fprintf(&b, "- Permission mode: `%s`\n", view.PermissionMode)
	fmt.Fprintf(&b, "- MCP servers detected: `%d`\n", view.MCPServerCount)
	fmt.Fprintf(&b, "- Static config files read: `%d`\n\n", view.StaticConfigFilesRead)
	fmt.Fprintf(&b, "## Findings\n\n")
	if len(view.FindingsBySeverity) == 0 {
		fmt.Fprintf(&b, "No upload-safe findings detected.\n\n")
	} else {
		for _, row := range view.FindingsBySeverity {
			fmt.Fprintf(&b, "- `%s`: %d\n", row.Name, row.Count)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Risk Codes\n\n")
	for _, row := range view.FindingsByRisk {
		fmt.Fprintf(&b, "- `%s`: %d\n", row.Name, row.Count)
	}
	if len(view.FindingsByRisk) == 0 {
		fmt.Fprintf(&b, "No risk codes emitted.\n")
	}
	fmt.Fprintf(&b, "\n## Privacy\n\n")
	fmt.Fprintf(&b, "This preview is generated from the anonymized RiskEnvelope only. Raw prompts, source code, secret values, command bodies, raw paths, and raw repository names are not present.\n")
	return []byte(b.String()), nil
}

func RenderHTML(envelope riskenvelope.RiskEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	tpl := template.Must(template.New("risk-preview").Parse(htmlPreviewTemplate))
	var b bytes.Buffer
	if err := tpl.Execute(&b, newPreviewView(envelope)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func UploadEnvelope(ctx context.Context, url string, body []byte) error {
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("upload url is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "helm-ai-kernel-scan")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed: %s %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func projectFindings(findings []shadow.Finding, obs ConfigObservation, salt []byte) ([]riskenvelope.EnvelopeFinding, error) {
	out := make([]riskenvelope.EnvelopeFinding, 0, len(findings))
	for i, finding := range findings {
		projected, ok, err := projectFinding(finding, obs, salt, i)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, projected)
		}
	}
	return out, nil
}

func projectFinding(f shadow.Finding, obs ConfigObservation, salt []byte, index int) (riskenvelope.EnvelopeFinding, bool, error) {
	if f.Vendor == "helm" {
		return riskenvelope.EnvelopeFinding{}, false, nil
	}
	risk, resource, evidence := mapFinding(f, obs)
	resourceID, err := riskenvelope.Pseudonym(salt, fmt.Sprintf("finding:%s:%s:%s:%d:%d", f.Kind, f.Vendor, f.Path, f.Line, index))
	if err != nil {
		return riskenvelope.EnvelopeFinding{}, false, err
	}
	return riskenvelope.EnvelopeFinding{
		ResourceID:   resourceID,
		ResourceType: resource,
		RiskCode:     risk,
		Severity:     mapSeverity(f.Severity),
		Evidence:     evidence,
	}, true, nil
}

func mapFinding(f shadow.Finding, obs ConfigObservation) (riskenvelope.RiskCode, riskenvelope.ResourceType, riskenvelope.EnvelopeEvidence) {
	managed := obs.ManagedSettingsPresent
	audit := false
	mcpWrite := true
	schemaPinned := false
	secretReadable := true
	mode := obs.PermissionMode
	if mode == "" {
		mode = riskenvelope.PermissionModeUnknown
	}
	switch f.Kind {
	case "mcp_config":
		return riskenvelope.RiskMCPWriteScopeWithoutApproval, riskenvelope.ResourceMCPServer, riskenvelope.EnvelopeEvidence{
			AgentTool:      riskenvelope.ToolClassMCPWrite,
			PermissionMode: mode,
			MCPWriteScopes: &mcpWrite,
			SchemaPinned:   &schemaPinned,
		}
	case "api_key":
		return riskenvelope.RiskSecretClassAgentReadable, riskenvelope.ResourceSecretClass, riskenvelope.EnvelopeEvidence{
			AgentTool:             riskenvelope.ToolClassSecretRead,
			PermissionMode:        mode,
			SecretValueAccessible: &secretReadable,
		}
	case "helm_absent":
		return riskenvelope.RiskAgentWriteWithoutEnvApproval, riskenvelope.ResourceRepo, riskenvelope.EnvelopeEvidence{
			AgentTool:       riskenvelope.ToolClassShellOperate,
			PermissionMode:  mode,
			ManagedSettings: &managed,
			AuditLogging:    &audit,
		}
	case "agt_detected":
		return riskenvelope.RiskNoAuditExport, riskenvelope.ResourceRepo, riskenvelope.EnvelopeEvidence{
			AgentTool:       riskenvelope.ToolClassUnknown,
			PermissionMode:  mode,
			ManagedSettings: &managed,
			AuditLogging:    &audit,
		}
	default:
		return riskenvelope.RiskNoManagedSettings, riskenvelope.ResourceRepo, riskenvelope.EnvelopeEvidence{
			AgentTool:       riskenvelope.ToolClassUnknown,
			PermissionMode:  mode,
			ManagedSettings: &managed,
		}
	}
}

func mapSeverity(value string) riskenvelope.Severity {
	switch strings.ToUpper(value) {
	case "INFO":
		return riskenvelope.SeverityInfo
	case "LOW":
		return riskenvelope.SeverityLow
	case "HIGH":
		return riskenvelope.SeverityHigh
	case "CRITICAL":
		return riskenvelope.SeverityCritical
	default:
		return riskenvelope.SeverityMedium
	}
}

func resolveAgentSurface(report *shadow.Report, obs ConfigObservation) riskenvelope.AgentSurface {
	if obs.AgentSurface != "" && obs.AgentSurface != riskenvelope.AgentSurfaceUnknown {
		return obs.AgentSurface
	}
	for _, finding := range report.Findings {
		if finding.Vendor == "anthropic" {
			return riskenvelope.AgentSurfaceClaudeCode
		}
	}
	if obs.MCPServerCount > 0 {
		return riskenvelope.AgentSurfaceMCP
	}
	return riskenvelope.AgentSurfaceUnknown
}

func applyConfigObservation(obs *ConfigObservation, kind string, data []byte, scope configScope) error {
	switch kind {
	case "claude_json":
		obs.AgentSurface = riskenvelope.AgentSurfaceClaudeCode
		if scope == configScopeProject {
			obs.ManagedSettingsPresent = true
		}
		return applyJSONConfig(obs, data, scope)
	case "claude_desktop_json":
		obs.AgentSurface = riskenvelope.AgentSurfaceClaudeCode
		return applyJSONConfig(obs, data, scope)
	case "mcp_json":
		if err := applyMCPJSONConfig(obs, data, scope, false); err != nil {
			return err
		}
		if obs.AgentSurface == riskenvelope.AgentSurfaceUnknown {
			obs.AgentSurface = riskenvelope.AgentSurfaceMCP
		}
	case "plugin_mcp_json":
		if err := applyMCPJSONConfig(obs, data, scope, true); err != nil {
			return err
		}
		if obs.AgentSurface == riskenvelope.AgentSurfaceUnknown {
			obs.AgentSurface = riskenvelope.AgentSurfaceMCP
		}
	case "codex_toml":
		obs.AgentSurface = riskenvelope.AgentSurfaceCodex
		return applyTOMLConfig(obs, data, scope)
	}
	return nil
}

func applyMCPJSONConfig(obs *ConfigObservation, data []byte, scope configScope, allowDirect bool) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("MCP configuration must be an object")
	}
	servers, ok := raw["mcpServers"]
	if ok {
		if _, ok := servers.(map[string]any); !ok {
			return fmt.Errorf("mcpServers must be an object")
		}
	} else if !allowDirect {
		return fmt.Errorf("mcpServers is required")
	} else {
		for _, server := range raw {
			if _, ok := server.(map[string]any); !ok {
				return fmt.Errorf("plugin MCP server configuration must be an object")
			}
		}
		obs.MCPServerCount += len(raw)
		if mode := findString(raw, "permissionMode", "defaultMode", "approval_policy", "approvalPolicy"); mode != "" {
			obs.setPermissionMode(normalizePermissionMode(mode), scope)
		}
		return nil
	}
	return applyJSONValue(obs, raw, scope)
}

func applyJSONConfig(obs *ConfigObservation, data []byte, scope configScope) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("agent configuration must be an object")
	}
	return applyJSONValue(obs, raw, scope)
}

func applyJSONValue(obs *ConfigObservation, raw map[string]any, scope configScope) error {
	mcpServerCount, err := countMap(raw, "mcpServers")
	if err != nil {
		return err
	}
	obs.MCPServerCount += mcpServerCount
	if mode := findString(raw, "permissionMode", "defaultMode", "approval_policy", "approvalPolicy"); mode != "" {
		obs.setPermissionMode(normalizePermissionMode(mode), scope)
	}
	return nil
}

func applyTOMLConfig(obs *ConfigObservation, data []byte, scope configScope) error {
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		return err
	}
	mcpServerCount, err := countMap(raw, "mcp_servers")
	if err != nil {
		return err
	}
	obs.MCPServerCount += mcpServerCount
	if mode := findString(raw, "approval_policy", "approvalPolicy", "permission_mode", "permissionMode"); mode != "" {
		obs.setPermissionMode(normalizePermissionMode(mode), scope)
	}
	return nil
}

func (obs *ConfigObservation) setPermissionMode(mode riskenvelope.PermissionMode, scope configScope) {
	if !obs.permissionModeSet || scope >= obs.permissionModeScope {
		obs.PermissionMode = mode
		obs.permissionModeScope = scope
		obs.permissionModeSet = true
	}
}

func countMap(v any, key string) (int, error) {
	switch typed := v.(type) {
	case map[string]any:
		total := 0
		for k, child := range typed {
			if k == key {
				m, ok := child.(map[string]any)
				if !ok {
					return 0, fmt.Errorf("%s must be an object", key)
				}
				total += len(m)
			}
			count, err := countMap(child, key)
			if err != nil {
				return 0, err
			}
			total += count
		}
		return total, nil
	case []any:
		total := 0
		for _, child := range typed {
			count, err := countMap(child, key)
			if err != nil {
				return 0, err
			}
			total += count
		}
		return total, nil
	default:
		return 0, nil
	}
}

func findString(v any, keys ...string) string {
	want := map[string]bool{}
	for _, key := range keys {
		want[strings.ToLower(key)] = true
	}
	switch typed := v.(type) {
	case map[string]any:
		for k, child := range typed {
			if want[strings.ToLower(k)] {
				if s, ok := child.(string); ok {
					return s
				}
			}
			if found := findString(child, keys...); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range typed {
			if found := findString(child, keys...); found != "" {
				return found
			}
		}
	}
	return ""
}

func normalizePermissionMode(value string) riskenvelope.PermissionMode {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(v, "bypass") || v == "never":
		return riskenvelope.PermissionModeBypassPermissions
	case strings.Contains(v, "accept") || strings.Contains(v, "edit"):
		return riskenvelope.PermissionModeAcceptEdits
	case strings.Contains(v, "ask"):
		return riskenvelope.PermissionModeAsk
	case strings.Contains(v, "plan"):
		return riskenvelope.PermissionModePlan
	default:
		return riskenvelope.PermissionModeUnknown
	}
}

func configKind(path string) (string, bool) {
	base := strings.ToLower(filepath.Base(path))
	parent := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch {
	case base == ".mcp.json" && isClaudePluginMCPConfig(path):
		return "plugin_mcp_json", true
	case base == ".mcp.json" || base == "mcp.json":
		return "mcp_json", true
	case base == ".claude.json":
		return "claude_json", true
	case base == "claude_desktop_config.json":
		return "claude_desktop_json", true
	case parent == ".claude" && strings.HasPrefix(base, "settings") && strings.HasSuffix(base, ".json"):
		return "claude_json", true
	case parent == ".codex" && base == "config.toml":
		return "codex_toml", true
	default:
		return "", false
	}
}

func isClaudePluginMCPConfig(path string) bool {
	info, err := os.Stat(filepath.Join(filepath.Dir(path), ".claude-plugin", "plugin.json"))
	return err == nil && info.Mode().IsRegular()
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".next", "dist", "build", "target":
		return true
	default:
		return false
	}
}

func shouldSkipPath(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(path)), "/") {
		if shouldSkipDir(part) {
			return true
		}
	}
	return false
}

type sourceSummary struct {
	FilesScanned          int            `json:"files_scanned"`
	FilesSkipped          int            `json:"files_skipped"`
	SummaryByVendor       map[string]int `json:"summary_by_vendor"`
	SummaryBySeverity     map[string]int `json:"summary_by_severity"`
	BoundaryGrade         string         `json:"boundary_grade"`
	HelmPresent           bool           `json:"helm_present"`
	MCPServerCount        int            `json:"mcp_server_count"`
	StaticConfigFilesRead int            `json:"static_config_files_read"`
}

type previewRow struct {
	Name  string
	Count int
}

type previewView struct {
	EnvelopeID            string
	ContentHash           string
	GeneratedAt           string
	AgentSurface          string
	PermissionMode        string
	MCPServerCount        int
	StaticConfigFilesRead int
	FindingsBySeverity    []previewRow
	FindingsByRisk        []previewRow
}

func newPreviewView(envelope riskenvelope.RiskEnvelope) previewView {
	severity := map[string]int{}
	risk := map[string]int{}
	for _, finding := range envelope.Findings {
		severity[string(finding.Severity)]++
		risk[string(finding.RiskCode)]++
	}
	return previewView{
		EnvelopeID:            envelope.EnvelopeID,
		ContentHash:           envelope.EnvelopeContentHash,
		GeneratedAt:           envelope.GeneratedAt.UTC().Format(time.RFC3339),
		AgentSurface:          string(envelope.Posture.AgentSurface),
		PermissionMode:        string(envelope.Posture.PermissionMode),
		MCPServerCount:        envelope.Posture.MCPServerCount,
		StaticConfigFilesRead: envelope.Posture.StaticConfigFilesRead,
		FindingsBySeverity:    sortedRows(severity),
		FindingsByRisk:        sortedRows(risk),
	}
}

func sortedRows(counts map[string]int) []previewRow {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]previewRow, 0, len(names))
	for _, name := range names {
		rows = append(rows, previewRow{Name: name, Count: counts[name]})
	}
	return rows
}

const htmlPreviewTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>HELM AI Agent Risk Surface</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #17202a; }
    main { max-width: 880px; }
    code { background: #f2f4f7; padding: 2px 5px; border-radius: 4px; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0 28px; }
    th, td { border-bottom: 1px solid #d8dee8; padding: 8px 4px; text-align: left; }
    th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #52606d; }
  </style>
</head>
<body>
<main>
  <h1>HELM AI Agent Risk Surface</h1>
  <p>Envelope <code>{{.EnvelopeID}}</code></p>
  <p>Content hash <code>{{.ContentHash}}</code></p>
  <table>
    <tr><th>Generated</th><td>{{.GeneratedAt}}</td></tr>
    <tr><th>Agent surface</th><td>{{.AgentSurface}}</td></tr>
    <tr><th>Permission mode</th><td>{{.PermissionMode}}</td></tr>
    <tr><th>MCP servers</th><td>{{.MCPServerCount}}</td></tr>
    <tr><th>Static config files read</th><td>{{.StaticConfigFilesRead}}</td></tr>
  </table>
  <h2>Findings By Severity</h2>
  <table><tr><th>Severity</th><th>Count</th></tr>{{range .FindingsBySeverity}}<tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="2">No upload-safe findings detected.</td></tr>{{end}}</table>
  <h2>Risk Codes</h2>
  <table><tr><th>Risk code</th><th>Count</th></tr>{{range .FindingsByRisk}}<tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>{{else}}<tr><td colspan="2">No risk codes emitted.</td></tr>{{end}}</table>
  <h2>Privacy</h2>
  <p>This preview is generated from the anonymized RiskEnvelope only. Raw prompts, source code, secret values, command bodies, raw paths, and raw repository names are not present.</p>
</main>
</body>
</html>
`
