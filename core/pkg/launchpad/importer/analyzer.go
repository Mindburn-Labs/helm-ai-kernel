package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

type Analyzer struct {
	Adapters []FrameworkAdapter
	Fetcher  SourceFetcher
}

type SourceFetcher interface {
	Fetch(context.Context, ImportRequest) (SourceSnapshot, error)
}

func NewAnalyzer(adapters []FrameworkAdapter, fetcher SourceFetcher) Analyzer {
	if len(adapters) == 0 {
		adapters = DefaultAdapters()
	}
	if fetcher == nil {
		fetcher = NewGitHubFetcher(nil)
	}
	sort.SliceStable(adapters, func(i, j int) bool {
		if adapters[i].Metadata.Priority == adapters[j].Metadata.Priority {
			return adapters[i].Metadata.ID < adapters[j].Metadata.ID
		}
		return adapters[i].Metadata.Priority > adapters[j].Metadata.Priority
	})
	return Analyzer{Adapters: adapters, Fetcher: fetcher}
}

func (a Analyzer) Import(ctx context.Context, req ImportRequest, now time.Time) (ImportRecord, error) {
	req.RepoURL = strings.TrimSpace(req.RepoURL)
	req.Ref = strings.TrimSpace(req.Ref)
	req.DesiredTarget = strings.TrimSpace(req.DesiredTarget)
	if req.RepoURL == "" {
		return ImportRecord{}, fmt.Errorf("repo_url is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	source, err := a.Fetcher.Fetch(ctx, req)
	if err != nil {
		return ImportRecord{}, err
	}
	if source.FetchedAt.IsZero() {
		source.FetchedAt = now
	}
	importID := importID(req, now)
	graph := BuildCapabilityGraph(source, a.Adapters)
	strategy := SelectBuildStrategy(source, graph, a.Adapters)
	recipe := BuildLaunchRecipe(importID, req, source, graph, strategy, now)
	ledger := ImportEvidenceLedger{
		Status:               "generated_untrusted",
		ReceiptRefs:          []string{"receipt:launchpad-import:" + importID + ":source", "receipt:launchpad-import:" + importID + ":capability-graph"},
		EvidencePackRefs:     []string{"evidencepack:launchpad-import:" + importID + ":preflight"},
		SBOMRef:              "pending:sbom:" + importID,
		VulnerabilityScanRef: "pending:vulnerability-scan:" + importID,
		ProvenanceRef:        "pending:provenance:" + importID,
		LicenseRef:           firstNonEmpty(source.LicenseSPDX, "NOASSERTION"),
		PolicyRefs:           []string{"policy:launchpad-import:quarantine:v1"},
		OfflineVerifyCommand: "helm-ai-kernel verify " + "evidencepack:launchpad-import:" + importID + ":preflight --offline",
	}
	return ImportRecord{
		ID:              importID,
		State:           StateImported,
		CreatedAt:       now,
		UpdatedAt:       now,
		Request:         req,
		SourceSnapshot:  source,
		CapabilityGraph: graph,
		LaunchRecipe:    recipe,
		EvidenceLedger:  ledger,
	}, nil
}

func BuildCapabilityGraph(source SourceSnapshot, adapters []FrameworkAdapter) CapabilityGraph {
	fileIndex := indexFiles(source.Files)
	var matches []AdapterMatch
	capSet := map[string]bool{}
	var frameworks []DetectedFramework
	var modules []DetectedModule
	var buildSignals, runtimeSignals, policySignals, securitySignals []string

	for _, adapter := range adapters {
		match := matchAdapter(adapter, source, fileIndex)
		if match.Confidence <= 0 {
			continue
		}
		matches = append(matches, match)
		if match.Confidence >= threshold(adapter.Match.ConfidenceThreshold) {
			frameworks = append(frameworks, DetectedFramework{
				ID:         adapter.Metadata.ID,
				Name:       adapter.Metadata.ID,
				Confidence: match.Confidence,
				Evidence:   match.Evidence,
			})
			for _, capability := range adapter.Capabilities {
				capSet[capability] = true
			}
		}
	}

	for _, f := range source.Files {
		name := strings.ToLower(path.Base(f.Path))
		switch name {
		case "dockerfile":
			capSet["container"] = true
			buildSignals = appendUnique(buildSignals, f.Path)
			modules = append(modules, DetectedModule{Path: path.Dir(f.Path), Kind: "container", Manifests: []string{f.Path}, BuildStrategy: "dockerfile"})
		case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
			capSet["compose"] = true
			capSet["localRuntime"] = true
			buildSignals = appendUnique(buildSignals, f.Path)
			modules = append(modules, DetectedModule{Path: path.Dir(f.Path), Kind: "compose-stack", Manifests: []string{f.Path}, BuildStrategy: "compose"})
		case "package.json":
			capSet["node"] = true
			module := detectPackageJSONModule(f)
			modules = append(modules, module)
			buildSignals = appendUnique(buildSignals, f.Path)
			for _, capability := range packageJSONCapabilities(f.Content) {
				capSet[capability] = true
			}
		case "pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock":
			capSet["python"] = true
			buildSignals = appendUnique(buildSignals, f.Path)
			modules = append(modules, DetectedModule{Path: path.Dir(f.Path), Kind: "python", Manifests: []string{f.Path}, BuildStrategy: "native"})
		case "cargo.toml":
			capSet["rust"] = true
			buildSignals = appendUnique(buildSignals, f.Path)
			modules = append(modules, DetectedModule{Path: path.Dir(f.Path), Kind: "rust", Manifests: []string{f.Path}, BuildStrategy: "native"})
		case "go.mod":
			capSet["go"] = true
			buildSignals = appendUnique(buildSignals, f.Path)
			modules = append(modules, DetectedModule{Path: path.Dir(f.Path), Kind: "go", Manifests: []string{f.Path}, BuildStrategy: "native"})
		case "pom.xml", "build.gradle", "build.gradle.kts":
			capSet["jvm"] = true
			buildSignals = appendUnique(buildSignals, f.Path)
			modules = append(modules, DetectedModule{Path: path.Dir(f.Path), Kind: "jvm", Manifests: []string{f.Path}, BuildStrategy: "native"})
		case "devcontainer.json":
			capSet["devcontainer"] = true
			runtimeSignals = appendUnique(runtimeSignals, f.Path)
		case "chart.yaml":
			capSet["helmChart"] = true
			runtimeSignals = appendUnique(runtimeSignals, f.Path)
		case "langgraph.json":
			capSet["agentFramework"] = true
			capSet["apiServer"] = true
			runtimeSignals = appendUnique(runtimeSignals, f.Path)
		case ".env.example", ".env.sample":
			policySignals = appendUnique(policySignals, f.Path)
		}
		if strings.Contains(strings.ToLower(f.Path), "mcp") {
			capSet["mcpTools"] = true
			runtimeSignals = appendUnique(runtimeSignals, f.Path)
		}
		if strings.Contains(strings.ToLower(f.Content), "ag-ui") || strings.Contains(strings.ToLower(f.Content), "agui") {
			capSet["agui"] = true
			runtimeSignals = appendUnique(runtimeSignals, f.Path)
		}
	}

	secrets := detectSecrets(source.Files)
	if len(secrets) > 0 {
		capSet["secrets"] = true
	}
	oauth := detectOAuth(source.Files)
	if len(oauth) > 0 {
		capSet["oauth"] = true
	}
	ports := detectPorts(source.Files)
	if len(ports) > 0 {
		capSet["network"] = true
	}
	if source.LicenseSPDX != "" {
		policySignals = appendUnique(policySignals, "license:"+source.LicenseSPDX)
	}
	if hasAnyFile(fileIndex, "SECURITY.md", ".github/dependabot.yml", ".github/workflows") {
		securitySignals = appendUnique(securitySignals, "repo-health-signal")
	}

	capabilities := keys(capSet)
	sort.Strings(capabilities)
	priorities := map[string]int{}
	for _, adapter := range adapters {
		priorities[adapter.Metadata.ID] = adapter.Metadata.Priority
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Confidence == matches[j].Confidence {
			if priorities[matches[i].AdapterID] != priorities[matches[j].AdapterID] {
				return priorities[matches[i].AdapterID] > priorities[matches[j].AdapterID]
			}
			return matches[i].AdapterID < matches[j].AdapterID
		}
		return matches[i].Confidence > matches[j].Confidence
	})
	confidence := graphConfidence(matches, buildSignals)
	return CapabilityGraph{
		Capabilities:     capabilities,
		Modules:          dedupeModules(modules),
		Frameworks:       frameworks,
		Secrets:          secrets,
		OAuth:            oauth,
		Ports:            ports,
		BuildSignals:     buildSignals,
		RuntimeSignals:   runtimeSignals,
		PolicySignals:    policySignals,
		SecuritySignals:  securitySignals,
		AdapterMatches:   matches,
		Confidence:       confidence,
		ConfidenceReason: confidenceReason(confidence, matches, buildSignals),
	}
}

func SelectBuildStrategy(source SourceSnapshot, graph CapabilityGraph, adapters []FrameworkAdapter) BuildStrategy {
	fileIndex := indexFiles(source.Files)
	for _, match := range graph.AdapterMatches {
		adapter := adapterByID(adapters, match.AdapterID)
		if match.Confidence < threshold(adapter.Match.ConfidenceThreshold) {
			continue
		}
		if adapter.Metadata.ID == "" || adapter.Build.Strategy == "" {
			continue
		}
		commands := adapterCommands(adapter)
		return BuildStrategy{Strategy: adapter.Build.Strategy, Confidence: match.Confidence, Reason: "framework-native adapter matched deterministic files", Commands: commands, ManifestSources: match.Evidence}
	}
	if hasAnyFile(fileIndex, "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") {
		return BuildStrategy{Strategy: "compose", Confidence: 0.86, Reason: "repo declares Compose runtime", Commands: [][]string{{"docker", "compose", "up", "--build"}}, ManifestSources: matchingFiles(fileIndex, "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")}
	}
	if hasAnyFile(fileIndex, "Dockerfile") {
		return BuildStrategy{Strategy: "dockerfile", Confidence: 0.82, Reason: "repo declares Dockerfile runtime", Commands: [][]string{{"docker", "buildx", "build", "--sbom", "--provenance", "."}}, ManifestSources: matchingFiles(fileIndex, "Dockerfile")}
	}
	if hasAnyFile(fileIndex, "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts") {
		return BuildStrategy{Strategy: "buildpacks", Confidence: 0.68, Reason: "service manifests exist but no explicit runtime contract won", Commands: [][]string{{"pack", "build", "<generated-image>", "--builder", "<trusted-builder>"}}, ManifestSources: matchingFiles(fileIndex, "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts")}
	}
	return BuildStrategy{Strategy: "generated_wrapper", Confidence: 0.35, Reason: "no explicit manifest or runtime contract found", Commands: [][]string{{"helm-ai-kernel", "launch", "import", "--repair-needed"}}, ManifestSources: nil}
}

func BuildLaunchRecipe(importID string, req ImportRequest, source SourceSnapshot, graph CapabilityGraph, strategy BuildStrategy, now time.Time) LaunchRecipe {
	appID := slug(source.Repo)
	if appID == "" {
		appID = slug(path.Base(strings.TrimSuffix(req.RepoURL, ".git")))
	}
	if appID == "" {
		appID = "imported-agent"
	}
	targets := []TargetPlan{
		localTargetPlan(graph, strategy),
		cloudTargetPlan(graph, strategy, source),
		hostedSandboxPlan(graph, strategy),
	}
	appSpec := GeneratedAppSpecCandidate{
		CandidateID: "generated-appspec-" + importID,
		Trusted:     false,
		AppSpec: registry.AppSpec{
			ID:                   "imported-" + appID,
			Name:                 firstNonEmpty(source.Repo, "Imported Agentic System"),
			Version:              firstNonEmpty(source.Ref, "imported"),
			License:              registry.LicenseSpec{Status: licenseStatus(source), SPDX: firstNonEmpty(source.LicenseSPDX, "NOASSERTION")},
			Redistribution:       "generated_untrusted",
			Availability:         registry.AvailabilityOSSCandidate,
			Install:              registry.InstallSpec{Strategy: strategy.Strategy, Source: source.RepoURL, Ref: source.Ref},
			Runtime:              registry.RuntimeSpec{Command: firstCommand(strategy.Commands), Ports: graph.Ports},
			ModelGatewayEnv:      detectedModelEnv(graph.Secrets),
			RequiredSecrets:      secretNames(graph.Secrets),
			FilesystemPolicy:     registry.PolicyRef{Mode: "deny_by_default"},
			NetworkPolicy:        registry.NetworkPolicy{Default: "deny"},
			MCPPolicy:            registry.MCPPolicy{UnknownServerPolicy: "quarantine", UnknownToolPolicy: "ESCALATE", RequireSchemaPin: true},
			Healthchecks:         generatedHealthchecks(graph),
			RiskClass:            "generated_untrusted",
			BudgetCeiling:        registry.BudgetCeiling{USDMax: 0, APICallsMax: 0, TimeMSMax: 0},
			EvidenceRequirements: []string{"source_snapshot", "capability_graph", "license_check", "sbom", "vulnerability_scan", "sandbox_preflight", "smoke_test", "teardown_recipe"},
			Conformance:          registry.ConformanceSpec{LicenseVerified: source.LicenseSPDX != "", PolicyPackPresent: true},
			Metadata: map[string]string{
				"source":          "universal_importer",
				"import_id":       importID,
				"repo_url":        source.RepoURL,
				"promotion_state": "generated_untrusted",
			},
		},
		PromotionRequirements: []string{"sandbox preflight PASS", "SBOM generated", "vulnerability scan PASS or accepted", "license policy ALLOW", "smoke test PASS", "teardown recipe proven"},
	}
	return LaunchRecipe{
		ImportID:              importID,
		GeneratedAt:           now,
		DetectionOrder:        []string{"framework-native manifest", "deterministic project manifests", "container or compose runtime", "buildpacks or nixpacks fallback", "generated wrapper", "LLM advisory only"},
		BuildStrategy:         strategy,
		TargetPlans:           targets,
		GeneratedAppSpecs:     []GeneratedAppSpecCandidate{appSpec},
		PromotionState:        "generated_untrusted",
		PromotionRequirements: appSpec.PromotionRequirements,
		CLIEquivalent:         "helm-ai-kernel launchpad import " + shellQuote(req.RepoURL),
	}
}

func Preflight(record ImportRecord, now time.Time) ImportRecord {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var checks []PreflightCheck
	add := func(id, status, summary string) {
		checks = append(checks, PreflightCheck{ID: id, Status: status, Summary: summary, EvidenceRef: "receipt:launchpad-import:" + record.ID + ":" + id})
	}
	add("source_snapshot", "PASS", "Repository metadata and deterministic file signals were captured before full launch.")
	add("capability_graph", "PASS", "Capability graph was generated from manifests and adapter matches.")
	if record.SourceSnapshot.LicenseSPDX == "" || strings.EqualFold(record.SourceSnapshot.LicenseSPDX, "NOASSERTION") {
		add("license_policy", "ESCALATE", "License is unknown; promotion requires operator review.")
	} else {
		add("license_policy", "PASS", "License normalized to "+record.SourceSnapshot.LicenseSPDX+".")
	}
	add("sandbox_quarantine", "PASS", "Import remains generated/untrusted and is not promoted to registry.")
	add("sbom", "PENDING", "SBOM generation is planned for build execution.")
	add("vulnerability_scan", "PENDING", "Vulnerability scan is planned for build execution.")
	add("smoke_test", "PENDING", "Smoke test requires executing selected target plan in quarantine.")

	var blocked []string
	for _, check := range checks {
		if check.Status == "ESCALATE" || check.Status == "PENDING" {
			blocked = append(blocked, check.Summary)
		}
	}
	status := "ESCALATE"
	state := StatePreflighted
	if len(blocked) == 0 {
		status = "PASS"
		state = StatePromotable
	}
	ledger := record.EvidenceLedger
	ledger.Status = "preflight_" + strings.ToLower(status)
	ledger.ReceiptRefs = appendUniqueMany(ledger.ReceiptRefs, evidenceRefs(checks)...)
	result := ImportPreflightResult{ImportID: record.ID, Status: status, Checks: checks, BlockedReasons: blocked, EvidenceLedger: ledger}
	record.Preflight = &result
	record.EvidenceLedger = ledger
	record.State = state
	record.UpdatedAt = now
	return record
}

func matchAdapter(adapter FrameworkAdapter, source SourceSnapshot, fileIndex map[string]SourceFileSummary) AdapterMatch {
	var evidence []string
	score := 0.0
	allMatched := true
	for _, file := range adapter.Match.FilesAll {
		if matched, actual := fileExists(fileIndex, file); matched {
			evidence = append(evidence, actual)
			score += 0.25
		} else {
			allMatched = false
		}
	}
	if len(adapter.Match.FilesAll) > 0 && !allMatched {
		return AdapterMatch{}
	}
	for _, file := range adapter.Match.FilesAny {
		if matched, actual := fileExists(fileIndex, file); matched {
			evidence = append(evidence, actual)
			score += 0.80
			break
		}
	}
	readme := combinedReadme(source.Files)
	for _, expr := range adapter.Match.ReadmeRegex {
		re, err := regexp.Compile("(?i)" + expr)
		if err == nil && re.MatchString(readme) {
			evidence = append(evidence, "README:"+expr)
			score += 0.10
		}
	}
	if len(evidence) == 0 {
		return AdapterMatch{}
	}
	if score > 1 {
		score = 1
	}
	if score < 0.50 && len(adapter.Match.FilesAll) == 0 {
		score = 0.50
	}
	return AdapterMatch{AdapterID: adapter.Metadata.ID, Confidence: score, Evidence: dedupeStrings(evidence)}
}

func localTargetPlan(graph CapabilityGraph, strategy BuildStrategy) TargetPlan {
	target := TargetPlan{TargetID: "local", Kind: "local", SubstrateID: "local-container", Deployable: true, RequiresApproval: false, SecretsBackend: "local-env-or-keychain", Risk: "quarantined", Reason: "Local plan generated from deterministic repo signals.", Commands: strategy.Commands, Rollback: []string{"helm-ai-kernel launchpad imports <id> teardown"}}
	if contains(graph.Capabilities, "desktopUI") {
		target.Kind = "desktop"
		target.SubstrateID = "desktop-local"
		target.Reason = "Desktop UI detected; prefer repo-native desktop/local path before containerized cloud."
	}
	if contains(graph.Capabilities, "compose") {
		target.SubstrateID = "compose-local"
		target.Commands = [][]string{{"docker", "compose", "up", "--build"}}
	}
	return target
}

func cloudTargetPlan(graph CapabilityGraph, strategy BuildStrategy, source SourceSnapshot) TargetPlan {
	deployable := strategy.Confidence >= 0.65 && !strings.EqualFold(source.LicenseSPDX, "NOASSERTION")
	return TargetPlan{
		TargetID:         "cloud",
		Kind:             "kubernetes-gitops",
		SubstrateID:      "kubernetes",
		Deployable:       deployable,
		RequiresApproval: true,
		Artifacts:        []string{"oci-image", "helm-chart", "gitops-application", "opentofu-module"},
		SecretsBackend:   "external-secrets-or-sealed-secrets",
		Risk:             "requires_policy_gate",
		Reason:           "Cloud target is generated as portable OCI + Helm + GitOps and stays gated until preflight evidence passes.",
		Commands:         [][]string{{"docker", "buildx", "build", "--sbom", "--provenance", "."}, {"helm", "upgrade", "--install", "<release>", "./charts/<release>"}, {"argocd", "app", "set", "<app>", "--sync-policy", "automated"}},
		Rollback:         []string{"helm rollback <release> <revision>", "kubectl rollout undo deployment/<app>", "git revert <gitops-revision>"},
		Healthcheck:      healthcheckMap(graph),
	}
}

func hostedSandboxPlan(graph CapabilityGraph, strategy BuildStrategy) TargetPlan {
	return TargetPlan{
		TargetID:         "hosted-sandbox",
		Kind:             "hosted-sandbox",
		SubstrateID:      "e2b-daytona-modal",
		Deployable:       strategy.Confidence >= 0.35,
		RequiresApproval: false,
		Artifacts:        []string{"sandbox-session", "egress-policy", "teardown-receipt"},
		SecretsBackend:   "launch-secret-grant",
		Risk:             "untrusted_code_quarantine",
		Reason:           "Untrusted imports should execute in disposable hosted sandboxes before promotion.",
		Commands:         [][]string{{"helm-ai-kernel", "sandbox", "exec", "--provider", "<provider>", "--", "<detected-command>"}},
		Rollback:         []string{"helm-ai-kernel sandbox teardown <sandbox-id>"},
		Healthcheck:      healthcheckMap(graph),
	}
}

func detectPackageJSONModule(f SourceFileSummary) DetectedModule {
	module := DetectedModule{Path: path.Dir(f.Path), Kind: "node", Manifests: []string{f.Path}, BuildStrategy: "native"}
	if f.Content == "" {
		return module
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal([]byte(f.Content), &pkg) == nil {
		for name := range pkg.Scripts {
			switch name {
			case "dev", "start", "serve", "tauri", "electron":
				module.Entrypoints = append(module.Entrypoints, "npm run "+name)
			}
		}
		sort.Strings(module.Entrypoints)
	}
	return module
}

func packageJSONCapabilities(content string) []string {
	if content == "" {
		return nil
	}
	lower := strings.ToLower(content)
	var out []string
	if strings.Contains(lower, "tauri") || strings.Contains(lower, "electron") {
		out = append(out, "desktopUI")
	}
	if strings.Contains(lower, "mcp") {
		out = append(out, "mcpTools")
	}
	if strings.Contains(lower, "ag-ui") || strings.Contains(lower, "agui") {
		out = append(out, "agui")
	}
	return out
}

func detectSecrets(files []SourceFileSummary) []SecretContract {
	seen := map[string]SecretContract{}
	for _, f := range files {
		if !strings.Contains(strings.ToLower(path.Base(f.Path)), ".env") && !strings.Contains(strings.ToLower(f.Path), "readme") {
			continue
		}
		for _, match := range secretRegex.FindAllString(f.Content, -1) {
			name := strings.TrimSpace(match)
			if name == "" {
				continue
			}
			seen[name] = SecretContract{Name: name, Source: f.Path, Required: true, Reason: "detected from environment contract", Targets: []string{"local", "cloud", "hosted-sandbox"}}
		}
	}
	out := make([]SecretContract, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var secretRegex = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|CREDENTIAL|CLIENT_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|LANGSMITH_API_KEY)\b`)

func detectOAuth(files []SourceFileSummary) []OAuthRequirement {
	seen := map[string]OAuthRequirement{}
	for _, f := range files {
		lower := strings.ToLower(f.Content)
		for _, provider := range []string{"google", "github", "slack", "discord", "microsoft"} {
			if strings.Contains(lower, provider+" oauth") || strings.Contains(lower, "oauth "+provider) {
				seen[provider] = OAuthRequirement{Provider: provider, Source: f.Path}
			}
		}
	}
	out := make([]OAuthRequirement, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

func detectPorts(files []SourceFileSummary) []int {
	seen := map[int]bool{}
	for _, f := range files {
		if f.Content == "" {
			continue
		}
		for _, m := range portRegex.FindAllStringSubmatch(f.Content, -1) {
			if len(m) < 2 {
				continue
			}
			port, err := strconv.Atoi(m[1])
			if err == nil && port > 0 && port < 65536 {
				seen[port] = true
			}
		}
	}
	out := make([]int, 0, len(seen))
	for port := range seen {
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

var portRegex = regexp.MustCompile(`(?i)(?:PORT|port|ports?|localhost:|127\.0\.0\.1:)[^\d]{0,8}([1-9][0-9]{2,4})`)

func indexFiles(files []SourceFileSummary) map[string]SourceFileSummary {
	index := map[string]SourceFileSummary{}
	for _, f := range files {
		index[strings.ToLower(strings.TrimPrefix(f.Path, "/"))] = f
	}
	return index
}

func fileExists(index map[string]SourceFileSummary, query string) (bool, string) {
	query = strings.ToLower(strings.TrimPrefix(query, "/"))
	for p := range index {
		if ok, _ := path.Match(query, path.Base(p)); ok {
			return true, p
		}
		if p == query || strings.HasSuffix(p, "/"+query) || path.Base(p) == query {
			return true, p
		}
	}
	return false, ""
}

func hasAnyFile(index map[string]SourceFileSummary, names ...string) bool {
	for _, name := range names {
		if ok, _ := fileExists(index, name); ok {
			return true
		}
	}
	return false
}

func matchingFiles(index map[string]SourceFileSummary, names ...string) []string {
	var out []string
	for _, name := range names {
		if ok, actual := fileExists(index, name); ok {
			out = append(out, actual)
		}
	}
	return dedupeStrings(out)
}

func combinedReadme(files []SourceFileSummary) string {
	var b strings.Builder
	for _, f := range files {
		if strings.Contains(strings.ToLower(path.Base(f.Path)), "readme") {
			b.WriteString("\n")
			b.WriteString(f.Content)
		}
	}
	return b.String()
}

func graphConfidence(matches []AdapterMatch, buildSignals []string) float64 {
	if len(matches) > 0 {
		conf := matches[0].Confidence
		if len(buildSignals) > 0 && conf < 0.95 {
			conf += 0.05
		}
		if conf > 1 {
			return 1
		}
		return conf
	}
	if len(buildSignals) > 0 {
		return 0.55
	}
	return 0.25
}

func confidenceReason(confidence float64, matches []AdapterMatch, buildSignals []string) string {
	switch {
	case len(matches) > 0 && confidence >= 0.85:
		return "high-confidence adapter match from deterministic manifests"
	case len(buildSignals) > 0:
		return "deterministic project manifests found, but no explicit framework contract won"
	default:
		return "low-confidence import; generated wrapper would require manual repair"
	}
}

func adapterByID(adapters []FrameworkAdapter, id string) FrameworkAdapter {
	for _, adapter := range adapters {
		if adapter.Metadata.ID == id {
			return adapter
		}
	}
	return FrameworkAdapter{}
}

func adapterCommands(adapter FrameworkAdapter) [][]string {
	var commands [][]string
	for _, cmd := range append(adapter.Entrypoints.Local, adapter.Entrypoints.Cloud...) {
		if len(cmd.Command) > 0 {
			commands = append(commands, cmd.Command)
		}
	}
	return commands
}

func firstCommand(commands [][]string) []string {
	if len(commands) > 0 {
		return commands[0]
	}
	return []string{"helm-ai-kernel", "launchpad", "import", "run"}
}

func detectedModelEnv(secrets []SecretContract) []string {
	var out []string
	for _, secret := range secrets {
		if strings.Contains(secret.Name, "OPENAI") || strings.Contains(secret.Name, "ANTHROPIC") || strings.Contains(secret.Name, "MODEL") {
			out = append(out, secret.Name)
		}
	}
	return dedupeStrings(out)
}

func secretNames(secrets []SecretContract) []string {
	out := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		out = append(out, strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(secret.Name, "_API_KEY"), "_TOKEN")))
	}
	return dedupeStrings(out)
}

func generatedHealthchecks(graph CapabilityGraph) []registry.HealthcheckSpec {
	if len(graph.Ports) == 0 {
		return []registry.HealthcheckSpec{{Type: "command", Command: "helm-ai-kernel launchpad import preflight"}}
	}
	return []registry.HealthcheckSpec{{Type: "http", URL: "http://127.0.0.1:" + strconv.Itoa(graph.Ports[0]) + "/"}}
}

func healthcheckMap(graph CapabilityGraph) map[string]string {
	if len(graph.Ports) == 0 {
		return map[string]string{"type": "command", "command": "helm-ai-kernel launchpad import preflight"}
	}
	return map[string]string{"type": "http", "url": "http://127.0.0.1:" + strconv.Itoa(graph.Ports[0]) + "/"}
}

func licenseStatus(source SourceSnapshot) string {
	if source.LicenseSPDX == "" || strings.EqualFold(source.LicenseSPDX, "NOASSERTION") {
		return "needs_review"
	}
	return "detected"
}

func importID(req ImportRequest, now time.Time) string {
	sum := sha256.Sum256([]byte(req.RepoURL + "\x00" + req.Ref + "\x00" + now.Format(time.RFC3339Nano)))
	return "imp_" + hex.EncodeToString(sum[:6])
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".git")
	value = strings.Trim(value, "/")
	if u, err := url.Parse(value); err == nil && u.Host != "" {
		value = path.Base(strings.TrimSuffix(u.Path, ".git"))
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func threshold(v float64) float64 {
	if v <= 0 {
		return 0.70
	}
	return v
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func appendUnique(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func appendUniqueMany(items []string, values ...string) []string {
	for _, value := range values {
		items = appendUnique(items, value)
	}
	return items
}

func dedupeStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func dedupeModules(items []DetectedModule) []DetectedModule {
	seen := map[string]DetectedModule{}
	for _, item := range items {
		key := item.Path + ":" + item.Kind + ":" + strings.Join(item.Manifests, ",")
		seen[key] = item
	}
	out := make([]DetectedModule, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func evidenceRefs(checks []PreflightCheck) []string {
	out := make([]string, 0, len(checks))
	for _, check := range checks {
		out = append(out, check.EvidenceRef)
	}
	return out
}
