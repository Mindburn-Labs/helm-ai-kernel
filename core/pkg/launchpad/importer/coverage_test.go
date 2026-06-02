package importer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCoverageLoadAdaptersBranches(t *testing.T) {
	if adapters, err := LoadAdapters(""); err != nil || len(adapters) == 0 {
		t.Fatalf("root discovery/default adapters failed: len=%d err=%v", len(adapters), err)
	}
	if adapters, err := LoadAdapters(filepath.Join(t.TempDir(), "missing")); err != nil || len(adapters) != len(DefaultAdapters()) {
		t.Fatalf("missing adapter dir should fall back to defaults: len=%d err=%v", len(adapters), err)
	}

	emptyRoot := t.TempDir()
	emptyDir := filepath.Join(emptyRoot, "registry", "launchpad", "adapters")
	if err := os.MkdirAll(filepath.Join(emptyDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, emptyRoot, "registry/launchpad/adapters/readme.txt", "ignored")
	if adapters, err := LoadAdapters(emptyRoot); err != nil || len(adapters) != len(DefaultAdapters()) {
		t.Fatalf("empty adapter dir should fall back to defaults: len=%d err=%v", len(adapters), err)
	}

	validRoot := t.TempDir()
	writeFile(t, validRoot, "registry/launchpad/adapters/low.yaml", adapterYAML("z-low", 10))
	writeFile(t, validRoot, "registry/launchpad/adapters/high.yml", adapterYAML("a-high", 50))
	writeFile(t, validRoot, "registry/launchpad/adapters/no-id.yaml", "metadata:\n  version: 1.0.0\n")
	adapters, err := LoadAdapters(validRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 2 || adapters[0].Metadata.ID != "a-high" || adapters[1].Metadata.ID != "z-low" {
		t.Fatalf("adapters not filtered/sorted: %#v", adapters)
	}

	invalidRoot := t.TempDir()
	writeFile(t, invalidRoot, "registry/launchpad/adapters/bad.yaml", "metadata: [")
	if _, err := LoadAdapters(invalidRoot); err == nil {
		t.Fatal("expected invalid adapter YAML error")
	}

	readErrorRoot := t.TempDir()
	readErrorDir := filepath.Join(readErrorRoot, "registry", "launchpad", "adapters")
	if err := os.MkdirAll(readErrorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(readErrorDir, "dangling.yaml")); err == nil {
		if _, err := LoadAdapters(readErrorRoot); err == nil {
			t.Fatal("expected dangling adapter symlink read error")
		}
	}
}

func TestCoverageStoreBranches(t *testing.T) {
	store := NewStore(t.TempDir())
	if !strings.HasSuffix(filepath.ToSlash(store.path("imp_a")), "/imports/imp_a.json") {
		t.Fatalf("unexpected store path: %s", store.path("imp_a"))
	}
	if err := store.Save(ImportRecord{}); err == nil {
		t.Fatal("expected empty import id error")
	}
	if err := store.Save(ImportRecord{ID: "../bad"}); err == nil {
		t.Fatal("expected invalid import id error")
	}
	if _, err := store.Get(""); err == nil {
		t.Fatal("expected empty get id error")
	}
	if _, err := store.Get("bad/id"); err == nil {
		t.Fatal("expected invalid get id error")
	}
	if _, err := store.Get("missing"); err == nil {
		t.Fatal("expected missing record error")
	}
	if records, err := NewStore(t.TempDir()).List(); err != nil || len(records) != 0 {
		t.Fatalf("missing imports dir should list empty: %#v err=%v", records, err)
	}

	older := ImportRecord{ID: "imp_older", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Request: ImportRequest{RepoURL: "https://github.com/acme/old"}}
	newer := ImportRecord{ID: "imp_newer", CreatedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Request: ImportRequest{RepoURL: "https://github.com/acme/new"}}
	if err := store.Save(older); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(newer); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Dir(filepath.Dir(store.path("ignored"))), "imports/ignored.txt", "ignored")
	if err := os.MkdirAll(filepath.Join(filepath.Dir(store.path("ignored")), "dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get("imp_newer")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Request.RepoURL != newer.Request.RepoURL || loaded.UpdatedAt.IsZero() {
		t.Fatalf("loaded record mismatch: %#v", loaded)
	}
	records, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ID != "imp_newer" || records[1].ID != "imp_older" {
		t.Fatalf("records not sorted newest first: %#v", records)
	}

	badJSONStore := NewStore(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(badJSONStore.path("imp_bad")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badJSONStore.path("imp_bad"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := badJSONStore.Get("imp_bad"); err == nil {
		t.Fatal("expected invalid JSON get error")
	}
	if _, err := badJSONStore.List(); err == nil {
		t.Fatal("expected invalid JSON list error")
	}

	blockerRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(blockerRoot, "imports"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(blockerRoot).Save(ImportRecord{ID: "imp_blocked"}); err == nil {
		t.Fatal("expected mkdir error when imports path is a file")
	}
	for _, id := range []string{"", "..", "bad/id", `bad\id`} {
		if err := validateImportID(id); err == nil {
			t.Fatalf("expected invalid id %q", id)
		}
	}
	if err := validateImportID("imp_ok"); err != nil {
		t.Fatalf("valid import id rejected: %v", err)
	}
}

func TestCoverageGitHubFetcherHTTPBranches(t *testing.T) {
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/repos/acme/agent":
			writeJSON(t, w, map[string]any{"default_branch": "main", "license": map[string]any{"spdx_id": "NOASSERTION"}})
		case "/repos/acme/agent/license":
			writeJSON(t, w, map[string]any{"license": map[string]any{"spdx_id": "MIT"}})
		case "/repos/acme/agent/contents":
			writeJSON(t, w, []githubContent{
				{Type: "dir", Path: "src"},
				{Type: "dir", Path: "node_modules"},
				{Type: "file", Path: "README.md", Size: 12, SHA: "sha-readme"},
				{Type: "file", Path: "large.bin", Size: maxFetchedFileBytes + 1, SHA: "sha-large"},
			})
		case "/repos/acme/agent/contents/src":
			writeJSON(t, w, []githubContent{{Type: "file", Path: "src/app.py", Size: 10, SHA: "sha-app"}})
		case "/repos/acme/agent/contents/README.md":
			writeJSON(t, w, map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("hello readme"))})
		case "/repos/acme/agent/contents/raw.txt":
			writeJSON(t, w, map[string]any{"encoding": "utf-8", "content": "raw content"})
		case "/repos/acme/agent/contents/bad-base64":
			writeJSON(t, w, map[string]any{"encoding": "base64", "content": "@@@"})
		case "/repos/acme/agent/contents/invalid":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("["))
		default:
			http.Error(w, "missing", http.StatusNotFound)
		}
	}))
	defer server.Close()

	fetcher := GitHubFetcher{Client: server.Client(), APIBase: server.URL, Token: "test-token"}
	snapshot, err := fetcher.Fetch(context.Background(), ImportRequest{RepoURL: "https://github.com/acme/agent.git"})
	if err != nil {
		t.Fatal(err)
	}
	if !sawAuth {
		t.Fatal("authorization header was not sent")
	}
	if snapshot.Owner != "acme" || snapshot.Repo != "agent" || snapshot.Ref != "main" || snapshot.LicenseSPDX != "MIT" || snapshot.Provider != "github" {
		t.Fatalf("snapshot metadata mismatch: %#v", snapshot)
	}
	if len(snapshot.Files) != 3 || snapshot.Files[0].Path == "node_modules" {
		t.Fatalf("unexpected fetched files: %#v", snapshot.Files)
	}
	if raw, err := fetcher.fetchFileContent(context.Background(), "acme", "agent", "main", "raw.txt"); err != nil || raw != "raw content" {
		t.Fatalf("raw content mismatch: %q err=%v", raw, err)
	}
	if _, err := fetcher.fetchFileContent(context.Background(), "acme", "agent", "main", "bad-base64"); err == nil {
		t.Fatal("expected bad base64 error")
	}
	if _, err := fetcher.githubJSON(context.Background(), "/repos/acme/agent/missing"); err == nil {
		t.Fatal("expected non-2xx GitHub JSON error")
	}
	if _, err := fetcher.fetchContents(context.Background(), "acme", "agent", "main", "invalid", 0); err == nil {
		t.Fatal("expected invalid contents JSON error")
	}
	if files, err := fetcher.fetchContents(context.Background(), "acme", "agent", "main", "", 4); err != nil || files != nil {
		t.Fatalf("depth guard mismatch: %#v err=%v", files, err)
	}
	if _, err := (GitHubFetcher{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}, APIBase: "https://api.github.invalid"}).githubJSON(context.Background(), "/repos/acme/agent"); err == nil {
		t.Fatal("expected client transport error")
	}
	if _, _, err := parseGitHubRepo("not a url"); err == nil {
		t.Fatal("expected non-url repo error")
	}
	if _, _, err := parseGitHubRepo("https://example.com/acme/agent"); err == nil {
		t.Fatal("expected non-GitHub repo error")
	}
	if _, _, err := parseGitHubRepo("https://github.com/acme"); err == nil {
		t.Fatal("expected missing repo path error")
	}
	if owner, repo, err := parseGitHubRepo("https://www.github.com/acme/agent.git"); err != nil || owner != "acme" || repo != "agent" {
		t.Fatalf("github parse mismatch: %s %s %v", owner, repo, err)
	}
	if _, err := fetcher.Fetch(context.Background(), ImportRequest{RepoURL: "https://example.com/acme/agent"}); err == nil {
		t.Fatal("expected fetch parse error")
	}
}

func TestCoverageLocalFetcherAndFetchHelpers(t *testing.T) {
	if localPath("repo") != "" {
		t.Fatal("localPath should require HELM_LAUNCHPAD_LOCAL_IMPORT_ROOT")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	writeFile(t, repo, "package.json", `{"scripts":{"start":"vite --host 127.0.0.1 --port 5173"}}`)
	writeFile(t, repo, "README.md", "Google OAuth, Slack OAuth, Discord OAuth, Microsoft OAuth. PORT=70000 PORT=8080")
	writeFile(t, repo, "LICENSE", "Apache License\nVersion 2.0\n")
	writeFile(t, repo, ".env.sample", "ANTHROPIC_API_KEY=\n")
	writeFile(t, repo, "node_modules/ignored/package.json", "{}")
	writeFile(t, repo, "a/b/c/d/e/too-deep.txt", "ignored")
	t.Setenv("HELM_LAUNCHPAD_LOCAL_IMPORT_ROOT", root)
	if got := localPath("repo"); got != repo {
		t.Fatalf("relative local path mismatch: %q != %q", got, repo)
	}
	if got := localPath("file://" + repo); got != repo {
		t.Fatalf("file local path mismatch: %q != %q", got, repo)
	}
	for _, raw := range []string{"https://github.com/acme/repo", "http://github.com/acme/repo", "git@github.com:acme/repo", "../escape", "missing"} {
		if got := localPath(raw); got != "" {
			t.Fatalf("localPath(%q)=%q", raw, got)
		}
	}
	if scoped, err := scopedLocalPath(root, repo); err != nil || scoped != repo {
		t.Fatalf("absolute scoped path mismatch: %q err=%v", scoped, err)
	}
	if _, err := scopedLocalPath(root, "."); err == nil {
		t.Fatal("expected scoped path root rejection")
	}
	if _, err := scopedLocalPath(root, "../escape"); err == nil {
		t.Fatal("expected scoped path escape rejection")
	}

	snapshot, err := fetchLocalSource(repo, ImportRequest{RepoURL: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Provider != "local" || snapshot.LicenseSPDX != "Apache-2.0" || snapshot.Ref != "local" {
		t.Fatalf("local snapshot mismatch: %#v", snapshot)
	}
	for _, file := range snapshot.Files {
		if strings.Contains(file.Path, "node_modules") || strings.Contains(file.Path, "too-deep") {
			t.Fatalf("skipped file was included: %#v", file)
		}
	}
	if _, err := fetchLocalSource(filepath.Join(root, "missing"), ImportRequest{}); err == nil {
		t.Fatal("expected missing local source error")
	}
	if !shouldDescend("apps", 0) || !shouldDescend("other", 1) || !shouldDescend("services/api", 3) {
		t.Fatal("expected shouldDescend true branches")
	}
	if shouldDescend("node_modules", 0) || shouldDescend("other/path", 2) {
		t.Fatal("expected shouldDescend false branches")
	}
	for _, dir := range []string{".git", "node_modules", "dist", "build", "target", ".next", ".venv", "vendor", ".cache"} {
		if !skipDir(dir) {
			t.Fatalf("skipDir did not skip %s", dir)
		}
	}
	for _, item := range []struct {
		path string
		size int64
		want bool
	}{
		{"README.md", 10, true},
		{"service.mcp.json", 10, true},
		{"src/mcp/server.py", 10, true},
		{"large.md", maxFetchedFileBytes + 1, false},
		{"negative.md", -1, false},
		{"unknown.bin", 1, false},
	} {
		if got := shouldFetchContent(item.path, item.size); got != item.want {
			t.Fatalf("shouldFetchContent(%q)=%v", item.path, got)
		}
	}
	for _, item := range []struct {
		path string
		want string
	}{
		{"app.ts", "typescript"},
		{"app.py", "python"},
		{"app.rs", "rust"},
		{"app.go", "go"},
		{"app.java", "jvm"},
		{"app.yaml", "yaml"},
		{"app.json", "json"},
		{"app.toml", "toml"},
		{"app.txt", ""},
	} {
		if got := languageForPath(item.path); got != item.want {
			t.Fatalf("languageForPath(%q)=%q", item.path, got)
		}
	}
	for _, item := range []struct {
		content string
		want    string
	}{
		{"GNU General Public License\nVersion 3", "GPL-3.0-only"},
		{"MIT License", "MIT"},
		{"Apache License\nVersion 2.0", "Apache-2.0"},
		{"unknown", ""},
	} {
		if got := detectLocalLicense([]SourceFileSummary{{Path: "LICENSE", Content: item.content}}); got != item.want {
			t.Fatalf("detectLocalLicense=%q want=%q", got, item.want)
		}
	}
}

func TestCoverageAnalyzerFallbacksAndHelpers(t *testing.T) {
	source := SourceSnapshot{RepoURL: "https://github.com/acme/service", Repo: "", LicenseSPDX: "NOASSERTION", Files: []SourceFileSummary{
		{Path: "Dockerfile", Content: "FROM scratch"},
		{Path: "README.md", Content: "pydantic ai and oauth github"},
		{Path: "config/service.mcp.json", Content: "{}"},
		{Path: ".github/dependabot.yml", Content: "version: 2"},
	}}
	graph := BuildCapabilityGraph(source, []FrameworkAdapter{{
		Metadata:     AdapterMetadata{ID: "low", Priority: 1},
		Match:        AdapterMatchSpec{ReadmeRegex: []string{"pydantic ai"}, ConfidenceThreshold: 0.95},
		Capabilities: []string{"agentFramework"},
		Build:        AdapterBuildSpec{Strategy: "native"},
	}})
	if !contains(graph.Capabilities, "container") || !contains(graph.SecuritySignals, "repo-health-signal") || graph.ConfidenceReason == "" {
		t.Fatalf("graph fallback signals missing: %#v", graph)
	}
	if strategy := SelectBuildStrategy(source, graph, []FrameworkAdapter{}); strategy.Strategy != "dockerfile" || len(strategy.ManifestSources) == 0 {
		t.Fatalf("dockerfile strategy mismatch: %#v", strategy)
	}
	if strategy := SelectBuildStrategy(SourceSnapshot{Files: []SourceFileSummary{{Path: "compose.yaml"}}}, CapabilityGraph{}, nil); strategy.Strategy != "compose" {
		t.Fatalf("compose strategy mismatch: %#v", strategy)
	}
	if strategy := SelectBuildStrategy(SourceSnapshot{Files: []SourceFileSummary{{Path: "go.mod"}}}, CapabilityGraph{}, nil); strategy.Strategy != "buildpacks" {
		t.Fatalf("buildpacks strategy mismatch: %#v", strategy)
	}
	if strategy := SelectBuildStrategy(SourceSnapshot{}, CapabilityGraph{}, nil); strategy.Strategy != "generated_wrapper" {
		t.Fatalf("wrapper strategy mismatch: %#v", strategy)
	}
	recipe := BuildLaunchRecipe("imp_x", ImportRequest{RepoURL: "https://github.com/acme/Fancy.Agent.git"}, SourceSnapshot{RepoURL: "https://github.com/acme/Fancy.Agent.git", Ref: "", LicenseSPDX: "NOASSERTION"}, CapabilityGraph{}, BuildStrategy{Strategy: "generated_wrapper", Confidence: 0.2}, time.Unix(1, 0).UTC())
	if recipe.GeneratedAppSpecs[0].AppSpec.ID != "imported-fancy-agent" || recipe.GeneratedAppSpecs[0].AppSpec.License.Status != "needs_review" {
		t.Fatalf("recipe fallback mismatch: %#v", recipe.GeneratedAppSpecs[0].AppSpec)
	}
	recipe = BuildLaunchRecipe("imp_y", ImportRequest{RepoURL: ""}, SourceSnapshot{}, CapabilityGraph{}, BuildStrategy{}, time.Unix(1, 0).UTC())
	if recipe.GeneratedAppSpecs[0].AppSpec.ID != "imported-imported-agent" || !strings.Contains(recipe.CLIEquivalent, "''") {
		t.Fatalf("empty recipe fallback mismatch: %#v", recipe)
	}

	fileIndex := indexFiles([]SourceFileSummary{{Path: "app/package.json"}, {Path: "README.md", Content: "Framework docs"}})
	if ok, actual := fileExists(fileIndex, "*.json"); !ok || actual != "app/package.json" {
		t.Fatalf("glob fileExists mismatch: %v %s", ok, actual)
	}
	if hasAnyFile(fileIndex, "missing") {
		t.Fatal("hasAnyFile should be false")
	}
	if files := matchingFiles(fileIndex, "package.json", "README.md", "missing"); len(files) != 2 {
		t.Fatalf("matchingFiles mismatch: %#v", files)
	}
	if match := matchAdapter(FrameworkAdapter{Metadata: AdapterMetadata{ID: "all"}, Match: AdapterMatchSpec{FilesAll: []string{"package.json", "missing"}}}, SourceSnapshot{}, fileIndex); match.Confidence != 0 {
		t.Fatalf("FilesAll mismatch should not match: %#v", match)
	}
	richAdapter := FrameworkAdapter{Metadata: AdapterMetadata{ID: "rich"}, Match: AdapterMatchSpec{FilesAll: []string{"package.json", "README.md"}, FilesAny: []string{"package.json"}, ReadmeRegex: []string{"Framework", "["}}}
	if match := matchAdapter(richAdapter, SourceSnapshot{Files: []SourceFileSummary{{Path: "README.md", Content: "Framework docs"}}}, fileIndex); match.Confidence != 1 {
		t.Fatalf("rich adapter should clamp to 1: %#v", match)
	}
	readmeOnly := FrameworkAdapter{Metadata: AdapterMetadata{ID: "readme"}, Match: AdapterMatchSpec{ReadmeRegex: []string{"Framework"}}}
	if match := matchAdapter(readmeOnly, SourceSnapshot{Files: []SourceFileSummary{{Path: "README.md", Content: "Framework docs"}}}, fileIndex); match.Confidence != 0.5 {
		t.Fatalf("readme-only adapter should floor to 0.5: %#v", match)
	}
	if graphConfidence([]AdapterMatch{{Confidence: 1.1}}, nil) != 1 || graphConfidence(nil, []string{"go.mod"}) != 0.55 || graphConfidence(nil, nil) != 0.25 {
		t.Fatal("graphConfidence mismatch")
	}
	if boosted := graphConfidence([]AdapterMatch{{Confidence: 0.94}}, []string{"Dockerfile"}); boosted <= 0.94 || boosted > 1 {
		t.Fatalf("graphConfidence boost mismatch: %f", boosted)
	}
	if confidenceReason(0.9, []AdapterMatch{{Confidence: 0.9}}, nil) == "" || confidenceReason(0.55, nil, []string{"go.mod"}) == "" || confidenceReason(0.25, nil, nil) == "" {
		t.Fatal("confidenceReason returned empty")
	}
	if adapterByID([]FrameworkAdapter{{Metadata: AdapterMetadata{ID: "a"}}}, "missing").Metadata.ID != "" {
		t.Fatal("missing adapterByID should return zero adapter")
	}
	if len(adapterCommands(FrameworkAdapter{Entrypoints: AdapterEntrypoints{Local: []AdapterCommand{{Command: []string{"local"}}}, Cloud: []AdapterCommand{{Command: []string{"cloud"}}, {}}}})) != 2 {
		t.Fatal("adapterCommands should include non-empty local and cloud commands")
	}
	if firstCommand(nil)[0] != "helm-ai-kernel" {
		t.Fatal("firstCommand fallback mismatch")
	}
	if detectPackageJSONModule(SourceFileSummary{Path: "package.json"}).Kind != "node" || len(detectPackageJSONModule(SourceFileSummary{Path: "package.json", Content: "{"}).Entrypoints) != 0 {
		t.Fatal("package json module edge mismatch")
	}
	if caps := packageJSONCapabilities(""); caps != nil {
		t.Fatalf("empty package capabilities should be nil: %#v", caps)
	}
	if ports := detectPorts([]SourceFileSummary{{Path: "README.md", Content: "PORT=70000 PORT=8080 localhost:3000 127.0.0.1:8080"}}); len(ports) != 2 || ports[0] != 3000 || ports[1] != 8080 {
		t.Fatalf("ports mismatch: %#v", ports)
	}
	if oauth := detectOAuth([]SourceFileSummary{{Path: "README.md", Content: "google oauth oauth slack discord oauth oauth microsoft"}}); len(oauth) != 4 {
		t.Fatalf("oauth mismatch: %#v", oauth)
	}
	if len(detectSecrets([]SourceFileSummary{{Path: "src/app.go", Content: "OPENAI_API_KEY"}})) != 0 {
		t.Fatal("non-env/readme secret should be ignored")
	}
	if generatedHealthchecks(CapabilityGraph{})[0].Type != "command" || generatedHealthchecks(CapabilityGraph{Ports: []int{8080}})[0].Type != "http" {
		t.Fatal("generated healthcheck mismatch")
	}
	if healthcheckMap(CapabilityGraph{})["type"] != "command" || healthcheckMap(CapabilityGraph{Ports: []int{8080}})["type"] != "http" {
		t.Fatal("healthcheck map mismatch")
	}
	if licenseStatus(SourceSnapshot{}) != "needs_review" || licenseStatus(SourceSnapshot{LicenseSPDX: "NOASSERTION"}) != "needs_review" || licenseStatus(SourceSnapshot{LicenseSPDX: "MIT"}) != "detected" {
		t.Fatal("licenseStatus mismatch")
	}
	if slug(" HTTPS://github.com/acme/Fancy.Agent.git ") != "fancy-agent" || slug("!!!") != "" {
		t.Fatal("slug mismatch")
	}
	if shellQuote("") != "''" || shellQuote("can't") != "'can'\"'\"'t'" {
		t.Fatal("shellQuote mismatch")
	}
	if threshold(0) != 0.70 || threshold(0.9) != 0.9 {
		t.Fatal("threshold mismatch")
	}
	if contains([]string{"a"}, "b") {
		t.Fatal("contains false branch mismatch")
	}
	if firstNonEmpty(" ", "") != "" {
		t.Fatal("firstNonEmpty all-empty mismatch")
	}
	if got := appendUnique([]string{"a"}, "a"); len(got) != 1 {
		t.Fatal("appendUnique duplicate mismatch")
	}
	if got := appendUnique([]string{"a"}, " "); len(got) != 1 {
		t.Fatal("appendUnique blank mismatch")
	}
	if got := appendUniqueMany([]string{"a"}, "b", "a"); len(got) != 2 {
		t.Fatal("appendUniqueMany mismatch")
	}
	if got := dedupeStrings([]string{" b ", "", "a", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("dedupeStrings mismatch: %#v", got)
	}
	if localTargetPlan(CapabilityGraph{Capabilities: []string{"desktopUI"}}, BuildStrategy{}).Kind != "desktop" || localTargetPlan(CapabilityGraph{Capabilities: []string{"compose"}}, BuildStrategy{}).SubstrateID != "compose-local" {
		t.Fatal("local target plan mismatch")
	}
	if cloudTargetPlan(CapabilityGraph{}, BuildStrategy{Confidence: 0.7}, SourceSnapshot{LicenseSPDX: "NOASSERTION"}).Deployable {
		t.Fatal("cloud target should not deploy with unknown license")
	}
	if hostedSandboxPlan(CapabilityGraph{}, BuildStrategy{Confidence: 0.2}).Deployable {
		t.Fatal("hosted sandbox should not deploy below confidence floor")
	}
}

func adapterYAML(id string, priority int) string {
	return "apiVersion: helm.platform/v1alpha1\nkind: FrameworkAdapter\nmetadata:\n  id: " + id + "\n  version: 1.0.0\n  priority: " + strconv.Itoa(priority) + "\nmatch:\n  filesAny: [package.json]\n  confidenceThreshold: 0.6\ncapabilities: [node]\nbuild:\n  strategy: native\nentrypoints:\n  local:\n    - name: run\n      command: [npm, start]\n"
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
