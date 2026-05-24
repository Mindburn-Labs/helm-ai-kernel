package importer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const maxFetchedFileBytes = 256 * 1024

type GitHubFetcher struct {
	Client  *http.Client
	APIBase string
	Token   string
}

func NewGitHubFetcher(client *http.Client) GitHubFetcher {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	apiBase := strings.TrimRight(strings.TrimSpace(os.Getenv("HELM_GITHUB_API_BASE")), "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	return GitHubFetcher{Client: client, APIBase: apiBase, Token: strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))}
}

func (f GitHubFetcher) Fetch(ctx context.Context, req ImportRequest) (SourceSnapshot, error) {
	if local := localPath(req.RepoURL); local != "" {
		return fetchLocalSource(local, req)
	}
	owner, repo, err := parseGitHubRepo(req.RepoURL)
	if err != nil {
		return SourceSnapshot{}, err
	}
	ref := req.Ref
	repoMeta, err := f.githubJSON(ctx, "/repos/"+owner+"/"+repo)
	if err != nil {
		return SourceSnapshot{}, err
	}
	if ref == "" {
		if branch, _ := repoMeta["default_branch"].(string); branch != "" {
			ref = branch
		}
	}
	licenseSPDX := ""
	if license, ok := repoMeta["license"].(map[string]any); ok {
		if spdx, _ := license["spdx_id"].(string); spdx != "" && spdx != "NOASSERTION" {
			licenseSPDX = spdx
		}
	}
	if licenseSPDX == "" {
		if licenseMeta, err := f.githubJSON(ctx, "/repos/"+owner+"/"+repo+"/license"); err == nil {
			if license, ok := licenseMeta["license"].(map[string]any); ok {
				licenseSPDX, _ = license["spdx_id"].(string)
			}
		}
	}
	files, err := f.fetchContents(ctx, owner, repo, ref, "", 0)
	if err != nil {
		return SourceSnapshot{}, err
	}
	return SourceSnapshot{
		RepoURL:      req.RepoURL,
		Provider:     "github",
		Owner:        owner,
		Repo:         repo,
		Ref:          ref,
		LicenseSPDX:  firstNonEmpty(licenseSPDX, "NOASSERTION"),
		LicenseState: "detected",
		FetchedAt:    time.Now().UTC(),
		Files:        files,
		APISource:    f.APIBase + "/repos/" + owner + "/" + repo + "/contents",
	}, nil
}

func (f GitHubFetcher) githubJSON(ctx context.Context, apiPath string) (map[string]any, error) {
	endpoint := f.APIBase + apiPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("github api %s: %s: %s", apiPath, resp.Status, strings.TrimSpace(string(body)))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (f GitHubFetcher) fetchContents(ctx context.Context, owner, repo, ref, dir string, depth int) ([]SourceFileSummary, error) {
	if depth > 3 {
		return nil, nil
	}
	apiPath := "/repos/" + owner + "/" + repo + "/contents"
	if dir != "" {
		apiPath += "/" + path.Clean(dir)
	}
	if ref != "" {
		apiPath += "?ref=" + url.QueryEscape(ref)
	}
	endpoint := f.APIBase + apiPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("github contents %s: %s: %s", dir, resp.Status, strings.TrimSpace(string(body)))
	}
	var entries []githubContent
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	var files []SourceFileSummary
	for _, entry := range entries {
		switch entry.Type {
		case "dir":
			if !shouldDescend(entry.Path, depth) {
				continue
			}
			child, err := f.fetchContents(ctx, owner, repo, ref, entry.Path, depth+1)
			if err != nil {
				return nil, err
			}
			files = append(files, child...)
		case "file":
			item := SourceFileSummary{Path: entry.Path, Kind: "file", Size: entry.Size, SHA: entry.SHA, Language: languageForPath(entry.Path)}
			if shouldFetchContent(entry.Path, entry.Size) {
				content, _ := f.fetchFileContent(ctx, owner, repo, ref, entry.Path)
				item.Content = content
			}
			files = append(files, item)
		}
	}
	return files, nil
}

func (f GitHubFetcher) fetchFileContent(ctx context.Context, owner, repo, ref, filePath string) (string, error) {
	apiPath := "/repos/" + owner + "/" + repo + "/contents/" + path.Clean(filePath)
	if ref != "" {
		apiPath += "?ref=" + url.QueryEscape(ref)
	}
	body, err := f.githubJSON(ctx, apiPath)
	if err != nil {
		return "", err
	}
	encoding, _ := body["encoding"].(string)
	raw, _ := body["content"].(string)
	if strings.EqualFold(encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(raw, "\n", ""))
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return raw, nil
}

type githubContent struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	SHA  string `json:"sha"`
}

func parseGitHubRepo(raw string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("repo_url must be a GitHub URL or local path")
	}
	host := strings.ToLower(strings.TrimPrefix(u.Host, "www."))
	if host != "github.com" {
		return "", "", fmt.Errorf("only GitHub URLs are supported in this importer pass")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("GitHub URL must include owner and repository")
	}
	return parts[0], strings.TrimSuffix(parts[1], ".git"), nil
}

func localPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	root := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_LOCAL_IMPORT_ROOT"))
	if root == "" {
		return ""
	}
	requested := raw
	if strings.HasPrefix(raw, "file://") {
		u, err := url.Parse(raw)
		if err == nil {
			requested = u.Path
		}
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "git@") {
		return ""
	}
	candidate, err := scopedLocalPath(root, requested)
	if err != nil {
		return ""
	}
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}
	return ""
}

func scopedLocalPath(root, requested string) (string, error) {
	base, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}
	rel := requested
	if filepath.IsAbs(requested) {
		absRequested, err := filepath.Abs(filepath.Clean(requested))
		if err != nil {
			return "", err
		}
		rel, err = filepath.Rel(base, absRequested)
		if err != nil {
			return "", err
		}
	}
	rel = filepath.Clean(rel)
	if rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("local import path must stay under configured root")
	}
	return filepath.Join(base, rel), nil
}

func fetchLocalSource(root string, req ImportRequest) (SourceSnapshot, error) {
	var files []SourceFileSummary
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDir(rel) {
				return filepath.SkipDir
			}
			if strings.Count(rel, "/") > 3 {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		item := SourceFileSummary{Path: rel, Kind: "file", Size: info.Size(), Language: languageForPath(rel)}
		if shouldFetchContent(rel, info.Size()) {
			if data, err := os.ReadFile(p); err == nil {
				item.Content = string(data)
			}
		}
		files = append(files, item)
		return nil
	})
	if err != nil {
		return SourceSnapshot{}, err
	}
	return SourceSnapshot{
		RepoURL:      req.RepoURL,
		Provider:     "local",
		Repo:         filepath.Base(root),
		Ref:          firstNonEmpty(req.Ref, "local"),
		LicenseSPDX:  firstNonEmpty(detectLocalLicense(files), "NOASSERTION"),
		LicenseState: "detected",
		FetchedAt:    time.Now().UTC(),
		Files:        files,
		APISource:    "local-filesystem",
	}, nil
}

func shouldDescend(p string, depth int) bool {
	lower := strings.ToLower(p)
	if skipDir(lower) {
		return false
	}
	if depth == 0 {
		return true
	}
	for _, keep := range []string{".github", ".devcontainer", "apps", "app", "src", "packages", "crates", "services", "server", "client", "desktop", "docker", "deploy", "charts"} {
		if lower == keep || strings.HasPrefix(lower, keep+"/") || strings.Contains(lower, "/"+keep+"/") {
			return true
		}
	}
	return depth < 2
}

func skipDir(p string) bool {
	base := path.Base(filepath.ToSlash(p))
	switch base {
	case ".git", "node_modules", "dist", "build", "target", ".next", ".venv", "vendor", ".cache":
		return true
	default:
		return false
	}
}

func shouldFetchContent(p string, size int64) bool {
	if size < 0 || size > maxFetchedFileBytes {
		return false
	}
	name := strings.ToLower(path.Base(p))
	switch name {
	case "readme.md", "readme", "license", "license.md", "copying", "package.json", "pyproject.toml", "requirements.txt", "cargo.toml", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "langgraph.json", ".env.example", ".env.sample", "devcontainer.json", "chart.yaml":
		return true
	}
	if strings.HasSuffix(name, ".mcp.json") || strings.Contains(strings.ToLower(p), "mcp") {
		return true
	}
	return false
}

func languageForPath(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".ts", ".tsx", ".js", ".jsx":
		return "typescript"
	case ".py":
		return "python"
	case ".rs":
		return "rust"
	case ".go":
		return "go"
	case ".java", ".kt", ".kts":
		return "jvm"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	default:
		return ""
	}
}

func detectLocalLicense(files []SourceFileSummary) string {
	for _, f := range files {
		if strings.EqualFold(path.Base(f.Path), "LICENSE") {
			lower := strings.ToLower(f.Content)
			switch {
			case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "version 3"):
				return "GPL-3.0-only"
			case strings.Contains(lower, "mit license"):
				return "MIT"
			case strings.Contains(lower, "apache license") && strings.Contains(lower, "version 2.0"):
				return "Apache-2.0"
			}
		}
	}
	return ""
}
