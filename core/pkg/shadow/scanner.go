package shadow

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Scanner walks a directory tree and produces a Report of shadow-AI findings.
// Zero-allocation-per-match is not a goal; deterministic output is.
type Scanner struct {
	// MaxFileBytes skips files larger than this (default 2 MiB).
	MaxFileBytes int64

	// Excludes are glob patterns (relative to scan root) to skip.
	// Defaults include node_modules, .git, dist, build, etc.
	Excludes []string

	// Clock returns the current time (injectable for testing).
	Clock func() time.Time
}

// NewScanner returns a Scanner with sensible defaults.
func NewScanner() *Scanner {
	return &Scanner{
		MaxFileBytes: 2 * 1024 * 1024,
		Excludes: []string{
			"node_modules", ".git", "dist", "build", "__pycache__",
			"vendor", "target", ".next", ".venv", "venv", ".tox",
			"coverage", ".pytest_cache", ".mypy_cache",
		},
		Clock: time.Now,
	}
}

// Scan walks the root directory and returns a Report.
func (s *Scanner) Scan(root string) (*Report, error) {
	start := s.Clock()
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	r := &Report{
		ScanRoot:          absRoot,
		Findings:          []Finding{},
		SummaryByVendor:   map[string]int{},
		SummaryBySeverity: map[string]int{},
	}

	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip unreadable paths rather than abort the whole scan.
			return nil
		}
		if d.IsDir() {
			if s.shouldSkipDir(absRoot, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !s.shouldScanFile(path) {
			r.FilesSkipped++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			r.FilesSkipped++
			return nil
		}
		if info.Size() > s.MaxFileBytes {
			r.FilesSkipped++
			return nil
		}
		r.FilesScanned++
		s.scanFile(path, absRoot, r)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Post-process: tag HELM absence findings once per agent-SDK file if no
	// HELM finding exists in the same directory.
	s.annotateHelmAbsence(r)

	// Deterministic ordering.
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Kind < b.Kind
	})

	for _, f := range r.Findings {
		r.SummaryByVendor[f.Vendor]++
		r.SummaryBySeverity[f.Severity]++
	}

	// HelmCoverage summary.
	var helmPaths []string
	for _, f := range r.Findings {
		if f.Vendor == "helm" {
			r.HelmCoverage.Count++
			if len(helmPaths) < 10 {
				helmPaths = append(helmPaths, f.Path)
			}
		}
	}
	r.HelmCoverage.Present = r.HelmCoverage.Count > 0
	r.HelmCoverage.Paths = helmPaths

	r.GeneratedAt = s.Clock()
	r.ScanDurationMs = r.GeneratedAt.Sub(start).Milliseconds()
	return r, nil
}

func (s *Scanner) shouldSkipDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts {
		for _, ex := range s.Excludes {
			if p == ex {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) shouldScanFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := filepath.Base(path)
	switch ext {
	case ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".mjs", ".cjs":
		return true
	case ".json", ".yaml", ".yml", ".toml":
		// Only scan these if they look like agent-related config.
		lb := strings.ToLower(base)
		return strings.Contains(lb, "mcp") || strings.Contains(lb, "agent") ||
			lb == "package.json" || lb == "pyproject.toml" || lb == "requirements.txt" ||
			lb == "go.mod" || lb == "settings.json"
	}
	return false
}

// scanFile inspects a single file and appends findings to the report.
func (s *Scanner) scanFile(path, root string, r *Report) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}

	ext := strings.ToLower(filepath.Ext(path))
	language := languageForExt(ext)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, rule := range importRules {
			if rule.Language != language && rule.Language != "any" {
				continue
			}
			if rule.Pattern.MatchString(line) {
				r.Findings = append(r.Findings, Finding{
					Kind:       rule.Kind,
					Vendor:     rule.Vendor,
					Language:   language,
					Path:       rel,
					Line:       lineNo,
					Severity:   rule.Severity,
					Evidence:   truncateEvidence(line, 140),
					Note:       rule.Note,
					DetectedAt: s.Clock(),
				})
			}
		}
	}

	// Filename-only rules: MCP config files match by path, not content
	base := strings.ToLower(filepath.Base(path))
	if base == "mcp.json" || base == ".mcp.json" || base == "claude_desktop_config.json" {
		r.Findings = append(r.Findings, Finding{
			Kind:       "mcp_config",
			Vendor:     "mcp",
			Language:   "config",
			Path:       rel,
			Severity:   "MEDIUM",
			Note:       "MCP server configuration file — verify servers are governed",
			DetectedAt: s.Clock(),
		})
	}
}

// annotateHelmAbsence upgrades SDK-import findings to HIGH severity when no
// HELM marker is present in the same directory (best-effort heuristic).
func (s *Scanner) annotateHelmAbsence(r *Report) {
	helmDirs := map[string]bool{}
	for _, f := range r.Findings {
		if f.Vendor == "helm" {
			helmDirs[filepath.Dir(f.Path)] = true
		}
	}
	for i, f := range r.Findings {
		if f.Vendor == "helm" || f.Kind != "sdk_import" {
			continue
		}
		dir := filepath.Dir(f.Path)
		if !helmDirs[dir] && !helmAnywhereAbove(dir, helmDirs) {
			r.Findings[i].Kind = "helm_absent"
			if severityRank(f.Severity) < severityRank("MEDIUM") {
				r.Findings[i].Severity = "MEDIUM"
			}
			if r.Findings[i].Note == "" {
				r.Findings[i].Note = "Agent SDK detected without HELM routing nearby — may be ungoverned"
			} else {
				r.Findings[i].Note += " (no HELM marker in same directory)"
			}
		}
	}
}

func helmAnywhereAbove(dir string, helmDirs map[string]bool) bool {
	for d := dir; d != "." && d != "/" && d != ""; d = filepath.Dir(d) {
		if helmDirs[d] {
			return true
		}
	}
	return false
}

func languageForExt(ext string) string {
	switch ext {
	case ".py":
		return "python"
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
		return "typescript"
	case ".go":
		return "go"
	case ".json", ".yaml", ".yml", ".toml":
		return "config"
	}
	return "unknown"
}

func truncateEvidence(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func severityRank(s string) int {
	switch s {
	case "INFO":
		return 1
	case "LOW":
		return 2
	case "MEDIUM":
		return 3
	case "HIGH":
		return 4
	}
	return 0
}

// importRule matches one SDK / framework signature.
type importRule struct {
	Kind     string
	Vendor   string
	Language string // "python" | "typescript" | "go" | "any"
	Pattern  *regexp.Regexp
	Severity string
	Note     string
}

// importRules is the static detection ruleset. Extending it is cheap —
// each rule is one regex + metadata. Ordering does not matter.
var importRules = []importRule{
	// ---- Python ----
	{Kind: "sdk_import", Vendor: "openai", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+openai|from\s+openai\s+import)`),
		Severity: "LOW",
		Note:     "OpenAI Python SDK"},
	{Kind: "sdk_import", Vendor: "anthropic", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+anthropic|from\s+anthropic\s+import)`),
		Severity: "LOW",
		Note:     "Anthropic Python SDK"},
	{Kind: "sdk_import", Vendor: "langchain", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*from\s+langchain(\.|_core|_community|graph)?\b`),
		Severity: "LOW",
		Note:     "LangChain / LangGraph"},
	{Kind: "sdk_import", Vendor: "crewai", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+crewai|from\s+crewai\s+import)`),
		Severity: "LOW",
		Note:     "CrewAI"},
	{Kind: "sdk_import", Vendor: "autogen", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+autogen|from\s+autogen(_agentchat|_core|_ext)?\b)`),
		Severity: "LOW",
		Note:     "AutoGen"},
	{Kind: "sdk_import", Vendor: "llamaindex", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*from\s+llama_index\b`),
		Severity: "LOW",
		Note:     "LlamaIndex"},
	{Kind: "agt_detected", Vendor: "agent-os", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+agent_os|from\s+agent_os\s+import|from\s+agentmesh\s+import)`),
		Severity: "MEDIUM",
		Note:     "Microsoft Agent Governance Toolkit (AGT) — consider if HELM is the non-bypassable layer beneath it"},
	{Kind: "sdk_import", Vendor: "helm", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+helm_sdk|from\s+helm_sdk\s+import)`),
		Severity: "INFO",
		Note:     "HELM Python SDK detected"},

	// ---- TypeScript / JavaScript ----
	{Kind: "sdk_import", Vendor: "openai", Language: "typescript",
		Pattern:  regexp.MustCompile(`(?m)(from\s+['"]openai['"]|require\(['"]openai['"]\))`),
		Severity: "LOW",
		Note:     "OpenAI JS SDK"},
	{Kind: "sdk_import", Vendor: "anthropic", Language: "typescript",
		Pattern:  regexp.MustCompile(`(?m)(from\s+['"]@anthropic-ai/sdk['"]|require\(['"]@anthropic-ai/sdk['"]\))`),
		Severity: "LOW",
		Note:     "Anthropic JS SDK"},
	{Kind: "sdk_import", Vendor: "langchain", Language: "typescript",
		Pattern:  regexp.MustCompile(`(?m)from\s+['"]@langchain/(core|community|openai|anthropic)['"]`),
		Severity: "LOW",
		Note:     "LangChain JS"},
	{Kind: "sdk_import", Vendor: "semantic-kernel", Language: "typescript",
		Pattern:  regexp.MustCompile(`(?m)from\s+['"]@microsoft/semantic-kernel['"]`),
		Severity: "LOW",
		Note:     "Microsoft Semantic Kernel (JS)"},
	{Kind: "sdk_import", Vendor: "helm", Language: "typescript",
		Pattern:  regexp.MustCompile(`(?m)from\s+['"]@mindburn/helm-ai-kernel(-cli)?['"]`),
		Severity: "INFO",
		Note:     "HELM TypeScript SDK detected"},

	// ---- Go ----
	{Kind: "sdk_import", Vendor: "openai", Language: "go",
		Pattern:  regexp.MustCompile(`(?m)"(github\.com/sashabaranov/go-openai|github\.com/openai/openai-go)"`),
		Severity: "LOW",
		Note:     "OpenAI Go SDK"},
	{Kind: "sdk_import", Vendor: "anthropic", Language: "go",
		Pattern:  regexp.MustCompile(`(?m)"github\.com/anthropics/anthropic-sdk-go"`),
		Severity: "LOW",
		Note:     "Anthropic Go SDK"},
	{Kind: "sdk_import", Vendor: "langchain", Language: "go",
		Pattern:  regexp.MustCompile(`(?m)"github\.com/tmc/langchaingo"`),
		Severity: "LOW",
		Note:     "langchaingo"},
	{Kind: "sdk_import", Vendor: "helm", Language: "go",
		Pattern:  regexp.MustCompile(`(?m)"github\.com/Mindburn-Labs/helm-ai-kernel(/.*)?"`),
		Severity: "INFO",
		Note:     "HELM Go SDK detected"},

	// ---- Hardcoded API key patterns (any language) ----
	{Kind: "api_key", Vendor: "openai", Language: "any",
		Pattern:  regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`),
		Severity: "HIGH",
		Note:     "Possible OpenAI API key in source — rotate immediately and move to secrets"},
	{Kind: "api_key", Vendor: "anthropic", Language: "any",
		Pattern:  regexp.MustCompile(`sk-ant-[A-Za-z0-9-]{40,}`),
		Severity: "HIGH",
		Note:     "Possible Anthropic API key in source — rotate immediately and move to secrets"},
}
