package shadow

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	scannerAbs     = filepath.Abs
	scannerWalkDir = filepath.WalkDir
	scannerRel     = filepath.Rel
	scannerOpen    = os.Open
)

// ErrScanCoverageIncomplete means a strict scanner could not inspect all
// relevant candidate inputs. Callers must not export a partial report.
var ErrScanCoverageIncomplete = errors.New("shadow: scan coverage incomplete")

// Scanner walks a directory tree and produces a Report of shadow-AI findings.
// Zero-allocation-per-match is not a goal; deterministic output is.
type Scanner struct {
	// MaxFileBytes skips files larger than this (default 2 MiB).
	MaxFileBytes int64

	// Excludes are glob patterns (relative to scan root) to skip.
	// Defaults include node_modules, .git, dist, build, etc.
	Excludes []string

	// RequireComplete fails the scan when a relevant candidate cannot be read,
	// inspected, or scanned. The default scanner remains best-effort for legacy
	// shadow-scan callers; RiskEnvelope scans enable this explicitly.
	RequireComplete bool

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
	absRoot, err := scannerAbs(root)
	if err != nil {
		return nil, err
	}

	r := &Report{
		ScanRoot:          absRoot,
		Findings:          []Finding{},
		SummaryByVendor:   map[string]int{},
		SummaryBySeverity: map[string]int{},
	}

	err = scannerWalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if s.RequireComplete && !s.shouldSkipDir(absRoot, path) {
				return incompleteScanError("unable to traverse declared scan scope")
			}
			// Legacy shadow scans skip unreadable paths rather than aborting.
			return nil
		}
		if d == nil {
			if s.RequireComplete {
				return incompleteScanError("unable to traverse declared scan scope")
			}
			return errors.New("shadow: nil directory entry")
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
			if s.RequireComplete {
				return incompleteScanError("unable to inspect candidate input")
			}
			r.FilesSkipped++
			return nil
		}
		if info.Size() > s.MaxFileBytes {
			if s.RequireComplete {
				return incompleteScanError("candidate input exceeds scan size limit")
			}
			r.FilesSkipped++
			return nil
		}
		r.FilesScanned++
		if err := s.scanFile(path, absRoot, r); err != nil && s.RequireComplete {
			return incompleteScanError("unable to read candidate input")
		}
		return nil
	})
	if err != nil {
		if s.RequireComplete && !errors.Is(err, ErrScanCoverageIncomplete) {
			return nil, incompleteScanError("unable to traverse declared scan scope")
		}
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
	r.Grade = ComputeGrade(r)

	r.GeneratedAt = s.Clock()
	r.ScanDurationMs = r.GeneratedAt.Sub(start).Milliseconds()
	return r, nil
}

func (s *Scanner) shouldSkipDir(root, path string) bool {
	rel, err := scannerRel(root, path)
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
	lb := strings.ToLower(filepath.Base(path))
	switch ext {
	case ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".mjs", ".cjs":
		return true
	case ".json", ".yaml", ".yml", ".toml":
		// Only scan these if they look like agent-related config or a
		// container-compose file (which may name a local-inference image).
		return strings.Contains(lb, "mcp") || strings.Contains(lb, "agent") ||
			lb == "package.json" || lb == "pyproject.toml" || lb == "requirements.txt" ||
			lb == "go.mod" || lb == "settings.json" ||
			lb == "docker-compose.yml" || lb == "docker-compose.yaml" ||
			lb == "compose.yml" || lb == "compose.yaml"
	}
	// Extensionless manifests that carry container-image or local-runtime
	// signatures (Dockerfile FROM/CMD lines, Ollama Modelfile).
	switch lb {
	case "dockerfile", "containerfile", "modelfile":
		return true
	}
	return false
}

// scanFile inspects a single file and appends findings to the report.
func (s *Scanner) scanFile(path, root string, r *Report) error {
	f, err := scannerOpen(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rel, err := scannerRel(root, path)
	if err != nil {
		if s.RequireComplete {
			return err
		}
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
					Evidence:   evidenceForRule(rule, line),
					Note:       rule.Note,
					DetectedAt: s.Clock(),
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
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
	// An Ollama Modelfile marks a local model server on this host.
	if base == "modelfile" {
		r.Findings = append(r.Findings, Finding{
			Kind:       "local_llm_runtime",
			Vendor:     "ollama",
			Language:   "config",
			Path:       rel,
			Severity:   "LOW",
			Note:       "Ollama Modelfile — local model server; route inference through the HELM proxy or Local Inference Gateway to govern it",
			DetectedAt: s.Clock(),
		})
	}
	return nil
}

func incompleteScanError(reason string) error {
	return fmt.Errorf("%w: %s", ErrScanCoverageIncomplete, reason)
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

func evidenceForRule(rule importRule, line string) string {
	if rule.Kind != "api_key" {
		return truncateEvidence(line, 140)
	}
	match := rule.Pattern.FindString(line)
	if match == "" {
		return "[REDACTED_SECRET]"
	}
	sum := sha256.Sum256([]byte(match))
	return fmt.Sprintf("[REDACTED_%s_API_KEY sha256:%s]", strings.ToUpper(rule.Vendor), hex.EncodeToString(sum[:])[:16])
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

	// ---- Local LLM runtimes (kind: local_llm_runtime) ----
	// Signatures are client-library imports, server CLI/module invocations,
	// container-image names, and distinctive localhost base-URL ports. Ports
	// that commonly collide (8000 / 8080 / 3000 / 5000) are deliberately NOT
	// used as standalone signals; those runtimes are matched by image or CLI.
	// Sources verified 2026-07-21: each runtime's own serving docs.

	// Ollama — :11434.
	{Kind: "local_llm_runtime", Vendor: "ollama", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+ollama|from\s+ollama\s+import)`),
		Severity: "LOW", Note: "Ollama Python client — route through the HELM proxy / Local Inference Gateway"},
	{Kind: "local_llm_runtime", Vendor: "ollama", Language: "typescript",
		Pattern:  regexp.MustCompile(`(?m)(from\s+['"]ollama['"]|require\(['"]ollama['"]\))`),
		Severity: "LOW", Note: "Ollama JS client — route through the HELM proxy / Local Inference Gateway"},
	{Kind: "local_llm_runtime", Vendor: "ollama", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):11434|\bollama\s+serve\b|(^|/)ollama/ollama\b`),
		Severity: "LOW", Note: "Ollama local model server (:11434) — govern via the HELM proxy / Local Inference Gateway"},

	// vLLM — :8000, image vllm/vllm-openai, `vllm serve`.
	{Kind: "local_llm_runtime", Vendor: "vllm", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)vllm/vllm-openai|\bvllm\s+serve\b|vllm\.entrypoints\.openai`),
		Severity: "LOW", Note: "vLLM OpenAI-compatible server — front it with the HELM proxy to govern inference"},

	// llama.cpp — llama-server, image ghcr.io/ggml-org/llama.cpp.
	{Kind: "local_llm_runtime", Vendor: "llamacpp", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)\bllama-server\b|ghcr\.io/ggml-org/llama\.cpp`),
		Severity: "LOW", Note: "llama.cpp server — front it with the HELM proxy to govern inference"},
	{Kind: "local_llm_runtime", Vendor: "llamacpp", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+llama_cpp|from\s+llama_cpp\s+import)`),
		Severity: "LOW", Note: "llama-cpp-python — local model server; route through the HELM proxy"},

	// SGLang — :30000, image lmsysorg/sglang, sglang.launch_server.
	{Kind: "local_llm_runtime", Vendor: "sglang", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)lmsysorg/sglang|sglang\.launch_server|(localhost|127\.0\.0\.1):30000`),
		Severity: "LOW", Note: "SGLang server — front it with the HELM proxy to govern inference"},

	// Hugging Face TGI — text-generation-launcher (archived / maintenance since 2026-03).
	{Kind: "local_llm_runtime", Vendor: "tgi", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)\btext-generation-launcher\b|ghcr\.io/huggingface/text-generation-inference`),
		Severity: "LOW", Note: "Hugging Face TGI (upstream archived / maintenance mode since 2026-03) — front it with the HELM proxy"},

	// NVIDIA Triton + NIM.
	{Kind: "local_llm_runtime", Vendor: "triton", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)nvcr\.io/nvidia/tritonserver|\btritonserver\b`),
		Severity: "LOW", Note: "NVIDIA Triton Inference Server — front the OpenAI-compatible endpoint with the HELM proxy"},
	{Kind: "local_llm_runtime", Vendor: "nvidia-nim", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)nvcr\.io/nim/`),
		Severity: "LOW", Note: "NVIDIA NIM microservice — front it with the HELM proxy to govern inference"},

	// LMDeploy — :23333, `lmdeploy serve api_server`.
	{Kind: "local_llm_runtime", Vendor: "lmdeploy", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)\blmdeploy\s+serve\b|(localhost|127\.0\.0\.1):23333`),
		Severity: "LOW", Note: "LMDeploy api_server — front it with the HELM proxy to govern inference"},

	// OpenVINO Model Server.
	{Kind: "local_llm_runtime", Vendor: "openvino", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)openvino/model_server`),
		Severity: "LOW", Note: "OpenVINO Model Server — front the OpenAI-compatible endpoint with the HELM proxy"},

	// Apple MLX — mlx_lm.server.
	{Kind: "local_llm_runtime", Vendor: "mlx", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)mlx_lm\.server`),
		Severity: "LOW", Note: "MLX local model server — route through the HELM proxy / Local Inference Gateway"},

	// Docker Model Runner — :12434 /engines/v1, `docker model`.
	{Kind: "local_llm_runtime", Vendor: "docker-model-runner", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):12434|\bdocker\s+model\s+(run|serve|status)\b`),
		Severity: "LOW", Note: "Docker Model Runner (:12434) — route through the HELM proxy / Local Inference Gateway"},

	// LM Studio — :1234, `lms` CLI.
	{Kind: "local_llm_runtime", Vendor: "lmstudio", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):1234\b`),
		Severity: "LOW", Note: "LM Studio local server (:1234) — route through the HELM proxy / Local Inference Gateway"},

	// GPT4All — :4891/v1.
	{Kind: "local_llm_runtime", Vendor: "gpt4all", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):4891`),
		Severity: "LOW", Note: "GPT4All local API server (:4891) — route through the HELM proxy / Local Inference Gateway"},
	{Kind: "local_llm_runtime", Vendor: "gpt4all", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+gpt4all|from\s+gpt4all\s+import)`),
		Severity: "LOW", Note: "GPT4All Python client — route through the HELM proxy / Local Inference Gateway"},

	// KoboldCpp — :5001.
	{Kind: "local_llm_runtime", Vendor: "koboldcpp", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):5001|\bkoboldcpp\b`),
		Severity: "LOW", Note: "KoboldCpp server (:5001) — route the OpenAI-compatible endpoint through the HELM proxy"},

	// Jan + cortex.cpp — :1337 / :39281.
	{Kind: "local_llm_runtime", Vendor: "jan", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):1337`),
		Severity: "LOW", Note: "Jan local API server (:1337) — route through the HELM proxy / Local Inference Gateway"},
	{Kind: "local_llm_runtime", Vendor: "cortex", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)(localhost|127\.0\.0\.1):3928[19]`),
		Severity: "LOW", Note: "cortex.cpp local server — route through the HELM proxy / Local Inference Gateway"},

	// Xinference — :9997, image xprobe/xinference.
	{Kind: "local_llm_runtime", Vendor: "xinference", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)xprobe/xinference|(localhost|127\.0\.0\.1):9997`),
		Severity: "LOW", Note: "Xinference server — front it with the HELM proxy to govern inference"},

	// GPUStack — image gpustack/gpustack.
	{Kind: "local_llm_runtime", Vendor: "gpustack", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)gpustack/gpustack`),
		Severity: "LOW", Note: "GPUStack server — front the OpenAI-compatible endpoint with the HELM proxy"},

	// ---- Local LLM gateways / routers (kind: llm_gateway) ----
	// Aggregators that reach models on a path that can bypass HELM unless HELM
	// sits in front — flagged one step above plain runtimes.

	// LiteLLM proxy — :4000, image ghcr.io/berriai/litellm.
	{Kind: "llm_gateway", Vendor: "litellm", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)ghcr\.io/berriai/litellm|\blitellm\s+--(config|port)\b|(localhost|127\.0\.0\.1):4000`),
		Severity: "MEDIUM", Note: "LiteLLM proxy — a routing layer that can reach models around HELM; keep HELM in front of it"},
	{Kind: "llm_gateway", Vendor: "litellm", Language: "python",
		Pattern:  regexp.MustCompile(`(?m)^\s*(import\s+litellm|from\s+litellm\s+import)`),
		Severity: "MEDIUM", Note: "LiteLLM library — a routing layer that can reach models around HELM; keep HELM in front of it"},

	// LocalAI — image localai/localai.
	{Kind: "llm_gateway", Vendor: "localai", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)\blocalai/localai\b`),
		Severity: "MEDIUM", Note: "LocalAI — an OpenAI-compatible aggregator; keep HELM in front of it to govern inference"},

	// FastChat — fastchat.serve.openai_api_server.
	{Kind: "llm_gateway", Vendor: "fastchat", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)fastchat\.serve`),
		Severity: "MEDIUM", Note: "FastChat OpenAI API server — a routing layer; keep HELM in front of it"},

	// Open WebUI — image ghcr.io/open-webui/open-webui.
	{Kind: "llm_gateway", Vendor: "open-webui", Language: "any",
		Pattern:  regexp.MustCompile(`(?m)ghcr\.io/open-webui/open-webui`),
		Severity: "MEDIUM", Note: "Open WebUI — a front-end/router over local models; keep HELM in front of it"},
}
