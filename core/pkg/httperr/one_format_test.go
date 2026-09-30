package httperr

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// oneFormatExempt lists the HELM API files allowed to write errors without
// this package, with the reason. Each entry must still match, so the list
// only shrinks.
var oneFormatExempt = map[string]string{
	// MCP transport: the MCP HTTP binding answers auth failures itself.
	"cmd/helm-ai-kernel/mcp_runtime.go": "MCP transport",
	// OpenAI-compatible proxy listener, a separate wire contract.
	"cmd/helm-ai-kernel/proxy_cmd.go": "OpenAI-compatible proxy",
}

var bypass = regexp.MustCompile(`http\.Error\(|"application/problem\+json"`)

// TestHELMAPIWritesOneErrorFormat fails when a HELM API handler writes an
// error body other than through this package (target architecture R4: one
// error format).
func TestHELMAPIWritesOneErrorFormat(t *testing.T) {
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	scanned := map[string]bool{}
	for _, dir := range []string{"pkg/api", "cmd/helm-ai-kernel"} {
		// Enterprise mirrors core/pkg but not the Kernel command, so the
		// command directory is checked only where it exists.
		if _, err := os.Stat(filepath.Join(root, dir)); dir == "cmd/helm-ai-kernel" && errors.Is(err, fs.ErrNotExist) {
			t.Logf("skipping %s: not in this checkout", dir)
			continue
		}
		scanned[dir] = true
		files, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files under %s: %v", dir, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			src, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			rel := filepath.ToSlash(strings.TrimPrefix(file, root+string(filepath.Separator)))
			if !bypass.Match(src) {
				continue
			}
			if _, ok := oneFormatExempt[rel]; ok {
				used[rel] = true
				continue
			}
			t.Errorf("%s writes an error body outside core/pkg/httperr; use httperr.WriteError / WriteProblem", rel)
		}
	}
	for rel := range oneFormatExempt {
		if scanned[path.Dir(rel)] && !used[rel] {
			t.Errorf("%s no longer bypasses httperr; remove it from oneFormatExempt", rel)
		}
	}
}
