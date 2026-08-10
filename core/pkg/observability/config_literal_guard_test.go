package observability_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoConfigLiteralOmitsSampleRate guards a latent trap rather than a bug.
//
// observability.Config.SampleRate is a float64 with no zero-value fallback:
// initTraceProvider maps SampleRate <= 0 to sdktrace.NeverSample(). So a
// struct literal that sets OTLPEndpoint and forgets SampleRate compiles, starts,
// connects to the collector, reports "observability initialized" — and exports
// nothing. The symptom is identical to HELM-495 (no spans at all) and there is
// no error anywhere to lead an investigator to the cause.
//
// Callers that go through DefaultConfig() are safe (it sets 1.0), which is why
// no offending literal exists today; this test keeps it that way instead of
// hardening the code against a mistake nobody has made yet.
func TestNoConfigLiteralOmitsSampleRate(t *testing.T) {
	root := coreModuleRoot(t)

	var offenders []string
	parsed := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		parsed++
		inObservabilityPkg := file.Name.Name == "observability"
		for _, bad := range configLiteralsWithoutSampleRate(file, inObservabilityPkg) {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			pos := fset.Position(bad)
			offenders = append(offenders, fmt.Sprintf("%s:%d:%d", rel, pos.Line, pos.Column))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	// A guard that inspected nothing is not a guard. If the walk found no Go
	// files the tree moved or the skip list swallowed it — fail loudly rather
	// than report success.
	if parsed < 100 {
		t.Fatalf("parsed only %d non-test Go files under %s; the guard is not scanning the tree", parsed, root)
	}

	if len(offenders) > 0 {
		t.Errorf("observability.Config literal(s) without an explicit SampleRate: %v\n"+
			"SampleRate 0 means NeverSample() — the provider starts, connects and exports nothing. "+
			"Set SampleRate explicitly, or build the config from observability.DefaultConfig().", offenders)
	}
}

// TestConfigLiteralDetectorSeesAnOmission proves the detector above is not
// blind. Without this, deleting the AST match arm would leave
// TestNoConfigLiteralOmitsSampleRate permanently, silently green.
func TestConfigLiteralDetectorSeesAnOmission(t *testing.T) {
	cases := []struct {
		name       string
		src        string
		inPkg      bool
		wantOffend int
	}{
		{
			name: "qualified literal without SampleRate is caught",
			src: `package x
import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
var c = &observability.Config{OTLPEndpoint: "localhost:4317", Insecure: true}
`,
			wantOffend: 1,
		},
		{
			name: "qualified literal with SampleRate is clean",
			src: `package x
import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
var c = &observability.Config{OTLPEndpoint: "localhost:4317", SampleRate: 1.0}
`,
			wantOffend: 0,
		},
		{
			name: "in-package literal without SampleRate is caught",
			src: `package observability
var c = &Config{OTLPEndpoint: "localhost:4317"}
`,
			inPkg:      true,
			wantOffend: 1,
		},
		{
			name: "DefaultConfig call site is clean",
			src: `package x
import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
var c = observability.DefaultConfig()
`,
			wantOffend: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			got := configLiteralsWithoutSampleRate(file, tc.inPkg)
			if len(got) != tc.wantOffend {
				t.Errorf("detector found %d offenders, want %d", len(got), tc.wantOffend)
			}
		})
	}
}

// configLiteralsWithoutSampleRate returns the positions of observability.Config
// composite literals in file that do not set SampleRate. inPkg selects whether
// the unqualified `Config{...}` form counts (true only inside package
// observability, where `Config` is unambiguous).
func configLiteralsWithoutSampleRate(file *ast.File, inPkg bool) []token.Pos {
	var out []token.Pos
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if !isObservabilityConfigType(lit.Type, inPkg) {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				// Positional literal: every field is set, SampleRate included.
				return true
			}
			if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == "SampleRate" {
				return true
			}
		}
		out = append(out, lit.Lbrace)
		return true
	})
	return out
}

func isObservabilityConfigType(expr ast.Expr, inPkg bool) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "observability" && t.Sel.Name == "Config"
	case *ast.Ident:
		return inPkg && t.Name == "Config"
	}
	return false
}

// coreModuleRoot walks up from this test's package directory to the `core`
// module root (the directory holding go.mod).
func coreModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.mod found above %s", dir)
	return ""
}

func skipDir(name string) bool {
	switch name {
	case "testdata", "vendor", ".git":
		return true
	}
	return false
}
