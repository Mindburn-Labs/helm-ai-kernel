package metrics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// prohibitedMetricLabels is the normative prohibited-list from the pilot
// business-telemetry contract §6 (docs_for_team, HELM-290): request-scoped
// identifiers must never become metric label names — each unique value mints
// a new time series, and an unbounded value set is a cardinality-explosion
// incident. Identity belongs in events, not metric labels.
var prohibitedMetricLabels = map[string]bool{
	"correlation_id": true,
	"request_id":     true,
	"run_id":         true,
	"receipt_id":     true,
	"decision_id":    true,
	"session_id":     true,
	"trace_id":       true,
	"span_id":        true,
	"actor_id":       true,
	"subject_id":     true,
	"principal":      true,
	"resource":       true,
}

// vecConstructors are the prometheus/client_golang (and promauto) metric-vec
// constructors whose label-name slice this check inspects.
var vecConstructors = map[string]bool{
	"NewCounterVec":   true,
	"NewGaugeVec":     true,
	"NewHistogramVec": true,
	"NewSummaryVec":   true,
}

// expositionLabelRe matches label names in hand-rolled Prometheus text
// exposition format strings, e.g. `helm_tool_decisions{tool=%q}`.
var expositionLabelRe = regexp.MustCompile(`\{(\w+)=%`)

// TestNoProhibitedMetricLabels statically scans core/ for metric label
// registrations — both prometheus *Vec constructors and hand-rolled
// exposition format strings — and fails when a label name is on the
// prohibited list. This is the CI check required by contract §6: a
// request-scoped identifier used as a metric label must fail review, not
// reach production.
func TestNoProhibitedMetricLabels(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving core root: %v", err)
	}

	type finding struct {
		pos   string
		label string
	}
	var violations []finding
	seenLabels := 0

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Hand-rolled exposition strings: helm_metric{label=%q}.
		for _, m := range expositionLabelRe.FindAllSubmatch(src, -1) {
			label := string(m[1])
			seenLabels++
			if prohibitedMetricLabels[label] {
				violations = append(violations, finding{pos: path, label: label})
			}
		}

		// prometheus *Vec constructors: the []string label-name argument.
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			// Non-parsing Go files are someone else's build problem.
			return nil //nolint:nilerr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !vecConstructors[sel.Sel.Name] {
				return true
			}
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.CompositeLit)
				if !ok {
					continue
				}
				if arr, ok := lit.Type.(*ast.ArrayType); !ok || arr == nil {
					continue
				}
				for _, elt := range lit.Elts {
					basic, ok := elt.(*ast.BasicLit)
					if !ok || basic.Kind != token.STRING {
						continue
					}
					label, err := strconv.Unquote(basic.Value)
					if err != nil {
						continue
					}
					seenLabels++
					if prohibitedMetricLabels[label] {
						violations = append(violations, finding{
							pos:   fset.Position(basic.Pos()).String(),
							label: label,
						})
					}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", root, walkErr)
	}

	// Self-check against scanner rot: the tree is known to register labeled
	// metrics (governance exposition `tool`/`reason`, pdp telemetry
	// `verdict`/`reason_code`/`backend`). Finding none means the scanner
	// went blind, not that the tree is clean.
	if seenLabels < 5 {
		t.Fatalf("label scanner found only %d label names — scanner is broken, not the tree clean", seenLabels)
	}

	for _, v := range violations {
		t.Errorf("prohibited metric label %q registered at %s (telemetry contract §6: request-scoped identity never becomes a metric label)", v.label, v.pos)
	}
}
