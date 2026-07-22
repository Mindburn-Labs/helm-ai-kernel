package metrics

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// expositionBlockRe matches the brace-delimited label block of hand-rolled
// Prometheus text exposition format strings, e.g. `helm_tool_decisions{tool=%q}`.
// Requiring single-line braces keeps non-metric format strings (HTTP
// challenge headers, debug output) and multi-line Go code blocks out of
// the scan; an exposition label block never spans lines.
var expositionBlockRe = regexp.MustCompile(`\{([^{}\n]*=\s*["']?%[^{}\n]*)\}`)

// expositionLabelRe extracts label names inside a matched block — every
// label whose value is a format verb, whether quoted by %q or by literal
// quotes in the format string (`{tool=%q,correlation_id="%s"}`).
var expositionLabelRe = regexp.MustCompile(`(\w+)\s*=\s*["']?%`)

func scanDecodedExpositionStringLiterals(fset *token.FileSet, f *ast.File, report func(string, string)) error {
	var unquoteErr error
	ast.Inspect(f, func(n ast.Node) bool {
		if unquoteErr != nil {
			return false
		}
		basic, ok := n.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(basic.Value)
		if err != nil {
			unquoteErr = fmt.Errorf("decode string literal at %s: %w", fset.Position(basic.Pos()), err)
			return false
		}
		for _, block := range expositionBlockRe.FindAllStringSubmatch(value, -1) {
			for _, match := range expositionLabelRe.FindAllStringSubmatch(block[1], -1) {
				report(fset.Position(basic.Pos()).String(), match[1])
			}
		}
		return true
	})
	return unquoteErr
}

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

		// prometheus *Vec constructors: the []string label-name argument.
		// A parse failure fails the gate: silently skipping a file would
		// exempt its metric registrations from the scan.
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		// Hand-rolled exposition strings: helm_metric{label=%q}. Decode only
		// Go string literals before applying the bounded scan so every legal Go
		// escape form is covered without scanning comments or arbitrary source.
		if err := scanDecodedExpositionStringLiterals(fset, f, func(pos, label string) {
			seenLabels++
			if prohibitedMetricLabels[label] {
				violations = append(violations, finding{pos: pos, label: label})
			}
		}); err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !vecConstructors[sel.Sel.Name] || len(call.Args) < 2 {
				return true
			}
			// The label-name slice is the constructor's last argument. The
			// gate is fail-closed: labels must be inline string literals at
			// the registration site — a slice passed through a variable,
			// constant, or call cannot be statically checked and would be an
			// evasion channel, so it is itself a violation.
			arg := call.Args[len(call.Args)-1]
			lit, ok := arg.(*ast.CompositeLit)
			if !ok {
				violations = append(violations, finding{
					pos:   fset.Position(arg.Pos()).String(),
					label: "<non-literal label slice — inline the label names>",
				})
				return true
			}
			for _, elt := range lit.Elts {
				basic, isBasic := elt.(*ast.BasicLit)
				if !isBasic || basic.Kind != token.STRING {
					violations = append(violations, finding{
						pos:   fset.Position(elt.Pos()).String(),
						label: "<non-literal label name — inline the label string>",
					})
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

func TestDecodedExpositionStringLiteralsCatchEscapedQuotes(t *testing.T) {
	tests := map[string]string{
		"escaped quote": `package probe
const metric = "helm_metric{correlation_id=\"%s\"}"`,
		"hex quote": `package probe
const metric = "helm_metric{correlation_id=\x22%s\x22}"`,
	}

	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "probe.go", source, 0)
			if err != nil {
				t.Fatalf("parse probe source: %v", err)
			}

			var labels []string
			if err := scanDecodedExpositionStringLiterals(fset, f, func(_ string, label string) {
				labels = append(labels, label)
			}); err != nil {
				t.Fatalf("scan decoded literals: %v", err)
			}
			if !slices.Contains(labels, "correlation_id") {
				t.Fatalf("decoded scanner labels = %v, want correlation_id", labels)
			}
		})
	}
}
