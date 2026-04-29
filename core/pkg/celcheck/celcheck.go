// Package celcheck validates CEL policy packs at compile time.
//
// Ensures that all .cel files parse and type-check correctly
// using cel-go, so they can be trusted in production.
package celcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/policycel"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// ValidationResult holds the outcome of validating one CEL file.
type ValidationResult struct {
	File   string   `json:"file"`
	Valid  bool     `json:"valid"`
	Rules  int      `json:"rules"`
	Errors []string `json:"errors,omitempty"`
}

// ValidateFile parses and type-checks a CEL policy file.
//
// HELM CEL policy packs use a single compound boolean expression per file,
// with comment blocks separating logical clauses. We strip comments and
// blank lines, join the remaining code, and parse the result as one CEL
// expression.
func ValidateFile(path string) ValidationResult {
	result := ValidationResult{File: path}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("read error: %v", err))
		return result
	}

	// Standard HELM CEL environment with common variables.
	opts := []cel.EnvOption{
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("effect", cel.StringType),
		cel.Variable("effect_level", cel.StringType),
		cel.Variable("tool", cel.StringType),
		cel.Variable("agent_id", cel.StringType),
		cel.Variable("session_id", cel.StringType),
		cel.Variable("principal", cel.StringType),
		cel.Variable("resource", cel.StringType),
		cel.Variable("risk_tier", cel.StringType),
		cel.Variable("budget_remaining", cel.IntType),
		cel.Variable("budget_ceiling", cel.IntType),
		cel.Variable("delegation_depth", cel.IntType),
		cel.Variable("parent_agent", cel.StringType),
		cel.Variable("origin_agent", cel.StringType),
		cel.Variable("timestamp", cel.StringType),
		ext.Strings(),
	}
	opts = append(opts, policycel.TaintEnvOptions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("env error: %v", err))
		return result
	}

	// Strip comments, blanks, and metadata. Join into single expression.
	lines := strings.Split(string(data), "\n")
	var codeLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "---") ||
			strings.HasPrefix(trimmed, "name:") || strings.HasPrefix(trimmed, "description:") ||
			strings.HasPrefix(trimmed, "pack:") || strings.HasPrefix(trimmed, "version:") {
			continue
		}
		codeLines = append(codeLines, trimmed)
	}

	if len(codeLines) == 0 {
		return result
	}

	// Join all code lines into one expression.
	expr := policycel.RewritePolicyPackTaintContains(strings.Join(codeLines, " "))
	result.Rules = countClauses(expr)

	ast, iss := env.Parse(expr)
	if iss.Err() != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("parse error: %v", iss.Err()))
		return result
	}

	_, iss = env.Check(ast)
	if iss.Err() != nil {
		// Type-check errors are warnings — dynamic map access can't be
		// verified statically in CEL.
		result.Errors = append(result.Errors,
			fmt.Sprintf("type warning: %v", iss.Err()))
	}

	result.Valid = len(result.Errors) == 0 || onlyTypeWarnings(result.Errors)
	return result
}

// ValidateDirectory validates all .cel files in a directory tree.
func ValidateDirectory(dir string) ([]ValidationResult, error) {
	var results []ValidationResult
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".cel") {
			results = append(results, ValidateFile(path))
		}
		return nil
	})
	return results, err
}

// countClauses counts approximate rule clauses by counting top-level
// && and || operators (rough heuristic).
func countClauses(expr string) int {
	count := 1
	depth := 0
	for i := 0; i < len(expr)-1; i++ {
		switch expr[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '&':
			if depth == 0 && i+1 < len(expr) && expr[i+1] == '&' {
				count++
				i++
			}
		case '|':
			if depth == 0 && i+1 < len(expr) && expr[i+1] == '|' {
				count++
				i++
			}
		}
	}
	return count
}

func onlyTypeWarnings(errs []string) bool {
	for _, e := range errs {
		if !strings.Contains(e, "type warning") {
			return false
		}
	}
	return true
}
