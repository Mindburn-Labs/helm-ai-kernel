// Package main implements a TCB import restriction linter.
//
// It scans Go source files under the TCB packages (core/pkg/) and ensures
// no forbidden imports leak into the kernel boundary.
//
// Usage:
//
//	go run tools/tcbcheck/main.go [-root <project-root>]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Forbidden import path fragments. Any non-test Go file in core/pkg/ that
// imports one of these is a TCB violation.
var forbiddenFragments = []string{
	"ingestion",
	"verification/refinement",
	"pkg/access",
	"controlroom",
	"apps/",
}

func main() {
	root := flag.String("root", ".", "Project root directory")
	flag.Parse()

	pkgDir := filepath.Join(*root, "core", "pkg")
	if _, err := os.Stat(pkgDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "ERROR: %s does not exist\n", pkgDir)
		os.Exit(1)
	}

	violations := 0
	fset := token.NewFileSet()

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip non-Go files, test files, and vendor
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "WARN: parse error in %s: %v\n", path, parseErr)
			return nil
		}

		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			for _, frag := range forbiddenFragments {
				if strings.Contains(importPath, frag) {
					pos := fset.Position(imp.Pos())
					relPath, _ := filepath.Rel(*root, pos.Filename)
					fmt.Printf("TCB VIOLATION: %s:%d imports %q (contains forbidden fragment %q)\n",
						relPath, pos.Line, importPath, frag)
					violations++
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: walk failed: %v\n", err)
		os.Exit(1)
	}

	if violations > 0 {
		fmt.Printf("\n❌ %d TCB violation(s) found\n", violations)
		os.Exit(1)
	}

	fmt.Println("✅ TCB isolation check passed — no forbidden imports in kernel")
}

// checkFile is used by AST-based type check validation.
func checkFile(fset *token.FileSet, f *ast.File, fragments []string) []string {
	var violations []string
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		for _, frag := range fragments {
			if strings.Contains(importPath, frag) {
				pos := fset.Position(imp.Pos())
				violations = append(violations,
					fmt.Sprintf("%s:%d imports %q (forbidden: %q)", pos.Filename, pos.Line, importPath, frag))
			}
		}
	}
	return violations
}
