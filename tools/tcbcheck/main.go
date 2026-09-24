// Package main implements a TCB import restriction linter.
//
// It scans Go source files under the TCB packages (core/pkg/) and ensures
// no forbidden imports leak into the kernel boundary.
//
// Before scanning, it checks itself: a synthetic file that imports each
// forbidden fragment must be flagged and a clean one must not. A parse error
// is fatal, and so is a scan that reads no files, so the gate cannot pass by
// inspecting nothing.
//
// Usage:
//
//	go run tools/tcbcheck/main.go [-root <project-root>]
package main

import (
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
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
	"apps/",
}

func main() {
	root := flag.String("root", ".", "Project root directory")
	flag.Parse()
	os.Exit(run(*root, forbiddenFragments))
}

// run returns 0 when the tree is clean, 1 on violations, and 2 when the check
// could not be trusted (failed self-test, unreadable tree, nothing scanned).
func run(root string, fragments []string) int {
	if err := selfTest(fragments); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: tcbcheck self-test failed, no verdict on the tree: %v\n", err)
		return 2
	}
	violations, scanned, err := scan(filepath.Join(root, "core", "pkg"), root, fragments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 2
	}
	if scanned == 0 {
		fmt.Fprintln(os.Stderr, "ERROR: no Go files scanned under core/pkg; an empty scan is not a pass")
		return 2
	}
	for _, v := range violations {
		fmt.Println("TCB VIOLATION: " + v)
	}
	if len(violations) > 0 {
		fmt.Printf("\n❌ %d TCB violation(s) found in %d file(s) scanned\n", len(violations), scanned)
		return 1
	}
	fmt.Printf("✅ TCB isolation check passed — %d files scanned, no forbidden imports in kernel\n", scanned)
	return 0
}

// scan walks dir and returns the violations and the number of files parsed.
func scan(dir, root string, fragments []string) ([]string, int, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", dir, err)
	}
	fset := token.NewFileSet()
	var violations []string
	scanned := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		scanned++
		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			for _, frag := range fragments {
				if strings.Contains(importPath, frag) {
					rel, relErr := filepath.Rel(root, fset.Position(imp.Pos()).Filename)
					if relErr != nil {
						rel = path
					}
					violations = append(violations, fmt.Sprintf("%s:%d imports %q (contains forbidden fragment %q)",
						rel, fset.Position(imp.Pos()).Line, importPath, frag))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, scanned, fmt.Errorf("walk failed: %w", err)
	}
	return violations, scanned, nil
}

// selfTest scans a synthetic tree: one file per forbidden fragment must be
// flagged, and a file with only allowed imports must not be.
func selfTest(fragments []string) error {
	if len(fragments) == 0 {
		return errors.New("no forbidden fragments configured")
	}
	dir, err := os.MkdirTemp("", "tcbcheck-selftest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	write := func(name, importPath string) error {
		src := fmt.Sprintf("package p\n\nimport _ %q\n", importPath)
		return os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600)
	}
	if err := write("clean.go", "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"); err != nil {
		return err
	}
	for i, frag := range fragments {
		if err := write(fmt.Sprintf("bad%d.go", i), "example.com/x/"+frag+"/y"); err != nil {
			return err
		}
	}
	violations, scanned, err := scan(dir, dir, fragments)
	if err != nil {
		return err
	}
	if scanned != len(fragments)+1 {
		return fmt.Errorf("scanned %d synthetic files, want %d", scanned, len(fragments)+1)
	}
	if len(violations) != len(fragments) {
		return fmt.Errorf("flagged %d synthetic violations, want %d: %v", len(violations), len(fragments), violations)
	}
	for _, v := range violations {
		if strings.HasPrefix(v, "clean.go") {
			return fmt.Errorf("clean synthetic file was flagged: %s", v)
		}
	}
	return nil
}
