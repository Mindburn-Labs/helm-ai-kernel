// Command doccheck validates HELM documentation integrity.
// Checks: broken file links, missing test/code anchors, dead references.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	var issues []string
	linkRe := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	fileRefRe := regexp.MustCompile("`([a-zA-Z_/]+\\.(?:go|yaml|yml|json|md|sh))`")

	err := filepath.Walk(filepath.Join(root, "docs"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Check markdown links
			matches := linkRe.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				link := m[2]
				if strings.HasPrefix(link, "http") || strings.HasPrefix(link, "#") {
					continue
				}
				// Resolve relative to doc dir
				target := filepath.Join(filepath.Dir(path), link)
				if _, err := os.Stat(target); os.IsNotExist(err) {
					// Try from root
					target = filepath.Join(root, link)
					if _, err := os.Stat(target); os.IsNotExist(err) {
						issues = append(issues, fmt.Sprintf("%s:%d: broken link %q", path, lineNum, link))
					}
				}
			}

			// Check file references in backticks
			fileMatches := fileRefRe.FindAllStringSubmatch(line, -1)
			for _, m := range fileMatches {
				ref := m[1]
				if strings.Contains(ref, "/") {
					// Looks like a path, check it exists
					target := filepath.Join(root, ref)
					if _, err := os.Stat(target); os.IsNotExist(err) {
						// Not always an error, could be a description
						// Only warn for .go and .yaml files
						if strings.HasSuffix(ref, ".go") || strings.HasSuffix(ref, ".yaml") {
							issues = append(issues, fmt.Sprintf("%s:%d: file ref %q not found", path, lineNum, ref))
						}
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", err)
		os.Exit(1)
	}

	if len(issues) > 0 {
		fmt.Println("Documentation issues found:")
		for _, issue := range issues {
			fmt.Println("  ", issue)
		}
		os.Exit(1)
	}

	fmt.Println("Documentation check passed.")
}
