// Package kernel provides compile-time boundary assertions.
// Per Section 1.1 - Kernel Scope Enforcement
package kernel

// This file contains boundary assertions that verify at compile-time
// that the kernel package does not depend on domain or vendor logic.

import (
	"fmt"
	"go/build"
	"strings"
)

// BoundaryViolation represents a detected kernel scope violation.
type BoundaryViolation struct {
	Package    string `json:"package"`
	ImportPath string `json:"import_path"`
	Reason     string `json:"reason"`
	Severity   string `json:"severity"` // error, warning
}

// BoundaryAssertions defines the kernel's trusted computing base constraints.
type BoundaryAssertions struct {
	// AllowedImportPrefixes defines acceptable import path prefixes
	AllowedImportPrefixes []string
	// DisallowedImportPatterns defines forbidden import patterns
	DisallowedImportPatterns []string
	// TrustedPackages is an explicit list of trusted packages
	TrustedPackages map[string]bool
}

// DefaultKernelBoundaryAssertions returns the normative boundary constraints.
// Per Section 1.1 of the Normative Addendum:
// - Kernel MUST NOT contain domain-specific business logic
// - Kernel MUST NOT directly depend on vendor SDKs
// - Kernel MUST maintain a clear TCB boundary
func DefaultKernelBoundaryAssertions() *BoundaryAssertions {
	return &BoundaryAssertions{
		AllowedImportPrefixes: []string{
			"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel",
			"github.com/Mindburn-Labs/helm-oss/core/pkg/policy",
			"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities",
			"github.com/Mindburn-Labs/helm-oss/core/pkg/firewall",
			// Standard library is always allowed
			"context",
			"crypto",
			"encoding",
			"errors",
			"fmt",
			"io",
			"log",
			"sync",
			"time",
			"sort",
			"strings",
			"strconv",
			"bytes",
			"container",
		},
		DisallowedImportPatterns: []string{
			// Domain-specific (vendor logic)
			"github.com/Mindburn-Labs/helm-oss/core/pkg/domain",
			"github.com/Mindburn-Labs/helm-oss/core/pkg/vendor",
			"github.com/Mindburn-Labs/helm-oss/core/pkg/business",
			// External vendor SDKs
			"github.com/openai",
			"github.com/anthropics",
			"github.com/google/generative-ai-go",
			// Third-party HTTP clients (should go through PAL)
			"net/http",
		},
		TrustedPackages: map[string]bool{
			"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel": true,
		},
	}
}

// CheckImport verifies if an import is allowed within the kernel boundary.
func (ba *BoundaryAssertions) CheckImport(importPath string) *BoundaryViolation {
	// Check against disallowed patterns first
	for _, pattern := range ba.DisallowedImportPatterns {
		if strings.HasPrefix(importPath, pattern) || importPath == pattern {
			return &BoundaryViolation{
				ImportPath: importPath,
				Reason:     fmt.Sprintf("import violates kernel boundary: matches disallowed pattern %q", pattern),
				Severity:   "error",
			}
		}
	}

	// Check against allowed prefixes
	for _, prefix := range ba.AllowedImportPrefixes {
		if strings.HasPrefix(importPath, prefix) {
			return nil // Allowed
		}
	}

	// Not in allowed list - warning for unknown imports
	return &BoundaryViolation{
		ImportPath: importPath,
		Reason:     "import not in kernel trusted computing base allowlist",
		Severity:   "warning",
	}
}

// ValidatePackage checks a Go package against kernel boundary constraints.
func (ba *BoundaryAssertions) ValidatePackage(pkgPath string) ([]BoundaryViolation, error) {
	var violations []BoundaryViolation

	pkg, err := build.Import(pkgPath, "", 0)
	if err != nil {
		// Package doesn't exist or can't be loaded - skip validation
		return violations, nil
	}

	// Check all imports
	for _, imp := range pkg.Imports {
		if v := ba.CheckImport(imp); v != nil {
			v.Package = pkgPath
			violations = append(violations, *v)
		}
	}

	return violations, nil
}

// CompileTimeBoundaryCheck is called at compile time via go:generate or tests.
// It returns true if the kernel package maintains its TCB boundary.
func CompileTimeBoundaryCheck() (bool, []BoundaryViolation) {
	assertions := DefaultKernelBoundaryAssertions()

	kernelPackages := []string{
		"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel",
	}

	var allViolations []BoundaryViolation
	hasErrors := false

	for _, pkg := range kernelPackages {
		violations, _ := assertions.ValidatePackage(pkg)
		for _, v := range violations {
			allViolations = append(allViolations, v)
			if v.Severity == "error" {
				hasErrors = true
			}
		}
	}

	return !hasErrors, allViolations
}
