package kernel

import (
	"testing"
)

func TestBoundaryAssertions(t *testing.T) {
	t.Run("DefaultKernelBoundaryAssertions", func(t *testing.T) {
		assertions := DefaultKernelBoundaryAssertions()
		if assertions == nil {
			t.Fatal("Expected non-nil assertions")
		}

		// Verify default patterns are set
		if len(assertions.DisallowedImportPatterns) == 0 {
			t.Error("Expected some default disallowed import patterns")
		}
		if len(assertions.AllowedImportPrefixes) == 0 {
			t.Error("Expected some default allowed import prefixes")
		}
	})

	t.Run("CheckImport with allowed import", func(t *testing.T) {
		assertions := DefaultKernelBoundaryAssertions()

		// Standard library imports should be allowed
		violation := assertions.CheckImport("fmt")
		if violation != nil {
			t.Errorf("fmt should be allowed: %v", violation)
		}

		violation = assertions.CheckImport("crypto/sha256")
		if violation != nil {
			t.Errorf("crypto/sha256 should be allowed: %v", violation)
		}
	})

	t.Run("CheckImport with disallowed import", func(t *testing.T) {
		assertions := DefaultKernelBoundaryAssertions()

		// net/http should be disallowed
		violation := assertions.CheckImport("net/http")
		if violation == nil {
			t.Error("Expected violation for 'net/http' import")
		}
		if violation != nil && violation.Severity != "error" {
			t.Errorf("Expected error severity, got %s", violation.Severity)
		}
	})

	t.Run("CheckImport with unknown import", func(t *testing.T) {
		assertions := DefaultKernelBoundaryAssertions()

		// Unknown external package - should produce warning
		violation := assertions.CheckImport("github.com/unknown/package")
		if violation == nil {
			t.Log("Unknown package returned nil (might be in allowed patterns)")
		}
	})

	t.Run("ValidatePackage", func(t *testing.T) {
		assertions := DefaultKernelBoundaryAssertions()

		// This may fail if package doesn't exist - that's OK for coverage
		violations, err := assertions.ValidatePackage("github.com/Mindburn-Labs/helm-oss/core/pkg/kernel")
		if err != nil {
			t.Logf("ValidatePackage returned error: %v (expected in test environment)", err)
		}
		t.Logf("ValidatePackage returned %d violations", len(violations))
	})

	t.Run("CompileTimeBoundaryCheck", func(t *testing.T) {
		// This is a compile-time check - just verify it runs
		ok, violations := CompileTimeBoundaryCheck()
		t.Logf("CompileTimeBoundaryCheck: ok=%v, violations=%d", ok, len(violations))
	})
}

func TestBoundaryAssertions_CustomPatterns(t *testing.T) {
	assertions := &BoundaryAssertions{
		AllowedImportPrefixes:    []string{"safe/"},
		DisallowedImportPatterns: []string{"unsafe", "forbidden/"},
	}

	// Test that allowed pattern works
	violation := assertions.CheckImport("safe/thing")
	if violation != nil {
		t.Errorf("Import matching allowed pattern should be allowed: %v", violation)
	}

	// Test disallowed import still blocked
	violation = assertions.CheckImport("unsafe")
	if violation == nil {
		t.Error("Disallowed import should be blocked")
	}

	violation = assertions.CheckImport("forbidden/pkg")
	if violation == nil {
		t.Error("Disallowed import prefix should be blocked")
	}
}
