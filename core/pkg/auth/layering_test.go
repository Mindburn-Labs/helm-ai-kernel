package auth_test

import (
	"go/build"
	"strings"
	"testing"
)

// serverPkg is the HTTP server package. It transitively pulls the OpenTelemetry
// SDK and the OTLP gRPC exporters, so importing it from here put 64 OTel
// packages into the dependency tree of everything that merely authenticates a
// request — pkg/executor among them (HELM-460).
const serverPkg = "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"

// TestAuthDoesNotImportServerPackage pins the layering direction: authentication
// is a library concern and must stay below the server. The three call sites that
// caused the inversion needed nothing from pkg/api but its RFC 7807 response
// writers, which now live in the stdlib-only pkg/httperr — reach for that
// instead of re-adding this import.
func TestAuthDoesNotImportServerPackage(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}

	// Test-only imports are exempt: a test may legitimately exercise the pair
	// together, and test files do not enter a consumer's dependency tree.
	for _, imp := range pkg.Imports {
		if imp == serverPkg || strings.HasPrefix(imp, serverPkg+"/") {
			t.Errorf("pkg/auth imports %q — use pkg/httperr for error responses", imp)
		}
	}
}
