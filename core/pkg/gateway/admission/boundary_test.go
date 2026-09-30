package admission

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The effect gateway must be movable to its own repository: nothing under
// core/pkg/gateway or core/cmd/helm-gateway may depend, even transitively, on
// the legacy kernel runtime (HELM-751 s2).
var forbiddenGatewayDeps = []string{
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian",
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proxy",
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp",
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/executor",
}

// forbiddenIn returns every dependency in deps that is, or is inside, a
// forbidden package.
func forbiddenIn(deps []string) []string {
	var out []string
	for _, dep := range deps {
		for _, forbidden := range forbiddenGatewayDeps {
			if dep == forbidden || strings.HasPrefix(dep, forbidden+"/") {
				out = append(out, dep)
			}
		}
	}
	return out
}

func TestGatewayDoesNotImportTheLegacyRuntime(t *testing.T) {
	// Known bad: the check flags a forbidden package and its subpackages,
	// and not a package that merely shares a prefix.
	planted := []string{
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp",
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian/firewall",
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcpx",
	}
	if got := forbiddenIn(planted); len(got) != 2 {
		t.Fatalf("the boundary check flagged %v in the planted list, want the first two", got)
	}

	_, file, _, _ := runtime.Caller(0)
	core := filepath.Join(filepath.Dir(file), "..", "..", "..")
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./pkg/gateway/...", "./cmd/helm-gateway")
	cmd.Dir = core
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	// Known good: the list is the real dependency set, which reaches the
	// packages the gateway is built on.
	for _, want := range []string{
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission",
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/mandates",
		"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks",
	} {
		if !contains(deps, want) {
			t.Fatalf("go list did not report %s; the check would see nothing", want)
		}
	}
	if bad := forbiddenIn(deps); len(bad) > 0 {
		t.Fatalf("the effect gateway depends on the legacy runtime: %v", bad)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
