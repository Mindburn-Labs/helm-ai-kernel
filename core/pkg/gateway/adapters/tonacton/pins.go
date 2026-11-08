package tonacton

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// checkPins compares the version pins an effect declares with what the
// configured binary reports for itself (acton --version), and refuses on any
// mismatch. A pin the binary does not report cannot be confirmed, so it is
// refused too: a pin is a measured fact here, not a claim.
func (a *Adapter) checkPins(ctx context.Context, tenantRoot string, ar args) *adapters.Refusal {
	if ar.ActonVersion == "" && ar.TolkCompilerVersion == "" {
		return nil
	}
	out, err := a.binaryVersion(ctx, tenantRoot)
	if err != nil {
		return adapters.Refuse(contracts.ReasonProviderError, "the Acton binary did not report its version")
	}
	if ar.ActonVersion != "" && !strings.Contains(out, ar.ActonVersion) {
		return adapters.Refuse(contracts.ReasonTONActonUnsupportedVersion, "the Acton binary does not report version %s", ar.ActonVersion)
	}
	if ar.TolkCompilerVersion != "" && !strings.Contains(out, ar.TolkCompilerVersion) {
		return adapters.Refuse(contracts.ReasonTONTolkCompilerMismatch, "the Acton binary does not report Tolk compiler %s", ar.TolkCompilerVersion)
	}
	return nil
}

// binaryVersion runs the binary's --version with an empty environment and no
// project, and remembers a successful answer.
func (a *Adapter) binaryVersion(ctx context.Context, cwd string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.version != "" {
		return a.version, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	name, argv := commandLine(a.cfg.Isolation, a.cfg.Binary, []string{"--version"})
	cmd := exec.CommandContext(ctx, name, argv...) // #nosec G204 -- operator-configured binary and isolation command
	cmd.Dir = cwd
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	a.version = string(out)
	return a.version, nil
}
