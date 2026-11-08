package effectargs

import (
	"regexp"
	"strings"
)

// The sandbox effect types (P17): create, run a command in, and terminate a
// sandbox of a configured provider. Their closed argument schemas are declared
// by the sandbox adapter (core/pkg/gateway/adapters/sandbox) and checked by
// admission; this file owns the one thing admission must know of them without
// the adapter: what a target looks like.
const (
	SandboxCreate    = "sandbox.create"
	SandboxExec      = "sandbox.exec"
	SandboxTerminate = "sandbox.terminate"
)

// SandboxProviders are the provider names a sandbox target may carry. Whether
// a provider is configured on a gateway is the adapter's business.
var SandboxProviders = []string{"claude-managed-agents", "daytona", "docker", "e2b", "opensandbox"}

var sandboxTargetPattern = regexp.MustCompile(`^sandbox/([a-z][a-z0-9-]{1,31})(?:/([A-Za-z0-9][A-Za-z0-9._-]{0,127}))?$`)

// IsSandboxEffect reports whether effectType is one of the sandbox effects.
func IsSandboxEffect(effectType string) bool {
	return effectType == SandboxCreate || effectType == SandboxExec || effectType == SandboxTerminate
}

// SandboxTarget splits a sandbox effect's target: "sandbox/{provider}" for
// sandbox.create, "sandbox/{provider}/{sandbox_id}" for the others. The
// provider and the sandbox come only from the target, never from the
// arguments (09-02).
func SandboxTarget(effectType, target string) (provider, sandboxID string, err error) {
	if !IsSandboxEffect(effectType) {
		return "", "", invalid("%q is not a sandbox effect type", effectType)
	}
	m := sandboxTargetPattern.FindStringSubmatch(target)
	if m == nil {
		return "", "", invalid("target %q is not sandbox/{provider}[/{sandbox_id}]", target)
	}
	provider, sandboxID = m[1], m[2]
	known := false
	for _, p := range SandboxProviders {
		known = known || p == provider
	}
	if !known {
		return "", "", invalid("target %q names provider %q, which is not one of %s", target, provider, strings.Join(SandboxProviders, ", "))
	}
	switch {
	case effectType == SandboxCreate && sandboxID != "":
		return "", "", invalid("%s targets sandbox/{provider}, not a sandbox", effectType)
	case effectType != SandboxCreate && sandboxID == "":
		return "", "", invalid("%s targets sandbox/{provider}/{sandbox_id}", effectType)
	}
	return provider, sandboxID, nil
}

func checkSandboxTarget(effectType, target string) error {
	_, _, err := SandboxTarget(effectType, target)
	return err
}
