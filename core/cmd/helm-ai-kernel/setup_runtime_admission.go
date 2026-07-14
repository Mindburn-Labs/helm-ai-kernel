package main

import (
	"fmt"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// requireCodexProjectRuntimeAdmission prevents a configured native client from
// silently booting under a newly generated local authority after its proven
// lifecycle state has been deleted or altered. A standalone `mcp serve`
// invocation with no Codex-project installation remains supported; once a
// binding or exact HELM config is present, however, the complete signed
// install proof is mandatory on every runtime admission boundary.
func admitCodexProjectRuntime(dataDir string) (helmcrypto.Signer, bool, error) {
	opts := setupOptions{Target: "codex", Scope: "project", DataDir: dataDir}
	binding, err := readSetupCodexProjectBinding(dataDir)
	if err != nil {
		return nil, false, fmt.Errorf("inspect Codex project install binding: %w", err)
	}
	summary, err := buildSetupSummary(opts)
	if err != nil {
		return nil, false, fmt.Errorf("inspect Codex project runtime configuration: %w", err)
	}
	refreshSetupConfiguration(opts, &summary)
	if binding == nil && !summary.MCPConfigured && !summary.HookConfigured {
		return nil, false, nil
	}

	clientState, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return nil, false, fmt.Errorf("inspect Codex project config for runtime admission: %w", err)
	}
	hookState, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return nil, false, fmt.Errorf("inspect Codex project hook for runtime admission: %w", err)
	}
	proof, err := validateCodexProjectInstallBindingForCurrentConfig(opts, clientState, hookState)
	if err != nil {
		return nil, false, fmt.Errorf("Codex project runtime provenance is invalid: %w", err)
	}
	if proof.Signer == nil {
		return nil, false, fmt.Errorf("Codex project runtime provenance has no existing lifecycle signer")
	}
	return proof.Signer, true, nil
}

func requireCodexProjectRuntimeAdmission(dataDir string) error {
	_, _, err := admitCodexProjectRuntime(dataDir)
	return err
}
