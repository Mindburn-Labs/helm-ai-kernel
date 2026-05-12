package acton

import (
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

type SandboxRequirements struct {
	RequireNetwork bool     `json:"require_network"`
	Writable       bool     `json:"writable"`
	Preopens       []string `json:"preopens"`
	EnvNames       []string `json:"env_names,omitempty"`
}

func RequirementsForAction(env *ActonCommandEnvelope) SandboxRequirements {
	spec := commandSpecs[env.ActionURN]
	req := SandboxRequirements{
		RequireNetwork: spec.RequiresNetworkGrant,
		Writable:       spec.RequiresWritablePreopen || localFilesystemWrite(env.ActionURN),
		Preopens:       []string{env.ProjectRoot},
	}
	if spec.RequiresNetworkGrant {
		req.EnvNames = []string{"TONCENTER_TESTNET_API_KEY", "TONCENTER_MAINNET_API_KEY", "ACTON_VERIFY_BACKEND"}
	}
	return req
}

func localFilesystemWrite(action ActionURN) bool {
	switch action {
	case ActionProjectNew, ActionProjectInit, ActionBuild, ActionFormat, ActionWrapperGenerate, ActionWrapperGenerateTS, ActionCompile, ActionFunc2Tolk, ActionLibraryFetch:
		return true
	default:
		return false
	}
}

func ValidateSandboxGrant(env *ActonCommandEnvelope, grant *contracts.SandboxGrant) error {
	if grant == nil {
		return fmt.Errorf("%s", ReasonSandboxGrantRequired)
	}
	if err := grant.Validate(); err != nil {
		return fmt.Errorf("%s: %w", ReasonSandboxGrantRequired, err)
	}
	sealed, err := grant.Seal()
	if err != nil {
		return fmt.Errorf("%s: %w", ReasonSandboxGrantRequired, err)
	}
	if env.SandboxGrantHash != "" && sealed.GrantHash != env.SandboxGrantHash {
		return fmt.Errorf("%s: hash mismatch", ReasonSandboxGrantRequired)
	}
	req := RequirementsForAction(env)
	if req.RequireNetwork && grant.Network.Mode != "allowlist" {
		return fmt.Errorf("%s", ReasonNetworkGrantRequired)
	}
	if !req.RequireNetwork && grant.Network.Mode != "deny-all" {
		return fmt.Errorf("%s: local action must deny network", ReasonNetworkGrantRequired)
	}
	if !hasPreopen(grant.FilesystemPreopens, env.ProjectRoot, req.Writable) {
		return fmt.Errorf("%s: missing filesystem preopen", ReasonSandboxGrantRequired)
	}
	if grant.Env.Mode == "allowlist" {
		for _, name := range grant.Env.Names {
			if strings.Contains(strings.ToUpper(name), "MNEMONIC") || strings.Contains(strings.ToUpper(name), "PRIVATE_KEY") {
				return fmt.Errorf("%s", ReasonPlaintextMnemonicForbidden)
			}
		}
	}
	return nil
}

func hasPreopen(preopens []contracts.FilesystemPreopen, path string, writable bool) bool {
	clean := cleanRel(path)
	for _, preopen := range preopens {
		p := cleanRel(preopen.Path)
		if p != clean && p != "." {
			continue
		}
		if writable && preopen.Mode != "rw" {
			continue
		}
		return true
	}
	return false
}
