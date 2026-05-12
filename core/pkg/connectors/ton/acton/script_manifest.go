package acton

import (
	"encoding/json"
	"fmt"
	"os"
)

const ScriptManifestSchemaVersion = "ton.acton.script_manifest.v1"

type ScriptManifest struct {
	SchemaVersion     string            `json:"schema_version"`
	ScriptPath        string            `json:"script_path"`
	ScriptHash        string            `json:"script_hash"`
	AllowedNetworks   []NetworkProfile  `json:"allowed_networks"`
	ExpectedEffects   []ExpectedEffect  `json:"expected_effects"`
	RequiredPreflight RequiredPreflight `json:"required_preflight"`
}

type ExpectedEffect struct {
	EffectKind                 string      `json:"effect_kind"`
	EffectClass                EffectClass `json:"effect_class"`
	Network                    string      `json:"network,omitempty"`
	WalletRef                  string      `json:"wallet_ref,omitempty"`
	MaxTONSpend                string      `json:"max_ton_spend,omitempty"`
	ContractAddress            string      `json:"contract_address,omitempty"`
	ContractCodeHash           string      `json:"contract_code_hash,omitempty"`
	RequiresSourceVerification bool        `json:"requires_source_verification,omitempty"`
	IrreversibleReason         string      `json:"irreversible_reason,omitempty"`
}

type RequiredPreflight struct {
	Build        bool `json:"build"`
	Test         bool `json:"test"`
	Check        bool `json:"check"`
	FormatCheck  bool `json:"fmt_check"`
	VerifyDryRun bool `json:"verify_dry_run"`
}

func LoadScriptManifest(path string) (*ScriptManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest ScriptManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, manifest.Validate()
}

func (m *ScriptManifest) Validate() error {
	if m == nil {
		return fmt.Errorf("%s", ReasonScriptManifestRequired)
	}
	if m.SchemaVersion != ScriptManifestSchemaVersion {
		return fmt.Errorf("%s: schema_version", ReasonArgvRejected)
	}
	if m.ScriptPath == "" || m.ScriptHash == "" {
		return fmt.Errorf("%s", ReasonScriptManifestRequired)
	}
	if len(m.AllowedNetworks) == 0 {
		return fmt.Errorf("%s: allowed_networks", ReasonExpectedEffectMismatch)
	}
	for _, effect := range m.ExpectedEffects {
		if effect.EffectKind == "" || effect.EffectClass == "" {
			return fmt.Errorf("%s", ReasonExpectedEffectMismatch)
		}
	}
	return nil
}

func (m *ScriptManifest) ValidateForEnvelope(env *ActonCommandEnvelope) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if cleanRel(m.ScriptPath) != cleanRel(env.ScriptPath) {
		return fmt.Errorf("%s: script_path", ReasonExpectedEffectMismatch)
	}
	if m.ScriptHash != env.ScriptHash {
		return fmt.Errorf("%s", ReasonScriptManifestHashMismatch)
	}
	allowed := false
	for _, network := range m.AllowedNetworks {
		if network == env.Network {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%s: network", ReasonExpectedEffectMismatch)
	}
	if len(m.ExpectedEffects) == 0 {
		return fmt.Errorf("%s", ReasonExpectedEffectMismatch)
	}
	return nil
}

func expectedEffectsFromParams(params map[string]any) []ExpectedEffect {
	raw, ok := params["expected_effects"]
	if !ok || raw == nil {
		return nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var effects []ExpectedEffect
	if err := json.Unmarshal(data, &effects); err != nil {
		return nil
	}
	return effects
}

func evidenceRequirementsFromParams(params map[string]any, spec CommandSpec) EvidenceRequirements {
	var req EvidenceRequirements
	if raw, ok := params["evidence_requirements"]; ok && raw != nil {
		data, err := json.Marshal(raw)
		if err == nil {
			_ = json.Unmarshal(data, &req)
		}
	}
	if spec.RequiresCompilerPin {
		req.RequireCompilerPin = true
	}
	if spec.RequiresFullEvidence {
		req.RequireFullEvidencePack = true
	}
	if spec.RiskClass == RiskT3 {
		req.RequireBuild = true
		req.RequireTests = true
		req.RequireFormatCheck = true
		req.RequireStaticCheck = true
		req.RequireVerifierDryRun = true
	}
	return req
}
