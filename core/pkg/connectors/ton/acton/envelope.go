package acton

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	CommandSchemaVersion = "ton.acton.command.v1"
)

type ActonCommandEnvelope struct {
	SchemaVersion        string                 `json:"schema_version"`
	ConnectorID          string                 `json:"connector_id"`
	CommandID            string                 `json:"command_id"`
	TenantID             string                 `json:"tenant_id"`
	WorkspaceID          string                 `json:"workspace_id"`
	Principal            string                 `json:"principal"`
	ActionURN            ActionURN              `json:"action_urn"`
	RiskClass            RiskClass              `json:"risk_class"`
	EffectClass          EffectClass            `json:"effect_class,omitempty"`
	ExecutorKind         ExecutorKind           `json:"executor_kind"`
	ActonVersion         string                 `json:"acton_version,omitempty"`
	TolkCompilerVersion  string                 `json:"tolk_compiler_version,omitempty"`
	ProjectRoot          string                 `json:"project_root"`
	ManifestPath         string                 `json:"manifest_path,omitempty"`
	ManifestHash         string                 `json:"manifest_hash,omitempty"`
	SourceTreeHash       string                 `json:"source_tree_hash,omitempty"`
	ScriptPath           string                 `json:"script_path,omitempty"`
	ScriptHash           string                 `json:"script_hash,omitempty"`
	Network              NetworkProfile         `json:"network,omitempty"`
	Argv                 []string               `json:"argv"`
	ExpectedEffects      []ExpectedEffect       `json:"expected_effects,omitempty"`
	EvidenceRequirements EvidenceRequirements   `json:"evidence_requirements,omitempty"`
	SandboxGrantRef      string                 `json:"sandbox_grant_ref,omitempty"`
	SandboxGrantHash     string                 `json:"sandbox_grant_hash,omitempty"`
	PolicyHash           string                 `json:"policy_hash,omitempty"`
	P0CeilingsHash       string                 `json:"p0_ceilings_hash,omitempty"`
	IdempotencyKey       string                 `json:"idempotency_key"`
	ApprovalRef          string                 `json:"approval_ref,omitempty"`
	WalletRef            string                 `json:"wallet_ref,omitempty"`
	MaxTONSpend          string                 `json:"max_ton_spend,omitempty"`
	CreatedAtLamport     uint64                 `json:"created_at_lamport"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

type EvidenceRequirements struct {
	RequireBuild            bool `json:"require_build,omitempty"`
	RequireTests            bool `json:"require_tests,omitempty"`
	RequireFormatCheck      bool `json:"require_format_check,omitempty"`
	RequireStaticCheck      bool `json:"require_static_check,omitempty"`
	RequireCoverageMin      int  `json:"require_coverage_min,omitempty"`
	RequireMutationScoreMin int  `json:"require_mutation_score_min,omitempty"`
	RequireGasSnapshot      bool `json:"require_gas_snapshot,omitempty"`
	RequireLocalScriptTrace bool `json:"require_local_script_trace,omitempty"`
	RequireTestnetReceipt   bool `json:"require_testnet_deploy_receipt,omitempty"`
	RequireVerifierDryRun   bool `json:"require_verifier_dry_run,omitempty"`
	RequireCompilerPin      bool `json:"require_compiler_pin,omitempty"`
	RequireFullEvidencePack bool `json:"require_full_evidence_pack,omitempty"`
}

func NewEnvelope(params map[string]any, action ActionURN, intentHash string, effectIndex int) (*ActonCommandEnvelope, error) {
	spec, ok := commandSpecs[action]
	if !ok {
		return nil, fmt.Errorf("%s: %s", ReasonUnknownCommand, action)
	}
	argv, err := BuildArgv(action, params)
	if err != nil {
		return nil, err
	}
	commandID, _ := stringParam(params, "command_id")
	if commandID == "" {
		commandID = deterministicID(intentHash, string(action), effectIndex)
	}
	projectRoot, _ := stringParam(params, "project_root")
	if projectRoot == "" {
		projectRoot = "."
	}
	manifestPath, _ := stringParam(params, "manifest_path")
	if manifestPath == "" {
		manifestPath = "Acton.toml"
	}
	env := &ActonCommandEnvelope{
		SchemaVersion:        CommandSchemaVersion,
		ConnectorID:          ConnectorID,
		CommandID:            commandID,
		TenantID:             fallbackString(params, "tenant_id", "local"),
		WorkspaceID:          fallbackString(params, "workspace_id", "local"),
		Principal:            fallbackString(params, "principal", "principal:local"),
		ActionURN:            action,
		RiskClass:            spec.RiskClass,
		EffectClass:          spec.EffectClass,
		ExecutorKind:         spec.ExecutorKind,
		ActonVersion:         fallbackString(params, "acton_version", ""),
		TolkCompilerVersion:  fallbackString(params, "tolk_compiler_version", ""),
		ProjectRoot:          cleanRel(projectRoot),
		ManifestPath:         cleanRel(manifestPath),
		ManifestHash:         fallbackString(params, "manifest_hash", ""),
		SourceTreeHash:       fallbackString(params, "source_tree_hash", ""),
		ScriptPath:           cleanRel(fallbackString(params, "script_path", "")),
		ScriptHash:           fallbackString(params, "script_hash", ""),
		Network:              spec.Network,
		Argv:                 argv,
		ExpectedEffects:      expectedEffectsFromParams(params),
		EvidenceRequirements: evidenceRequirementsFromParams(params, spec),
		SandboxGrantRef:      fallbackString(params, "sandbox_grant_ref", ""),
		SandboxGrantHash:     fallbackString(params, "sandbox_grant_hash", ""),
		PolicyHash:           fallbackString(params, "policy_hash", ""),
		P0CeilingsHash:       fallbackString(params, "p0_ceilings_hash", ""),
		ApprovalRef:          fallbackString(params, "approval_ref", ""),
		WalletRef:            fallbackString(params, "wallet_ref", ""),
		MaxTONSpend:          fallbackString(params, "max_ton_spend", ""),
		CreatedAtLamport:     uint64Param(params, "created_at_lamport", uint64(time.Now().UnixNano())),
		Metadata:             metadataFromParams(params),
	}
	env.IdempotencyKey = DeriveIdempotencyKey(intentHash, string(action), effectIndex)
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return env, nil
}

func metadataFromParams(params map[string]any) map[string]interface{} {
	metadata := map[string]interface{}{}
	if raw, ok := params["metadata"]; ok && raw != nil {
		if typed, ok := raw.(map[string]interface{}); ok {
			for key, value := range typed {
				metadata[key] = value
			}
		}
	}
	for _, key := range []string{"generic", "raw_acton", "dry_run_fixture"} {
		if value, ok := params[key]; ok {
			metadata[key] = value
		}
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func (e *ActonCommandEnvelope) Validate() error {
	if e.SchemaVersion != CommandSchemaVersion {
		return fmt.Errorf("%s: schema_version", ReasonArgvRejected)
	}
	if e.ConnectorID != ConnectorID {
		return fmt.Errorf("%s: connector_id", ReasonArgvRejected)
	}
	if _, ok := commandSpecs[e.ActionURN]; !ok {
		return fmt.Errorf("%s: %s", ReasonUnknownCommand, e.ActionURN)
	}
	if len(e.Argv) == 0 || e.Argv[0] != "acton" {
		return fmt.Errorf("%s: argv[0]", ReasonArgvRejected)
	}
	_, err := validateArgvForAction(e.ActionURN, e.Argv)
	return err
}

func (e *ActonCommandEnvelope) CanonicalBytes() ([]byte, error) {
	return canonicalize.JCS(e)
}

func (e *ActonCommandEnvelope) Hash() (string, error) {
	h, err := canonicalize.CanonicalHash(e)
	if err != nil {
		return "", err
	}
	return "sha256:" + h, nil
}

func DeriveIdempotencyKey(intentHash, connectorURN string, effectIndex int) string {
	preimage := intentHash + "\x00" + connectorURN + "\x00" + strconv.Itoa(effectIndex)
	sum := sha256.Sum256([]byte(preimage))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func deterministicID(intentHash, action string, effectIndex int) string {
	sum := sha256.Sum256([]byte(intentHash + "\x00" + action + "\x00" + strconv.Itoa(effectIndex)))
	return "ton-acton-" + hex.EncodeToString(sum[:8])
}

func fallbackString(params map[string]any, key, fallback string) string {
	if v, ok := stringParam(params, key); ok && v != "" {
		return v
	}
	return fallback
}

func uint64Param(params map[string]any, key string, fallback uint64) uint64 {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case uint64:
		return n
	case int:
		if n >= 0 {
			return uint64(n)
		}
	case int64:
		if n >= 0 {
			return uint64(n)
		}
	case float64:
		if n >= 0 {
			return uint64(n)
		}
	case string:
		if parsed, err := strconv.ParseUint(n, 10, 64); err == nil {
			return parsed
		}
	}
	return fallback
}
