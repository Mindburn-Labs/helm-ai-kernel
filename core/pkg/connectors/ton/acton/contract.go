package acton

import (
	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry/connectors"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/tooling"
)

const ConnectorVersion = "0.1.0"

var SupportedActonVersions = []string{"fixture-acton-1.0.0", "0.5.0", "0.6.0", "1.0.0"}
var SupportedTolkCompilerVersions = []string{"fixture-tolk-1.0.0", "0.12.0", "0.13.0", "1.4.0"}

type ConnectorContractBundle struct {
	SchemaVersion                 string                        `json:"schema_version"`
	ConnectorID                   string                        `json:"connector_id"`
	ConnectorVersion              string                        `json:"connector_version"`
	ExecutorKind                  ExecutorKind                  `json:"executor_kind"`
	SupportedActonVersions        []string                      `json:"supported_acton_versions"`
	SupportedTolkCompilerVersions []string                      `json:"supported_tolk_compiler_versions"`
	AllowedCommands               []ActionURN                   `json:"allowed_commands"`
	SchemaArtifacts               SchemaArtifacts               `json:"schema_artifacts"`
	NetworkProfiles               map[NetworkProfile]NetProfile `json:"network_profiles"`
	IdempotencyStrategy           map[string]string             `json:"idempotency_strategy"`
	IrreversibilityTags           []string                      `json:"irreversibility_tags"`
	DriftDetection                DriftDetectionContract        `json:"drift_detection"`
	EffectClasses                 map[ActionURN]EffectClass     `json:"effect_classes"`
}

type SchemaArtifacts struct {
	CommandSchemaHash        string `json:"command_schema_hash"`
	ReceiptSchemaHash        string `json:"receipt_schema_hash"`
	ScriptManifestSchemaHash string `json:"script_manifest_schema_hash"`
	EvidenceSchemaHash       string `json:"evidence_schema_hash,omitempty"`
}

type NetProfile struct {
	Broadcast        bool      `json:"broadcast"`
	NetworkEgress    bool      `json:"network_egress"`
	DefaultRiskClass RiskClass `json:"default_risk_class,omitempty"`
}

type DriftDetectionContract struct {
	Fixtures   []string `json:"fixtures"`
	FailClosed bool     `json:"fail_closed"`
}

func ContractBundle() ConnectorContractBundle {
	effectClasses := map[ActionURN]EffectClass{}
	for _, urn := range AllActionURNs() {
		effectClasses[urn] = commandSpecs[urn].EffectClass
	}
	return ConnectorContractBundle{
		SchemaVersion:                 "helm.connector_contract.v1",
		ConnectorID:                   ConnectorID,
		ConnectorVersion:              ConnectorVersion,
		ExecutorKind:                  ExecutorDigital,
		SupportedActonVersions:        append([]string{}, SupportedActonVersions...),
		SupportedTolkCompilerVersions: append([]string{}, SupportedTolkCompilerVersions...),
		AllowedCommands:               AllActionURNs(),
		SchemaArtifacts: SchemaArtifacts{
			CommandSchemaHash:        "sha256:56ca14b9d0d64a9812a2132b7b0ac2a15fc974ee9f898b575e18c097ce027488",
			ReceiptSchemaHash:        "sha256:6d6eba08ba0c94b5e1185537b3ea6ff9908ce96841f775672e6633df7dcbcff0",
			ScriptManifestSchemaHash: "sha256:83084b4de17844e4722e2022930a2b15e52751d0ecc5110e88718138c1040121",
			EvidenceSchemaHash:       "sha256:06990b8bf936e9a3e009f6ef35ee7c3e4426ea8c3323be7d5fa1ce5c39b78b6e",
		},
		NetworkProfiles: map[NetworkProfile]NetProfile{
			NetworkLocal:       {Broadcast: false, NetworkEgress: false},
			NetworkForkTestnet: {Broadcast: false, NetworkEgress: true},
			NetworkForkMainnet: {Broadcast: false, NetworkEgress: true},
			NetworkTestnet:     {Broadcast: true, NetworkEgress: true},
			NetworkMainnet:     {Broadcast: true, NetworkEgress: true, DefaultRiskClass: RiskT3},
		},
		IdempotencyStrategy: map[string]string{
			"derivation": "sha256(intent_hash || connector_urn || effect_index)",
		},
		IrreversibilityTags: []string{"TON_DEPLOY", "TON_TRANSACTION", "TON_SOURCE_VERIFY_TX", "TON_LIBRARY_PUBLISH", "TON_LIBRARY_TOPUP"},
		DriftDetection: DriftDetectionContract{
			Fixtures:   []string{"build_output", "test_output", "verification_dry_run", "library_info", "wrapper_abi"},
			FailClosed: true,
		},
		EffectClasses: effectClasses,
	}
}

func ConnectorRelease(binaryHash, signatureRef string) connectors.ConnectorRelease {
	return connectors.ConnectorRelease{
		ConnectorID:    ConnectorID,
		Name:           "TON Acton",
		Version:        ConnectorVersion,
		State:          connectors.ConnectorCandidate,
		SchemaRefs:     []string{"protocols/json-schemas/connectors/ton/acton_command.schema.json", "protocols/json-schemas/connectors/ton/acton_receipt.schema.json"},
		ExecutorKind:   connectors.ExecDigital,
		SandboxProfile: "ton-acton",
		DriftPolicyRef: "policy://ton-acton-drift-v1",
		BinaryHash:     binaryHash,
		SignatureRef:   signatureRef,
	}
}

func ToolDescriptor() *tooling.ToolDescriptor {
	return &tooling.ToolDescriptor{
		ToolID:             ConnectorID,
		Version:            ConnectorVersion,
		Endpoint:           "helm://connectors/ton.acton",
		AuthMethodClass:    "helm-pep-cpi-sandbox",
		DeterministicFlags: []string{"typed-argv", "no-shell", "sandbox-grant-required", "fail-closed-drift"},
		CostEnvelope:       tooling.CostEnvelope{MaxLatencyMs: 120000, MaxCostUnits: 1, RateLimitRPS: 1},
		InputSchemaHash:    ContractBundle().SchemaArtifacts.CommandSchemaHash,
		OutputSchemaHash:   ContractBundle().SchemaArtifacts.ReceiptSchemaHash,
		Metadata: map[string]string{
			"connector_id": ConnectorID,
			"risk":         "T0-T3",
		},
	}
}
