package acton

import (
	"encoding/json"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts/actuators"
)

const ReceiptSchemaVersion = "ton.acton.receipt.v1"

type ActonReceipt struct {
	SchemaVersion       string                 `json:"schema_version"`
	ConnectorID         string                 `json:"connector_id"`
	CommandID           string                 `json:"command_id"`
	ActionURN           ActionURN              `json:"action_urn"`
	Verdict             contracts.Verdict      `json:"verdict"`
	Status              string                 `json:"status"`
	ReasonCode          ReasonCode             `json:"reason_code"`
	RiskClass           RiskClass              `json:"risk_class"`
	EffectClass         EffectClass            `json:"effect_class,omitempty"`
	ExecutorKind        ExecutorKind           `json:"executor_kind"`
	RequestHash         string                 `json:"request_hash"`
	ResponseHash        string                 `json:"response_hash,omitempty"`
	StdoutHash          string                 `json:"stdout_hash,omitempty"`
	StderrHash          string                 `json:"stderr_hash,omitempty"`
	SandboxGrantHash    string                 `json:"sandbox_grant_hash,omitempty"`
	ActonVersion        string                 `json:"acton_version,omitempty"`
	TolkCompilerVersion string                 `json:"tolk_compiler_version,omitempty"`
	Environment         EnvironmentReceipt     `json:"environment"`
	Artifacts           ArtifactReceipt        `json:"artifacts"`
	Network             NetworkProfile         `json:"network,omitempty"`
	WalletRef           string                 `json:"wallet_ref,omitempty"`
	Redactions          []string               `json:"redactions,omitempty"`
	Tx                  TransactionReceipt     `json:"tx"`
	Drift               DriftReceipt           `json:"drift"`
	EvidenceRefs        []string               `json:"evidence_refs,omitempty"`
	ExitCode            int                    `json:"exit_code,omitempty"`
	ToolError           string                 `json:"tool_error,omitempty"`
	CompletedAt         time.Time              `json:"completed_at"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

type EnvironmentReceipt struct {
	OS             string `json:"os,omitempty"`
	Arch           string `json:"arch,omitempty"`
	ImageDigest    string `json:"image_digest,omitempty"`
	TemplateDigest string `json:"template_digest,omitempty"`
	Runtime        string `json:"runtime,omitempty"`
	Provider       string `json:"provider,omitempty"`
}

type ArtifactReceipt struct {
	SourceTreeHash       string `json:"source_tree_hash,omitempty"`
	ManifestHash         string `json:"manifest_hash,omitempty"`
	BuildOutputHash      string `json:"build_output_hash,omitempty"`
	CodeBOC64Hash        string `json:"code_boc64_hash,omitempty"`
	ContractCodeHash     string `json:"contract_code_hash,omitempty"`
	WrapperHash          string `json:"wrapper_hash,omitempty"`
	TestReportHash       string `json:"test_report_hash,omitempty"`
	CoverageReportHash   string `json:"coverage_report_hash,omitempty"`
	MutationReportHash   string `json:"mutation_report_hash,omitempty"`
	GasReportHash        string `json:"gas_report_hash,omitempty"`
	LibraryArtifactHash  string `json:"library_artifact_hash,omitempty"`
	ScriptHash           string `json:"script_hash,omitempty"`
	VerifierResponseHash string `json:"verifier_response_hash,omitempty"`
}

type TransactionReceipt struct {
	TxHash    string `json:"tx_hash,omitempty"`
	Address   string `json:"address,omitempty"`
	AmountTON string `json:"amount_ton,omitempty"`
}

func NewPreDispatchReceipt(env *ActonCommandEnvelope, decision PolicyDecision) (*ActonReceipt, error) {
	reqHash, err := env.Hash()
	if err != nil {
		return nil, err
	}
	status := "ok"
	if decision.Verdict == contracts.VerdictDeny {
		status = "denied"
	}
	if decision.Verdict == contracts.VerdictEscalate {
		status = "escalated"
	}
	return &ActonReceipt{
		SchemaVersion:       ReceiptSchemaVersion,
		ConnectorID:         ConnectorID,
		CommandID:           env.CommandID,
		ActionURN:           env.ActionURN,
		Verdict:             decision.Verdict,
		Status:              status,
		ReasonCode:          decision.ReasonCode,
		RiskClass:           env.RiskClass,
		EffectClass:         env.EffectClass,
		ExecutorKind:        env.ExecutorKind,
		RequestHash:         reqHash,
		SandboxGrantHash:    env.SandboxGrantHash,
		ActonVersion:        env.ActonVersion,
		TolkCompilerVersion: env.TolkCompilerVersion,
		Network:             env.Network,
		WalletRef:           RedactWalletRef(env.WalletRef),
		Redactions:          []string{"wallet_ref"},
		Artifacts: ArtifactReceipt{
			SourceTreeHash: env.SourceTreeHash,
			ManifestHash:   env.ManifestHash,
			ScriptHash:     env.ScriptHash,
		},
		CompletedAt: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"policy_reason": decision.Reason,
			"dispatch":      decision.Dispatch,
		},
	}, nil
}

func ReceiptFromExec(env *ActonCommandEnvelope, result *actuators.ExecResult, provider string, drift DriftReceipt) (*ActonReceipt, error) {
	reqHash, err := env.Hash()
	if err != nil {
		return nil, err
	}
	status := "ok"
	reason := ReasonOK
	verdict := contracts.VerdictAllow
	var toolErr string
	if result == nil {
		status = "error"
		reason = ReasonArgvRejected
		toolErr = "missing execution result"
	} else if result.TimedOut {
		status = "timeout"
		reason = ReasonComputeTimeExhausted
		toolErr = "execution timed out"
	} else if result.OOMKilled {
		status = "resource_exhausted"
		reason = ReasonComputeGasExhausted
		toolErr = "execution exhausted sandbox resources"
	} else if !result.Success() {
		status = "tool_error"
		toolErr = "acton exited non-zero"
	}
	responseHash, _ := canonicalize.CanonicalHash(map[string]any{
		"exit_code": resultExitCode(result),
		"stdout":    resultStdoutHash(result),
		"stderr":    resultStderrHash(result),
		"status":    status,
	})
	receipt := &ActonReceipt{
		SchemaVersion:       ReceiptSchemaVersion,
		ConnectorID:         ConnectorID,
		CommandID:           env.CommandID,
		ActionURN:           env.ActionURN,
		Verdict:             verdict,
		Status:              status,
		ReasonCode:          reason,
		RiskClass:           env.RiskClass,
		EffectClass:         env.EffectClass,
		ExecutorKind:        env.ExecutorKind,
		RequestHash:         reqHash,
		ResponseHash:        "sha256:" + responseHash,
		StdoutHash:          resultStdoutHash(result),
		StderrHash:          resultStderrHash(result),
		SandboxGrantHash:    env.SandboxGrantHash,
		ActonVersion:        env.ActonVersion,
		TolkCompilerVersion: env.TolkCompilerVersion,
		Environment: EnvironmentReceipt{
			Provider: provider,
			Runtime:  "sandbox",
		},
		Artifacts: ArtifactReceipt{
			SourceTreeHash: env.SourceTreeHash,
			ManifestHash:   env.ManifestHash,
			ScriptHash:     env.ScriptHash,
		},
		Network:     env.Network,
		WalletRef:   RedactWalletRef(env.WalletRef),
		Redactions:  []string{"wallet_ref", "stdout", "stderr"},
		Tx:          TransactionReceipt{AmountTON: env.MaxTONSpend},
		Drift:       drift,
		ExitCode:    resultExitCode(result),
		ToolError:   toolErr,
		CompletedAt: time.Now().UTC(),
	}
	if result != nil {
		receipt.Environment.ImageDigest = result.Receipt.ImageDigest
	}
	return receipt, nil
}

func (r *ActonReceipt) CanonicalJSON() ([]byte, error) {
	return canonicalize.JCS(r)
}

func (r *ActonReceipt) Hash() (string, error) {
	h, err := canonicalize.CanonicalHash(r)
	if err != nil {
		return "", err
	}
	return "sha256:" + h, nil
}

func (r *ActonReceipt) ToToolReceipt() map[string]any {
	data, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

func resultExitCode(result *actuators.ExecResult) int {
	if result == nil {
		return -1
	}
	return result.ExitCode
}

func resultStdoutHash(result *actuators.ExecResult) string {
	if result == nil {
		return ""
	}
	if result.Receipt.StdoutHash != "" {
		return result.Receipt.StdoutHash
	}
	return "sha256:" + canonicalize.HashBytes(result.Stdout)
}

func resultStderrHash(result *actuators.ExecResult) string {
	if result == nil {
		return ""
	}
	if result.Receipt.StderrHash != "" {
		return result.Receipt.StderrHash
	}
	return "sha256:" + canonicalize.HashBytes(result.Stderr)
}
