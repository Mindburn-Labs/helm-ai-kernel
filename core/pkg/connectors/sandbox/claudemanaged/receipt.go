package claudemanaged

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const (
	ReceiptVersionManagedAgentExecution = "managed_agent_execution_receipt.v1"
	localPreviewSignerKeyID             = "claude-managed-agents-local-preview"
)

type deterministicPreviewSigner struct{}

func (deterministicPreviewSigner) Sign(data []byte) (string, error) {
	return strings.TrimPrefix(hashBytes(append([]byte("managed-agent-preview|"), data...)), "sha256:"), nil
}

func (deterministicPreviewSigner) SignerKeyID() string { return localPreviewSignerKeyID }

type ManagedAgentExecutionReceipt struct {
	ReceiptVersion   string                     `json:"receipt_version"`
	ReceiptID        string                     `json:"receipt_id"`
	AgentID          string                     `json:"agent_id"`
	AgentVersion     string                     `json:"agent_version"`
	SessionID        string                     `json:"session_id"`
	EnvironmentID    string                     `json:"environment_id"`
	WorkID           string                     `json:"work_id"`
	Worker           ManagedAgentWorker         `json:"worker"`
	SandboxGrantHash string                     `json:"sandbox_grant_hash"`
	MCPProfiles      []ManagedAgentMCPProfile   `json:"mcp_profiles,omitempty"`
	ToolActions      []ManagedAgentToolAction   `json:"tool_actions"`
	DeniedEffects    []ManagedAgentDeniedEffect `json:"denied_effects"`
	ArtifactHashes   map[string]string          `json:"artifact_hashes"`
	CreatedAt        time.Time                  `json:"created_at"`
	CompletedAt      *time.Time                 `json:"completed_at,omitempty"`
	ReceiptHash      string                     `json:"receipt_hash"`
	Signature        string                     `json:"signature"`
	SignerKeyID      string                     `json:"signer_key_id"`
}

type ManagedAgentWorker struct {
	WorkerID          string `json:"worker_id"`
	WorkerImageDigest string `json:"worker_image_digest"`
	SkillManifestHash string `json:"skill_manifest_hash"`
}

type ManagedAgentMCPProfile struct {
	MCPProfileHash          string   `json:"mcp_profile_hash"`
	TunnelDomainHash        string   `json:"tunnel_domain_hash"`
	UpstreamMCPServerID     string   `json:"upstream_mcp_server_id"`
	OAuthResource           string   `json:"oauth_resource"`
	RequiredScopes          []string `json:"required_scopes"`
	ProtocolVersion         string   `json:"protocol_version"`
	CACertRefHash           string   `json:"ca_cert_ref_hash"`
	AllowedUpstreamHostHash string   `json:"allowed_upstream_host_hash"`
	Route                   string   `json:"route"`
}

type ManagedAgentToolAction struct {
	ActionID   string            `json:"action_id"`
	ToolID     string            `json:"tool_id"`
	EffectType string            `json:"effect_type"`
	Target     string            `json:"target,omitempty"`
	ArgsHash   string            `json:"args_hash,omitempty"`
	Verdict    contracts.Verdict `json:"verdict"`
	ReasonCode string            `json:"reason_code,omitempty"`
	ReceiptRef string            `json:"receipt_ref"`
	OccurredAt time.Time         `json:"occurred_at"`
}

type ManagedAgentDeniedEffect struct {
	EffectID   string    `json:"effect_id"`
	EffectType string    `json:"effect_type"`
	ReasonCode string    `json:"reason_code"`
	Reason     string    `json:"reason,omitempty"`
	ReceiptRef string    `json:"receipt_ref"`
	OccurredAt time.Time `json:"occurred_at"`
}

func (a *Adapter) managedReceiptForTool(req ToolRequest, verdict contracts.Verdict, reason contracts.ReasonCode, reasonText string, artifactHashes map[string]string, receiptRef string, occurredAt time.Time) (*ManagedAgentExecutionReceipt, error) {
	state, err := a.runningState(req.SandboxID)
	if err != nil {
		return nil, err
	}
	if receiptRef == "" {
		receiptRef = denialReceiptID(req, reason)
	}
	if artifactHashes == nil {
		artifactHashes = map[string]string{}
	}
	action := ManagedAgentToolAction{
		ActionID:   req.RequestID,
		ToolID:     managedToolID(req),
		EffectType: managedEffectType(req.Class),
		Target:     managedTarget(req),
		ArgsHash:   hashManagedToolArgs(req),
		Verdict:    verdict,
		ReceiptRef: receiptRef,
		OccurredAt: occurredAt,
	}
	if reason != "" {
		action.ReasonCode = string(reason)
	}
	receipt := &ManagedAgentExecutionReceipt{
		ReceiptVersion: ReceiptVersionManagedAgentExecution,
		AgentID:        state.metadata["agent_id"],
		AgentVersion:   state.metadata["agent_version"],
		SessionID:      state.metadata["session_id"],
		EnvironmentID:  state.metadata["environment_id"],
		WorkID:         state.metadata["work_id"],
		Worker: ManagedAgentWorker{
			WorkerID:          state.metadata["worker_id"],
			WorkerImageDigest: state.metadata[metadataImageDigest],
			SkillManifestHash: state.metadata["skill_manifest_hash"],
		},
		SandboxGrantHash: state.metadata["sandbox_grant_hash"],
		MCPProfiles:      a.managedMCPProfiles(),
		ToolActions:      []ManagedAgentToolAction{action},
		DeniedEffects:    []ManagedAgentDeniedEffect{},
		ArtifactHashes:   artifactHashes,
		CreatedAt:        occurredAt,
		CompletedAt:      &occurredAt,
	}
	if verdict == contracts.VerdictDeny {
		receipt.DeniedEffects = append(receipt.DeniedEffects, ManagedAgentDeniedEffect{
			EffectID:   req.RequestID,
			EffectType: managedEffectType(req.Class),
			ReasonCode: string(reason),
			Reason:     reasonText,
			ReceiptRef: receiptRef,
			OccurredAt: occurredAt,
		})
	}
	receipt.ReceiptID = managedReceiptID(receipt)
	receipt.ReceiptHash = bareHashAny(receipt.withoutSignature())
	if a.receiptSigner == nil {
		a.receiptSigner = deterministicPreviewSigner{}
	}
	receipt.SignerKeyID = a.receiptSigner.SignerKeyID()
	signature, err := a.receiptSigner.Sign([]byte(receipt.ReceiptHash))
	if err != nil {
		return nil, fmt.Errorf("claude managed agents: sign managed-agent receipt: %w", err)
	}
	receipt.Signature = signature
	return receipt, nil
}

func (r ManagedAgentExecutionReceipt) withoutSignature() ManagedAgentExecutionReceipt {
	r.ReceiptHash = ""
	r.Signature = ""
	return r
}

func managedReceiptID(receipt *ManagedAgentExecutionReceipt) string {
	return hashAny(struct {
		Version   string                     `json:"version"`
		AgentID   string                     `json:"agent_id"`
		SessionID string                     `json:"session_id"`
		WorkID    string                     `json:"work_id"`
		Actions   []ManagedAgentToolAction   `json:"actions"`
		Denied    []ManagedAgentDeniedEffect `json:"denied"`
	}{
		Version:   receipt.ReceiptVersion,
		AgentID:   receipt.AgentID,
		SessionID: receipt.SessionID,
		WorkID:    receipt.WorkID,
		Actions:   receipt.ToolActions,
		Denied:    receipt.DeniedEffects,
	})
}

func (a *Adapter) managedMCPProfiles() []ManagedAgentMCPProfile {
	if !a.cfg.Tunnel.Enabled {
		return nil
	}
	profile := ManagedAgentMCPProfile{
		TunnelDomainHash:        a.cfg.Tunnel.TunnelDomainHash,
		UpstreamMCPServerID:     a.cfg.Tunnel.UpstreamMCPServerID,
		OAuthResource:           a.cfg.Tunnel.OAuthResource,
		RequiredScopes:          append([]string(nil), a.cfg.Tunnel.RequiredScopes...),
		ProtocolVersion:         a.cfg.Tunnel.ProtocolVersion,
		CACertRefHash:           a.cfg.Tunnel.CACertRefHash,
		AllowedUpstreamHostHash: a.cfg.Tunnel.AllowedUpstreamHostHash,
		Route:                   "helm-mcp-gateway",
	}
	profile.MCPProfileHash = hashAny(struct {
		TunnelDomainHash        string   `json:"tunnel_domain_hash"`
		UpstreamMCPServerID     string   `json:"upstream_mcp_server_id"`
		OAuthResource           string   `json:"oauth_resource"`
		RequiredScopes          []string `json:"required_scopes"`
		ProtocolVersion         string   `json:"protocol_version"`
		CACertRefHash           string   `json:"ca_cert_ref_hash"`
		AllowedUpstreamHostHash string   `json:"allowed_upstream_host_hash"`
		Route                   string   `json:"route"`
	}{
		TunnelDomainHash:        profile.TunnelDomainHash,
		UpstreamMCPServerID:     profile.UpstreamMCPServerID,
		OAuthResource:           profile.OAuthResource,
		RequiredScopes:          profile.RequiredScopes,
		ProtocolVersion:         profile.ProtocolVersion,
		CACertRefHash:           profile.CACertRefHash,
		AllowedUpstreamHostHash: profile.AllowedUpstreamHostHash,
		Route:                   profile.Route,
	})
	return []ManagedAgentMCPProfile{profile}
}

func managedToolID(req ToolRequest) string {
	if req.ToolName != "" {
		return req.ToolName
	}
	return string(req.Class)
}

func managedTarget(req ToolRequest) string {
	if req.Target != "" {
		return req.Target
	}
	if req.Path != "" {
		return req.Path
	}
	if len(req.Command) > 0 {
		return strings.Join(req.Command, " ")
	}
	return string(req.Class)
}

func managedEffectType(class ToolClass) string {
	switch class {
	case ToolBash:
		return "MANAGED_AGENT_BASH"
	case ToolCode:
		return "MANAGED_AGENT_CODE"
	case ToolFileRead:
		return "MANAGED_AGENT_FILE_READ"
	case ToolFileWrite:
		return "MANAGED_AGENT_FILE_WRITE"
	case ToolFileList:
		return "MANAGED_AGENT_FILE_LIST"
	case ToolValidation:
		return "MANAGED_AGENT_VALIDATION_RUN"
	case ToolOutputArtifact:
		return "MANAGED_AGENT_OUTPUT_ARTIFACT"
	case ToolMCP:
		return "MANAGED_AGENT_MCP_TOOL_CALL"
	case ToolMemoryWrite:
		return "MANAGED_AGENT_MEMORY_WRITE"
	default:
		return "MANAGED_AGENT_UNKNOWN"
	}
}

func hashManagedToolArgs(req ToolRequest) string {
	return hashAny(struct {
		RequestID string            `json:"request_id"`
		ToolName  string            `json:"tool_name,omitempty"`
		Class     ToolClass         `json:"class"`
		Command   []string          `json:"command,omitempty"`
		Path      string            `json:"path,omitempty"`
		Target    string            `json:"target,omitempty"`
		Metadata  map[string]string `json:"metadata,omitempty"`
		DataHash  string            `json:"data_hash,omitempty"`
	}{
		RequestID: req.RequestID,
		ToolName:  req.ToolName,
		Class:     req.Class,
		Command:   req.Command,
		Path:      req.Path,
		Target:    req.Target,
		Metadata:  req.Metadata,
		DataHash:  hashBytes(req.Data),
	})
}

func hashAny(value any) string {
	data, err := canonicalize.JCS(value)
	if err != nil {
		data, _ = json.Marshal(value)
	}
	return hashBytes(data)
}

func bareHashAny(value any) string {
	return strings.TrimPrefix(hashAny(value), "sha256:")
}
