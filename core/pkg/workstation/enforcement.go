// quantum_posture: enforcement signs and verifies classical Ed25519 receipts;
// it is not a post-quantum or hybrid cryptographic control.
package workstation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type DecisionOptions struct {
	SigningSeed []byte
}

func LoadPolicyProfileFile(path string) (contracts.WorkstationPolicyProfile, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultObserveDraftProfile(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return contracts.WorkstationPolicyProfile{}, fmt.Errorf("read policy profile: %w", err)
	}
	var profile contracts.WorkstationPolicyProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return contracts.WorkstationPolicyProfile{}, fmt.Errorf("parse policy profile: %w", err)
	}
	if profile.ID == "" {
		return contracts.WorkstationPolicyProfile{}, errors.New("policy profile id is required")
	}
	return profile, nil
}

func Decide(
	profile contracts.WorkstationPolicyProfile,
	req contracts.WorkstationDecisionRequest,
	opts DecisionOptions,
) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	normalizeDecisionRequest(&req)
	event := ToolEvent{
		EventID:    req.RequestID,
		Type:       eventTypeForEffect(req.EffectType),
		ToolID:     req.ToolID,
		Action:     req.Action,
		EffectType: req.EffectType,
		EffectMode: req.EffectMode,
		Target:     req.Target,
		OccurredAt: req.OccurredAt,
		Metadata:   req.Metadata,
	}
	verdict, reasonCode, reason := EvaluateEvent(profile, event)
	receipt := &contracts.WorkstationPolicyDecisionReceipt{
		ReceiptVersion: contracts.AgentRunReceiptVersion,
		DecisionID: deterministicID(
			"wpd",
			req.RequestID,
			req.EffectType,
			req.Target,
			firstNonEmpty(profile.ID, contracts.PolicyProfileWorkstationObserveDraftV1),
		),
		Request:       req,
		PolicyProfile: firstNonEmpty(profile.ID, contracts.PolicyProfileWorkstationObserveDraftV1),
		Verdict:       verdict,
		ReasonCode:    reasonCode,
		Reason:        reason,
		ObservedOnly:  false,
		CreatedAt:     decisionTimestamp(req),
	}
	if err := signDecisionReceipt(receipt, opts.SigningSeed); err != nil {
		return nil, err
	}
	return receipt, nil
}

// VerifyDecisionReceiptSignature checks receipt integrity against the public key
// embedded in the receipt itself. It does not establish signer trust. Call
// VerifyDecisionReceiptWithTrustedKey when a caller-owned trust anchor is available.
func VerifyDecisionReceiptSignature(receipt *contracts.WorkstationPolicyDecisionReceipt) (bool, error) {
	if receipt == nil {
		return false, errors.New("decision receipt is nil")
	}
	keyHex := strings.TrimPrefix(receipt.SignerKeyID, "ed25519:")
	pub, err := hex.DecodeString(keyHex)
	if err != nil {
		return false, fmt.Errorf("decode signer key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("signer key must be %d bytes", ed25519.PublicKeySize)
	}
	sig, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	copyReceipt := *receipt
	copyReceipt.Signature = ""
	copyReceipt.ReceiptHash = ""
	canonical, err := canonicalize.JCS(&copyReceipt)
	if err != nil {
		return false, fmt.Errorf("canonicalize decision receipt: %w", err)
	}
	hash := sha256.Sum256(canonical)
	if hex.EncodeToString(hash[:]) != receipt.ReceiptHash {
		return false, nil
	}
	return ed25519.Verify(ed25519.PublicKey(pub), canonical, sig), nil
}

// VerifyDecisionReceiptWithTrustedKey verifies receipt integrity only when its
// declared signer matches the caller-owned trusted public key.
func VerifyDecisionReceiptWithTrustedKey(receipt *contracts.WorkstationPolicyDecisionReceipt, trusted ed25519.PublicKey) (bool, error) {
	if receipt == nil {
		return false, errors.New("decision receipt is nil")
	}
	if len(trusted) != ed25519.PublicKeySize {
		return false, fmt.Errorf("trusted signer key must be %d bytes", ed25519.PublicKeySize)
	}
	if receipt.SignerKeyID != ed25519SignerKeyID(trusted) {
		return false, nil
	}
	if receipt.SignerKeyID == retiredObserveOnlySignerKeyID {
		return false, nil
	}
	return VerifyDecisionReceiptSignature(receipt)
}

func LoadDecisionReceipt(path string) (*contracts.WorkstationPolicyDecisionReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var receipt contracts.WorkstationPolicyDecisionReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, err
	}
	if receipt.DecisionID == "" || receipt.ReceiptHash == "" {
		return nil, errors.New("not a workstation policy decision receipt")
	}
	return &receipt, nil
}

func EffectDefaults(effectClass string) (effectType, effectMode, action, toolID string) {
	switch strings.ToLower(strings.TrimSpace(effectClass)) {
	case "network", "egress", "network_egress":
		return contracts.EffectTypeWorkstationNetworkEgress, contracts.WorkstationEffectModeOperate, "network_egress", "network.egress"
	case "mcp", "mcp_tool", "mcp_tool_call":
		return contracts.EffectTypeWorkstationMCPToolCall, contracts.WorkstationEffectModeOperate, "mcp_tool_call", "mcp.tool"
	case "memory", "memory_write":
		return contracts.EffectTypeWorkstationMemoryWrite, contracts.WorkstationEffectModeOperate, "memory_write", "memory.write"
	case "loop", "recurring", "recurring_loop":
		return contracts.EffectTypeWorkstationRecurringLoop, contracts.WorkstationEffectModeOperate, "recurring_loop", "automation.register"
	case "deploy", "publish", "deploy_publish":
		return contracts.EffectTypeWorkstationDeployPublish, contracts.WorkstationEffectModeOperate, "deploy_publish", "deploy.publish"
	case "secret", "secret_read":
		return contracts.EffectTypeWorkstationSecretRead, contracts.WorkstationEffectModeOperate, "secret_read", "secret.read"
	case "payment", "payment_initiate":
		return contracts.EffectTypeWorkstationPaymentInitiate, contracts.WorkstationEffectModeOperate, "payment_initiate", "payment.initiate"
	case "shell-operate", "shell_operate":
		return contracts.EffectTypeWorkstationShellCommand, contracts.WorkstationEffectModeOperate, "shell_operate", "shell"
	case "file", "draft", "write":
		return contracts.EffectTypeWorkstationFileWrite, contracts.WorkstationEffectModeDraft, "file_write", "workspace.write"
	default:
		return contracts.EffectTypeWorkstationShellCommand, contracts.WorkstationEffectModeObserve, "shell_command", "shell"
	}
}

func normalizeDecisionRequest(req *contracts.WorkstationDecisionRequest) {
	if req.RequestID == "" {
		req.RequestID = deterministicID("wreq", req.RunID, req.EffectType, req.Target, req.ToolID, req.Action)
	}
	if req.ActorID == "" {
		req.ActorID = "agent.local"
	}
	if req.WorkspaceID == "" {
		req.WorkspaceID = defaultWorkspaceID
	}
	if req.AgentSurface == "" {
		req.AgentSurface = defaultSurface
	}
	if req.ToolID == "" {
		req.ToolID = "workstation"
	}
	if req.Action == "" {
		req.Action = "observed"
	}
	if req.EffectType == "" {
		req.EffectType = contracts.EffectTypeWorkstationShellCommand
	}
	if req.EffectMode == "" {
		req.EffectMode = effectModeForEffect(req.EffectType)
	}
	if req.OccurredAt.IsZero() {
		req.OccurredAt = time.Unix(0, 0).UTC()
	}
}

func effectModeForEffect(effectType string) string {
	switch effectType {
	case contracts.EffectTypeWorkstationFileDraft, contracts.EffectTypeWorkstationFileWrite:
		return contracts.WorkstationEffectModeDraft
	case contracts.EffectTypeWorkstationNetworkEgress,
		contracts.EffectTypeWorkstationMCPToolCall,
		contracts.EffectTypeWorkstationMemoryWrite,
		contracts.EffectTypeWorkstationRecurringLoop,
		contracts.EffectTypeWorkstationDeployPublish,
		contracts.EffectTypeWorkstationSecretRead,
		contracts.EffectTypeWorkstationPaymentInitiate:
		return contracts.WorkstationEffectModeOperate
	default:
		return contracts.WorkstationEffectModeObserve
	}
}

func eventTypeForEffect(effectType string) string {
	switch effectType {
	case contracts.EffectTypeWorkstationNetworkEgress:
		return "network_egress"
	case contracts.EffectTypeWorkstationMCPToolCall:
		return "mcp_tool_call"
	case contracts.EffectTypeWorkstationMemoryWrite:
		return "memory_write"
	case contracts.EffectTypeWorkstationRecurringLoop:
		return "recurring_loop"
	case contracts.EffectTypeWorkstationDeployPublish:
		return "deploy_publish"
	case contracts.EffectTypeWorkstationSecretRead:
		return "secret_read"
	case contracts.EffectTypeWorkstationPaymentInitiate:
		return "payment_initiate"
	case contracts.EffectTypeWorkstationFileDraft, contracts.EffectTypeWorkstationFileWrite:
		return "file_write"
	default:
		return "shell_command"
	}
}

func signDecisionReceipt(receipt *contracts.WorkstationPolicyDecisionReceipt, seed []byte) error {
	if len(seed) == 0 {
		return errors.New("signing seed is required")
	}
	if err := validateSigningSeed(seed); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	receipt.SignerKeyID = ed25519SignerKeyID(pub)
	receipt.Signature = ""
	receipt.ReceiptHash = ""
	canonical, err := canonicalize.JCS(receipt)
	if err != nil {
		return fmt.Errorf("canonicalize workstation decision receipt: %w", err)
	}
	hash := sha256.Sum256(canonical)
	receipt.ReceiptHash = hex.EncodeToString(hash[:])
	receipt.Signature = hex.EncodeToString(ed25519.Sign(priv, canonical))
	return nil
}

func decisionTimestamp(req contracts.WorkstationDecisionRequest) time.Time {
	if !req.OccurredAt.IsZero() {
		return req.OccurredAt.UTC()
	}
	return time.Unix(0, 0).UTC()
}
