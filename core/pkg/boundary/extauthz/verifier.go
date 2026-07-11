// quantum_posture: ext-authz verifies classical Ed25519 receipt material;
// scoped-stop enforcement changes authorization, not cryptographic posture.
package extauthz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

var (
	ErrVerificationFailed = errors.New("extauthz verification failed")
	ErrDispatchDenied     = errors.New("extauthz dispatch denied")
)

// EvaluateGatewayResponse verifies a Kernel response but never authorizes an
// ALLOW dispatch. Gateways must use EvaluateAndConsumeGatewayResponse with a
// durable permit consumer for side-effectful actions.
func EvaluateGatewayResponse(req AuthorizationRequest, resp AuthorizationResponse, store TrustStore, opts VerifyOptions, now time.Time) (Evaluation, error) {
	if err := VerifyResponse(req, resp, store, opts, now); err != nil {
		return Evaluation{Verdict: VerdictDeny, ReasonCode: err.Error()}, err
	}
	if resp.Verdict == VerdictAllow {
		return Evaluation{
			Verdict:            VerdictDeny,
			ReasonCode:         ReasonPermitConsumerRequired,
			DispatchAuthorized: false,
			KernelVerdictRef:   resp.KernelVerdictRef,
			EffectPermitRef:    resp.EffectPermitRef,
		}, fmt.Errorf("%w: %s", ErrDispatchDenied, ReasonPermitConsumerRequired)
	}
	return noDispatchEvaluation(resp), nil
}

// EvaluateAndConsumeGatewayResponse verifies the signed Kernel response and
// consumes the single-use EffectPermit in one boundary call.
func EvaluateAndConsumeGatewayResponse(req AuthorizationRequest, resp AuthorizationResponse, store TrustStore, opts VerifyOptions, now time.Time) (Evaluation, *DispatchRecord, error) {
	if err := VerifyResponse(req, resp, store, opts, now); err != nil {
		return Evaluation{Verdict: VerdictDeny, ReasonCode: err.Error()}, nil, err
	}
	if resp.Verdict != VerdictAllow {
		eval := noDispatchEvaluation(resp)
		return eval, nil, fmt.Errorf("%w: %s", ErrDispatchDenied, eval.ReasonCode)
	}
	if opts.PermitConsumer == nil {
		return Evaluation{Verdict: VerdictDeny, ReasonCode: ReasonPermitConsumerRequired}, nil, fmt.Errorf("%w: %s", ErrDispatchDenied, ReasonPermitConsumerRequired)
	}
	if !opts.PermitConsumer.DurableCompareAndSwap() {
		return Evaluation{Verdict: VerdictDeny, ReasonCode: ReasonDurablePermitStoreRequired}, nil, fmt.Errorf("%w: %s", ErrDispatchDenied, ReasonDurablePermitStoreRequired)
	}
	record, err := opts.PermitConsumer.ConsumePermit(req, resp, now)
	if err != nil {
		return Evaluation{Verdict: VerdictDeny, ReasonCode: err.Error()}, nil, err
	}
	return Evaluation{
		Verdict:            VerdictAllow,
		ReasonCode:         ReasonAllowVerified,
		DispatchAuthorized: true,
		KernelVerdictRef:   resp.KernelVerdictRef,
		EffectPermitRef:    resp.EffectPermitRef,
	}, record, nil
}

func noDispatchEvaluation(resp AuthorizationResponse) Evaluation {
	reason := ReasonDenyNoDispatch
	if resp.Verdict == VerdictEscalate {
		reason = ReasonEscalateNoDispatch
	}
	return Evaluation{
		Verdict:            resp.Verdict,
		ReasonCode:         reason,
		DispatchAuthorized: false,
		KernelVerdictRef:   resp.KernelVerdictRef,
	}
}

func VerifyResponse(req AuthorizationRequest, resp AuthorizationResponse, store TrustStore, opts VerifyOptions, now time.Time) error {
	if err := ValidateRequest(req); err != nil {
		return err
	}
	if err := verifyResponseShape(resp); err != nil {
		return err
	}
	if err := verifyRequestEcho(req, resp); err != nil {
		return err
	}
	if resp.Verdict == VerdictAllow && opts.ExpectedPolicyEpoch == "" {
		return fmt.Errorf("%w: allow requires expected policy epoch", ErrVerificationFailed)
	}
	if opts.ExpectedPolicyEpoch != "" && resp.PolicyEpoch != opts.ExpectedPolicyEpoch {
		return fmt.Errorf("%w: stale policy epoch", ErrVerificationFailed)
	}
	if err := verifyTemporal(resp, opts, now); err != nil {
		return err
	}
	if err := verifyVerdictShape(resp); err != nil {
		return err
	}
	if err := verifySignature(resp, store, opts); err != nil {
		return err
	}
	return nil
}

// ValidateRequest checks the source-owned v1 request shape before a producer
// evaluates it. Consumers also call it as part of response verification.
func ValidateRequest(req AuthorizationRequest) error {
	return verifyRequestShape(req)
}

func verifyRequestShape(req AuthorizationRequest) error {
	if req.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("%w: unsupported request schema_version", ErrVerificationFailed)
	}
	if req.ContractVersion != ContractVersionV1 {
		return fmt.Errorf("%w: unsupported request contract_version", ErrVerificationFailed)
	}
	required := map[string]string{
		"request_id":                 req.RequestID,
		"tenant_id":                  req.TenantID,
		"workspace_id":               req.WorkspaceID,
		"principal_id":               req.PrincipalID,
		"agent_identity_profile_ref": req.AgentIdentityProfileRef,
		"protocol":                   req.Protocol,
		"action_urn":                 req.ActionURN,
		"tool_urn":                   req.ToolURN,
		"connector_id":               req.ConnectorID,
		"connector_contract_hash":    req.ConnectorContractHash,
		"executor_kind":              req.ExecutorKind,
		"effect_class":               req.EffectClass,
		"risk_class":                 req.RiskClass,
		"args_c14n_hash":             req.ArgsC14NHash,
		"request_body_hash":          req.RequestBodyHash,
		"plan_hash":                  req.PlanHash,
		"policy_hash":                req.PolicyHash,
		"p0_hash":                    req.P0Hash,
		"policy_epoch":               req.PolicyEpoch,
		"idempotency_key_candidate":  req.IdempotencyKeyCandidate,
		"payload_class":              req.PayloadClass,
		"redaction_profile":          req.RedactionProfile,
		"upstream_trace_id":          req.UpstreamTraceID,
		"upstream_run_id":            req.UpstreamRunID,
		"risk_context_hash":          req.RiskContextHash,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("%w: missing request %s", ErrVerificationFailed, field)
		}
	}
	if err := verifyHashURNFields("request", map[string]string{
		"connector_contract_hash": req.ConnectorContractHash,
		"args_c14n_hash":          req.ArgsC14NHash,
		"request_body_hash":       req.RequestBodyHash,
		"plan_hash":               req.PlanHash,
		"policy_hash":             req.PolicyHash,
		"p0_hash":                 req.P0Hash,
		"risk_context_hash":       req.RiskContextHash,
	}); err != nil {
		return err
	}
	switch req.Protocol {
	case "mcp", "a2a", "http", "grpc", "openai":
	default:
		return fmt.Errorf("%w: unsupported protocol", ErrVerificationFailed)
	}
	if req.DeadlineMS == 0 {
		return fmt.Errorf("%w: missing request deadline_ms", ErrVerificationFailed)
	}
	return nil
}

func verifyResponseShape(resp AuthorizationResponse) error {
	if resp.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("%w: unsupported response schema_version", ErrVerificationFailed)
	}
	if resp.ContractVersion != ContractVersionV1 {
		return fmt.Errorf("%w: unsupported response contract_version", ErrVerificationFailed)
	}
	required := map[string]string{
		"request_id":                 resp.RequestID,
		"tenant_id":                  resp.TenantID,
		"workspace_id":               resp.WorkspaceID,
		"principal_id":               resp.PrincipalID,
		"agent_identity_profile_ref": resp.AgentIdentityProfileRef,
		"protocol":                   resp.Protocol,
		"action_urn":                 resp.ActionURN,
		"tool_urn":                   resp.ToolURN,
		"connector_id":               resp.ConnectorID,
		"connector_contract_hash":    resp.ConnectorContractHash,
		"executor_kind":              resp.ExecutorKind,
		"effect_class":               resp.EffectClass,
		"risk_class":                 resp.RiskClass,
		"args_c14n_hash":             resp.ArgsC14NHash,
		"request_body_hash":          resp.RequestBodyHash,
		"plan_hash":                  resp.PlanHash,
		"policy_hash":                resp.PolicyHash,
		"p0_hash":                    resp.P0Hash,
		"policy_epoch":               resp.PolicyEpoch,
		"idempotency_key_candidate":  resp.IdempotencyKeyCandidate,
		"payload_class":              resp.PayloadClass,
		"redaction_profile":          resp.RedactionProfile,
		"upstream_trace_id":          resp.UpstreamTraceID,
		"upstream_run_id":            resp.UpstreamRunID,
		"risk_context_hash":          resp.RiskContextHash,
		"verdict":                    resp.Verdict,
		"reason_code":                resp.ReasonCode,
		"kernel_trust_root_id":       resp.KernelTrustRootID,
		"signing_key_ref":            resp.SigningKeyRef,
		"kernel_verdict_ref":         resp.KernelVerdictRef,
		"kernel_verdict_hash":        resp.KernelVerdictHash,
		"kernel_verdict_signature":   resp.KernelVerdictSignature,
		"kernel_verdict_issued_at":   resp.KernelVerdictIssuedAt,
		"kernel_verdict_expires_at":  resp.KernelVerdictExpiresAt,
		"cache_policy":               resp.CachePolicy,
		"replay_hint":                resp.ReplayHint,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("%w: missing response %s", ErrVerificationFailed, field)
		}
	}
	if err := verifyHashURNFields("response", map[string]string{
		"connector_contract_hash": resp.ConnectorContractHash,
		"args_c14n_hash":          resp.ArgsC14NHash,
		"request_body_hash":       resp.RequestBodyHash,
		"plan_hash":               resp.PlanHash,
		"policy_hash":             resp.PolicyHash,
		"p0_hash":                 resp.P0Hash,
		"risk_context_hash":       resp.RiskContextHash,
	}); err != nil {
		return err
	}
	if resp.DeadlineMS == 0 {
		return fmt.Errorf("%w: missing response deadline_ms", ErrVerificationFailed)
	}
	return nil
}

func verifySignature(resp AuthorizationResponse, store TrustStore, opts VerifyOptions) error {
	if resp.Verdict == VerdictAllow && opts.ExpectedKernelTrustRootID == "" {
		return fmt.Errorf("%w: allow requires expected kernel trust root", ErrVerificationFailed)
	}
	if opts.ExpectedKernelTrustRootID != "" && resp.KernelTrustRootID != opts.ExpectedKernelTrustRootID {
		return fmt.Errorf("%w: kernel trust root mismatch", ErrVerificationFailed)
	}
	key, ok := store.Keys[resp.SigningKeyRef]
	if !ok || !key.Enabled {
		return fmt.Errorf("%w: unknown or disabled signing key", ErrVerificationFailed)
	}
	if key.TrustRootID != resp.KernelTrustRootID {
		return fmt.Errorf("%w: signing key trust root mismatch", ErrVerificationFailed)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid signing key length", ErrVerificationFailed)
	}
	payload, err := CanonicalResponsePayload(resp)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	expectedHash := hex.EncodeToString(sum[:])
	if !constantStringEqual(expectedHash, resp.KernelVerdictHash) {
		return fmt.Errorf("%w: verdict hash mismatch", ErrVerificationFailed)
	}
	sig, err := hex.DecodeString(resp.KernelVerdictSignature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid verdict signature", ErrVerificationFailed)
	}
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), payload, sig) {
		return fmt.Errorf("%w: bad verdict signature", ErrVerificationFailed)
	}
	return nil
}

func verifyTemporal(resp AuthorizationResponse, opts VerifyOptions, now time.Time) error {
	issued, err := time.Parse(time.RFC3339Nano, resp.KernelVerdictIssuedAt)
	if err != nil || issued.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("%w: invalid verdict issued_at", ErrVerificationFailed)
	}
	expires, err := time.Parse(time.RFC3339Nano, resp.KernelVerdictExpiresAt)
	if err != nil || !expires.After(now) {
		return fmt.Errorf("%w: stale verdict", ErrVerificationFailed)
	}
	if !expires.After(issued) {
		return fmt.Errorf("%w: verdict expiry must be after issued_at", ErrVerificationFailed)
	}
	if opts.MaxVerdictTTL > 0 && expires.Sub(issued) > opts.MaxVerdictTTL {
		return fmt.Errorf("%w: verdict ttl exceeds maximum", ErrVerificationFailed)
	}
	if resp.Verdict == VerdictAllow {
		permitExpiry, err := time.Parse(time.RFC3339Nano, resp.PermitExpiry)
		if err != nil || !permitExpiry.After(now) {
			return fmt.Errorf("%w: stale permit", ErrVerificationFailed)
		}
		if permitExpiry.After(expires) {
			return fmt.Errorf("%w: permit expiry exceeds verdict expiry", ErrVerificationFailed)
		}
		if opts.MaxPermitTTL > 0 && permitExpiry.Sub(issued) > opts.MaxPermitTTL {
			return fmt.Errorf("%w: permit ttl exceeds maximum", ErrVerificationFailed)
		}
	}
	return nil
}

func verifyVerdictShape(resp AuthorizationResponse) error {
	switch resp.Verdict {
	case VerdictAllow:
		required := map[string]string{
			"effect_permit_ref":        resp.EffectPermitRef,
			"permit_nonce":             resp.PermitNonce,
			"permit_expiry":            resp.PermitExpiry,
			"proof_session_ref":        resp.ProofSessionRef,
			"evidence_reservation_ref": resp.EvidenceReservationRef,
			"proof_obligation":         resp.ProofObligation,
		}
		for field, value := range required {
			if value == "" {
				return fmt.Errorf("%w: allow missing %s", ErrVerificationFailed, field)
			}
		}
		if resp.CachePolicy != CachePolicyNoStore {
			return fmt.Errorf("%w: allow must be no_store", ErrVerificationFailed)
		}
		if resp.ReplayHint != ReplayHintSingleUse {
			return fmt.Errorf("%w: allow must be single-use", ErrVerificationFailed)
		}
	case VerdictDeny, VerdictEscalate:
		if resp.EffectPermitRef != "" || resp.PermitNonce != "" || resp.PermitExpiry != "" || resp.ProofSessionRef != "" || resp.EvidenceReservationRef != "" {
			return fmt.Errorf("%w: non-allow response carries permit material", ErrVerificationFailed)
		}
	default:
		return fmt.Errorf("%w: unknown verdict", ErrVerificationFailed)
	}
	return nil
}

func verifyRequestEcho(req AuthorizationRequest, resp AuthorizationResponse) error {
	matches := []struct {
		name string
		a    any
		b    any
	}{
		{"schema_version", req.SchemaVersion, resp.SchemaVersion},
		{"contract_version", req.ContractVersion, resp.ContractVersion},
		{"request_id", req.RequestID, resp.RequestID},
		{"tenant_id", req.TenantID, resp.TenantID},
		{"workspace_id", req.WorkspaceID, resp.WorkspaceID},
		{"principal_id", req.PrincipalID, resp.PrincipalID},
		{"principal_seq", req.PrincipalSeq, resp.PrincipalSeq},
		{"agent_identity_profile_ref", req.AgentIdentityProfileRef, resp.AgentIdentityProfileRef},
		{"protocol", req.Protocol, resp.Protocol},
		{"action_urn", req.ActionURN, resp.ActionURN},
		{"tool_urn", req.ToolURN, resp.ToolURN},
		{"connector_id", req.ConnectorID, resp.ConnectorID},
		{"connector_contract_hash", req.ConnectorContractHash, resp.ConnectorContractHash},
		{"executor_kind", req.ExecutorKind, resp.ExecutorKind},
		{"effect_class", req.EffectClass, resp.EffectClass},
		{"risk_class", req.RiskClass, resp.RiskClass},
		{"args_c14n_hash", req.ArgsC14NHash, resp.ArgsC14NHash},
		{"request_body_hash", req.RequestBodyHash, resp.RequestBodyHash},
		{"plan_hash", req.PlanHash, resp.PlanHash},
		{"policy_hash", req.PolicyHash, resp.PolicyHash},
		{"p0_hash", req.P0Hash, resp.P0Hash},
		{"policy_epoch", req.PolicyEpoch, resp.PolicyEpoch},
		{"idempotency_key_candidate", req.IdempotencyKeyCandidate, resp.IdempotencyKeyCandidate},
		{"payload_class", req.PayloadClass, resp.PayloadClass},
		{"redaction_profile", req.RedactionProfile, resp.RedactionProfile},
		{"upstream_trace_id", req.UpstreamTraceID, resp.UpstreamTraceID},
		{"upstream_run_id", req.UpstreamRunID, resp.UpstreamRunID},
		{"deadline_ms", req.DeadlineMS, resp.DeadlineMS},
		{"risk_context_hash", req.RiskContextHash, resp.RiskContextHash},
	}
	for _, match := range matches {
		if match.a != match.b {
			return fmt.Errorf("%w: request echo mismatch for %s", ErrVerificationFailed, match.name)
		}
	}
	return nil
}

func CanonicalResponsePayload(resp AuthorizationResponse) ([]byte, error) {
	copy := resp
	copy.KernelVerdictHash = ""
	copy.KernelVerdictSignature = ""
	return canonicalize.JCS(copy)
}

func SignResponse(resp AuthorizationResponse, privateKey ed25519.PrivateKey) (AuthorizationResponse, error) {
	payload, err := CanonicalResponsePayload(resp)
	if err != nil {
		return resp, err
	}
	sum := sha256.Sum256(payload)
	resp.KernelVerdictHash = hex.EncodeToString(sum[:])
	resp.KernelVerdictSignature = hex.EncodeToString(ed25519.Sign(privateKey, payload))
	return resp, nil
}

func constantStringEqual(a, b string) bool {
	return bytes.Equal([]byte(a), []byte(b))
}

func verifyHashURNFields(scope string, fields map[string]string) error {
	for field, value := range fields {
		if !isSHA256URN(value) {
			return fmt.Errorf("%w: invalid %s %s", ErrVerificationFailed, scope, field)
		}
	}
	return nil
}

func isSHA256URN(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest := value[len(prefix):]
	if len(digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}
