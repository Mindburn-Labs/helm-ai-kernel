package crypto

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// CanonicalMarshal marshals v with HELM's local canonical JSON profile.
// Signature preimages must use the same canonicalizer as the artifact and
// receipt-chain layers; this is intentionally not labelled RFC 8785 or a
// cross-SDK contract until the canonicalize package passes the full official
// JCS vector suite.
func CanonicalMarshal(v interface{}) ([]byte, error) {
	encoded, err := canonicalize.JCS(v)
	if err != nil {
		return nil, fmt.Errorf("canonical encoding failed: %w", err)
	}
	return encoded, nil
}

// Signature components separators and prefixes
const (
	SigSeparator     = ":"
	SigPrefixEd25519 = "ed25519"
	SigPrefixMLDSA65 = "ml-dsa-65"

	// DecisionSignatureSchemaV2 binds the evaluated request and the security
	// relevant decision metadata in a canonical JSON payload. The empty schema
	// remains reserved for legacy v1 signatures so already-issued decisions can
	// still be verified without a silent downgrade.
	DecisionSignatureSchemaV2 = "helm.decision.signature.v2"

	// IntentSignatureSchemaV2 binds every field consumed at the execution
	// boundary, including its validity window. The empty schema is reserved for
	// historic v1 intent signatures, which remain audit-verifiable only.
	IntentSignatureSchemaV2 = "helm.execution.intent.signature.v2"

	// ReceiptSignatureSchemaV2 binds the evidence and emergency-authority
	// fields emitted at the execution boundary. The empty schema remains the
	// legacy audit preimage for receipts issued before this migration.
	ReceiptSignatureSchemaV2 = "helm.receipt.signature.v2"
)

// CanonicalizeDecision creates the legacy v1 string payload for decision
// signatures. New request-bound decisions use CanonicalizeDecisionV2; this
// helper remains only so historic signatures can be verified.
func CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s", id, SigSeparator, verdict, SigSeparator, reason, SigSeparator, phenotypeHash, SigSeparator, policyContentHash, SigSeparator, effectDigest)
}

// CanonicalizeDecisionStrict is the validating counterpart to the retained v1
// helper. New request-bound code paths must use the v2 decision schema instead.
func CanonicalizeDecisionStrict(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("decision ID is required for canonicalization")
	}
	if verdict == "" {
		return "", fmt.Errorf("verdict is required for canonicalization")
	}
	return CanonicalizeDecision(id, verdict, reason, phenotypeHash, policyContentHash, effectDigest), nil
}

// decisionSignatureV2 is deliberately an explicit, map-free signing envelope.
// InputContext is excluded: it is caller-supplied explanatory data, while the
// governed effect is bound by EffectDigest. Adding another security-relevant
// field requires a new schema version rather than changing this preimage.
type decisionSignatureV2 struct {
	SignatureSchema        string                          `json:"signature_schema"`
	ID                     string                          `json:"id"`
	ProposalID             string                          `json:"proposal_id"`
	StepID                 string                          `json:"step_id"`
	PhenotypeHash          string                          `json:"phenotype_hash"`
	PolicyVersion          string                          `json:"policy_version"`
	SubjectID              string                          `json:"subject_id"`
	Action                 string                          `json:"action"`
	Resource               string                          `json:"resource"`
	TenantID               string                          `json:"tenant_id"`
	WorkspaceID            string                          `json:"workspace_id"`
	SessionID              string                          `json:"session_id"`
	EffectDigest           string                          `json:"effect_digest"`
	PolicyBackend          string                          `json:"policy_backend"`
	PolicyContentHash      string                          `json:"policy_content_hash"`
	PolicyEpoch            string                          `json:"policy_epoch"`
	PolicyDecisionHash     string                          `json:"policy_decision_hash"`
	StateCursor            string                          `json:"state_cursor"`
	Snapshot               string                          `json:"snapshot"`
	EnvFingerprint         string                          `json:"env_fingerprint"`
	Verdict                string                          `json:"verdict"`
	Reason                 string                          `json:"reason"`
	ReasonCode             string                          `json:"reason_code"`
	TrajectoryRiskScore    float64                         `json:"trajectory_risk_score"`
	SessionCentroidHash    string                          `json:"session_centroid_hash"`
	RiskAccumulationWindow int                             `json:"risk_accumulation_window"`
	RequirementSetHash     string                          `json:"requirement_set_hash"`
	SignatureType          string                          `json:"signature_type"`
	Timestamp              time.Time                       `json:"timestamp"`
	Intervention           *contracts.InterventionMetadata `json:"intervention"`
}

func hasRequestBinding(d *contracts.DecisionRecord) bool {
	return d != nil && d.SubjectID != "" && d.Action != "" && d.Resource != ""
}

// RequireExecutableDecisionSignature rejects legacy signatures at the effect
// boundary. V1 remains verifiable for audit and migration, but it did not bind
// the evaluated request tuple and therefore must never authorize an intent or
// a dispatch. V2 verification still runs separately with the configured key.
func RequireExecutableDecisionSignature(d *contracts.DecisionRecord) error {
	if d == nil {
		return fmt.Errorf("decision is required for executable signature validation")
	}
	if d.SignatureSchema == "" {
		return fmt.Errorf("legacy v1 decision signature is audit-only and cannot authorize execution")
	}
	if d.SignatureSchema != DecisionSignatureSchemaV2 {
		return fmt.Errorf("unsupported decision signature schema %q cannot authorize execution", d.SignatureSchema)
	}
	if !hasRequestBinding(d) {
		return fmt.Errorf("decision signature schema %q requires subject_id, action, and resource for execution", DecisionSignatureSchemaV2)
	}
	return nil
}

// PrepareDecisionForSigning assigns a signer-owned signature type and opts a
// complete request-bound decision into the v2 schema. Incomplete decisions
// remain legacy v1 so callers cannot accidentally claim request binding.
func PrepareDecisionForSigning(d *contracts.DecisionRecord, signatureType string) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is required for signing")
	}
	if signatureType == "" {
		return nil, fmt.Errorf("decision signature type is required")
	}
	if d.SignatureSchema == "" && hasRequestBinding(d) {
		d.SignatureSchema = DecisionSignatureSchemaV2
	}
	if d.SignatureSchema == DecisionSignatureSchemaV2 && !hasRequestBinding(d) {
		return nil, fmt.Errorf("decision signature schema %q requires subject_id, action, and resource", DecisionSignatureSchemaV2)
	}
	d.SignatureType = signatureType
	return CanonicalDecisionPayload(d)
}

// CanonicalDecisionPayload returns the exact preimage indicated by the
// persisted decision schema. An empty schema is the legacy v1 format; unknown
// schemas fail closed instead of being treated as legacy.
func CanonicalDecisionPayload(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is required for canonicalization")
	}

	switch d.SignatureSchema {
	case "":
		return []byte(CanonicalizeDecision(d.ID, d.Verdict, d.Reason, d.PhenotypeHash, d.PolicyContentHash, d.EffectDigest)), nil
	case DecisionSignatureSchemaV2:
		return CanonicalizeDecisionV2(d)
	default:
		return nil, fmt.Errorf("unsupported decision signature schema %q", d.SignatureSchema)
	}
}

// CanonicalizeDecisionV2 returns the versioned, unambiguous signing payload
// for a request-bound decision. It includes the request identity/effect tuple,
// policy/effect bindings, and the signer-selected signature type.
func CanonicalizeDecisionV2(d *contracts.DecisionRecord) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("decision is required for canonicalization")
	}
	if d.SignatureSchema != DecisionSignatureSchemaV2 {
		return nil, fmt.Errorf("decision signature schema must be %q, got %q", DecisionSignatureSchemaV2, d.SignatureSchema)
	}
	if d.ID == "" {
		return nil, fmt.Errorf("decision ID is required for canonicalization")
	}
	if !hasRequestBinding(d) {
		return nil, fmt.Errorf("decision signature schema %q requires subject_id, action, and resource", DecisionSignatureSchemaV2)
	}
	if d.SignatureType == "" {
		return nil, fmt.Errorf("decision signature type is required for canonicalization")
	}

	return CanonicalMarshal(decisionSignatureV2{
		SignatureSchema:        d.SignatureSchema,
		ID:                     d.ID,
		ProposalID:             d.ProposalID,
		StepID:                 d.StepID,
		PhenotypeHash:          d.PhenotypeHash,
		PolicyVersion:          d.PolicyVersion,
		SubjectID:              d.SubjectID,
		Action:                 d.Action,
		Resource:               d.Resource,
		TenantID:               d.TenantID,
		WorkspaceID:            d.WorkspaceID,
		SessionID:              d.SessionID,
		EffectDigest:           d.EffectDigest,
		PolicyBackend:          d.PolicyBackend,
		PolicyContentHash:      d.PolicyContentHash,
		PolicyEpoch:            d.PolicyEpoch,
		PolicyDecisionHash:     d.PolicyDecisionHash,
		StateCursor:            d.StateCursor,
		Snapshot:               d.Snapshot,
		EnvFingerprint:         d.EnvFingerprint,
		Verdict:                d.Verdict,
		Reason:                 d.Reason,
		ReasonCode:             d.ReasonCode,
		TrajectoryRiskScore:    d.TrajectoryRiskScore,
		SessionCentroidHash:    d.SessionCentroidHash,
		RiskAccumulationWindow: d.RiskAccumulationWindow,
		RequirementSetHash:     d.RequirementSetHash,
		SignatureType:          d.SignatureType,
		// Protobuf and generated REST clients represent instants independently
		// of a Go location offset. Sign the UTC instant so a lossless transport
		// round-trip cannot alter the v2 preimage merely by normalizing timezones.
		Timestamp:    d.Timestamp.UTC(),
		Intervention: d.Intervention,
	})
}

// intentSignatureV2 is deliberately explicit and map-free. It binds all
// fields the executor uses to decide whether an effect may proceed; the
// signature itself is intentionally excluded from its own preimage.
type intentSignatureV2 struct {
	SignatureSchema              string    `json:"signature_schema"`
	ID                           string    `json:"id"`
	DecisionID                   string    `json:"decision_id"`
	EffectDigestHash             string    `json:"effect_digest_hash"`
	IdempotencyKey               string    `json:"idempotency_key"`
	IssuedAt                     time.Time `json:"issued_at"`
	ExpiresAt                    time.Time `json:"expires_at"`
	Signer                       string    `json:"signer"`
	SignatureType                string    `json:"signature_type"`
	AllowedTool                  string    `json:"allowed_tool"`
	Taint                        []string  `json:"taint"`
	EmergencyActivationID        string    `json:"emergency_activation_id"`
	EmergencyDelegationSessionID string    `json:"emergency_delegation_session_id"`
	EmergencyScopeHash           string    `json:"emergency_scope_hash"`
}

// CanonicalizeIntent creates a canonical string representation of an intent for signing.
// This is the retained legacy v1 preimage. New executable intents use
// CanonicalIntentPayload with IntentSignatureSchemaV2; the variadic form
// remains for audit verification of historic signatures.
func CanonicalizeIntent(id, decisionID, allowedTool string, effectDigestHash ...string) string {
	if len(effectDigestHash) == 0 {
		return fmt.Sprintf("%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool)
	}
	return fmt.Sprintf("%s%s%s%s%s%s%s", id, SigSeparator, decisionID, SigSeparator, allowedTool, SigSeparator, effectDigestHash[0])
}

// RequireExecutableIntentSignature rejects legacy intent signatures at the
// effect boundary. V1 remains available only for audit and migration because
// it did not bind expiry or the complete authorization tuple.
func RequireExecutableIntentSignature(i *contracts.AuthorizedExecutionIntent) error {
	if i == nil {
		return fmt.Errorf("execution intent is required for executable signature validation")
	}
	if i.SignatureSchema == "" {
		return fmt.Errorf("legacy v1 execution intent signature is audit-only and cannot authorize execution")
	}
	if i.SignatureSchema != IntentSignatureSchemaV2 {
		return fmt.Errorf("unsupported execution intent signature schema %q cannot authorize execution", i.SignatureSchema)
	}
	if i.ID == "" || i.DecisionID == "" || i.EffectDigestHash == "" || i.AllowedTool == "" {
		return fmt.Errorf("execution intent signature schema %q requires id, decision_id, effect_digest_hash, and allowed_tool", IntentSignatureSchemaV2)
	}
	if i.IssuedAt.IsZero() || i.ExpiresAt.IsZero() || !i.ExpiresAt.After(i.IssuedAt) {
		return fmt.Errorf("execution intent signature schema %q requires a non-empty validity window with expires_at after issued_at", IntentSignatureSchemaV2)
	}
	if i.SignatureType == "" {
		return fmt.Errorf("execution intent signature schema %q requires signature_type", IntentSignatureSchemaV2)
	}
	return nil
}

// PrepareIntentForSigning assigns the signer-owned signature type and opts an
// intent into the versioned v2 preimage. Unlike v1, v2 binds expiry and all
// authorization-relevant intent metadata before any signature is created.
func PrepareIntentForSigning(i *contracts.AuthorizedExecutionIntent, signatureType string) ([]byte, error) {
	if i == nil {
		return nil, fmt.Errorf("execution intent is required for signing")
	}
	if signatureType == "" {
		return nil, fmt.Errorf("execution intent signature type is required")
	}
	if i.SignatureSchema == "" {
		i.SignatureSchema = IntentSignatureSchemaV2
	}
	if i.SignatureSchema != IntentSignatureSchemaV2 {
		return nil, fmt.Errorf("unsupported execution intent signature schema %q", i.SignatureSchema)
	}
	i.SignatureType = signatureType
	i.Taint = contracts.NormalizeTaintLabels(i.Taint)
	if err := RequireExecutableIntentSignature(i); err != nil {
		return nil, fmt.Errorf("invalid execution intent for signing: %w", err)
	}
	return CanonicalIntentPayload(i)
}

// CanonicalIntentPayload returns the exact preimage indicated by the persisted
// intent schema. The empty schema is the legacy v1 format; unknown schemas
// fail closed instead of silently degrading to v1.
func CanonicalIntentPayload(i *contracts.AuthorizedExecutionIntent) ([]byte, error) {
	if i == nil {
		return nil, fmt.Errorf("execution intent is required for canonicalization")
	}
	switch i.SignatureSchema {
	case "":
		return []byte(CanonicalizeIntent(i.ID, i.DecisionID, i.AllowedTool, i.EffectDigestHash)), nil
	case IntentSignatureSchemaV2:
		if i.SignatureType == "" {
			return nil, fmt.Errorf("execution intent signature type is required for canonicalization")
		}
		return CanonicalMarshal(intentSignatureV2{
			SignatureSchema:              i.SignatureSchema,
			ID:                           i.ID,
			DecisionID:                   i.DecisionID,
			EffectDigestHash:             i.EffectDigestHash,
			IdempotencyKey:               i.IdempotencyKey,
			IssuedAt:                     i.IssuedAt.UTC(),
			ExpiresAt:                    i.ExpiresAt.UTC(),
			Signer:                       i.Signer,
			SignatureType:                i.SignatureType,
			AllowedTool:                  i.AllowedTool,
			Taint:                        i.Taint,
			EmergencyActivationID:        i.EmergencyActivationID,
			EmergencyDelegationSessionID: i.EmergencyDelegationSessionID,
			EmergencyScopeHash:           i.EmergencyScopeHash,
		})
	default:
		return nil, fmt.Errorf("unsupported execution intent signature schema %q", i.SignatureSchema)
	}
}

// receiptSignatureV2 is explicit rather than a serialization of Receipt so
// the signed evidence contract is reviewable. Every field that can describe
// the governed effect, causal chain, SafeDep authority, or signer identity is
// bound before the signature is produced. Transparency assignment is excluded:
// the log assigns its leaf index only after it receives the signed receipt
// hash, so including those returned fields would create a circular preimage.
// Anchor metadata is instead verified against the stable ReceiptChainHash.
type receiptSignatureV2 struct {
	SignatureSchema              string                        `json:"signature_schema"`
	Type                         string                        `json:"type"`
	ReceiptID                    string                        `json:"receipt_id"`
	DecisionID                   string                        `json:"decision_id"`
	EffectID                     string                        `json:"effect_id"`
	ExternalReferenceID          string                        `json:"external_reference_id"`
	Status                       string                        `json:"status"`
	BlobHash                     string                        `json:"blob_hash"`
	OutputHash                   string                        `json:"output_hash"`
	Timestamp                    time.Time                     `json:"timestamp"`
	ExecutorID                   string                        `json:"executor_id"`
	Metadata                     map[string]any                `json:"metadata"`
	PrevHash                     string                        `json:"prev_hash"`
	LamportClock                 uint64                        `json:"lamport_clock"`
	ArgsHash                     string                        `json:"args_hash"`
	EffectType                   string                        `json:"effect_type"`
	ToolFingerprint              string                        `json:"tool_fingerprint"`
	IdempotencyKey               string                        `json:"idempotency_key"`
	ToolName                     string                        `json:"tool_name"`
	ReasonCode                   string                        `json:"reason_code"`
	PolicyHash                   string                        `json:"policy_hash"`
	SessionID                    string                        `json:"session_id"`
	ScopeHash                    string                        `json:"scope_hash"`
	IssuedAt                     time.Time                     `json:"issued_at"`
	EmergencyActivationID        string                        `json:"emergency_activation_id"`
	EmergencyDelegationSessionID string                        `json:"emergency_delegation_session_id"`
	EmergencyScopeHash           string                        `json:"emergency_scope_hash"`
	SafeDepState                 string                        `json:"safe_dep_state"`
	SafeDepReasonCode            string                        `json:"safe_dep_reason_code"`
	NetworkLogRef                string                        `json:"network_log_ref"`
	SecretEventsRef              string                        `json:"secret_events_ref"`
	PortExposures                []contracts.PortExposureEvent `json:"port_exposures"`
	SandboxLeaseID               string                        `json:"sandbox_lease_id"`
	EffectGraphNodeID            string                        `json:"effect_graph_node_id"`
	ReplayScript                 *contracts.ReplayScriptRef    `json:"replay_script"`
	Provenance                   *contracts.ReceiptProvenance  `json:"provenance"`
	BundledArtifacts             []contracts.ParsedArtifact    `json:"bundled_artifacts"`
	GatewayID                    string                        `json:"gateway_id"`
	RuntimeType                  string                        `json:"runtime_type"`
	RuntimeVersion               string                        `json:"runtime_version"`
	ModelHash                    string                        `json:"model_hash"`
	LaunchID                     string                        `json:"launch_id"`
	DecisionHash                 string                        `json:"decision_hash"`
	Verdict                      string                        `json:"verdict"`
	Subject                      any                           `json:"subject"`
	CreatedAt                    time.Time                     `json:"created_at"`
	PackID                       string                        `json:"pack_id"`
	PackName                     string                        `json:"pack_name"`
	PackVersion                  string                        `json:"pack_version"`
	PackHash                     string                        `json:"pack_hash"`
	Action                       string                        `json:"action"`
	InstalledBy                  string                        `json:"installed_by"`
	InstalledAt                  time.Time                     `json:"installed_at"`
	PrevReceiptID                string                        `json:"prev_receipt_id"`
	ContentHash                  string                        `json:"content_hash"`
	ID                           string                        `json:"id"`
	RiskTier                     contracts.RiskTier            `json:"risk_tier"`
	Evidence                     map[string]string             `json:"evidence"`
	RetryCount                   int                           `json:"retry_count"`
	SkillID                      string                        `json:"skill_id"`
	SkillContentHash             string                        `json:"skill_content_hash"`
	ProjectionPaths              []contracts.Projection        `json:"projection_paths"`
	Direction                    string                        `json:"direction"`
	Counterparty                 string                        `json:"counterparty"`
	SignatureProfile             string                        `json:"signature_profile"`
	SignatureAlgorithm           string                        `json:"signature_algorithm"`
	KeyID                        string                        `json:"key_id"`
	PublicKeySet                 map[string]string             `json:"public_key_set"`
}

// PrepareReceiptForSigning sets signer-owned metadata and returns the v2
// canonical receipt preimage. It prevents newly-issued receipts from silently
// using the historical preimage that omitted SafeDep/evidence authority.
func PrepareReceiptForSigning(r *contracts.Receipt, profile, algorithm, keyID string, publicKeySet map[string]string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is required for signing")
	}
	if profile == "" || algorithm == "" || keyID == "" || len(publicKeySet) == 0 {
		return nil, fmt.Errorf("receipt signing metadata is required")
	}
	if r.SignatureSchema == "" {
		r.SignatureSchema = ReceiptSignatureSchemaV2
	}
	if r.SignatureSchema != ReceiptSignatureSchemaV2 {
		return nil, fmt.Errorf("unsupported receipt signature schema %q", r.SignatureSchema)
	}
	r.SignatureProfile = profile
	r.SignatureAlgorithm = algorithm
	r.KeyID = keyID
	r.PublicKeySet = publicKeySet
	return CanonicalReceiptPayload(r)
}

// CanonicalReceiptPayload returns the exact preimage indicated by the receipt
// schema. Historic receipts remain verifiable for audit; unknown schemas fail
// closed rather than being treated as legacy.
func CanonicalReceiptPayload(r *contracts.Receipt) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("receipt is required for canonicalization")
	}
	switch r.SignatureSchema {
	case "":
		return []byte(CanonicalizeReceipt(r.ReceiptID, r.DecisionID, r.EffectID, r.Status, r.OutputHash, r.PrevHash, r.LamportClock, r.ArgsHash)), nil
	case ReceiptSignatureSchemaV2:
		if r.SignatureProfile == "" || r.SignatureAlgorithm == "" || r.KeyID == "" || len(r.PublicKeySet) == 0 {
			return nil, fmt.Errorf("receipt signature schema %q requires signer metadata", ReceiptSignatureSchemaV2)
		}
		return CanonicalMarshal(receiptSignatureV2{
			SignatureSchema:              r.SignatureSchema,
			Type:                         r.Type,
			ReceiptID:                    r.ReceiptID,
			DecisionID:                   r.DecisionID,
			EffectID:                     r.EffectID,
			ExternalReferenceID:          r.ExternalReferenceID,
			Status:                       r.Status,
			BlobHash:                     r.BlobHash,
			OutputHash:                   r.OutputHash,
			Timestamp:                    r.Timestamp.UTC(),
			ExecutorID:                   r.ExecutorID,
			Metadata:                     r.Metadata,
			PrevHash:                     r.PrevHash,
			LamportClock:                 r.LamportClock,
			ArgsHash:                     r.ArgsHash,
			EffectType:                   r.EffectType,
			ToolFingerprint:              r.ToolFingerprint,
			IdempotencyKey:               r.IdempotencyKey,
			ToolName:                     r.ToolName,
			ReasonCode:                   r.ReasonCode,
			PolicyHash:                   r.PolicyHash,
			SessionID:                    r.SessionID,
			ScopeHash:                    r.ScopeHash,
			IssuedAt:                     r.IssuedAt.UTC(),
			EmergencyActivationID:        r.EmergencyActivationID,
			EmergencyDelegationSessionID: r.EmergencyDelegationSessionID,
			EmergencyScopeHash:           r.EmergencyScopeHash,
			SafeDepState:                 r.SafeDepState,
			SafeDepReasonCode:            r.SafeDepReasonCode,
			NetworkLogRef:                r.NetworkLogRef,
			SecretEventsRef:              r.SecretEventsRef,
			PortExposures:                r.PortExposures,
			SandboxLeaseID:               r.SandboxLeaseID,
			EffectGraphNodeID:            r.EffectGraphNodeID,
			ReplayScript:                 r.ReplayScript,
			Provenance:                   r.Provenance,
			BundledArtifacts:             r.BundledArtifacts,
			GatewayID:                    r.GatewayID,
			RuntimeType:                  r.RuntimeType,
			RuntimeVersion:               r.RuntimeVersion,
			ModelHash:                    r.ModelHash,
			LaunchID:                     r.LaunchID,
			DecisionHash:                 r.DecisionHash,
			Verdict:                      r.Verdict,
			Subject:                      r.Subject,
			CreatedAt:                    r.CreatedAt.UTC(),
			PackID:                       r.PackID,
			PackName:                     r.PackName,
			PackVersion:                  r.PackVersion,
			PackHash:                     r.PackHash,
			Action:                       r.Action,
			InstalledBy:                  r.InstalledBy,
			InstalledAt:                  r.InstalledAt.UTC(),
			PrevReceiptID:                r.PrevReceiptID,
			ContentHash:                  r.ContentHash,
			ID:                           r.ID,
			RiskTier:                     r.RiskTier,
			Evidence:                     r.Evidence,
			RetryCount:                   r.RetryCount,
			SkillID:                      r.SkillID,
			SkillContentHash:             r.SkillContentHash,
			ProjectionPaths:              r.ProjectionPaths,
			Direction:                    r.Direction,
			Counterparty:                 r.Counterparty,
			SignatureProfile:             r.SignatureProfile,
			SignatureAlgorithm:           r.SignatureAlgorithm,
			KeyID:                        r.KeyID,
			PublicKeySet:                 r.PublicKeySet,
		})
	default:
		return nil, fmt.Errorf("unsupported receipt signature schema %q", r.SignatureSchema)
	}
}

// CanonicalizeReceipt creates a canonical string representation of a receipt for signing.
// V4: includes ArgsHash for PEP boundary binding.
func CanonicalizeReceipt(receiptID, decisionID, effectID, status, outputHash, prevHash string, lamportClock uint64, argsHash string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%d%s%s", receiptID, SigSeparator, decisionID, SigSeparator, effectID, SigSeparator, status, SigSeparator, outputHash, SigSeparator, prevHash, SigSeparator, lamportClock, SigSeparator, argsHash)
}
