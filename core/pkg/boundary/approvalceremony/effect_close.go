package approvalceremony

import (
	"context"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

var (
	ErrEffectCloseConflict = errors.New("effect close conflicts with durable reservation state")
	ErrEffectCloseTerminal = errors.New("effect reservation cannot be closed from its current state")
)

type EffectAcknowledgementVerifier interface {
	VerifyEnvelope(contracts.ConnectorEffectAcknowledgementEnvelope) error
	VerifyStoredEnvelope(contracts.ConnectorEffectAcknowledgementEnvelope) error
}

// EffectEvidencePackVerifier proves that the close request references a
// source-owned, sealed EvidencePack whose identity and hash match the signed
// connector acknowledgement. Implementations may load remote evidence, so the
// service calls this before acquiring the reservation transaction lock.
type EffectEvidencePackVerifier interface {
	VerifyEffectEvidencePack(
		context.Context,
		ConsumerIdentity,
		string,
		string,
		contracts.ConnectorEffectAcknowledgementEnvelope,
	) error
}

// EffectCloseRequest carries connector evidence and EvidencePack identity into
// the Kernel close boundary. Tenant/workspace/workload authority always comes
// from the verified transport identity and is checked against the signed ack.
type EffectCloseRequest struct {
	AdmissionID      string                                           `json:"admission_id"`
	Acknowledgement  contracts.ConnectorEffectAcknowledgementEnvelope `json:"acknowledgement"`
	EvidencePackRef  string                                           `json:"evidence_pack_ref"`
	EvidencePackHash string                                           `json:"evidence_pack_hash"`
}

// EffectClosureRecord is the immutable close proof persisted atomically with
// the reservation's COMPLETED event.
type EffectClosureRecord struct {
	Acknowledgement    contracts.ConnectorEffectAcknowledgementEnvelope `json:"acknowledgement"`
	Receipt            contracts.EffectCloseReceipt                     `json:"receipt"`
	SignatureAlgorithm string                                           `json:"signature_algorithm"`
	Signature          string                                           `json:"signature"`
	CreatedAt          time.Time                                        `json:"created_at"`
}

// EffectCloser is the only Kernel capability that may turn STARTED or
// UNCERTAIN into COMPLETED. A signed connector acknowledgement alone has no
// terminal authority.
type EffectCloser struct {
	store                   *PostgresStore
	consumer                ConsumerIdentityProvider
	releaseAuthorities      *connectorregistry.PostgresReleaseAuthorityStore
	acknowledgementVerifier EffectAcknowledgementVerifier
	dispositionVerifier     EffectDispositionCommandVerifier
	evidencePackVerifier    EffectEvidencePackVerifier
	signer                  crypto.Signer
}
