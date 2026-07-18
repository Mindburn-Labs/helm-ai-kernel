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

func (r EffectCloseRequest) Validate() error {
	if !validToken(r.AdmissionID) || len(r.AdmissionID) > 512 {
		return ErrEffectCloseConflict
	}
	if err := r.Acknowledgement.Validate(); err != nil {
		return errors.Join(ErrEffectCloseConflict, err)
	}
	if r.AdmissionID != r.Acknowledgement.Acknowledgement.AdmissionID {
		return ErrEffectCloseConflict
	}
	if !validToken(r.EvidencePackRef) || len(r.EvidencePackRef) > 512 || !validSHA256(r.EvidencePackHash) {
		return ErrEffectCloseConflict
	}
	return nil
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

func (r EffectClosureRecord) Validate() error {
	if err := r.Acknowledgement.Validate(); err != nil {
		return err
	}
	if err := r.Receipt.ValidateAcknowledgement(r.Acknowledgement.Acknowledgement); err != nil {
		return err
	}
	if r.SignatureAlgorithm != GrantSignatureEd25519 || !validEd25519Signature(r.Signature) {
		return invalidRecord("effect close receipt signature is invalid")
	}
	if r.CreatedAt.IsZero() || !r.CreatedAt.Equal(r.Receipt.ClosedAt) {
		return invalidRecord("effect close record timestamp is invalid")
	}
	return nil
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

func NewEffectCloser(
	store *PostgresStore,
	consumer ConsumerIdentityProvider,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	acknowledgementVerifier EffectAcknowledgementVerifier,
	dispositionVerifier EffectDispositionCommandVerifier,
	evidencePackVerifier EffectEvidencePackVerifier,
	signer crypto.Signer,
) (*EffectCloser, error) {
	if store == nil || consumer == nil || releaseAuthorities == nil || acknowledgementVerifier == nil || dispositionVerifier == nil ||
		evidencePackVerifier == nil || signer == nil {
		return nil, errors.New("effect close dependencies are required")
	}
	return &EffectCloser{
		store: store, consumer: consumer, releaseAuthorities: releaseAuthorities,
		acknowledgementVerifier: acknowledgementVerifier, dispositionVerifier: dispositionVerifier,
		evidencePackVerifier: evidencePackVerifier, signer: signer,
	}, nil
}

func (s *EffectCloser) Close(ctx context.Context, request EffectCloseRequest) (EffectClosureRecord, error) {
	if s == nil || s.store == nil || s.acknowledgementVerifier == nil || s.dispositionVerifier == nil ||
		s.evidencePackVerifier == nil || s.signer == nil {
		return EffectClosureRecord{}, errors.New("effect closer is not initialized")
	}
	if err := request.Validate(); err != nil {
		return EffectClosureRecord{}, err
	}
	if err := s.acknowledgementVerifier.VerifyEnvelope(request.Acknowledgement); err != nil {
		return EffectClosureRecord{}, err
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	if err := s.evidencePackVerifier.VerifyEffectEvidencePack(
		ctx, identity, request.EvidencePackRef, request.EvidencePackHash, request.Acknowledgement,
	); err != nil {
		return EffectClosureRecord{}, err
	}
	return s.store.closeEffectReservation(
		ctx, identity, request, s.releaseAuthorities, s.acknowledgementVerifier, s.dispositionVerifier, s.signer,
	)
}

func (s *EffectCloser) Recover(ctx context.Context, admissionID string) (EffectClosureRecord, error) {
	if s == nil || s.store == nil || s.acknowledgementVerifier == nil || s.dispositionVerifier == nil {
		return EffectClosureRecord{}, errors.New("effect closer is not initialized")
	}
	if !validToken(admissionID) || len(admissionID) > 512 {
		return EffectClosureRecord{}, ErrEffectCloseConflict
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectClosureRecord{}, err
	}
	return s.store.recoverEffectClosure(
		ctx, identity, admissionID, s.releaseAuthorities, s.acknowledgementVerifier, s.dispositionVerifier,
	)
}
