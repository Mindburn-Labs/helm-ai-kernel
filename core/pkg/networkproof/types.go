// Package networkproof verifies request-bound claim presentations for HELM
// Network. A successful appraisal proves only the exact subject, claim,
// disclosure, audience, purpose, transaction, profile, and evaluation time
// named by source-owned inputs.
package networkproof

import (
	"context"
	"errors"
	"time"
)

const (
	ContextW3CCredentials        = "https://www.w3.org/ns/credentials/v2"
	ContextNetworkClaim          = "https://helm.mindburn.org/ns/network-claim/v1"
	TypeVerifiableCredential     = "VerifiableCredential"
	TypeNetworkClaimCredential   = "HELMNetworkClaimCredential"
	TypeVerifiablePresentation   = "VerifiablePresentation"
	TypeNetworkClaimPresentation = "HELMNetworkClaimPresentation"

	// ProofTypeHELMJCS2026 is the source-owned RFC 8785 proof suite. It must
	// not be represented as the unrelated Ed25519Signature2020 suite.
	ProofTypeHELMJCS2026       = "HELMJcsEd25519Signature2026"
	AlgorithmEd25519           = "Ed25519"
	ProofPurposeAssertion      = "assertionMethod"
	ProofPurposeAuthentication = "authentication"

	HolderBindingSubjectKeyV1 = "subject-held-key-v1"
	ReceiptSchemaV1           = "helm.network.verification-receipt/v1"
	// ChallengeGenerationUnresolved records that challenge authority could not
	// supply a trustworthy generation for a non-VERIFIED historical receipt.
	ChallengeGenerationUnresolved = "unresolved"
)

type ActorType string

const (
	ActorPerson       ActorType = "person"
	ActorOrganization ActorType = "organization"
	ActorAgent        ActorType = "agent"
	ActorService      ActorType = "service"
)

// VerificationStatus is the historical decision made at evaluation time.
// It is not a current rendering authority; only ReceiptAppraisal can render a
// current VERIFIED mark.
type VerificationStatus string

const (
	StatusPending  VerificationStatus = "PENDING"
	StatusVerified VerificationStatus = "VERIFIED"
	StatusExpired  VerificationStatus = "EXPIRED"
	StatusRevoked  VerificationStatus = "REVOKED"
	StatusDisputed VerificationStatus = "DISPUTED"
	StatusInvalid  VerificationStatus = "INVALID"
	StatusUnknown  VerificationStatus = "UNKNOWN"
)

type TrustState string

const (
	TrustActive      TrustState = "active"
	TrustRevoked     TrustState = "revoked"
	TrustDisputed    TrustState = "disputed"
	TrustQuarantined TrustState = "quarantined"
	TrustCompromised TrustState = "compromised"
	TrustUnknown     TrustState = "unknown"
)

type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	VerificationMethod string    `json:"verificationMethod"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofValue         string    `json:"proofValue"`
}

type ArtifactReference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type EvidenceReference struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

type CredentialStatusReference struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type ClaimSubject struct {
	ID          string    `json:"id"`
	ActorType   ActorType `json:"actorType"`
	ClaimID     string    `json:"claimId"`
	Predicate   string    `json:"predicate"`
	ValueDigest string    `json:"valueDigest"`
	Scope       []string  `json:"scope"`
	Audience    []string  `json:"audience"`
	Purpose     string    `json:"purpose"`
	IssuedAt    time.Time `json:"issuedAt"`
}

type Credential struct {
	Context           []string                  `json:"@context"`
	ID                string                    `json:"id"`
	Type              []string                  `json:"type"`
	SchemaID          string                    `json:"schemaId"`
	SchemaVersion     string                    `json:"schemaVersion"`
	Issuer            string                    `json:"issuer"`
	ValidFrom         time.Time                 `json:"validFrom"`
	ValidUntil        time.Time                 `json:"validUntil"`
	CredentialSubject ClaimSubject              `json:"credentialSubject"`
	CredentialStatus  CredentialStatusReference `json:"credentialStatus"`
	Evidence          []EvidenceReference       `json:"evidence"`
	Proof             *Proof                    `json:"proof,omitempty"`
}

// Presentation is a HELM Network envelope with OpenID4VP-style verifier
// bindings. Transport-level OpenID4VP conformance is owned by the wallet
// adapter, not inferred from this type.
type Presentation struct {
	Context       []string     `json:"@context"`
	ID            string       `json:"id"`
	Type          []string     `json:"type"`
	Holder        string       `json:"holder"`
	Audience      []string     `json:"audience"`
	Nonce         string       `json:"nonce"`
	Purpose       string       `json:"purpose"`
	TransactionID string       `json:"transactionId"`
	IssuedAt      time.Time    `json:"issuedAt"`
	Credentials   []Credential `json:"verifiableCredential"`
	Proof         *Proof       `json:"proof,omitempty"`
}

// VerificationRequest is server-owned authority. ExpectedProfileDigest pins
// the exact immutable profile, and ChallengeID must name a previously issued
// ChallengeStore record.
type VerificationRequest struct {
	RequestID             string    `json:"requestId"`
	ChallengeID           string    `json:"challengeId"`
	SubjectID             string    `json:"subjectId"`
	ActorType             ActorType `json:"actorType"`
	ClaimID               string    `json:"claimId"`
	Predicate             string    `json:"predicate"`
	ValueDigest           string    `json:"valueDigest"`
	Scope                 []string  `json:"scope"`
	Audience              []string  `json:"audience"`
	Nonce                 string    `json:"nonce"`
	Purpose               string    `json:"purpose"`
	TransactionID         string    `json:"transactionId"`
	SchemaID              string    `json:"schemaId"`
	SchemaVersion         string    `json:"schemaVersion"`
	DisclosureDigest      string    `json:"disclosureDigest"`
	ExpectedProfileDigest string    `json:"expectedProfileDigest"`
}

type AssuranceProfile struct {
	ID                        string        `json:"id"`
	Version                   string        `json:"version"`
	VerifierVersion           string        `json:"verifierVersion"`
	HolderBinding             string        `json:"holderBinding"`
	AllowedActorTypes         []ActorType   `json:"allowedActorTypes"`
	MaxCredentialAge          time.Duration `json:"maxCredentialAge"`
	MaxPresentationAge        time.Duration `json:"maxPresentationAge"`
	MaxDependencyAge          time.Duration `json:"maxDependencyAge"`
	ClockSkew                 time.Duration `json:"clockSkew"`
	AllowedCredentialProofs   []string      `json:"allowedCredentialProofs"`
	AllowedPresentationProofs []string      `json:"allowedPresentationProofs"`
	AllowedCredentialStatuses []string      `json:"allowedCredentialStatuses"`
	AllowedEvidenceKinds      []string      `json:"allowedEvidenceKinds"`
}

// DependencyAttestation is a fresh, immutable, exact-input adapter decision.
// BindingDigest is recomputed by the verifier; SnapshotDigest identifies the
// source bytes or decision record, and Generation prevents stale substitution.
type DependencyAttestation struct {
	DecisionRef    string    `json:"decisionRef"`
	BindingDigest  string    `json:"bindingDigest"`
	SnapshotDigest string    `json:"snapshotDigest"`
	Generation     string    `json:"generation"`
	CheckedAt      time.Time `json:"checkedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type KeyRequest struct {
	ControllerID  string    `json:"controllerId"`
	MethodID      string    `json:"methodId"`
	Purpose       string    `json:"purpose"`
	ProofCreated  time.Time `json:"proofCreated"`
	ProfileDigest string    `json:"profileDigest"`
}

type VerificationMethod struct {
	ID          string
	Controller  string
	Algorithm   string
	Purposes    []string
	PublicKey   []byte
	ValidFrom   time.Time
	ValidUntil  time.Time
	State       TrustState
	Attestation DependencyAttestation
}

type KeyResolver interface {
	ResolveVerificationMethod(ctx context.Context, request KeyRequest) (VerificationMethod, error)
}

type ClaimSchemaRequest struct {
	SchemaID         string    `json:"schemaId"`
	SchemaVersion    string    `json:"schemaVersion"`
	ActorType        ActorType `json:"actorType"`
	SubjectID        string    `json:"subjectId"`
	ClaimID          string    `json:"claimId"`
	Predicate        string    `json:"predicate"`
	ValueDigest      string    `json:"valueDigest"`
	DisclosureDigest string    `json:"disclosureDigest"`
	ProfileDigest    string    `json:"profileDigest"`
}

type ClaimSchemaResult struct {
	Allowed      bool
	SchemaDigest string
	Attestation  DependencyAttestation
}

type ClaimSchemaRegistry interface {
	AuthorizeClaimSchema(ctx context.Context, request ClaimSchemaRequest) (ClaimSchemaResult, error)
}

type AuthorityRequest struct {
	Issuer           string    `json:"issuer"`
	SubjectID        string    `json:"subjectId"`
	ActorType        ActorType `json:"actorType"`
	ClaimID          string    `json:"claimId"`
	Predicate        string    `json:"predicate"`
	ValueDigest      string    `json:"valueDigest"`
	Scope            []string  `json:"scope"`
	Audience         []string  `json:"audience"`
	Purpose          string    `json:"purpose"`
	TransactionID    string    `json:"transactionId"`
	DisclosureDigest string    `json:"disclosureDigest"`
	SchemaDigest     string    `json:"schemaDigest"`
	ProfileDigest    string    `json:"profileDigest"`
}

type AuthorityResult struct {
	Authorized  bool
	State       TrustState
	Attestation DependencyAttestation
}

type IssuerAuthorizer interface {
	AuthorizeIssuer(ctx context.Context, request AuthorityRequest) (AuthorityResult, error)
}

type CredentialStatus string

const (
	CredentialStatusValid     CredentialStatus = "valid"
	CredentialStatusRevoked   CredentialStatus = "revoked"
	CredentialStatusSuspended CredentialStatus = "suspended"
	CredentialStatusDisputed  CredentialStatus = "disputed"
	CredentialStatusUnknown   CredentialStatus = "unknown"
)

type StatusRequest struct {
	Reference        CredentialStatusReference `json:"reference"`
	CredentialID     string                    `json:"credentialId"`
	CredentialDigest string                    `json:"credentialDigest"`
	Issuer           string                    `json:"issuer"`
	SubjectID        string                    `json:"subjectId"`
	ClaimID          string                    `json:"claimId"`
	ValueDigest      string                    `json:"valueDigest"`
	ProfileDigest    string                    `json:"profileDigest"`
}

type StatusResult struct {
	Status      CredentialStatus
	Attestation DependencyAttestation
}

type StatusResolver interface {
	ResolveCredentialStatus(ctx context.Context, request StatusRequest) (StatusResult, error)
}

type EvidenceRequest struct {
	Reference        EvidenceReference `json:"reference"`
	CredentialID     string            `json:"credentialId"`
	CredentialDigest string            `json:"credentialDigest"`
	Issuer           string            `json:"issuer"`
	SubjectID        string            `json:"subjectId"`
	ActorType        ActorType         `json:"actorType"`
	ClaimID          string            `json:"claimId"`
	Predicate        string            `json:"predicate"`
	ValueDigest      string            `json:"valueDigest"`
	Scope            []string          `json:"scope"`
	Audience         []string          `json:"audience"`
	Purpose          string            `json:"purpose"`
	TransactionID    string            `json:"transactionId"`
	DisclosureDigest string            `json:"disclosureDigest"`
	ProfileDigest    string            `json:"profileDigest"`
}

type EvidenceResult struct {
	State            TrustState
	Attestation      DependencyAttestation
	ProofGraphRoot   ArtifactReference
	EvidencePackRoot ArtifactReference
}

type EvidenceResolver interface {
	VerifyEvidence(ctx context.Context, request EvidenceRequest) (EvidenceResult, error)
}

var (
	ErrChallengeNotFound = errors.New("networkproof: challenge not found")
	ErrChallengeConflict = errors.New("networkproof: challenge binding conflict")
)

// Challenge is issued and persisted by server authority before presentation.
// RequestBindingDigest covers every VerificationRequest field, including a
// digest of the nonce, so PresentationID cannot create a fresh replay key.
type Challenge struct {
	ID                   string
	RequestBindingDigest string
	ProfileDigest        string
	NonceDigest          string
	Audience             []string
	TransactionID        string
	IssuedAt             time.Time
	ExpiresAt            time.Time
	Generation           string
}

type ChallengeRecord struct {
	Challenge Challenge
	Decision  *VerificationReceipt
}

type ChallengeCommitResult struct {
	Decision VerificationReceipt
	Existing bool
}

// ChallengeStore must load source-issued challenges and atomically store the
// first signed decision while consuming the challenge. A concurrent commit for
// the same exact request and decision input (including the full presentation
// artifact digest) returns the original stored decision, including after
// challenge expiry once that first decision exists.
// Expiry prevents a first decision, a mismatched input returns
// ErrChallengeConflict, and implementations must not consume on a failed
// commit.
type ChallengeStore interface {
	LoadChallenge(ctx context.Context, challengeID string) (ChallengeRecord, error)
	CommitDecision(ctx context.Context, challengeID, requestBindingDigest, decisionInputDigest string, decision VerificationReceipt) (ChallengeCommitResult, error)
}

// ReceiptSigner signs RFC8785-canonical, domain-separated receipt bytes.
type ReceiptSigner interface {
	KeyID() string
	Algorithm() string
	PublicKey() []byte
	Sign(payload []byte) (string, error)
}

type ReceiptDependency struct {
	Kind        string                `json:"kind"`
	Subject     string                `json:"subject"`
	State       TrustState            `json:"state"`
	Attestation DependencyAttestation `json:"attestation"`
}

// VerificationReceipt is immutable historical evidence. Its status is
// deliberately named DecisionStatusAtEvaluation so clients cannot confuse a
// past VERIFIED decision with current rendering authority.
type VerificationReceipt struct {
	SchemaVersion               string              `json:"schemaVersion"`
	ReceiptID                   string              `json:"receiptId"`
	RequestID                   string              `json:"requestId"`
	ChallengeID                 string              `json:"challengeId"`
	ChallengeGeneration         string              `json:"challengeGeneration"`
	RequestBindingDigest        string              `json:"requestBindingDigest"`
	DecisionInputDigest         string              `json:"decisionInputDigest,omitempty"`
	PresentationID              string              `json:"presentationId,omitempty"`
	CanonicalPresentationDigest string              `json:"canonicalPresentationDigest,omitempty"`
	CredentialID                string              `json:"credentialId,omitempty"`
	CanonicalCredentialDigest   string              `json:"canonicalCredentialDigest,omitempty"`
	CredentialSchemaID          string              `json:"credentialSchemaId"`
	CredentialSchemaVersion     string              `json:"credentialSchemaVersion"`
	CredentialSchemaDigest      string              `json:"credentialSchemaDigest,omitempty"`
	SubjectID                   string              `json:"subjectId"`
	ActorType                   ActorType           `json:"actorType"`
	ClaimID                     string              `json:"claimId"`
	Predicate                   string              `json:"predicate"`
	ValueDigest                 string              `json:"valueDigest"`
	Scope                       []string            `json:"scope"`
	Audience                    []string            `json:"audience"`
	NonceDigest                 string              `json:"nonceDigest"`
	Purpose                     string              `json:"purpose"`
	TransactionID               string              `json:"transactionId"`
	DisclosureDigest            string              `json:"disclosureDigest"`
	AssuranceProfileID          string              `json:"assuranceProfileId"`
	AssuranceProfileVersion     string              `json:"assuranceProfileVersion"`
	AssuranceProfileDigest      string              `json:"assuranceProfileDigest"`
	VerifierVersion             string              `json:"verifierVersion"`
	EvaluatedAt                 time.Time           `json:"evaluatedAt"`
	FreshUntil                  time.Time           `json:"freshUntil,omitempty"`
	DecisionStatusAtEvaluation  VerificationStatus  `json:"decisionStatusAtEvaluation"`
	ReasonCode                  string              `json:"reasonCode"`
	Issuer                      string              `json:"issuer,omitempty"`
	IssuerKeyID                 string              `json:"issuerKeyId,omitempty"`
	Holder                      string              `json:"holder,omitempty"`
	HolderKeyID                 string              `json:"holderKeyId,omitempty"`
	Dependencies                []ReceiptDependency `json:"dependencies"`
	DependencySnapshotDigest    string              `json:"dependencySnapshotDigest"`
	ProofGraphRoots             []ArtifactReference `json:"proofGraphRoots"`
	EvidencePackRoots           []ArtifactReference `json:"evidencePackRoots"`
	SignerKeyID                 string              `json:"signerKeyId"`
	SignatureAlgorithm          string              `json:"signatureAlgorithm"`
	Signature                   string              `json:"signature"`
}

type Dependencies struct {
	Keys       KeyResolver
	Schemas    ClaimSchemaRegistry
	Authority  IssuerAuthorizer
	Statuses   StatusResolver
	Evidence   EvidenceResolver
	Challenges ChallengeStore
	Signer     ReceiptSigner
	Clock      func() time.Time
	NewID      func() string
}

type AppraisalStatus string

const (
	AppraisalVerified AppraisalStatus = "CURRENT_VERIFIED"
	AppraisalRevoked  AppraisalStatus = "CURRENT_REVOKED"
	AppraisalWarning  AppraisalStatus = "WARNING"
	AppraisalInvalid  AppraisalStatus = "INVALID"
)

type ReceiptAppraisal struct {
	ReceiptID   string
	Status      AppraisalStatus
	ReasonCode  string
	AppraisedAt time.Time
}

// CanRenderVerified is the only package API that authorizes a current
// VERIFIED mark.
func (a ReceiptAppraisal) CanRenderVerified() bool { return a.Status == AppraisalVerified }

type AppraisalExpectation struct {
	RequestBindingDigest string    `json:"requestBindingDigest"`
	SubjectID            string    `json:"subjectId"`
	ActorType            ActorType `json:"actorType"`
	ClaimID              string    `json:"claimId"`
	Predicate            string    `json:"predicate"`
	ValueDigest          string    `json:"valueDigest"`
	Scope                []string  `json:"scope"`
	Audience             []string  `json:"audience"`
	Purpose              string    `json:"purpose"`
	TransactionID        string    `json:"transactionId"`
	DisclosureDigest     string    `json:"disclosureDigest"`
	ProfileDigest        string    `json:"profileDigest"`
}

type AppraisalBindingRequest struct {
	Kind          string `json:"kind"`
	Subject       string `json:"subject"`
	ReceiptID     string `json:"receiptId"`
	ProfileDigest string `json:"profileDigest"`
	BindingDigest string `json:"bindingDigest"`
	Generation    string `json:"generation"`
}

type CurrentTrustResult struct {
	State       TrustState
	PublicKey   []byte            // populated only for receipt_signer
	Algorithm   string            // populated only for receipt_signer
	Profile     *AssuranceProfile // populated only for assurance_profile
	Attestation DependencyAttestation
}

// ReceiptTrustResolver owns current profile, receipt-key, and dependency
// status. The appraiser never accepts a key or trust label from a receipt or
// caller as authority.
type ReceiptTrustResolver interface {
	ResolveCurrentTrust(ctx context.Context, request AppraisalBindingRequest) (CurrentTrustResult, error)
}
