package contracts

// quantum_posture: company activation records use classical Ed25519 over SHA-256;
// this contract does not provide a post-quantum signature profile.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	CompanyActivationRecordSchemaV1           = "company-activation-record.v1"
	CompanyActivationRecordStatusActive       = "ACTIVE"
	CompanyActivationRecordSignatureProfile   = "classical"
	CompanyActivationRecordSignatureAlgorithm = "ed25519-sha256"

	companyActivationRecordMaxTokenBytes     = 512
	companyActivationRecordMaxCanonicalBytes = 32 * 1024
	companyActivationRecordMaxLifetime       = 25 * time.Hour
)

var (
	ErrCompanyActivationRecordInvalid   = errors.New("company activation record invalid")
	ErrCompanyActivationBindingMismatch = errors.New("company activation binding mismatch")
	ErrCompanyActivationCeilingExceeded = errors.New("company activation ceiling exceeded")
)

// CompanyActivationRecord is the control-plane-signed capability that lets a
// specific company runtime ask the Kernel to evaluate effects. The envelope
// fields follow the signed payload and are verified against a pinned key.
type CompanyActivationRecord struct {
	SchemaVersion string `json:"schema_version"`
	RecordRef     string `json:"record_ref"`
	TenantID      string `json:"tenant_id"`
	CompanyID     string `json:"company_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`

	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	PackManifestHash string `json:"pack_manifest_hash"`

	ActivationDecisionRef        string `json:"activation_decision_ref"`
	ActivationDecisionTargetHash string `json:"activation_decision_target_hash"`
	GenesisCeremonyRef           string `json:"genesis_ceremony_ref"`
	GenesisReceiptHash           string `json:"genesis_receipt_hash"`
	InstallReceiptRef            string `json:"install_receipt_ref"`
	InstallReceiptHash           string `json:"install_receipt_hash"`

	EffectCeiling           string `json:"effect_ceiling"`
	AutonomyCeiling         string `json:"autonomy_ceiling"`
	MaxMonthlyExposureCents int64  `json:"max_monthly_exposure_cents"`
	CertificationDigest     string `json:"certification_digest"`
	Status                  string `json:"status"`

	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	SignatureProfile   string    `json:"signature_profile"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SigningKeyID       string    `json:"signing_key_id"`

	RecordHash     string `json:"record_hash"`
	Signature      string `json:"signature"`
	CanonicalBytes []byte `json:"canonical_bytes"`
}

type companyActivationRecordPayload struct {
	SchemaVersion string `json:"schema_version"`
	RecordRef     string `json:"record_ref"`
	TenantID      string `json:"tenant_id"`
	CompanyID     string `json:"company_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`

	PackID           string `json:"pack_id"`
	PackVersion      string `json:"pack_version"`
	PackManifestHash string `json:"pack_manifest_hash"`

	ActivationDecisionRef        string `json:"activation_decision_ref"`
	ActivationDecisionTargetHash string `json:"activation_decision_target_hash"`
	GenesisCeremonyRef           string `json:"genesis_ceremony_ref"`
	GenesisReceiptHash           string `json:"genesis_receipt_hash"`
	InstallReceiptRef            string `json:"install_receipt_ref"`
	InstallReceiptHash           string `json:"install_receipt_hash"`

	EffectCeiling           string `json:"effect_ceiling"`
	AutonomyCeiling         string `json:"autonomy_ceiling"`
	MaxMonthlyExposureCents int64  `json:"max_monthly_exposure_cents"`
	CertificationDigest     string `json:"certification_digest"`
	Status                  string `json:"status"`

	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	SignatureProfile   string    `json:"signature_profile"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SigningKeyID       string    `json:"signing_key_id"`
}

// CompanyActivationBinding is trusted request context supplied by the Kernel
// transport boundary, never by the activation-record envelope itself.
type CompanyActivationBinding struct {
	TenantID      string
	WorkspaceID   string
	EnvironmentID string
	EffectClass   string
	AutonomyLevel string
	Now           time.Time
}

// DecodeCompanyActivationRecord rejects unbound extension fields before the
// record reaches signature verification.
func DecodeCompanyActivationRecord(data []byte) (CompanyActivationRecord, error) {
	var record CompanyActivationRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return CompanyActivationRecord{}, companyActivationRecordInvalid("decode: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return CompanyActivationRecord{}, companyActivationRecordInvalid("decode: trailing JSON value")
	}
	return record, nil
}

// SigningPayload reconstructs the exact JSON bytes signed by the control
// plane. Struct field order is part of this v1 wire contract.
func (r CompanyActivationRecord) SigningPayload() ([]byte, error) {
	if err := r.validatePayload(); err != nil {
		return nil, err
	}
	return json.Marshal(companyActivationRecordPayload{
		SchemaVersion: r.SchemaVersion, RecordRef: r.RecordRef,
		TenantID: r.TenantID, CompanyID: r.CompanyID, WorkspaceID: r.WorkspaceID, EnvironmentID: r.EnvironmentID,
		PackID: r.PackID, PackVersion: r.PackVersion, PackManifestHash: r.PackManifestHash,
		ActivationDecisionRef: r.ActivationDecisionRef, ActivationDecisionTargetHash: r.ActivationDecisionTargetHash,
		GenesisCeremonyRef: r.GenesisCeremonyRef, GenesisReceiptHash: r.GenesisReceiptHash,
		InstallReceiptRef: r.InstallReceiptRef, InstallReceiptHash: r.InstallReceiptHash,
		EffectCeiling: r.EffectCeiling, AutonomyCeiling: r.AutonomyCeiling,
		MaxMonthlyExposureCents: r.MaxMonthlyExposureCents, CertificationDigest: r.CertificationDigest, Status: r.Status,
		IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		SignatureProfile: r.SignatureProfile, SignatureAlgorithm: r.SignatureAlgorithm, SigningKeyID: r.SigningKeyID,
	})
}

// VerifyCompanyActivationRecord establishes shape, integrity, pinned-key
// signature trust, request binding, liveness, and effect/autonomy ceilings.
func VerifyCompanyActivationRecord(record CompanyActivationRecord, publicKey ed25519.PublicKey, binding CompanyActivationBinding) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return companyActivationRecordInvalid("pinned Ed25519 public key is invalid")
	}
	if err := record.validateEnvelope(); err != nil {
		return err
	}
	canonical, err := record.SigningPayload()
	if err != nil {
		return err
	}
	if len(record.CanonicalBytes) > companyActivationRecordMaxCanonicalBytes || !bytes.Equal(record.CanonicalBytes, canonical) {
		return companyActivationRecordInvalid("canonical_bytes mismatch")
	}
	digest := sha256.Sum256(canonical)
	if record.RecordHash != "sha256:"+hex.EncodeToString(digest[:]) {
		return companyActivationRecordInvalid("record_hash mismatch")
	}
	signature, err := decodeCompanyActivationSignature(record.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, digest[:], signature) {
		return companyActivationRecordInvalid("signature verification failed")
	}

	now := binding.Now.UTC()
	if binding.Now.IsZero() {
		return companyActivationBindingMismatch("current time is required")
	}
	if now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) {
		return companyActivationRecordInvalid("record is not active at the requested time")
	}
	if strings.TrimSpace(binding.TenantID) != record.TenantID || strings.TrimSpace(binding.WorkspaceID) != record.WorkspaceID {
		return companyActivationBindingMismatch("authenticated tenant or workspace does not match")
	}
	if record.CompanyID != record.TenantID {
		return companyActivationBindingMismatch("company_id must match the authenticated tenant domain")
	}
	if strings.TrimSpace(binding.EnvironmentID) != record.EnvironmentID {
		return companyActivationBindingMismatch("configured environment does not match")
	}
	requestedEffect, ok := companyActivationLevel(binding.EffectClass, 'E', 4)
	if !ok {
		return companyActivationBindingMismatch("requested effect class is invalid")
	}
	if requestedEffect > 3 {
		return companyActivationCeilingExceeded("requested effect class exceeds the OrganizationRuntime maximum")
	}
	effectCeiling, _ := companyActivationLevel(record.EffectCeiling, 'E', 3)
	if requestedEffect > effectCeiling {
		return companyActivationCeilingExceeded("requested effect class exceeds activation ceiling")
	}
	requestedAutonomy, ok := companyActivationLevel(binding.AutonomyLevel, 'A', 5)
	if !ok {
		return companyActivationBindingMismatch("requested autonomy level is invalid")
	}
	autonomyCeiling, _ := companyActivationLevel(record.AutonomyCeiling, 'A', 5)
	if requestedAutonomy > autonomyCeiling {
		return companyActivationCeilingExceeded("requested autonomy level exceeds activation ceiling")
	}
	return nil
}

// VerifyUncertifiedCompanyActivationCheckpoint applies the fail-closed limits
// required until company-pack certification is independently verified.
func VerifyUncertifiedCompanyActivationCheckpoint(record CompanyActivationRecord) error {
	if record.EffectCeiling != "E0" {
		return companyActivationCeilingExceeded("uncertified company activation effect ceiling must be E0")
	}
	if record.AutonomyCeiling != "A0" {
		return companyActivationCeilingExceeded("uncertified company activation autonomy ceiling must be A0")
	}
	if record.MaxMonthlyExposureCents != 0 {
		return companyActivationCeilingExceeded("uncertified company activation exposure ceiling must be zero")
	}
	return nil
}

func (r CompanyActivationRecord) validatePayload() error {
	if r.SchemaVersion != CompanyActivationRecordSchemaV1 {
		return companyActivationRecordInvalid("unsupported schema_version")
	}
	for field, value := range map[string]string{
		"record_ref": r.RecordRef, "tenant_id": r.TenantID, "company_id": r.CompanyID,
		"workspace_id": r.WorkspaceID, "environment_id": r.EnvironmentID,
		"pack_id": r.PackID, "pack_version": r.PackVersion,
		"activation_decision_ref": r.ActivationDecisionRef, "genesis_ceremony_ref": r.GenesisCeremonyRef,
		"install_receipt_ref": r.InstallReceiptRef, "signing_key_id": r.SigningKeyID,
	} {
		if !isApprovalGrantToken(value) || len(value) > companyActivationRecordMaxTokenBytes {
			return companyActivationRecordInvalid("%s is required and must be a bounded token", field)
		}
	}
	for field, value := range map[string]string{
		"pack_manifest_hash":              r.PackManifestHash,
		"activation_decision_target_hash": r.ActivationDecisionTargetHash,
		"genesis_receipt_hash":            r.GenesisReceiptHash,
		"install_receipt_hash":            r.InstallReceiptHash,
		"certification_digest":            r.CertificationDigest,
	} {
		if !isApprovalGrantSHA256(value) {
			return companyActivationRecordInvalid("%s must be a lowercase sha256 reference", field)
		}
	}
	if _, ok := companyActivationLevel(r.EffectCeiling, 'E', 3); !ok {
		return companyActivationRecordInvalid("effect_ceiling must be E0 through E3")
	}
	if _, ok := companyActivationLevel(r.AutonomyCeiling, 'A', 5); !ok {
		return companyActivationRecordInvalid("autonomy_ceiling must be A0 through A5")
	}
	if r.MaxMonthlyExposureCents < 0 {
		return companyActivationRecordInvalid("max_monthly_exposure_cents must be nonnegative")
	}
	if r.Status != CompanyActivationRecordStatusActive {
		return companyActivationRecordInvalid("status must be ACTIVE")
	}
	if r.IssuedAt.IsZero() || r.ExpiresAt.IsZero() || !isApprovalGrantUTC(r.IssuedAt) || !isApprovalGrantUTC(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) {
		return companyActivationRecordInvalid("issued_at and expires_at must be ordered UTC timestamps")
	}
	if r.ExpiresAt.Sub(r.IssuedAt) > companyActivationRecordMaxLifetime {
		return companyActivationRecordInvalid("activation lifetime exceeds 25 hours")
	}
	if r.SignatureProfile != CompanyActivationRecordSignatureProfile {
		return companyActivationRecordInvalid("signature_profile must be classical")
	}
	if r.SignatureAlgorithm != CompanyActivationRecordSignatureAlgorithm {
		return companyActivationRecordInvalid("signature_algorithm must be ed25519-sha256")
	}
	return nil
}

func (r CompanyActivationRecord) validateEnvelope() error {
	if err := r.validatePayload(); err != nil {
		return err
	}
	if !isApprovalGrantSHA256(r.RecordHash) {
		return companyActivationRecordInvalid("record_hash must be a lowercase sha256 reference")
	}
	if len(r.CanonicalBytes) == 0 || len(r.CanonicalBytes) > companyActivationRecordMaxCanonicalBytes {
		return companyActivationRecordInvalid("canonical_bytes must be present and bounded")
	}
	_, err := decodeCompanyActivationSignature(r.Signature)
	return err
}

func decodeCompanyActivationSignature(value string) ([]byte, error) {
	const prefix = "ed25519:"
	if !strings.HasPrefix(value, prefix) {
		return nil, companyActivationRecordInvalid("signature must use ed25519 prefix")
	}
	encoded := strings.TrimPrefix(value, prefix)
	if len(encoded) != ed25519.SignatureSize*2 || strings.ToLower(encoded) != encoded {
		return nil, companyActivationRecordInvalid("signature must be canonical lowercase Ed25519 hex")
	}
	signature, err := hex.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, companyActivationRecordInvalid("signature must be canonical lowercase Ed25519 hex")
	}
	return signature, nil
}

func companyActivationLevel(value string, prefix byte, maximum int) (int, bool) {
	if len(value) != 2 || value[0] != prefix || value[1] < '0' || value[1] > byte('0'+maximum) {
		return 0, false
	}
	return int(value[1] - '0'), true
}

func companyActivationRecordInvalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCompanyActivationRecordInvalid, fmt.Sprintf(format, args...))
}

func companyActivationBindingMismatch(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCompanyActivationBindingMismatch, fmt.Sprintf(format, args...))
}

func companyActivationCeilingExceeded(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCompanyActivationCeilingExceeded, fmt.Sprintf(format, args...))
}
