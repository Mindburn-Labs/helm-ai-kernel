package contracts

// quantum_posture: these fixtures test classical Ed25519 activation signatures;
// they do not establish post-quantum security.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVerifyCompanyActivationRecord(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	record, publicKey := signedCompanyActivationRecordFixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	binding := CompanyActivationBinding{
		TenantID: "tenant-1", WorkspaceID: "workspace-1", EnvironmentID: "production",
		EffectClass: "E2", AutonomyLevel: "A3", Now: now,
	}
	if err := VerifyCompanyActivationRecord(record, publicKey, binding); err != nil {
		t.Fatalf("verify valid record: %v", err)
	}

	for name, test := range map[string]struct {
		mutate    func(*CompanyActivationRecord, *CompanyActivationBinding)
		wantError error
	}{
		"tampered payload": {
			mutate:    func(r *CompanyActivationRecord, _ *CompanyActivationBinding) { r.PackID = "pack-tampered" },
			wantError: ErrCompanyActivationRecordInvalid,
		},
		"wrong tenant": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.TenantID = "tenant-2" },
			wantError: ErrCompanyActivationBindingMismatch,
		},
		"wrong workspace": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.WorkspaceID = "workspace-2" },
			wantError: ErrCompanyActivationBindingMismatch,
		},
		"wrong environment": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.EnvironmentID = "local" },
			wantError: ErrCompanyActivationBindingMismatch,
		},
		"expired": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.Now = now.Add(2 * time.Hour) },
			wantError: ErrCompanyActivationRecordInvalid,
		},
		"effect ceiling": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.EffectClass = "E3" },
			wantError: ErrCompanyActivationCeilingExceeded,
		},
		"E4 platform ceiling": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.EffectClass = "E4" },
			wantError: ErrCompanyActivationCeilingExceeded,
		},
		"autonomy ceiling": {
			mutate:    func(_ *CompanyActivationRecord, b *CompanyActivationBinding) { b.AutonomyLevel = "A5" },
			wantError: ErrCompanyActivationCeilingExceeded,
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := record
			candidateBinding := binding
			test.mutate(&candidate, &candidateBinding)
			if err := VerifyCompanyActivationRecord(candidate, publicKey, candidateBinding); !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
		})
	}
	candidate := record
	candidate.EffectCeiling = "E4"
	if _, err := candidate.SigningPayload(); !errors.Is(err, ErrCompanyActivationRecordInvalid) {
		t.Fatalf("E4 record error = %v", err)
	}
	candidate = record
	candidate.ExpiresAt = candidate.IssuedAt.Add(companyActivationRecordMaxLifetime + time.Nanosecond)
	if _, err := candidate.SigningPayload(); !errors.Is(err, ErrCompanyActivationRecordInvalid) {
		t.Fatalf("overlong activation error = %v", err)
	}
}

func TestDecodeCompanyActivationRecordRejectsUnknownFields(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	record, _ := signedCompanyActivationRecordFixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"unbound_authority":true}`)...)
	if _, err := DecodeCompanyActivationRecord(encoded); !errors.Is(err, ErrCompanyActivationRecordInvalid) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestVerifyUncertifiedCompanyActivationCheckpoint(t *testing.T) {
	record := CompanyActivationRecord{
		EffectCeiling: "E0", AutonomyCeiling: "A0", MaxMonthlyExposureCents: 0,
	}
	if err := VerifyUncertifiedCompanyActivationCheckpoint(record); err != nil {
		t.Fatalf("verify E0/A0/zero checkpoint: %v", err)
	}
	for name, mutate := range map[string]func(*CompanyActivationRecord){
		"effect ceiling":   func(r *CompanyActivationRecord) { r.EffectCeiling = "E1" },
		"autonomy ceiling": func(r *CompanyActivationRecord) { r.AutonomyCeiling = "A1" },
		"exposure ceiling": func(r *CompanyActivationRecord) { r.MaxMonthlyExposureCents = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := record
			mutate(&candidate)
			if err := VerifyUncertifiedCompanyActivationCheckpoint(candidate); !errors.Is(err, ErrCompanyActivationCeilingExceeded) {
				t.Fatalf("error = %v, want %v", err, ErrCompanyActivationCeilingExceeded)
			}
		})
	}
}

func signedCompanyActivationRecordFixture(t *testing.T, issuedAt, expiresAt time.Time) (CompanyActivationRecord, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("company-activation-record-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	record := CompanyActivationRecord{
		SchemaVersion: CompanyActivationRecordSchemaV1,
		RecordRef:     "activation-record-1", TenantID: "tenant-1", CompanyID: "tenant-1",
		WorkspaceID: "workspace-1", EnvironmentID: "production",
		PackID: "company-builder", PackVersion: "1.0.0", PackManifestHash: activationTestHash("1"),
		ActivationDecisionRef: "decision-1", ActivationDecisionTargetHash: activationTestHash("2"),
		GenesisCeremonyRef: "ceremony-1", GenesisReceiptHash: activationTestHash("3"),
		InstallReceiptRef: "install-1", InstallReceiptHash: activationTestHash("4"),
		EffectCeiling: "E2", AutonomyCeiling: "A4", MaxMonthlyExposureCents: 100_00,
		CertificationDigest: activationTestHash("5"), Status: CompanyActivationRecordStatusActive,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
		SignatureProfile:   CompanyActivationRecordSignatureProfile,
		SignatureAlgorithm: CompanyActivationRecordSignatureAlgorithm,
		SigningKeyID:       "control-plane-key-1",
	}
	canonical, err := record.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	record.CanonicalBytes = canonical
	record.RecordHash = "sha256:" + hex.EncodeToString(digest[:])
	record.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	return record, privateKey.Public().(ed25519.PublicKey)
}

func activationTestHash(digit string) string {
	return "sha256:" + strings.Repeat(digit, 64)
}
