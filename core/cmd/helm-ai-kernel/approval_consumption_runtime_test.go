package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestApprovalConsumptionConfigIsExplicitAndFailClosed(t *testing.T) {
	approvalConsumptionTestEnv(t)
	if _, enabled, err := approvalConsumptionConfigFromEnv(); err != nil || enabled {
		t.Fatalf("disabled config enabled=%t err=%v", enabled, err)
	}

	t.Setenv(approvalConsumptionEnabledEnv, "1")
	if _, enabled, err := approvalConsumptionConfigFromEnv(); err == nil || !enabled {
		t.Fatalf("incomplete config enabled=%t err=%v", enabled, err)
	}

	t.Setenv(approvalConsumerJWKSURLEnv, "https://identity.example.test/.well-known/jwks.json")
	t.Setenv(approvalConsumerIssuerEnv, "https://identity.example.test")
	t.Setenv(approvalConsumerAudienceEnv, "helm-data-plane")
	t.Setenv(approvalConsumerResourceEnv, "https://kernel.example.test/internal/v1/approval-grants")
	t.Setenv(approvalSigningKeyRefEnv, "kernel-approval-key-1")
	t.Setenv(approvalKernelTrustRootIDEnv, "kernel-root-1")
	config, enabled, err := approvalConsumptionConfigFromEnv()
	if err != nil || !enabled {
		t.Fatalf("complete config enabled=%t err=%v", enabled, err)
	}
	if config.Scope != defaultApprovalConsumerScope || config.Audience != "helm-data-plane" ||
		config.DispatchScope != defaultApprovalDispatchScope ||
		config.DispatchAdmissionTTL != defaultApprovalDispatchAdmissionTTL ||
		config.MaxTokenTTL != defaultApprovalConsumerMaxTokenTTL {
		t.Fatalf("config = %+v", config)
	}
	t.Setenv(approvalConsumerMaxTokenTTLEnv, "16m")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("overlong workload token TTL was accepted")
	}
	t.Setenv(approvalConsumerMaxTokenTTLEnv, "")
	t.Setenv(approvalDispatchAdmissionTTLEnv, "61s")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("overlong dispatch admission TTL was accepted")
	}
	t.Setenv(approvalDispatchAdmissionTTLEnv, "")
	t.Setenv(approvalDispatchScopeEnv, defaultApprovalConsumerScope)
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("shared consumption and dispatch scope was accepted")
	}
	t.Setenv(approvalDispatchScopeEnv, "")

	t.Setenv(approvalConsumerJWKSURLEnv, "http://identity.example.test/jwks.json")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("HTTP JWKS URL was accepted")
	}
}

func TestEffectDispositionRuntimeConfigRequiresDistinctScopeAndPinnedKeyrings(t *testing.T) {
	approvalConsumptionTestEnv(t)
	t.Setenv(effectDispositionEnabledEnv, "1")
	if _, enabled, err := approvalConsumptionConfigFromEnv(); err == nil || !enabled {
		t.Fatalf("standalone disposition enabled=%t err=%v", enabled, err)
	}
	setCompleteApprovalConsumptionEnv(t)
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("effect disposition accepted missing keyrings")
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	t.Setenv(effectDispositionCommandKeyringEnv, runtimeKeyringJSON(t, effectDispositionCommandKeyringV1, runtimeAuthorityKeyringKey{
		AuthorityID: "spiffe://helm/control-plane", SigningKeyRef: "kms://helm/control-plane/disposition-a",
		Audience: "helm-data-plane", PublicKey: hex.EncodeToString(make(ed25519.PublicKey, ed25519.PublicKeySize)),
		Enabled: true, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
	}))
	t.Setenv(connectorReleaseAuthorityKeyringEnv, runtimeKeyringJSON(t, connectorReleaseAuthorityKeyringV1, runtimeAuthorityKeyringKey{
		AuthorityID: "connector-registry-a", SigningKeyRef: "kms://helm/connector-registry-a",
		PublicKey: hex.EncodeToString(make(ed25519.PublicKey, ed25519.PublicKeySize)),
		Enabled:   true, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
	}))
	config, enabled, err := approvalConsumptionConfigFromEnv()
	if err != nil || !enabled || !config.DispositionEnabled || config.DispositionScope != defaultEffectDispositionScope ||
		len(config.DispositionKeys) != 1 || len(config.ReleaseAuthorityKeys) != 1 || config.ReleaseAuthorityID != "connector-registry-a" {
		t.Fatalf("disposition config=%+v enabled=%t err=%v", config, enabled, err)
	}
	t.Setenv(effectDispositionScopeEnv, defaultApprovalConsumerScope)
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("effect disposition accepted shared workload scope")
	}
}

func TestApprovalConsumptionRuntimeDisabledDoesNotRequireDatabase(t *testing.T) {
	approvalConsumptionTestEnv(t)
	runtime, err := newApprovalConsumptionRuntime(context.Background(), nil, "sqlite", nil, nil)
	if err != nil || runtime != nil {
		t.Fatalf("disabled runtime=%v err=%v", runtime, err)
	}
}

func TestApprovalConsumptionRuntimeRequiresEmergencyStopCoordination(t *testing.T) {
	approvalConsumptionTestEnv(t)
	t.Setenv(approvalConsumptionEnabledEnv, "1")
	t.Setenv(approvalConsumerJWKSURLEnv, "https://identity.example.test/.well-known/jwks.json")
	t.Setenv(approvalConsumerIssuerEnv, "https://identity.example.test")
	t.Setenv(approvalConsumerAudienceEnv, "helm-data-plane")
	t.Setenv(approvalConsumerResourceEnv, "https://kernel.example.test/internal/v1/approval-grants")
	t.Setenv(approvalSigningKeyRefEnv, "kernel-approval-key-1")
	t.Setenv(approvalKernelTrustRootIDEnv, "kernel-root-1")
	_, err := newApprovalConsumptionRuntime(context.Background(), new(sql.DB), "postgres", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "emergency-stop scope coordination") {
		t.Fatalf("missing stop coordination error = %v", err)
	}
}

func TestClassicalApprovalSignerRejectsUnknownSigner(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("approval-test")
	if err != nil {
		t.Fatal(err)
	}
	got, err := classicalApprovalSigner(signer)
	if err != nil || got != signer {
		t.Fatalf("classicalApprovalSigner() = %T err=%v", got, err)
	}
	if _, err := classicalApprovalSigner(nil); err == nil {
		t.Fatal("classicalApprovalSigner(nil) succeeded")
	}
}

func approvalConsumptionTestEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		approvalConsumptionEnabledEnv, approvalConsumerJWKSURLEnv, approvalConsumerIssuerEnv,
		approvalConsumerAudienceEnv, approvalConsumerResourceEnv, approvalConsumerScopeEnv,
		approvalDispatchScopeEnv, approvalDispatchAdmissionTTLEnv, approvalSigningKeyRefEnv,
		approvalKernelTrustRootIDEnv, approvalConsumerMaxTokenTTLEnv,
		effectDispositionEnabledEnv, effectDispositionScopeEnv, effectDispositionCommandKeyringEnv,
		connectorReleaseAuthorityKeyringEnv,
	} {
		t.Setenv(name, "")
	}
}

func setCompleteApprovalConsumptionEnv(t *testing.T) {
	t.Helper()
	t.Setenv(approvalConsumptionEnabledEnv, "1")
	t.Setenv(approvalConsumerJWKSURLEnv, "https://identity.example.test/.well-known/jwks.json")
	t.Setenv(approvalConsumerIssuerEnv, "https://identity.example.test")
	t.Setenv(approvalConsumerAudienceEnv, "helm-data-plane")
	t.Setenv(approvalConsumerResourceEnv, "https://kernel.example.test/internal/v1/approval-grants")
	t.Setenv(approvalSigningKeyRefEnv, "kernel-approval-key-1")
	t.Setenv(approvalKernelTrustRootIDEnv, "kernel-root-1")
}

func runtimeKeyringJSON(t *testing.T, version string, key runtimeAuthorityKeyringKey) string {
	t.Helper()
	raw, err := json.Marshal(runtimeAuthorityKeyring{KeyringVersion: version, Keys: []runtimeAuthorityKeyringKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
