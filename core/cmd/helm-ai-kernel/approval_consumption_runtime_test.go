package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"

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
		config.MaxTokenTTL != defaultApprovalConsumerMaxTokenTTL {
		t.Fatalf("config = %+v", config)
	}
	t.Setenv(approvalConsumerMaxTokenTTLEnv, "16m")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("overlong workload token TTL was accepted")
	}
	t.Setenv(approvalConsumerMaxTokenTTLEnv, "")

	t.Setenv(approvalConsumerJWKSURLEnv, "http://identity.example.test/jwks.json")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("HTTP JWKS URL was accepted")
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
		approvalSigningKeyRefEnv, approvalKernelTrustRootIDEnv, approvalConsumerMaxTokenTTLEnv,
	} {
		t.Setenv(name, "")
	}
}
