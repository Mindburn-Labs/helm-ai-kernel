package main

// quantum_posture: tests cover classical Ed25519 disposition-command and
// grant-consumption signature verification with RSA-JWKS (RS256) OAuth tokens;
// no post-quantum path is exercised or claimed.

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestApprovalControlRuntimeConfigRequiresConsumptionAndDistinctScope(t *testing.T) {
	approvalConsumptionTestEnv(t)
	t.Setenv(approvalControlEnabledEnv, "1")
	if _, enabled, err := approvalConsumptionConfigFromEnv(); err == nil || !enabled {
		t.Fatalf("standalone control enabled=%t err=%v", enabled, err)
	}

	approvalConsumptionTestEnv(t)
	setCompleteApprovalConsumptionEnv(t)
	t.Setenv(approvalControlEnabledEnv, "1")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("approval control accepted missing source configuration")
	}
	t.Setenv(approvalControlSourceURLEnv, "https://control.example.test")
	t.Setenv(approvalControlSourceTokenEnv, "source-service-token")
	t.Setenv(approvalControlServerIdentityEnv, "spiffe://helm/kernel-a")
	config, enabled, err := approvalConsumptionConfigFromEnv()
	if err != nil || !enabled || !config.ControlEnabled || config.ControlScope != defaultApprovalControlScope ||
		config.ControlMinHoldDuration != defaultApprovalControlMinHoldDuration ||
		config.ControlMaxAssertions != defaultApprovalControlMaxAssertions {
		t.Fatalf("approval control config=%+v enabled=%t err=%v", config, enabled, err)
	}
	for name, value := range map[string]string{
		"consume collision":  defaultApprovalConsumerScope,
		"dispatch collision": defaultApprovalDispatchScope,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(approvalControlScopeEnv, value)
			if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
				t.Fatalf("approval control accepted shared scope %q", value)
			}
		})
	}
	t.Setenv(approvalControlScopeEnv, "")
	for name, value := range map[string]string{
		"http":  "http://control.example.test",
		"query": "https://control.example.test?tenant_id=attacker",
		"user":  "https://attacker@control.example.test",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(approvalControlSourceURLEnv, value)
			if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
				t.Fatalf("approval control accepted source URL %q", value)
			}
		})
	}
	t.Setenv(approvalControlSourceURLEnv, "https://control.example.test")
	t.Setenv(approvalControlChallengeTTLEnv, "30m")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("approval control accepted challenge TTL outside the lifetime budget")
	}
}

func TestApprovalCeremonySourceClientPinsBindingAndAuthority(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	snapshot, err := approvalceremony.SealAuthoritySnapshot(approvalceremony.AuthoritySnapshot{
		AuthoritySource: "control-plane-approver-registry", AuthorityVersion: "authority-v1",
		Keys: []approvalceremony.AuthoritySnapshotKey{{
			KeyID: "key-1", TenantID: "tenant-a", PrincipalID: "approver-a", CredentialID: "credential-a",
			DeviceID: "device-a", PublicKey: strings.Repeat("ab", ed25519.PublicKeySize),
			WorkspaceIDs: []string{"workspace-a"}, Roles: []string{"reviewer"},
			Actions: []string{contracts.ApprovalGrantActionInstall}, Audiences: []string{"helm-data-plane"},
			Enabled: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := approvalControlTestBinding(snapshot.AuthoritySnapshotHash)
	authorityResponse := snapshot
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer source-service-token" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("source request method=%s headers=%v", r.Method, r.Header)
			http.Error(w, "rejected", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case approvalCeremonyBindingSourcePath:
			var request approvalCeremonyBindingSourceRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.TenantID != "tenant-a" ||
				request.WorkspaceID != "workspace-a" || request.BindingRef != binding.BindingRef {
				t.Errorf("binding source request = %+v", request)
				http.Error(w, "rejected", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(binding)
		case approvalCeremonyAuthoritySourcePath:
			var request approvalCeremonyAuthoritySourceRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.TenantID != "tenant-a" ||
				request.WorkspaceID != "workspace-a" || request.AuthoritySource != snapshot.AuthoritySource ||
				request.AuthorityVersion != snapshot.AuthorityVersion || request.AuthoritySnapshotHash != snapshot.AuthoritySnapshotHash {
				t.Errorf("authority source request = %+v", request)
				http.Error(w, "rejected", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(authorityResponse)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := newApprovalCeremonySourceClient(server.URL, "source-service-token", server.Client(), "helm-data-plane", true)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := client.LoadApprovalBinding(t.Context(), "tenant-a", "workspace-a", binding.BindingRef)
	if err != nil || loaded != binding {
		t.Fatalf("LoadApprovalBinding()=%+v err=%v", loaded, err)
	}
	store, err := client.LoadApprovalAuthority(
		t.Context(), "tenant-a", "workspace-a", snapshot.AuthoritySource,
		snapshot.AuthorityVersion, snapshot.AuthoritySnapshotHash,
	)
	if err != nil || len(store.Keys) != 1 || requests != 2 {
		t.Fatalf("LoadApprovalAuthority()=%+v requests=%d err=%v", store, requests, err)
	}
	authorityResponse.Keys = append([]approvalceremony.AuthoritySnapshotKey(nil), snapshot.Keys...)
	authorityResponse.Keys[0].Roles = []string{"administrator"}
	if _, err := client.LoadApprovalAuthority(
		t.Context(), "tenant-a", "workspace-a", snapshot.AuthoritySource,
		snapshot.AuthorityVersion, snapshot.AuthoritySnapshotHash,
	); !errors.Is(err, approvalceremony.ErrAuthorityUnavailable) {
		t.Fatalf("tampered authority error=%v, want ErrAuthorityUnavailable", err)
	}
}

func approvalControlTestBinding(snapshotHash string) approvalceremony.ChallengeSpec {
	authority := approvalRouteConnectorAuthority()
	return approvalceremony.ChallengeSpec{
		BindingRef: authority.BindingRef, TenantID: authority.TenantID, WorkspaceID: authority.WorkspaceID,
		Audience: "helm-data-plane", PackID: authority.PackID, PackVersion: authority.PackVersion,
		PackManifestHash: authority.PackManifestHash, Action: authority.Action, ConnectorAuthority: authority,
		IntentHash: "sha256:" + strings.Repeat("d", 64), EffectHash: authority.EffectHash,
		PlanHash: "sha256:" + strings.Repeat("f", 64), Decision: contracts.ApprovalGrantDecisionAllow,
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", PolicyHash: authority.PolicyHash,
		AuthoritySource: "control-plane-approver-registry", AuthorityVersion: "authority-v1",
		AuthoritySnapshotHash: snapshotHash, RequiredRole: "reviewer", Quorum: 1,
		ServerIdentity: "spiffe://helm/kernel-a",
	}
}

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

func TestEffectReconciliationCandidatesRuntimeConfigIsDefaultOffAndRouteScoped(t *testing.T) {
	approvalConsumptionTestEnv(t)
	t.Setenv(effectReconciliationCandidatesEnabledEnv, "1")
	if _, enabled, err := approvalConsumptionConfigFromEnv(); err == nil || !enabled {
		t.Fatalf("standalone reconciliation enabled=%t err=%v", enabled, err)
	}
	approvalConsumptionTestEnv(t)
	setCompleteApprovalConsumptionEnv(t)
	config, enabled, err := approvalConsumptionConfigFromEnv()
	if err != nil || !enabled || config.ReconciliationCandidatesEnabled {
		t.Fatalf("default reconciliation config=%+v enabled=%t err=%v", config, enabled, err)
	}

	t.Setenv(effectReconciliationCandidatesEnabledEnv, "1")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("reconciliation candidates accepted missing route resource and keyrings")
	}
	t.Setenv(effectReconciliationCandidatesResourceEnv, "https://kernel.example.test/internal/effect-dispositions/reconciliation-candidates")
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
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
	config, enabled, err = approvalConsumptionConfigFromEnv()
	if err != nil || !enabled || !config.ReconciliationCandidatesEnabled ||
		config.ReconciliationCandidatesScope != defaultEffectReconciliationCandidatesScope ||
		config.ReconciliationCandidatesResource != "https://kernel.example.test/internal/effect-dispositions/reconciliation-candidates" {
		t.Fatalf("reconciliation config=%+v enabled=%t err=%v", config, enabled, err)
	}
	t.Setenv(effectReconciliationCandidatesScopeEnv, "helm.effect.reconciliation.other")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("reconciliation candidates accepted a noncanonical read scope")
	}
	t.Setenv(effectReconciliationCandidatesScopeEnv, defaultEffectDispositionScope)
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("reconciliation candidates accepted the write scope")
	}
	t.Setenv(effectReconciliationCandidatesScopeEnv, "")
	t.Setenv(effectReconciliationCandidatesResourceEnv, "https://kernel.example.test/internal/v1/approval-grants")
	if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
		t.Fatal("reconciliation candidates accepted the approval-consumption resource")
	}
	for name, resource := range map[string]string{
		"origin":  "https://kernel.example.test",
		"sibling": "https://kernel.example.test/internal/effect-dispositions/reconciliation-candidates-next",
		"query":   "https://kernel.example.test/internal/effect-dispositions/reconciliation-candidates?tenant_id=attacker",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(effectReconciliationCandidatesResourceEnv, resource)
			if _, _, err := approvalConsumptionConfigFromEnv(); err == nil {
				t.Fatalf("reconciliation candidates accepted non-exact resource %q", resource)
			}
		})
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
		approvalControlEnabledEnv, approvalControlSourceURLEnv, approvalControlSourceTokenEnv,
		approvalControlOutboundCAFileEnv, approvalControlScopeEnv, approvalControlMinHoldDurationEnv,
		approvalControlChallengeTTLEnv, approvalControlMaxChallengeLifetimeEnv,
		approvalControlGrantTTLEnv, approvalControlMaxAssertionsEnv, approvalControlServerIdentityEnv,
		effectDispositionEnabledEnv, effectDispositionScopeEnv, effectDispositionCommandKeyringEnv,
		effectReconciliationCandidatesEnabledEnv, effectReconciliationCandidatesResourceEnv, effectReconciliationCandidatesScopeEnv,
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
