package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapprovalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestGeneratedSpecApprovalConfigIsExplicitAndFailClosed(t *testing.T) {
	generatedSpecApprovalTestEnv(t)
	if _, enabled, err := generatedSpecApprovalRuntimeConfigFromEnv(); err != nil || enabled {
		t.Fatalf("disabled config enabled=%t err=%v", enabled, err)
	}
	t.Setenv(generatedSpecApprovalEnabledEnv, "1")
	if _, enabled, err := generatedSpecApprovalRuntimeConfigFromEnv(); err == nil || !enabled {
		t.Fatalf("incomplete config enabled=%t err=%v", enabled, err)
	}
	setCompleteGeneratedSpecApprovalEnv(t)
	cfg, enabled, err := generatedSpecApprovalRuntimeConfigFromEnv()
	if err != nil || !enabled || cfg.ControlScope != defaultGeneratedSpecApprovalControlScope ||
		cfg.ConsumerScope != defaultGeneratedSpecApprovalConsumerScope || cfg.MaxTokenTTL != defaultGeneratedSpecApprovalMaxTokenTTL {
		t.Fatalf("config=%+v enabled=%t err=%v", cfg, enabled, err)
	}
	t.Setenv(generatedSpecApprovalMaxTokenTTLEnv, "16m")
	if _, _, err := generatedSpecApprovalRuntimeConfigFromEnv(); err == nil {
		t.Fatal("overlong workload token TTL was accepted")
	}
	t.Setenv(generatedSpecApprovalMaxTokenTTLEnv, "")
	t.Setenv(generatedSpecApprovalControlScopeEnv, defaultGeneratedSpecApprovalConsumerScope)
	if _, _, err := generatedSpecApprovalRuntimeConfigFromEnv(); err == nil {
		t.Fatal("shared control and consumer scope was accepted")
	}
	t.Setenv(generatedSpecApprovalControlScopeEnv, "")
	t.Setenv(generatedSpecApprovalSourceURLEnv, "http://control.example.test")
	if _, _, err := generatedSpecApprovalRuntimeConfigFromEnv(); err == nil {
		t.Fatal("HTTP source URL was accepted")
	}
}

func TestGeneratedSpecApprovalSourceClientPinsBindingAndAuthority(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	snapshot, err := generatedspecapprovalceremony.SealAuthoritySnapshot(generatedspecapprovalceremony.AuthoritySnapshot{
		AuthoritySource: "control-plane-approver-registry", AuthorityVersion: "authority-v1",
		Keys: []generatedspecapprovalceremony.AuthoritySnapshotKey{{
			KeyID: "key-a", TenantID: "tenant-a", PrincipalID: "approver-a", CredentialID: "credential-a", DeviceID: "device-a",
			PublicKey: hex.EncodeToString(make([]byte, 32)), WorkspaceIDs: []string{"workspace-a"}, Roles: []string{"approver"},
			Actions: []string{contracts.GeneratedSpecApprovalActionV1}, Audiences: []string{contracts.GeneratedSpecApprovalAudienceV1},
			Enabled: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := generatedspecapprovalceremony.Binding{
		BindingRef: "binding-a", TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: contracts.GeneratedSpecApprovalAudienceV1,
		GeneratedSpecID: "spec-a", GeneratedSpecHash: testGeneratedSpecApprovalHash("1"), ExecutionPlanHash: testGeneratedSpecApprovalHash("2"),
		PlanTransactionHash: testGeneratedSpecApprovalHash("3"), WriteSetHash: testGeneratedSpecApprovalHash("4"),
		VerificationScopeHash: testGeneratedSpecApprovalHash("5"), PolicyEnvelopeHash: testGeneratedSpecApprovalHash("6"),
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", Action: contracts.GeneratedSpecApprovalActionV1,
		RequestingPrincipalID: "requester-a", AuthoritySource: snapshot.AuthoritySource, AuthorityVersion: snapshot.AuthorityVersion,
		AuthoritySnapshotHash: snapshot.AuthoritySnapshotHash, RequiredRole: "approver", Quorum: 1, ServerIdentity: "kernel-a",
	}
	authorityResponse := snapshot
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer source-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected source request method=%s headers=%v", r.Method, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case generatedSpecApprovalBindingSourcePath:
			_ = json.NewEncoder(w).Encode(binding)
		case generatedSpecApprovalAuthoritySourcePath:
			_ = json.NewEncoder(w).Encode(authorityResponse)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := newGeneratedSpecApprovalSourceClient(server.URL, "source-token", server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	loadedBinding, err := client.LoadGeneratedSpecApprovalBinding(t.Context(), "tenant-a", "workspace-a", "binding-a")
	if err != nil || loadedBinding.GeneratedSpecHash != binding.GeneratedSpecHash {
		t.Fatalf("binding=%+v err=%v", loadedBinding, err)
	}
	store, err := client.LoadGeneratedSpecApprovalAuthority(t.Context(), "tenant-a", "workspace-a", snapshot.AuthoritySource, snapshot.AuthorityVersion, snapshot.AuthoritySnapshotHash)
	if err != nil || len(store.Keys) != 1 {
		t.Fatalf("trust store=%+v err=%v", store, err)
	}
	authorityResponse.Keys = append([]generatedspecapprovalceremony.AuthoritySnapshotKey(nil), snapshot.Keys...)
	authorityResponse.Keys[0].Roles = []string{"administrator"}
	if _, err := client.LoadGeneratedSpecApprovalAuthority(t.Context(), "tenant-a", "workspace-a", snapshot.AuthoritySource, snapshot.AuthorityVersion, snapshot.AuthoritySnapshotHash); !errors.Is(err, generatedspecapprovalceremony.ErrAuthorityUnavailable) {
		t.Fatalf("tampered authority error=%v", err)
	}
}

func TestGeneratedSpecApprovalVerifierErrorsRemainActionable(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code int
	}{
		{"verification", generatedspecapproval.ErrVerificationFailed, http.StatusBadRequest},
		{"duplicate", approvalverify.ErrDuplicateSigner, http.StatusConflict},
		{"quorum", generatedspecapproval.ErrQuorumNotMet, http.StatusConflict},
		{"signature", generatedspecapproval.ErrAssertionRejected, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeGeneratedSpecApprovalError(response, test.err)
			if response.Code != test.code {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func generatedSpecApprovalTestEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		generatedSpecApprovalEnabledEnv, generatedSpecApprovalSourceURLEnv, generatedSpecApprovalSourceTokenEnv,
		generatedSpecApprovalJWKSURLEnv, generatedSpecApprovalIssuerEnv, generatedSpecApprovalAudienceEnv,
		generatedSpecApprovalResourceEnv, generatedSpecApprovalControlScopeEnv, generatedSpecApprovalConsumerScopeEnv,
		generatedSpecApprovalMaxTokenTTLEnv, generatedSpecApprovalMinHoldDurationEnv, generatedSpecApprovalChallengeTTLEnv,
		generatedSpecApprovalMaxChallengeLifetimeEnv, generatedSpecApprovalGrantTTLEnv, generatedSpecApprovalMaxAssertionsEnv,
		generatedSpecApprovalServerIdentityEnv, generatedSpecApprovalSigningKeyRefEnv, generatedSpecApprovalKernelTrustRootIDEnv,
	} {
		t.Setenv(name, "")
	}
}

func setCompleteGeneratedSpecApprovalEnv(t *testing.T) {
	t.Helper()
	t.Setenv(generatedSpecApprovalEnabledEnv, "1")
	t.Setenv(generatedSpecApprovalSourceURLEnv, "https://control.example.test")
	t.Setenv(generatedSpecApprovalSourceTokenEnv, "source-token")
	t.Setenv(generatedSpecApprovalJWKSURLEnv, "https://identity.example.test/.well-known/jwks.json")
	t.Setenv(generatedSpecApprovalIssuerEnv, "https://identity.example.test")
	t.Setenv(generatedSpecApprovalAudienceEnv, contracts.GeneratedSpecApprovalAudienceV1)
	t.Setenv(generatedSpecApprovalResourceEnv, "https://kernel.example.test/internal/v1/generated-spec-approvals")
	t.Setenv(generatedSpecApprovalServerIdentityEnv, "kernel-a")
	t.Setenv(generatedSpecApprovalSigningKeyRefEnv, "kernel-generated-spec-key-a")
	t.Setenv(generatedSpecApprovalKernelTrustRootIDEnv, "kernel-root-a")
}

func testGeneratedSpecApprovalHash(digit string) string {
	return "sha256:" + strings.Repeat(digit, 64)
}
