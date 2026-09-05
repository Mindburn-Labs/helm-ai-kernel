package main

// quantum_posture: these tests cover classical Ed25519 activation verification;
// they do not establish post-quantum security.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

const testOrganizationRuntimeAPIKey = "test-organization-runtime-key"

func TestEvaluateRouteRequiresValidCompanyActivationRecordForOrganizationRuntime(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "principal-1")
	now := time.Now().UTC()
	base, privateKey := routeCompanyActivationRecord(t, now.Add(-time.Hour), now.Add(time.Hour))
	publicKey := privateKey.Public().(ed25519.PublicKey)

	tests := []struct {
		name          string
		prepare       func(*contracts.CompanyActivationRecord, *string)
		autonomyLevel string
		withoutKey    bool
		wantReason    contracts.ReasonCode
	}{
		{name: "valid"},
		{
			name: "tampered",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.PackID = "tampered-pack"
			},
			wantReason: contracts.ReasonActivationRecordInvalid,
		},
		{
			name: "wrong tenant",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.TenantID = "tenant-2"
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationBindingMismatch,
		},
		{
			name: "wrong workspace",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.WorkspaceID = "workspace-2"
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationBindingMismatch,
		},
		{
			name: "wrong environment",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.EnvironmentID = "local"
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationBindingMismatch,
		},
		{
			name: "company outside tenant domain",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.CompanyID = "company-2"
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationBindingMismatch,
		},
		{
			name: "expired",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.IssuedAt = now.Add(-2 * time.Hour)
				record.ExpiresAt = now.Add(-time.Hour)
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationRecordInvalid,
		},
		{
			name: "over ceiling",
			prepare: func(_ *contracts.CompanyActivationRecord, effectClass *string) {
				*effectClass = "E1"
			},
			wantReason: contracts.ReasonActivationCeilingExceeded,
		},
		{
			name:          "autonomy over ceiling",
			autonomyLevel: "A1",
			wantReason:    contracts.ReasonActivationCeilingExceeded,
		},
		{
			name: "uncertified effect ceiling",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.EffectCeiling = "E1"
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationCeilingExceeded,
		},
		{
			name: "uncertified autonomy ceiling",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.AutonomyCeiling = "A1"
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationCeilingExceeded,
		},
		{
			name: "uncertified exposure ceiling",
			prepare: func(record *contracts.CompanyActivationRecord, _ *string) {
				record.MaxMonthlyExposureCents = 1
				sealRouteCompanyActivationRecord(t, record, privateKey)
			},
			wantReason: contracts.ReasonActivationCeilingExceeded,
		},
		{
			name:       "trust unavailable",
			withoutKey: true,
			wantReason: contracts.ReasonActivationTrustUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := base
			effectClass := "E0"
			autonomyLevel := "A0"
			if test.autonomyLevel != "" {
				autonomyLevel = test.autonomyLevel
			}
			if test.prepare != nil {
				test.prepare(&record, &effectClass)
			}
			capturing := &evaluateRouteCapturingPDP{}
			svc, receipts := newEvaluateRouteTestServices(t, guardian.WithPDP(capturing))
			svc.CompanyActivationEnvironmentID = "managed"
			if !test.withoutKey {
				svc.CompanyActivationPublicKey = publicKey
			}
			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)

			body, err := json.Marshal(api.EvaluateRequest{
				Tool: "EXECUTE_TOOL", Resource: "connector://crm/contact-123", EffectLevel: effectClass,
				SessionID: "activation-session-" + strings.ReplaceAll(test.name, " ", "-"),
				Originator: &contracts.OrganizationRuntimeOriginatorAssertion{
					PrincipalID: "human-originator-1", AssertionSource: contracts.OrganizationRuntimeOriginatorAssertionSourceControlPlane,
				},
				Context: map[string]any{
					"organization_runtime":      "caller-controlled-marker",
					"autonomy_level":            autonomyLevel,
					"company_id":                "caller-company",
					"environment_id":            "caller-environment",
					"effect_class":              "E3",
					"activation_record_ref":     "caller-record",
					"activation_record_hash":    routeActivationHash("9"),
					"company_activation_record": record,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, companyActivationOrganizationRuntimePath, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+testOrganizationRuntimeAPIKey)
			req.Header.Set(tenantHeader, "tenant-1")
			req.Header.Set(principalHeader, "principal-1")
			req.Header.Set(workspaceHeader, "workspace-1")
			req.Header.Set(companyActivationExecutionProfileHeader, companyActivationOrganizationRuntimeProfile)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			var response api.EvaluateResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if test.wantReason == "" {
				if capturing.request == nil {
					t.Fatalf("valid activation did not reach Guardian: response=%+v", response)
				}
				if capturing.request.Context["activation_record_ref"] != record.RecordRef || capturing.request.Context["activation_record_hash"] != record.RecordHash {
					t.Fatalf("Guardian activation binding = ref:%#v hash:%#v", capturing.request.Context["activation_record_ref"], capturing.request.Context["activation_record_hash"])
				}
				if capturing.request.Context["company_id"] != record.CompanyID || capturing.request.Context["environment_id"] != record.EnvironmentID || capturing.request.Context["effect_class"] != effectClass || capturing.request.Context["autonomy_level"] != autonomyLevel {
					t.Fatalf("Guardian canonical runtime context = %#v", capturing.request.Context)
				}
				if capturing.request.Resource != "connector://crm/contact-123" ||
					capturing.request.Context["organization_runtime"] != true ||
					capturing.request.Context["execution_profile"] != companyActivationOrganizationRuntimeProfile {
					t.Fatalf("Guardian execution profile binding = %+v", capturing.request)
				}
				if _, exists := capturing.request.Context["company_activation_record"]; exists {
					t.Fatal("raw company activation record reached Guardian")
				}
				return
			}
			if capturing.request != nil {
				t.Fatalf("activation denial reached Guardian: %+v", capturing.request)
			}
			if response.Verdict != string(contracts.VerdictDeny) || response.ReasonCode != string(test.wantReason) {
				t.Fatalf("response = %+v, want DENY/%s", response, test.wantReason)
			}
			if response.Signature == "" {
				t.Fatal("activation denial decision is unsigned")
			}
			if receipts.stored == nil || receipts.stored.ReasonCode != string(test.wantReason) {
				t.Fatalf("activation denial receipt = %+v", receipts.stored)
			}
			if receipts.stored.Signature == "" {
				t.Fatal("activation denial receipt is unsigned")
			}
		})
	}
}

func TestEvaluateRouteRejectsExecutionProfileRouteMismatch(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "principal-1")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)
	body := []byte(`{"tool":"EXECUTE_TOOL","resource":"connector://crm/contact-123","effect_level":"E0","session_id":"profile-mismatch"}`)

	tests := []struct {
		name    string
		path    string
		profile string
		token   string
	}{
		{name: "organization route without profile", path: companyActivationOrganizationRuntimePath, token: testOrganizationRuntimeAPIKey},
		{name: "generic route with organization profile", path: "/api/v1/evaluate", profile: companyActivationOrganizationRuntimeProfile, token: testAdminAPIKey},
		{name: "organization route with unknown profile", path: companyActivationOrganizationRuntimePath, profile: "unknown", token: testOrganizationRuntimeAPIKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+test.token)
			req.Header.Set(tenantHeader, "tenant-1")
			req.Header.Set(principalHeader, "principal-1")
			req.Header.Set(workspaceHeader, "workspace-1")
			if test.profile != "" {
				req.Header.Set(companyActivationExecutionProfileHeader, test.profile)
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			if receipts.stored != nil {
				t.Fatalf("route/profile mismatch persisted receipt: %+v", receipts.stored)
			}
		})
	}
}

func TestEvaluateRoutesRejectCrossCredentialBypass(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "principal-1")
	svc, receipts := newEvaluateRouteTestServices(t)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	for _, test := range []struct {
		name  string
		path  string
		token string
	}{
		{name: "admin cannot select organization runtime route", path: companyActivationOrganizationRuntimePath, token: testAdminAPIKey},
		{name: "organization runtime cannot select generic route", path: "/api/v1/evaluate", token: testOrganizationRuntimeAPIKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(`{"tool":"EXECUTE_TOOL","resource":"connector://crm/contact-123","effect_level":"E0","session_id":"cross-credential"}`))
			req.Header.Set("Authorization", "Bearer "+test.token)
			req.Header.Set(tenantHeader, "tenant-1")
			req.Header.Set(principalHeader, "principal-1")
			req.Header.Set(workspaceHeader, "workspace-1")
			req.Header.Set(companyActivationExecutionProfileHeader, companyActivationOrganizationRuntimeProfile)
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
			}
			if receipts.stored != nil {
				t.Fatalf("cross-credential request persisted receipt: %+v", receipts.stored)
			}
		})
	}
}

func TestEvaluateRouteKeepsGenericEvaluationOutsideCompanyActivationGate(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "principal-1")
	record, privateKey := routeCompanyActivationRecord(t, time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(time.Hour))
	capturing := &evaluateRouteCapturingPDP{}
	svc, receipts := newEvaluateRouteTestServices(t, guardian.WithPDP(capturing))
	svc.CompanyActivationPublicKey = privateKey.Public().(ed25519.PublicKey)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	body, err := json.Marshal(api.EvaluateRequest{
		Tool: "EXECUTE_TOOL", EffectLevel: "local.echo", SessionID: "generic-session",
		Context: map[string]any{"company_activation_record": record},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-1")
	req.Header.Set(principalHeader, "principal-1")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	var response api.EvaluateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || !response.Allow || receipts.stored == nil {
		t.Fatalf("generic evaluation was gated: status=%d response=%+v receipt=%+v", recorder.Code, response, receipts.stored)
	}
	if capturing.request == nil {
		t.Fatal("generic evaluation did not reach Guardian")
	}
	if _, exists := capturing.request.Context["company_activation_record"]; exists {
		t.Fatal("caller activation record leaked into generic Guardian context")
	}
}

func TestConfiguredCompanyActivationPublicKey(t *testing.T) {
	seed := sha256.Sum256([]byte("company-activation-config-test-key"))
	publicKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	encoded := hex.EncodeToString(publicKey)
	for _, value := range []string{encoded, "ed25519:" + encoded} {
		t.Setenv(companyActivationPublicKeyEnv, value)
		configured, err := configuredCompanyActivationPublicKey()
		if err != nil || !bytes.Equal(configured, publicKey) {
			t.Fatalf("configured key = %x, err=%v", configured, err)
		}
	}
	t.Setenv(companyActivationPublicKeyEnv, strings.ToUpper(encoded))
	if _, err := configuredCompanyActivationPublicKey(); err == nil {
		t.Fatal("uppercase activation public key was accepted")
	}
}

func TestConfiguredCompanyActivationEnvironmentID(t *testing.T) {
	for input, want := range map[string]string{
		"": "managed", "managed": "managed", " LOCAL ": "local",
		"HIGH_ASSURANCE": "high-assurance", "high-assurance": "high-assurance",
	} {
		t.Run(input, func(t *testing.T) {
			t.Setenv(companyActivationDeploymentModeEnv, input)
			got, err := configuredCompanyActivationEnvironmentID()
			if err != nil || got != want {
				t.Fatalf("environment ID = %q, want %q", got, want)
			}
		})
	}
	t.Setenv(companyActivationDeploymentModeEnv, "unknown")
	if _, err := configuredCompanyActivationEnvironmentID(); err == nil {
		t.Fatal("unknown deployment mode was accepted")
	}
}

func TestValidateCompanyActivationRuntimeConfigurationRequiresPairedTrust(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for _, test := range []struct {
		name      string
		publicKey ed25519.PublicKey
		key       string
		wantErr   bool
	}{
		{name: "disabled"},
		{name: "configured", publicKey: publicKey, key: testOrganizationRuntimeAPIKey},
		{name: "public key only", publicKey: publicKey, wantErr: true},
		{name: "credential only", key: testOrganizationRuntimeAPIKey, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCompanyActivationRuntimeConfiguration(test.publicKey, test.key)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func routeCompanyActivationRecord(t *testing.T, issuedAt, expiresAt time.Time) (contracts.CompanyActivationRecord, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("company-activation-route-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	record := contracts.CompanyActivationRecord{
		SchemaVersion: contracts.CompanyActivationRecordSchemaV1,
		RecordRef:     "activation-record-1", TenantID: "tenant-1", CompanyID: "tenant-1",
		WorkspaceID: "workspace-1", EnvironmentID: "managed",
		PackID: "company-builder", PackVersion: "1.0.0", PackManifestHash: routeActivationHash("1"),
		ActivationDecisionRef: "decision-1", ActivationDecisionTargetHash: routeActivationHash("2"),
		GenesisCeremonyRef: "ceremony-1", GenesisReceiptHash: routeActivationHash("3"),
		InstallReceiptRef: "install-1", InstallReceiptHash: routeActivationHash("4"),
		EffectCeiling: "E0", AutonomyCeiling: "A0", MaxMonthlyExposureCents: 0,
		CertificationDigest: routeActivationHash("5"), Status: contracts.CompanyActivationRecordStatusActive,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
		SignatureProfile:   contracts.CompanyActivationRecordSignatureProfile,
		SignatureAlgorithm: contracts.CompanyActivationRecordSignatureAlgorithm,
		SigningKeyID:       "control-plane-key-1",
	}
	sealRouteCompanyActivationRecord(t, &record, privateKey)
	return record, privateKey
}

func sealRouteCompanyActivationRecord(t *testing.T, record *contracts.CompanyActivationRecord, privateKey ed25519.PrivateKey) {
	t.Helper()
	canonical, err := record.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	record.CanonicalBytes = canonical
	record.RecordHash = "sha256:" + hex.EncodeToString(digest[:])
	record.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, digest[:]))
}

func routeActivationHash(digit string) string {
	return "sha256:" + strings.Repeat(digit, 64)
}
