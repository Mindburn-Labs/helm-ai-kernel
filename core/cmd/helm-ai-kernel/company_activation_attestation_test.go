package main

// quantum_posture: these tests cover classical Ed25519 decision attestation;
// they do not establish post-quantum security.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func TestOrganizationRuntimeDecisionAttestationEndToEnd(t *testing.T) {
	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(organizationRuntimeAPIKeyEnv, testOrganizationRuntimeAPIKey)
	t.Setenv(runtimeTenantIDEnv, "tenant-1")
	t.Setenv(runtimePrincipalIDEnv, "helm-workflow-runner")
	now := time.Now().UTC()
	record, activationPrivateKey := routeCompanyActivationRecord(t, now.Add(-time.Hour), now.Add(time.Hour))
	capturing := &evaluateRouteCapturingPDP{}
	svc, _ := newEvaluateRouteTestServices(t, guardian.WithPDP(capturing))
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		t.Fatal(err)
	}
	svc.ReceiptStore = receiptStore
	svc.DataDir = t.TempDir()
	svc.CompanyActivationEnvironmentID = "managed"
	svc.CompanyActivationPublicKey = activationPrivateKey.Public().(ed25519.PublicKey)
	mux := http.NewServeMux()
	registerReceiptRoutes(mux, svc)

	post := func(sessionID string, activation contracts.CompanyActivationRecord) api.EvaluateResponse {
		t.Helper()
		body, err := json.Marshal(api.EvaluateRequest{
			Tool: "EXECUTE_TOOL", Resource: "connector://crm/contact-123", EffectLevel: "E0", SessionID: sessionID,
			Args: map[string]any{"business_field": "kept", "requesting_principal_id": "spoofed-arg-requester"},
			Originator: &contracts.OrganizationRuntimeOriginatorAssertion{
				PrincipalID: "human-originator-1", AssertionSource: contracts.OrganizationRuntimeOriginatorAssertionSourceControlPlane,
			},
			Context: map[string]any{
				"autonomy_level":              "A0",
				"company_activation_record":   activation,
				"requesting_principal_id":     "spoofed-requester",
				"originator_principal_id":     "spoofed-originator",
				"originator_assertion_source": "spoofed-source",
				"activation_record_ref":       "spoofed-activation",
				"activation_record_hash":      routeActivationHash("9"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, companyActivationOrganizationRuntimePath, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testOrganizationRuntimeAPIKey)
		req.Header.Set(tenantHeader, "tenant-1")
		req.Header.Set(principalHeader, "helm-workflow-runner")
		req.Header.Set(workspaceHeader, "workspace-1")
		req.Header.Set(companyActivationExecutionProfileHeader, companyActivationOrganizationRuntimeProfile)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("organization runtime status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		var response api.EvaluateResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	response := post("attestation-valid", record)
	if response.OrganizationRuntimeDecisionAttestation == nil {
		t.Fatalf("organization runtime companion missing: response=%+v", response)
	}
	stored := fetchOrganizationRuntimeReceipt(t, mux, response.ReceiptID)
	assertOrganizationRuntimeReceiptSignatures(t, svc, &stored)
	attestation := stored.OrganizationRuntimeDecisionAttestation
	if attestation.ExecutorPrincipalID != "helm-workflow-runner" || attestation.OriginatorPrincipalID != "human-originator-1" ||
		attestation.OriginatorAssertionSource != contracts.OrganizationRuntimeOriginatorAssertionSourceControlPlane {
		t.Fatalf("executor/originator binding = %+v", attestation)
	}
	if attestation.ActivationIdentityKind != contracts.OrganizationRuntimeActivationIdentityVerified ||
		attestation.ActivationRecordRef != record.RecordRef || attestation.ActivationRecordHash != record.RecordHash {
		t.Fatalf("verified activation binding = %+v", attestation)
	}
	if capturing.request == nil {
		t.Fatal("valid organization runtime request did not reach Guardian")
	}
	for _, alias := range []string{
		"requesting_principal_id", "originator_principal_id", "originator_assertion_source",
	} {
		if _, exists := capturing.request.Context[alias]; exists {
			t.Fatalf("caller authority alias %q reached policy context: %#v", alias, capturing.request.Context)
		}
	}
	canonicalOriginator, ok := capturing.request.Context[organizationRuntimeOriginatorContextKey].(map[string]any)
	if !ok || canonicalOriginator["principal_id"] != "human-originator-1" ||
		canonicalOriginator["assertion_source"] != contracts.OrganizationRuntimeOriginatorAssertionSourceControlPlane {
		t.Fatalf("canonical originator assertion = %#v", capturing.request.Context[organizationRuntimeOriginatorContextKey])
	}
	if capturing.request.Context["activation_record_ref"] != record.RecordRef || capturing.request.Context["activation_record_hash"] != record.RecordHash {
		t.Fatalf("canonical activation identity = %#v", capturing.request.Context)
	}
	policyArgs, ok := capturing.request.Context["args"].(map[string]any)
	if !ok || policyArgs["business_field"] != "kept" {
		t.Fatalf("sanitized policy args = %#v", capturing.request.Context["args"])
	}
	if _, exists := policyArgs["requesting_principal_id"]; exists {
		t.Fatalf("originator alias reached nested policy args: %#v", policyArgs)
	}
	countBeforeAliasOnly, err := receiptStore.CountReceipts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	aliasOnlyBody, err := json.Marshal(api.EvaluateRequest{
		Tool: "EXECUTE_TOOL", Resource: "connector://crm/contact-123", EffectLevel: "E0", SessionID: "alias-only-originator",
		Context: map[string]any{
			"autonomy_level":            "A0",
			"company_activation_record": record,
			"requesting_principal_id":   "human-originator-1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	aliasOnlyRequest := httptest.NewRequest(http.MethodPost, companyActivationOrganizationRuntimePath, bytes.NewReader(aliasOnlyBody))
	aliasOnlyRequest.Header.Set("Authorization", "Bearer "+testOrganizationRuntimeAPIKey)
	aliasOnlyRequest.Header.Set(tenantHeader, "tenant-1")
	aliasOnlyRequest.Header.Set(principalHeader, "helm-workflow-runner")
	aliasOnlyRequest.Header.Set(workspaceHeader, "workspace-1")
	aliasOnlyRequest.Header.Set(companyActivationExecutionProfileHeader, companyActivationOrganizationRuntimeProfile)
	aliasOnlyRecorder := httptest.NewRecorder()
	mux.ServeHTTP(aliasOnlyRecorder, aliasOnlyRequest)
	countAfterAliasOnly, err := receiptStore.CountReceipts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if aliasOnlyRecorder.Code != http.StatusBadRequest || countAfterAliasOnly != countBeforeAliasOnly {
		t.Fatalf("context-only originator was not rejected before persistence: status=%d body=%s", aliasOnlyRecorder.Code, aliasOnlyRecorder.Body.String())
	}

	fetched := fetchOrganizationRuntimeReceipt(t, mux, response.ReceiptID)
	assertOrganizationRuntimeReceiptSignatures(t, svc, &fetched)
	packedReceipt, packedAttestation := readOrganizationRuntimeEvidencePack(t, svc.DataDir, response.ReceiptID)
	assertOrganizationRuntimeReceiptSignatures(t, svc, &packedReceipt)
	if packedAttestation.Signature != packedReceipt.OrganizationRuntimeDecisionAttestation.Signature {
		t.Fatal("portable attestation artifact does not match the packed receipt companion")
	}

	substitutions := []struct {
		name   string
		mutate func(*contracts.OrganizationRuntimeDecisionAttestationV1)
	}{
		{name: "executor", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.ExecutorPrincipalID = "other-runner" }},
		{name: "originator", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.OriginatorPrincipalID = "other-human" }},
		{name: "originator source", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			a.OriginatorAssertionSource = "other-control-plane"
		}},
		{name: "activation ref", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			a.ActivationRecordRef = "other-activation"
		}},
		{name: "activation hash", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			a.ActivationRecordHash = routeActivationHash("8")
		}},
		{name: "presented activation", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			a.PresentedActivationIdentityHash = routeActivationHash("7")
		}},
		{name: "activation identity kind", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			a.ActivationIdentityKind = contracts.OrganizationRuntimeActivationIdentityPresented
			a.ActivationRecordRef = ""
			a.ActivationRecordHash = ""
		}},
		{name: "company", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.CompanyID = "other-company" }},
		{name: "environment", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.EnvironmentID = "other-environment" }},
		{name: "tenant", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.TenantID = "other-tenant" }},
		{name: "workspace", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.WorkspaceID = "other-workspace" }},
		{name: "effect", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.EffectClass = "E1" }},
		{name: "autonomy", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.AutonomyLevel = "A1" }},
		{name: "receipt", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.ReceiptID = "other-receipt" }},
		{name: "decision", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.DecisionID = "other-decision" }},
		{name: "output", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.OutputHash = routeActivationHash("6") }},
		{name: "verdict", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			if a.Verdict == string(contracts.VerdictAllow) {
				a.Verdict = string(contracts.VerdictDeny)
			} else {
				a.Verdict = string(contracts.VerdictAllow)
			}
		}},
		{name: "reason code", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			if a.ReasonCode == "PDP_DENY" {
				a.ReasonCode = "POLICY_VIOLATION"
			} else {
				a.ReasonCode = "PDP_DENY"
			}
		}},
		{name: "reason", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) { a.Reason = "substituted reason" }},
		{name: "timestamp", mutate: func(a *contracts.OrganizationRuntimeDecisionAttestationV1) {
			a.Timestamp = a.Timestamp.Add(time.Second)
		}},
	}
	for _, substitution := range substitutions {
		t.Run("reject substitution "+substitution.name, func(t *testing.T) {
			candidate := fetched
			candidateAttestation := *fetched.OrganizationRuntimeDecisionAttestation
			candidate.OrganizationRuntimeDecisionAttestation = &candidateAttestation
			substitution.mutate(&candidateAttestation)
			if err := contracts.VerifyOrganizationRuntimeReceiptAttestation(&candidate, svc.ReceiptSigner.PublicKeyBytes()); err == nil {
				t.Fatal("substituted organization runtime attestation verified")
			}
		})
	}
	missing := fetched
	missing.OrganizationRuntimeDecisionAttestation = nil
	if err := contracts.VerifyOrganizationRuntimeReceiptAttestation(&missing, svc.ReceiptSigner.PublicKeyBytes()); err == nil {
		t.Fatal("organization runtime verification accepted a missing companion")
	}

	tampered := record
	tampered.PackID = "tampered-pack"
	capturing.request = nil
	denied := post("attestation-early-denial", tampered)
	if denied.Verdict != string(contracts.VerdictDeny) || denied.ReasonCode != string(contracts.ReasonActivationRecordInvalid) || capturing.request != nil {
		t.Fatalf("early activation denial = %+v Guardian=%+v", denied, capturing.request)
	}
	storedDenial := fetchOrganizationRuntimeReceipt(t, mux, denied.ReceiptID)
	assertOrganizationRuntimeReceiptSignatures(t, svc, &storedDenial)
	denialAttestation := storedDenial.OrganizationRuntimeDecisionAttestation
	if denialAttestation.ActivationIdentityKind != contracts.OrganizationRuntimeActivationIdentityPresented ||
		denialAttestation.ActivationRecordRef != "" || denialAttestation.ActivationRecordHash != "" ||
		denialAttestation.PresentedActivationIdentityHash != presentedCompanyActivationIdentityHash(true, tampered) ||
		denialAttestation.PresentedActivationIdentityHash == attestation.PresentedActivationIdentityHash {
		t.Fatalf("early denial activation presentation = %+v", denialAttestation)
	}
	_, packedDenialAttestation := readOrganizationRuntimeEvidencePack(t, svc.DataDir, denied.ReceiptID)
	if packedDenialAttestation.Signature != denialAttestation.Signature {
		t.Fatal("early denial companion missing from portable evidence pack")
	}
}

func assertOrganizationRuntimeReceiptSignatures(t *testing.T, svc *Services, receipt *contracts.Receipt) {
	t.Helper()
	verifier, ok := svc.ReceiptSigner.(interface {
		VerifyReceipt(*contracts.Receipt) (bool, error)
	})
	if !ok {
		t.Fatalf("test receipt signer %T cannot verify", svc.ReceiptSigner)
	}
	valid, err := verifier.VerifyReceipt(receipt)
	if err != nil || !valid {
		t.Fatalf("Receipt V5 signature invalid: valid=%v err=%v", valid, err)
	}
	if err := contracts.VerifyOrganizationRuntimeReceiptAttestation(receipt, svc.ReceiptSigner.PublicKeyBytes()); err != nil {
		t.Fatalf("organization runtime companion signature invalid: %v", err)
	}
}

func fetchOrganizationRuntimeReceipt(t *testing.T, mux *http.ServeMux, receiptID string) contracts.Receipt {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/receipts/"+receiptID, nil)
	req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
	req.Header.Set(tenantHeader, "tenant-1")
	req.Header.Set(principalHeader, "helm-workflow-runner")
	req.Header.Set(workspaceHeader, "workspace-1")
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("receipt fetch status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var receipt contracts.Receipt
	if err := json.Unmarshal(recorder.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func readOrganizationRuntimeEvidencePack(t *testing.T, dataDir, receiptID string) (contracts.Receipt, contracts.OrganizationRuntimeDecisionAttestationV1) {
	t.Helper()
	packPath := portableEvaluateEvidencePackPath(dataDir, receiptID)
	receiptRaw, err := readTarEntry(packPath, "02_PROOFGRAPH/receipts/"+sanitizeReceiptFileName(receiptID)+".json")
	if err != nil {
		t.Fatal(err)
	}
	attestationRaw, err := readTarEntry(packPath, "02_PROOFGRAPH/attestations/"+sanitizeReceiptFileName(receiptID)+".organization-runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt contracts.Receipt
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	var attestation contracts.OrganizationRuntimeDecisionAttestationV1
	if err := json.Unmarshal(attestationRaw, &attestation); err != nil {
		t.Fatal(err)
	}
	return receipt, attestation
}
