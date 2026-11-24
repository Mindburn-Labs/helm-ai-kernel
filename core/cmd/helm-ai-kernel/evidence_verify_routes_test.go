package main

// quantum_posture: These route tests use classical Ed25519 receipt signatures.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func TestEvidenceVerifyDetectsTamperedEvidenceBundle(t *testing.T) {
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)

	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"verified-session","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}

	tampered, err := tamperEvidenceReceipt(exportRec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(tampered))
	verifyReq.Header.Set("Content-Type", "application/octet-stream")
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["outcome"] != "FAILED" {
		t.Fatalf("expected tampered bundle to fail verification, got %+v", result)
	}
	if !resultErrorsContain(result, "trusted evidence bundle seal verification failed") {
		t.Fatalf("expected trusted seal failure, got %+v", result)
	}
}

// A bundle sealed and signed by a key it carries about itself is intact but
// unproven: UNVERIFIABLE, never VERIFIED, and not FAILED either.
func TestEvidenceVerifyReportsForgedSelfConsistentBundleUnverifiable(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	trustedSigner, err := helmcrypto.NewHybridSigner("trusted")
	if err != nil {
		t.Fatalf("create trusted signer: %v", err)
	}
	forgedSigner, err := helmcrypto.NewHybridSigner("forged")
	if err != nil {
		t.Fatalf("create forged signer: %v", err)
	}
	valid := &contracts.Receipt{
		ReceiptID:    "rcpt-trusted",
		DecisionID:   "dec-trusted",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		SessionID:    "trusted-session",
		LamportClock: 1,
		ArgsHash:     "args-trusted",
	}
	if err := trustedSigner.SignReceipt(valid); err != nil {
		t.Fatalf("sign trusted receipt: %v", err)
	}
	forged := *valid
	forged.ReceiptID = "rcpt-forged"
	forged.DecisionID = "dec-forged"
	forged.SessionID = "forged-session"
	forged.ArgsHash = "args-forged"
	forged.Signature = ""
	if err := forgedSigner.SignReceipt(&forged); err != nil {
		t.Fatalf("sign forged receipt: %v", err)
	}

	validBundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("trusted-session", []*contracts.Receipt{valid}, nil, &Services{ReceiptSigner: trustedSigner})
	if err != nil {
		t.Fatalf("build trusted bundle: %v", err)
	}
	forgedBundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("forged-session", []*contracts.Receipt{&forged}, nil, &Services{ReceiptSigner: forgedSigner})
	if err != nil {
		t.Fatalf("build forged bundle: %v", err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: trustedSigner})

	for _, endpoint := range []string{"/api/v1/evidence/verify"} {
		t.Run(endpoint+" trusted", func(t *testing.T) {
			result := postEvidenceVerification(t, mux, endpoint, validBundle)
			if result["outcome"] != "VERIFIED" {
				t.Fatalf("trusted bundle verification = %+v", result)
			}
		})
		t.Run(endpoint+" forged", func(t *testing.T) {
			result := postEvidenceVerification(t, mux, endpoint, forgedBundle)
			if result["outcome"] != "UNVERIFIABLE" {
				t.Fatalf("forged bundle verification = %+v", result)
			}
			statuses := evidenceCheckStatuses(t, result)
			if statuses["bundle_seal"] != "UNVERIFIABLE" || statuses["receipt_signatures"] != "UNVERIFIABLE" {
				t.Fatalf("self-supplied key must leave seal and signatures unverifiable: %+v", result)
			}
			if statuses["manifest_hashes"] != "VERIFIED" || statuses["receipt_chain"] != "VERIFIED" {
				t.Fatalf("intact forged bundle should still pass its integrity checks: %+v", result)
			}
		})
	}
}

func TestEvidenceVerifyRejectsTamperedUnsignedReceiptAttachments(t *testing.T) {
	svc, cleanup := newVerifiedEvidenceRouteTestServices(t)
	defer cleanup()
	registry := boundarypkg.NewSurfaceRegistry(func() time.Time { return time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC) })
	scope, err := registry.PutVerificationScope(contracts.VerificationScope{
		VerificationScopeID: "scope-unsigned",
		SubjectHash:         "sha256:subject-unsigned",
		RiskClass:           "T2",
		ChecksPerformed:     []string{"hash"},
		VerifierHash:        "sha256:verifier",
		PolicyHash:          "sha256:policy",
	})
	if err != nil {
		t.Fatalf("seed verification scope: %v", err)
	}
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "unsigned-fields-session", &contracts.Receipt{
		ReceiptID:    "rcpt-unsigned-fields",
		DecisionID:   "dec-unsigned-fields",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 2, 0, time.UTC),
		ExecutorID:   "agent.test",
		DecisionHash: "sha256:unsigned-fields-decision",
		ArgsHash:     "args-unsigned-fields",
		ScopeHash:    scope.ScopeHash,
		Evidence: map[string]string{
			"scope_ref": scope.ScopeHash,
		},
		Metadata: map[string]any{
			"risk_class": "T2",
			"scope_hash": scope.ScopeHash,
		},
	}, svc.ReceiptSigner)
	svc.BoundarySurfaces = registry

	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)
	exportReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/export", strings.NewReader(`{"session_id":"unsigned-fields-session","format":"tar.gz"}`))
	authorizeTestRequest(exportReq)
	exportRec := httptest.NewRecorder()
	mux.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", exportRec.Code, exportRec.Body.String())
	}

	tampered, err := tamperEvidenceReceiptFields(exportRec.Body.Bytes(), func(receipt *contracts.Receipt) {
		receipt.ScopeHash = "sha256:tampered-scope"
		if receipt.Evidence == nil {
			receipt.Evidence = map[string]string{}
		}
		receipt.Evidence["scope_ref"] = "sha256:tampered-scope"
		if receipt.Metadata == nil {
			receipt.Metadata = map[string]any{}
		}
		receipt.Metadata["scope_hash"] = "sha256:tampered-scope"
		receipt.Metadata["operator_note"] = "tampered after issuance"
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := readEvidenceBundle(tampered)
	if err != nil {
		t.Fatalf("read tampered bundle: %v", err)
	}
	var tamperedReceipt contracts.Receipt
	for name, data := range parsed.Files {
		if strings.HasPrefix(name, "receipts/") {
			if err := json.Unmarshal(data, &tamperedReceipt); err != nil {
				t.Fatalf("decode tampered receipt: %v", err)
			}
			break
		}
	}
	if err := verifyTrustedEvidenceReceipt(svc, &tamperedReceipt); err != nil {
		t.Fatalf("tampered unsigned fields unexpectedly broke receipt signature: %v", err)
	}

	for _, endpoint := range []string{"/api/v1/evidence/verify"} {
		result := postEvidenceVerification(t, mux, endpoint, tampered)
		if result["outcome"] != "FAILED" {
			t.Fatalf("%s expected tampered unsigned fields to fail, got %+v", endpoint, result)
		}
		if !resultErrorsContain(result, "trusted evidence bundle seal verification failed") {
			t.Fatalf("%s expected trusted seal failure, got %+v", endpoint, result)
		}
	}
}

func TestTrustedEvidenceBundleSealSignerRejectsUnsupportedRuntimeProfiles(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "")
	mldsaSigner, err := helmcrypto.NewMLDSASigner("mldsa-only")
	if err != nil {
		t.Fatalf("create mldsa signer: %v", err)
	}
	if _, _, err := trustedEvidenceBundleSealSigner(&Services{ReceiptSigner: mldsaSigner}); err == nil || !strings.Contains(err.Error(), "MLDSA-only") {
		t.Fatalf("expected MLDSA-only compatibility error, got %v", err)
	}

	keyring := helmcrypto.NewKeyRing()
	edSigner, err := helmcrypto.NewEd25519Signer("keyring-ed25519")
	if err != nil {
		t.Fatalf("create keyring signer: %v", err)
	}
	keyring.AddKey(edSigner)
	if _, _, err := trustedEvidenceBundleSealSigner(&Services{ReceiptSigner: keyring}); err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("expected keyring compatibility error, got %v", err)
	}
}

func TestEvidenceVerifyDetectsReceiptChainBreakWithValidManifest(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("chain-test")
	if err != nil {
		t.Fatal(err)
	}
	good := &contracts.Receipt{
		ReceiptID:    "rcpt-good",
		DecisionID:   "dec-good",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-good",
		LamportClock: 1,
		ArgsHash:     "args-good",
	}
	broken := &contracts.Receipt{
		ReceiptID:    "rcpt-broken",
		DecisionID:   "dec-broken",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 1, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		Signature:    "sig-broken",
		PrevHash:     "wrong-prev-hash",
		LamportClock: 2,
		ArgsHash:     "args-broken",
	}
	if err := signer.SignReceipt(good); err != nil {
		t.Fatal(err)
	}
	if err := signer.SignReceipt(broken); err != nil {
		t.Fatal(err)
	}
	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("session-test", []*contracts.Receipt{good, broken}, nil, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build valid-manifest bundle: %v", err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(bundle))
	verifyReq.Header.Set("Content-Type", "application/octet-stream")
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["outcome"] != "FAILED" {
		t.Fatalf("expected chain break to fail verification, got %+v", result)
	}
	statuses := evidenceCheckStatuses(t, result)
	if statuses["receipt_chain"] != "FAILED" || statuses["receipt_signatures"] != "VERIFIED" {
		t.Fatalf("expected only the receipt chain to fail, got %+v", result)
	}
}

func TestEvidenceVerifyScopesReceiptChainsBySession(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("session-chain-test")
	if err != nil {
		t.Fatal(err)
	}
	newReceipt := func(id, sessionID string, lamport uint64, prevHash string) *contracts.Receipt {
		return &contracts.Receipt{
			ReceiptID:    id,
			DecisionID:   "decision-" + id,
			EffectID:     "EXECUTE_TOOL",
			Status:       string(contracts.VerdictAllow),
			Timestamp:    time.Date(2026, 5, 5, 0, int(lamport), 0, 0, time.UTC),
			ExecutorID:   "agent.test",
			SessionID:    sessionID,
			PrevHash:     prevHash,
			LamportClock: lamport,
			ArgsHash:     "args-" + id,
		}
	}

	firstSessionGenesis := newReceipt("first-session-1", "session-first", 1, "")
	if err := signer.SignReceipt(firstSessionGenesis); err != nil {
		t.Fatal(err)
	}
	firstSessionHash, err := contracts.ReceiptChainHash(firstSessionGenesis)
	if err != nil {
		t.Fatal(err)
	}
	firstSessionNext := newReceipt("first-session-2", "session-first", 2, firstSessionHash)
	if err := signer.SignReceipt(firstSessionNext); err != nil {
		t.Fatal(err)
	}
	secondSessionGenesis := newReceipt("second-session-1", "session-second", 1, "")
	if err := signer.SignReceipt(secondSessionGenesis); err != nil {
		t.Fatal(err)
	}
	secondSessionHash, err := contracts.ReceiptChainHash(secondSessionGenesis)
	if err != nil {
		t.Fatal(err)
	}
	secondSessionNext := newReceipt("second-session-2", "session-second", 2, secondSessionHash)
	if err := signer.SignReceipt(secondSessionNext); err != nil {
		t.Fatal(err)
	}

	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("", []*contracts.Receipt{
		firstSessionNext,
		secondSessionNext,
		firstSessionGenesis,
		secondSessionGenesis,
	}, nil, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build multi-session evidence bundle: %v", err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/evidence/verify", bytes.NewReader(bundle))
	verifyReq.Header.Set("Content-Type", "application/octet-stream")
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["outcome"] != "VERIFIED" {
		t.Fatalf("expected independent session chains to verify, got %+v", result)
	}
	if evidenceCheckStatuses(t, result)["receipt_chain"] != "VERIFIED" {
		t.Fatalf("expected receipt chain verification to pass, got %+v", result)
	}
}

func newVerifiedEvidenceRouteTestServices(t *testing.T) (*Services, func()) {
	t.Helper()
	t.Setenv("HELM_PRODUCTION", "")
	svc, cleanup := newContractRouteTestServices(t)
	signer, err := helmcrypto.NewEd25519Signer("evidence-route-test")
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	svc.ReceiptSigner = signer
	appendTenantScopedReceipt(t, svc.ReceiptStore.(*store.SQLiteReceiptStore), defaultRuntimeTenantID, "verified-session", &contracts.Receipt{
		ReceiptID:    "rcpt-verified",
		DecisionID:   "dec-verified",
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		DecisionHash: "sha256:verified-decision",
		ArgsHash:     "args-verified",
	}, signer)
	return svc, cleanup
}

func tamperEvidenceReceipt(bundle []byte) ([]byte, error) {
	return tamperEvidenceReceiptFields(bundle, func(receipt *contracts.Receipt) {
		receipt.Signature = strings.Repeat("0", len(receipt.Signature))
	})
}

func tamperEvidenceReceiptFields(bundle []byte, mutate func(*contracts.Receipt)) ([]byte, error) {
	files, err := readRawEvidenceBundleFiles(bundle)
	if err != nil {
		return nil, err
	}
	for name, data := range files {
		if strings.HasPrefix(name, "receipts/") {
			var receipt contracts.Receipt
			if err := json.Unmarshal(data, &receipt); err != nil {
				return nil, err
			}
			mutate(&receipt)
			updated, err := json.Marshal(&receipt)
			if err != nil {
				return nil, err
			}
			files[name] = updated
			return tarEvidenceBundleFiles(files)
		}
	}
	return nil, fmt.Errorf("evidence bundle has no receipt")
}

func readRawEvidenceBundleFiles(bundle []byte) (map[string][]byte, error) {
	if len(bundle) == 0 {
		return nil, fmt.Errorf("empty evidence bundle")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, err
		}
		files[header.Name] = data
	}
}

// evidenceCheckStatuses maps each check in checks_run to its status and fails
// the test on a duplicate check or a status outside the evidence verifier
// vocabulary.
func evidenceCheckStatuses(t *testing.T, result map[string]any) map[string]string {
	t.Helper()
	checks, ok := result["checks_run"].([]any)
	if !ok {
		t.Fatalf("checks_run missing or not a list: %+v", result)
	}
	statuses := make(map[string]string, len(checks))
	for _, raw := range checks {
		check, _ := raw.(map[string]any)
		name, _ := check["name"].(string)
		status, _ := check["status"].(string)
		detail, _ := check["detail"].(string)
		if name == "" || detail == "" {
			t.Fatalf("check without name or detail: %+v", check)
		}
		switch status {
		case "VERIFIED", "FAILED", "UNVERIFIABLE":
		default:
			t.Fatalf("check %s has status %q outside VERIFIED/FAILED/UNVERIFIABLE", name, status)
		}
		if _, dup := statuses[name]; dup {
			t.Fatalf("check %s reported twice: %+v", name, result)
		}
		statuses[name] = status
	}
	return statuses
}

func resultErrorsContain(result map[string]any, want string) bool {
	values, _ := result["errors"].([]any)
	for _, value := range values {
		if text, ok := value.(string); ok && strings.Contains(text, want) {
			return true
		}
	}
	return false
}

func postEvidenceVerification(t *testing.T, mux *http.ServeMux, endpoint string, bundle []byte) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bundle))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify %s status=%d body=%s", endpoint, rec.Code, rec.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func newEvidenceVerifyTestReceipt(id, sessionID string, lamport uint64, prevHash string) *contracts.Receipt {
	return &contracts.Receipt{
		ReceiptID:    id,
		DecisionID:   "decision-" + id,
		EffectID:     "EXECUTE_TOOL",
		Status:       string(contracts.VerdictAllow),
		Timestamp:    time.Date(2026, 5, 5, 0, int(lamport), 0, 0, time.UTC),
		ExecutorID:   "agent.test",
		SessionID:    sessionID,
		PrevHash:     prevHash,
		LamportClock: lamport,
		ArgsHash:     "args-" + id,
	}
}

func signedEvidenceVerifyTestBundle(t *testing.T, signer helmcrypto.Signer) []byte {
	t.Helper()
	first := newEvidenceVerifyTestReceipt("contract-1", "contract-session", 1, "")
	if err := signer.SignReceipt(first); err != nil {
		t.Fatal(err)
	}
	firstHash, err := contracts.ReceiptChainHash(first)
	if err != nil {
		t.Fatal(err)
	}
	second := newEvidenceVerifyTestReceipt("contract-2", "contract-session", 2, firstHash)
	if err := signer.SignReceipt(second); err != nil {
		t.Fatal(err)
	}
	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("contract-session", []*contracts.Receipt{first, second}, nil, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatalf("build evidence bundle: %v", err)
	}
	return bundle
}

// The response names only checks that ran, in the evidence verifier
// vocabulary, and carries none of the retired synthesized fields.
func TestEvidenceVerifyReportsOnlyChecksThatRan(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("contract-signer")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", signedEvidenceVerifyTestBundle(t, signer))
	if result["outcome"] != "VERIFIED" {
		t.Fatalf("outcome = %v, want VERIFIED: %+v", result["outcome"], result)
	}
	for _, retired := range []string{"verdict", "checks"} {
		if _, ok := result[retired]; ok {
			t.Fatalf("response still carries retired field %q: %+v", retired, result)
		}
	}
	checks, _ := result["checks_run"].([]any)
	var names []string
	for _, raw := range checks {
		check, _ := raw.(map[string]any)
		name, _ := check["name"].(string)
		names = append(names, name)
		if check["status"] != "VERIFIED" {
			t.Fatalf("check %s = %v, want VERIFIED", name, check["status"])
		}
	}
	want := []string{"bundle_format", "bundle_seal", "manifest_hashes", "receipt_signatures", "receipt_chain"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("checks_run = %v, want %v (required_artifacts must not appear when no receipt requires an artifact, policy_compliance never)", names, want)
	}
	if roots, _ := result["roots"].(map[string]any); roots["entry_count"] != float64(2) {
		t.Fatalf("roots = %+v, want entry_count 2", result["roots"])
	}
	if errs, _ := result["errors"].([]any); len(errs) != 0 {
		t.Fatalf("errors = %v, want none", errs)
	}
}

// Without a runtime trust anchor nothing can be proven: the seal and the
// signatures are UNVERIFIABLE while the integrity checks still run.
func TestEvidenceVerifyWithoutTrustAnchorIsUnverifiable(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("unanchored-signer")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", signedEvidenceVerifyTestBundle(t, signer))
	if result["outcome"] != "UNVERIFIABLE" {
		t.Fatalf("outcome = %v, want UNVERIFIABLE: %+v", result["outcome"], result)
	}
	statuses := evidenceCheckStatuses(t, result)
	if statuses["bundle_seal"] != "UNVERIFIABLE" || statuses["receipt_signatures"] != "UNVERIFIABLE" {
		t.Fatalf("seal and signatures must be unverifiable without a trust anchor: %+v", result)
	}
	if statuses["manifest_hashes"] != "VERIFIED" || statuses["receipt_chain"] != "VERIFIED" {
		t.Fatalf("integrity checks should still run: %+v", result)
	}
}

// A receipt that fails under the runtime key is UNVERIFIABLE when it verifies
// under the key it carries, and FAILED when it verifies under nothing.
func TestEvidenceVerifyClassifiesReceiptsSignedByAnotherKey(t *testing.T) {
	trusted, err := helmcrypto.NewEd25519Signer("runtime-signer")
	if err != nil {
		t.Fatal(err)
	}
	other, err := helmcrypto.NewEd25519Signer("other-signer")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: trusted})

	for _, tc := range []struct {
		name           string
		stripCarried   bool
		wantSignatures string
	}{
		{name: "carried key", wantSignatures: "UNVERIFIABLE"},
		{name: "no carried key", stripCarried: true, wantSignatures: "FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt := newEvidenceVerifyTestReceipt("other-1", "other-session", 1, "")
			if err := other.SignReceipt(receipt); err != nil {
				t.Fatal(err)
			}
			if tc.stripCarried {
				receipt.PublicKeySet = nil
			}
			// Sealed by the runtime key, so only the receipt signature differs.
			bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("other-session", []*contracts.Receipt{receipt}, nil, &Services{ReceiptSigner: trusted})
			if err != nil {
				t.Fatal(err)
			}
			result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", bundle)
			statuses := evidenceCheckStatuses(t, result)
			if statuses["bundle_seal"] != "VERIFIED" {
				t.Fatalf("runtime-sealed bundle seal = %s: %+v", statuses["bundle_seal"], result)
			}
			if statuses["receipt_signatures"] != tc.wantSignatures || result["outcome"] != tc.wantSignatures {
				t.Fatalf("receipt_signatures = %s outcome = %v, want %s: %+v", statuses["receipt_signatures"], result["outcome"], tc.wantSignatures, result)
			}
		})
	}
}

// An unreadable request runs the format check only, so no later check can be
// reported as passing next to an early error.
func TestEvidenceVerifyMalformedRequestRunsOnlyFormatCheck(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("format-signer")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})
	for name, body := range map[string][]byte{
		"empty":    nil,
		"not gzip": []byte("not a bundle"),
	} {
		t.Run(name, func(t *testing.T) {
			result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", body)
			if result["outcome"] != "FAILED" {
				t.Fatalf("outcome = %v, want FAILED", result["outcome"])
			}
			if statuses := evidenceCheckStatuses(t, result); len(statuses) != 1 || statuses["bundle_format"] != "FAILED" {
				t.Fatalf("checks_run = %+v, want only bundle_format FAILED", result["checks_run"])
			}
		})
	}
}

func TestEvidenceVerificationConclude(t *testing.T) {
	verified := receiptverify.VerdictVerified
	all := func(override map[string]receiptverify.Verdict, skip ...string) []evidenceCheck {
		var checks []evidenceCheck
		for _, name := range evidenceChecksRequiredForVerified {
			if slices.Contains(skip, name) {
				continue
			}
			status := verified
			if s, ok := override[name]; ok {
				status = s
			}
			checks = append(checks, evidenceCheck{Name: name, Status: status, Detail: "test"})
		}
		return checks
	}
	for _, tc := range []struct {
		name   string
		checks []evidenceCheck
		want   receiptverify.Verdict
	}{
		{name: "no checks", want: receiptverify.VerdictFailed},
		{name: "all required verified", checks: all(nil), want: receiptverify.VerdictVerified},
		{name: "required check skipped", checks: all(nil, evidenceCheckReceiptChain), want: receiptverify.VerdictUnverifiable},
		{name: "one unverifiable", checks: all(map[string]receiptverify.Verdict{evidenceCheckBundleSeal: receiptverify.VerdictUnverifiable}), want: receiptverify.VerdictUnverifiable},
		{name: "failed beats unverifiable", checks: all(map[string]receiptverify.Verdict{
			evidenceCheckBundleSeal:     receiptverify.VerdictUnverifiable,
			evidenceCheckManifestHashes: receiptverify.VerdictFailed,
		}), want: receiptverify.VerdictFailed},
		{name: "unknown status fails", checks: all(map[string]receiptverify.Verdict{evidenceCheckReceiptChain: "PASS"}), want: receiptverify.VerdictFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := evidenceVerification{ChecksRun: tc.checks}
			result.conclude()
			if result.Outcome != tc.want {
				t.Fatalf("outcome = %s, want %s", result.Outcome, tc.want)
			}
		})
	}
}

// Every default install signs with the same key id but its own key. A bundle
// from another instance is intact but unproven here, not tampered.
func TestEvidenceVerifySameKeyIDOtherKeyIsUnverifiable(t *testing.T) {
	local, err := helmcrypto.NewEd25519Signer("root")
	if err != nil {
		t.Fatal(err)
	}
	other, err := helmcrypto.NewEd25519Signer("root")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: local})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", signedEvidenceVerifyTestBundle(t, other))
	statuses := evidenceCheckStatuses(t, result)
	if statuses["bundle_seal"] != "UNVERIFIABLE" || statuses["receipt_signatures"] != "UNVERIFIABLE" || result["outcome"] != "UNVERIFIABLE" {
		t.Fatalf("bundle from another instance with the same key id = %+v, want seal, signatures and outcome UNVERIFIABLE", result)
	}
}

// Without a trust anchor the seal still separates intact from altered: an
// altered pack is FAILED, and no error leaks the server's workspace path.
func TestEvidenceVerifyWithoutTrustAnchorStillFailsAlteredBundles(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("unanchored-signer")
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := tamperEvidenceReceiptFields(signedEvidenceVerifyTestBundle(t, signer), func(receipt *contracts.Receipt) {
		receipt.ArgsHash = "args-rewritten"
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", tampered)
	if statuses := evidenceCheckStatuses(t, result); statuses["bundle_seal"] != "FAILED" || result["outcome"] != "FAILED" {
		t.Fatalf("altered bundle without a trust anchor = %+v, want seal and outcome FAILED", result)
	}
	if resultErrorsContain(result, "helm-evidence-verify-") {
		t.Fatalf("errors leak the verify workspace path: %+v", result["errors"])
	}
}

// One receipt signed by another key and one with a broken signature: the
// broken one fails the check, and both are reported.
func TestEvidenceVerifyMixedReceiptSignaturesFail(t *testing.T) {
	trusted, err := helmcrypto.NewEd25519Signer("runtime-signer")
	if err != nil {
		t.Fatal(err)
	}
	other, err := helmcrypto.NewEd25519Signer("other-signer")
	if err != nil {
		t.Fatal(err)
	}
	carried := newEvidenceVerifyTestReceipt("mixed-carried", "mixed-a", 1, "")
	if err := other.SignReceipt(carried); err != nil {
		t.Fatal(err)
	}
	broken := newEvidenceVerifyTestReceipt("mixed-broken", "mixed-b", 1, "")
	if err := trusted.SignReceipt(broken); err != nil {
		t.Fatal(err)
	}
	broken.ArgsHash = "args-rewritten-after-signing"
	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("", []*contracts.Receipt{carried, broken}, nil, &Services{ReceiptSigner: trusted})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: trusted})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", bundle)
	if statuses := evidenceCheckStatuses(t, result); statuses["receipt_signatures"] != "FAILED" || result["outcome"] != "FAILED" {
		t.Fatalf("mixed receipts = %+v, want receipt_signatures and outcome FAILED", result)
	}
	if !resultErrorsContain(result, "mixed-broken signature verification failed") || !resultErrorsContain(result, "mixed-carried is signed by a key it carries") {
		t.Fatalf("both receipts must be reported: %+v", result["errors"])
	}
}

// required_artifacts runs when a receipt declares a requirement and fails
// when the bundle lacks the artifact.
func TestEvidenceVerifyRequiredArtifactMissingFails(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("artifact-signer")
	if err != nil {
		t.Fatal(err)
	}
	receipt := newEvidenceVerifyTestReceipt("needs-scope", "artifact-session", 1, "")
	receipt.Metadata = map[string]any{"risk_class": "T2"}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	bundle, err := buildTrustedEvidenceBundleWithSurfaceArtifacts("artifact-session", []*contracts.Receipt{receipt}, nil, &Services{ReceiptSigner: signer})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", bundle)
	if statuses := evidenceCheckStatuses(t, result); statuses["required_artifacts"] != "FAILED" || result["outcome"] != "FAILED" {
		t.Fatalf("receipt requiring a scope without one = %+v, want required_artifacts and outcome FAILED", result)
	}
	if !resultErrorsContain(result, "needs-scope missing verification scope") {
		t.Fatalf("missing artifact not named: %+v", result["errors"])
	}
}

// Seal errors name files inside the server's verify workspace; the public
// route reports them relative to the pack.
func TestEvidenceVerifySealErrorsDoNotLeakWorkspacePath(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("leak-signer")
	if err != nil {
		t.Fatal(err)
	}
	files, err := readRawEvidenceBundleFiles(signedEvidenceVerifyTestBundle(t, signer))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[evidenceBundleIndexPath]; !ok {
		t.Fatalf("bundle has no %s to remove", evidenceBundleIndexPath)
	}
	delete(files, evidenceBundleIndexPath)
	stripped, err := tarEvidenceBundleFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerContractRoutes(mux, &Services{ReceiptSigner: signer})

	result := postEvidenceVerification(t, mux, "/api/v1/evidence/verify", stripped)
	if statuses := evidenceCheckStatuses(t, result); statuses["bundle_seal"] != "FAILED" {
		t.Fatalf("bundle without its index = %+v, want bundle_seal FAILED", result)
	}
	if !resultErrorsContain(result, evidenceBundleIndexPath) {
		t.Fatalf("seal errors should name the missing index: %+v", result["errors"])
	}
	if resultErrorsContain(result, "helm-evidence-verify-") || resultErrorsContain(result, os.TempDir()) {
		t.Fatalf("errors leak the verify workspace path: %+v", result["errors"])
	}
}

// The verify routes that could not fail are gone: none of them may answer a
// verification again, and none may stay in the route registry.
func TestTautologicalVerifyRoutesAreNotServed(t *testing.T) {
	// Configured services, so tenant and admin handlers run past their
	// guards and a still-wired verify branch would answer.
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	mux := http.NewServeMux()
	registerContractRoutes(mux, svc)
	removed := []string{
		"/api/v1/replay/verify",
		"/api/v1/boundary/records/rec-1/verify",
		"/api/v1/boundary/checkpoints/cp-1/verify",
		"/api/v1/evidence/verification-scopes/scope-1/verify",
		"/api/v1/telemetry/harness-traces/trace-1/verify",
		"/api/v1/plans/transactions/tx-1/verify",
		"/api/v1/harness/change-contracts/change-1/verify",
		"/api/v1/evidence/envelopes/manifest-1/verify",
		"/api/v1/sandbox/grants/grant-1/verify",
	}
	for _, path := range removed {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		authorizeTestRequest(req)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		// The id segment now carries "/verify", which the remaining prefix
		// handlers reject as an invalid id; the checkpoint prefix is gone.
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("POST %s = %d, want 400 or 404: body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `"verified"`) || strings.Contains(rec.Body.String(), `"checks"`) {
			t.Fatalf("POST %s still answers a verification: body=%s", path, rec.Body.String())
		}
	}
	for _, spec := range PublicRuntimeRouteSpecs() {
		if strings.HasSuffix(spec.Path, "/verify") && spec.Path != "/api/v1/evidence/verify" && spec.Path != "/api/demo/verify" {
			t.Errorf("route registry still lists verify route %s %s", spec.Method, spec.Path)
		}
	}
}
