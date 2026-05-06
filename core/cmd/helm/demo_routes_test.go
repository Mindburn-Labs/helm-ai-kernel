package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

func TestDemoRunVerifyAndTamper(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("demo-test")
	if err != nil {
		t.Fatal(err)
	}
	store := &captureReceiptStore{}
	svc := &Services{ReceiptStore: store, ReceiptSigner: signer}
	mux := http.NewServeMux()
	registerDemoRoutes(mux, svc)

	runBody := []byte(`{"action_id":"export_customer_list","policy_id":"agent_tool_call_boundary"}`)
	runReq := httptest.NewRequest(http.MethodPost, "/api/demo/run", bytes.NewReader(runBody))
	runRec := httptest.NewRecorder()
	mux.ServeHTTP(runRec, runReq)
	if runRec.Code != http.StatusOK {
		t.Fatalf("demo run status = %d body=%s", runRec.Code, runRec.Body.String())
	}
	var runPayload struct {
		Verdict    string            `json:"verdict"`
		Reason     string            `json:"reason_code"`
		Receipt    contracts.Receipt `json:"receipt"`
		Sandbox    string            `json:"sandbox_label"`
		ProofRefs  map[string]string `json:"proof_refs"`
		Policy     map[string]any    `json:"active_policy"`
		HelmOSSVer string            `json:"helm_oss_version"`
	}
	if err := json.Unmarshal(runRec.Body.Bytes(), &runPayload); err != nil {
		t.Fatalf("decode demo run: %v", err)
	}
	if runPayload.Verdict != string(contracts.VerdictDeny) {
		t.Fatalf("verdict = %s, want DENY", runPayload.Verdict)
	}
	if runPayload.Receipt.Signature == "" || runPayload.ProofRefs["receipt_hash"] == "" {
		t.Fatalf("receipt was not signed or proof refs missing: %+v", runPayload)
	}
	if runPayload.Sandbox != demoSandboxLabel {
		t.Fatalf("sandbox label = %q", runPayload.Sandbox)
	}
	if store.stored != nil {
		t.Fatalf("demo run stored receipt in shared receipt store: %+v", store.stored)
	}

	expectedHash := runPayload.ProofRefs["receipt_hash"]
	verifyBody, _ := json.Marshal(map[string]any{"receipt": runPayload.Receipt, "expected_receipt_hash": expectedHash})
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/demo/verify", bytes.NewReader(verifyBody))
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("demo verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if verifyPayload["valid"] != true {
		t.Fatalf("verify valid = %v body=%s", verifyPayload["valid"], verifyRec.Body.String())
	}
	if verifyPayload["signature_valid"] != true || verifyPayload["hash_matches"] != true {
		t.Fatalf("verify did not bind signature and receipt hash: %s", verifyRec.Body.String())
	}

	tamperBody, _ := json.Marshal(map[string]any{"receipt": runPayload.Receipt, "expected_receipt_hash": expectedHash, "mutation": "flip_verdict"})
	tamperReq := httptest.NewRequest(http.MethodPost, "/api/demo/tamper", bytes.NewReader(tamperBody))
	tamperRec := httptest.NewRecorder()
	mux.ServeHTTP(tamperRec, tamperReq)
	if tamperRec.Code != http.StatusOK {
		t.Fatalf("demo tamper status = %d body=%s", tamperRec.Code, tamperRec.Body.String())
	}
	var tamperPayload map[string]any
	if err := json.Unmarshal(tamperRec.Body.Bytes(), &tamperPayload); err != nil {
		t.Fatalf("decode tamper: %v", err)
	}
	if tamperPayload["valid"] != false {
		t.Fatalf("tamper valid = %v body=%s", tamperPayload["valid"], tamperRec.Body.String())
	}
	if tamperPayload["signature_valid"] != false || tamperPayload["hash_matches"] != false {
		t.Fatalf("tamper did not fail both signature and receipt hash checks: %s", tamperRec.Body.String())
	}
	if tamperPayload["original_hash"] == tamperPayload["tampered_hash"] {
		t.Fatalf("tamper hash did not change: %v", tamperPayload)
	}
}

func TestDemoRunDoesNotRequireReceiptStore(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("demo-test")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDemoRoutes(mux, &Services{ReceiptSigner: signer})

	req := httptest.NewRequest(http.MethodPost, "/api/demo/run", bytes.NewReader([]byte(`{"action_id":"read_ticket"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("demo run status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Receipt   contracts.Receipt `json:"receipt"`
		ProofRefs map[string]string `json:"proof_refs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode demo run: %v", err)
	}
	if payload.Receipt.Signature == "" || payload.ProofRefs["receipt_hash"] == "" {
		t.Fatalf("receipt was not signed or proof refs missing: %+v", payload)
	}
}

func TestDemoVerifyRejectsUnsignedEnvelopeMutation(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("demo-test")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDemoRoutes(mux, &Services{ReceiptSigner: signer})

	runReq := httptest.NewRequest(http.MethodPost, "/api/demo/run", bytes.NewReader([]byte(`{"action_id":"small_refund"}`)))
	runRec := httptest.NewRecorder()
	mux.ServeHTTP(runRec, runReq)
	if runRec.Code != http.StatusOK {
		t.Fatalf("demo run status = %d body=%s", runRec.Code, runRec.Body.String())
	}
	var runPayload struct {
		Receipt   contracts.Receipt `json:"receipt"`
		ProofRefs map[string]string `json:"proof_refs"`
	}
	if err := json.Unmarshal(runRec.Body.Bytes(), &runPayload); err != nil {
		t.Fatalf("decode demo run: %v", err)
	}
	expectedHash := runPayload.ProofRefs["receipt_hash"]
	if expectedHash == "" {
		t.Fatalf("receipt hash missing")
	}

	tampered := runPayload.Receipt
	tampered.Metadata["truth_label"] = "tampered public claim"
	verifyBody, _ := json.Marshal(map[string]any{"receipt": tampered, "expected_receipt_hash": expectedHash})
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/demo/verify", bytes.NewReader(verifyBody))
	verifyRec := httptest.NewRecorder()
	mux.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("demo verify status = %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if verifyPayload["valid"] != false {
		t.Fatalf("mutated envelope valid = %v body=%s", verifyPayload["valid"], verifyRec.Body.String())
	}
	if verifyPayload["signature_valid"] != true || verifyPayload["hash_matches"] != false {
		t.Fatalf("unsigned envelope mutation should keep signature valid but fail hash match: %s", verifyRec.Body.String())
	}
}

func TestDemoEscalateActionUsesCanonicalVerdict(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("demo-test")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Services{ReceiptSigner: signer}
	mux := http.NewServeMux()
	registerDemoRoutes(mux, svc)

	req := httptest.NewRequest(http.MethodPost, "/api/demo/run", bytes.NewReader([]byte(`{"action_id":"modify_policy"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("demo run status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode demo run: %v", err)
	}
	if payload.Verdict != string(contracts.VerdictEscalate) {
		t.Fatalf("verdict = %s, want ESCALATE body=%s", payload.Verdict, rec.Body.String())
	}
	if payload.Reason == "" {
		t.Fatalf("reason code missing")
	}
}
