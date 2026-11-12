package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
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
		Verdict         string            `json:"verdict"`
		Reason          string            `json:"reason_code"`
		Receipt         contracts.Receipt `json:"receipt"`
		Sandbox         string            `json:"sandbox_label"`
		ProofRefs       map[string]string `json:"proof_refs"`
		Policy          map[string]any    `json:"active_policy"`
		HelmAIKernelVer string            `json:"helm_ai_kernel_version"`
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

func TestBuildDemoReceiptBindsDecisionGovernanceFields(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("demo-governance-fields")
	if err != nil {
		t.Fatal(err)
	}
	decision := &contracts.DecisionRecord{
		ID:                "demo-decision-v5",
		Action:            "READ_TICKET",
		Verdict:           string(contracts.VerdictDeny),
		ReasonCode:        string(contracts.ReasonPolicyViolation),
		PolicyContentHash: "sha256:demo-policy",
		InputContext:      map[string]any{"session_id": " demo-session "},
	}
	receipt, err := buildDemoReceipt(&Services{ReceiptSigner: signer}, decision, []byte("demo body"), nil)
	if err != nil {
		t.Fatalf("build demo receipt: %v", err)
	}
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 || receipt.Verdict != decision.Verdict || receipt.ReasonCode != decision.ReasonCode || receipt.PolicyHash != decision.PolicyContentHash || receipt.SessionID != "demo-session" {
		t.Fatalf("demo receipt did not bind decision governance fields: %+v", receipt)
	}
	if valid, err := signer.VerifyReceipt(receipt); err != nil || !valid {
		t.Fatalf("demo receipt signature invalid: valid=%v err=%v", valid, err)
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

// TestDemoVerifyReadsTheReceiptAsItsReaderDoes: the public demo verifier
// decoded the receipt with encoding/json alone, so a receipt that says ALLOW by
// exact name and restores the signed DENY in "Verdict" came back valid. It
// also listed the eight members of the legacy preimage as verified_fields for
// a receipt.v5 receipt, and reported a receipt it had not checked as a failed
// signature. It now reads the receipt with the parser receipt_verify uses and
// reports what it checked.
func TestDemoVerifyReadsTheReceiptAsItsReaderDoes(t *testing.T) {
	signer, err := helmcrypto.NewEd25519Signer("demo-test")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDemoRoutes(mux, &Services{ReceiptSigner: signer})

	runRec := httptest.NewRecorder()
	mux.ServeHTTP(runRec, httptest.NewRequest(http.MethodPost, "/api/demo/run", bytes.NewReader([]byte(`{"action_id":"dangerous_shell"}`))))
	var run struct {
		Receipt   json.RawMessage   `json:"receipt"`
		ProofRefs map[string]string `json:"proof_refs"`
	}
	if err := json.Unmarshal(runRec.Body.Bytes(), &run); err != nil || runRec.Code != http.StatusOK {
		t.Fatalf("demo run status = %d (%v) body=%s", runRec.Code, err, runRec.Body.String())
	}
	genuine := []byte(run.Receipt)
	if bytes.Count(genuine, []byte(`"verdict":"DENY"`)) != 1 || bytes.Count(genuine, []byte(`"signature_version":"receipt.v5"`)) != 1 {
		t.Fatalf("the demo receipt is not a receipt.v5 DENY with one verdict member: %s", genuine)
	}
	post := func(receipt []byte) (int, map[string]any) {
		t.Helper()
		body := []byte(`{"receipt":` + string(receipt) + `,"expected_receipt_hash":"` + run.ProofRefs["receipt_hash"] + `"}`)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/demo/verify", bytes.NewReader(body)))
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode verify (status %d): %v\n%s", rec.Code, err, rec.Body.String())
		}
		return rec.Code, payload
	}
	fields := func(payload map[string]any) map[string]bool {
		list, _ := payload["verified_fields"].([]any)
		out := map[string]bool{}
		for _, item := range list {
			name, _ := item.(string)
			out[name] = true
		}
		return out
	}

	code, payload := post(genuine)
	if code != http.StatusOK || payload["valid"] != true || payload["signature_valid"] != true {
		t.Fatalf("the genuine demo receipt does not verify; the cases prove nothing: %d %v", code, payload)
	}
	// verified_fields are the members the receipt.v5 signature covers: the
	// verdict is one, the signature itself and unsigned members are not.
	verified := fields(payload)
	if len(verified) != 13 || !verified["verdict"] || !verified["policy_hash"] || !verified["session_id"] || verified["signature"] || verified["tool_name"] {
		t.Fatalf("verified_fields of a receipt.v5 receipt must be the 13 signed members, got %v", payload["verified_fields"])
	}

	shadow := append([]byte(`{"verdict":"ALLOW",`), bytes.Replace(genuine, []byte(`"verdict":"DENY"`), []byte(`"Verdict":"DENY"`), 1)[1:]...)
	var exact map[string]any
	if err := json.Unmarshal(shadow, &exact); err != nil || exact["verdict"] != "ALLOW" {
		t.Fatalf("the planted receipt does not read ALLOW by exact name; the case proves nothing (%v)", err)
	}
	for name, receipt := range map[string][]byte{
		"letter-case shadow":    shadow,
		"verdict written twice": append([]byte(`{"verdict":"ALLOW",`), genuine[1:]...),
	} {
		code, payload := post(receipt)
		if code != http.StatusBadRequest || payload["valid"] == true {
			t.Fatalf("%s: status %d, want 400 and no verification result: %v", name, code, payload)
		}
	}

	// A receipt with no signature_version is not checked, and the answer says
	// that, not that its signature failed.
	var members map[string]any
	if err := json.Unmarshal(genuine, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "signature_version")
	unversioned, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	code, payload = post(unversioned)
	reason, _ := payload["reason"].(string)
	if code != http.StatusOK || payload["valid"] != false || payload["signature_valid"] != false {
		t.Fatalf("an unversioned receipt: status %d, want 200 with valid false: %v", code, payload)
	}
	if !strings.Contains(reason, "not checked") || strings.Contains(reason, "verification failed") || len(fields(payload)) != 0 {
		t.Fatalf("an unversioned receipt must be reported as not checked, with no verified_fields: reason %q, verified_fields %v", reason, payload["verified_fields"])
	}
}
