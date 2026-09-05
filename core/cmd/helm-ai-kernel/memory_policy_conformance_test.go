// quantum_posture: this conformance test verifies classical Ed25519 receipt.v5
// signatures and SHA-256 bindings; it adds no post-quantum assurance.
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/agentruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const (
	memoryPolicyTenantID    = "tenant-memory"
	memoryPolicyPrincipalID = "principal-memory"
	memoryPolicyWorkspaceID = "workspace-memory"
)

type memoryPolicyConformancePack struct {
	PackID            string   `json:"pack_id"`
	Version           string   `json:"version"`
	Status            string   `json:"status"`
	Scope             string   `json:"scope"`
	PolicyInputSchema string   `json:"policy_input_schema"`
	ManagedPolicy     string   `json:"managed_policy"`
	TestVectors       string   `json:"test_vectors"`
	SourceRefs        []string `json:"source_refs"`
	Invariants        []string `json:"invariants"`
}

type memoryPolicyTestVectorSet struct {
	SchemaVersion string                   `json:"schema_version"`
	Vectors       []memoryPolicyTestVector `json:"vectors"`
}

type memoryPolicyTestVector struct {
	ID                 string                 `json:"id"`
	SchemaValid        bool                   `json:"schema_valid"`
	Authenticated      bool                   `json:"authenticated"`
	WorkspaceBound     bool                   `json:"workspace_bound"`
	MissingPolicy      bool                   `json:"missing_policy"`
	ExpectedExecutorID string                 `json:"expected_executor_id"`
	CPAuthority        *memoryPolicyAuthority `json:"cp_authority,omitempty"`
	Request            api.EvaluateRequest    `json:"request"`
	Expected           struct {
		HTTPStatus           int    `json:"http_status"`
		Verdict              string `json:"verdict"`
		ReasonCode           string `json:"reason_code"`
		SignedReceipt        bool   `json:"signed_receipt"`
		TamperedReceiptValid *bool  `json:"tampered_receipt_valid"`
	} `json:"expected"`
}

// memoryPolicyAuthority mirrors the Control Plane EvaluateClient's
// post-validation reserved args envelope. It is test metadata so the source
// memory args remain schema-valid before the CP binding is added at the wire
// boundary.
type memoryPolicyAuthority struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	PrincipalID string `json:"principal_id"`
	SessionID   string `json:"session_id"`
	Tool        string `json:"tool"`
	EffectLevel string `json:"effect_level"`
}

// TestMemoryPolicyConformancePack exercises the source-owned memory contract
// through the real authenticated daemon route, Guardian managed-policy PDP,
// receipt persistence, and offline V5 signature verification path.
func TestMemoryPolicyConformancePack(t *testing.T) {
	root := memoryPolicyRepoRoot(t)
	packDir := filepath.Join(root, "protocols", "conformance", "memory", "v1")

	var pack memoryPolicyConformancePack
	readMemoryPolicyJSON(t, filepath.Join(packDir, "conformance-pack.json"), &pack)
	if pack.PackID != "helm-memory-policy-v1" || pack.Version != "1.0.0" {
		t.Fatalf("unexpected memory conformance pack identity: %+v", pack)
	}
	if len(pack.SourceRefs) == 0 {
		t.Fatal("memory conformance pack must bind at least one policy source reference")
	}

	schema := compileMemoryPolicySchema(t, filepath.Clean(filepath.Join(packDir, pack.PolicyInputSchema)))
	policyRaw, err := os.ReadFile(filepath.Clean(filepath.Join(packDir, pack.ManagedPolicy)))
	if err != nil {
		t.Fatalf("read managed memory policy: %v", err)
	}
	managedPolicy, err := pdp.NewManagedPolicyPDP(policyRaw, pack.SourceRefs)
	if err != nil {
		t.Fatalf("compile managed memory policy: %v", err)
	}

	var vectorSet memoryPolicyTestVectorSet
	readMemoryPolicyJSON(t, filepath.Clean(filepath.Join(packDir, pack.TestVectors)), &vectorSet)
	if vectorSet.SchemaVersion != "helm.memory.policy.conformance.v1" || len(vectorSet.Vectors) == 0 {
		t.Fatalf("unexpected or empty memory policy vectors: %+v", vectorSet)
	}

	t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
	t.Setenv(runtimeTenantIDEnv, memoryPolicyTenantID)
	t.Setenv(runtimePrincipalIDEnv, memoryPolicyPrincipalID)

	for _, vector := range vectorSet.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			schemaErr := schema.Validate(vector.Request.Args)
			if got := schemaErr == nil; got != vector.SchemaValid {
				t.Fatalf("schema validity = %t, want %t: %v", got, vector.SchemaValid, schemaErr)
			}

			wireVector := vector
			if vector.CPAuthority != nil {
				wireVector.Request.Args = memoryPolicyArgsWithAuthority(vector.Request.Args, *vector.CPAuthority)
			}

			var (
				svc      *Services
				receipts *captureReceiptStore
			)
			if vector.MissingPolicy {
				svc = &Services{}
			} else {
				svc, receipts = newEvaluateRouteTestServices(t, guardian.WithPDP(managedPolicy))
			}

			mux := http.NewServeMux()
			registerReceiptRoutes(mux, svc)
			body, err := json.Marshal(wireVector.Request)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/evaluate", bytes.NewReader(body))
			if vector.Authenticated {
				req.Header.Set("Authorization", "Bearer "+testAdminAPIKey)
				req.Header.Set(tenantHeader, memoryPolicyTenantID)
				req.Header.Set(principalHeader, memoryPolicyPrincipalID)
			}
			if vector.WorkspaceBound {
				req.Header.Set(workspaceHeader, memoryPolicyWorkspaceID)
			}

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			if recorder.Code != vector.Expected.HTTPStatus {
				t.Fatalf("evaluate status = %d, want %d: %s", recorder.Code, vector.Expected.HTTPStatus, recorder.Body.String())
			}

			if recorder.Code == http.StatusOK {
				var response api.EvaluateResponse
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode evaluate response: %v", err)
				}
				if response.Verdict != vector.Expected.Verdict || response.ReasonCode != vector.Expected.ReasonCode {
					t.Fatalf("evaluate verdict = %q/%q, want %q/%q", response.Verdict, response.ReasonCode, vector.Expected.Verdict, vector.Expected.ReasonCode)
				}
			}

			if vector.Expected.SignedReceipt {
				assertMemoryPolicyReceipt(t, svc, receipts, managedPolicy, wireVector)
			} else if receipts != nil && receipts.stored != nil {
				t.Fatalf("rejected request persisted a receipt: %+v", receipts.stored)
			}
		})
	}
}

func memoryPolicyArgsWithAuthority(source map[string]any, authority memoryPolicyAuthority) map[string]any {
	args := make(map[string]any, len(source)+1)
	for key, value := range source {
		args[key] = value
	}
	args[evaluateAuthorityArgsKey] = map[string]any{
		"tenant_id":    authority.TenantID,
		"workspace_id": authority.WorkspaceID,
		"principal_id": authority.PrincipalID,
		"session_id":   authority.SessionID,
		"tool":         authority.Tool,
		"effect_level": authority.EffectLevel,
	}
	return args
}

func assertMemoryPolicyReceipt(t *testing.T, svc *Services, receipts *captureReceiptStore, managedPolicy *pdp.ManagedPolicyPDP, vector memoryPolicyTestVector) {
	t.Helper()
	if receipts == nil || receipts.stored == nil {
		t.Fatal("policy decision did not persist a receipt")
	}
	receipt := receipts.stored
	if receipt.SignatureVersion != contracts.ReceiptSignatureV5 {
		t.Fatalf("receipt signature version = %q, want %q", receipt.SignatureVersion, contracts.ReceiptSignatureV5)
	}
	if receipt.EffectID != vector.Request.Tool || receipt.SessionID != vector.Request.SessionID {
		t.Fatalf("receipt action/session binding = %q/%q, want %q/%q", receipt.EffectID, receipt.SessionID, vector.Request.Tool, vector.Request.SessionID)
	}
	if receipt.Verdict != vector.Expected.Verdict || receipt.ReasonCode != vector.Expected.ReasonCode {
		t.Fatalf("receipt verdict = %q/%q, want %q/%q", receipt.Verdict, receipt.ReasonCode, vector.Expected.Verdict, vector.Expected.ReasonCode)
	}
	if receipt.PolicyHash != managedPolicy.PolicyHash() {
		t.Fatalf("receipt policy hash = %q, want %q", receipt.PolicyHash, managedPolicy.PolicyHash())
	}
	args, err := json.Marshal(vector.Request.Args)
	if err != nil {
		t.Fatalf("marshal receipt args: %v", err)
	}
	wantArgsHash, err := agentruntime.ComputeArgsHash(args)
	if err != nil {
		t.Fatalf("compute canonical receipt args hash: %v", err)
	}
	if receipt.ArgsHash != wantArgsHash {
		t.Fatalf("receipt args hash = %q, want %q", receipt.ArgsHash, wantArgsHash)
	}
	wantExecutorID := vector.ExpectedExecutorID
	if wantExecutorID == "" {
		wantExecutorID = memoryPolicyPrincipalID
	}
	if receipt.ExecutorID != wantExecutorID {
		t.Fatalf("receipt executor = %q, want authenticated %q", receipt.ExecutorID, wantExecutorID)
	}

	signer, ok := svc.ReceiptSigner.(*helmcrypto.Ed25519Signer)
	if !ok {
		t.Fatalf("receipt signer type = %T, want Ed25519 signer", svc.ReceiptSigner)
	}
	valid, err := signer.VerifyReceipt(receipt)
	if err != nil || !valid {
		t.Fatalf("signed V5 receipt verification = %t, err=%v", valid, err)
	}
	if vector.Expected.TamperedReceiptValid != nil {
		tampered := *receipt
		tampered.OutputHash = "sha256:" + strings.Repeat("0", 64)
		if tampered.OutputHash == receipt.OutputHash {
			tampered.OutputHash = "sha256:" + strings.Repeat("f", 64)
		}
		valid, err := signer.VerifyReceipt(&tampered)
		if err != nil {
			t.Fatalf("verify tampered receipt: %v", err)
		}
		if valid != *vector.Expected.TamperedReceiptValid {
			t.Fatalf("tampered receipt verification = %t, want %t", valid, *vector.Expected.TamperedReceiptValid)
		}
	}
}

func compileMemoryPolicySchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read memory policy schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	resourceURL := "file:///" + strings.ReplaceAll(path, string(filepath.Separator), "/")
	if err := compiler.AddResource(resourceURL, strings.NewReader(string(payload))); err != nil {
		t.Fatalf("add memory policy schema: %v", err)
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		t.Fatalf("compile memory policy schema: %v", err)
	}
	return schema
}

func readMemoryPolicyJSON(t *testing.T, path string, target any) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func memoryPolicyRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}
