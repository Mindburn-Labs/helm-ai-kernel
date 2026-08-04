package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapprovalceremony"
)

func TestGeneratedSpecApprovalResponseCarriesPendingSpecBinding(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeGeneratedSpecApprovalResult(recorder, generatedspecapprovalceremony.Record{
		State: generatedspecapprovalceremony.StateHoldPending, ApprovalID: "approval-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", HoldStartedAt: time.Now().UTC(), Version: 1,
		Binding: generatedspecapprovalceremony.Binding{GeneratedSpecID: "generated-spec-a"},
	}, nil)
	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Helm-Contract-Status") != generatedSpecApprovalContractStatus {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var response generatedSpecApprovalRecordResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.GeneratedSpecID != "generated-spec-a" {
		t.Fatalf("generated_spec_id=%q", response.GeneratedSpecID)
	}
}
