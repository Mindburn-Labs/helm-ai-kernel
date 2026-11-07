package mcpserver

// CTL-059 through the MCP tools (listed in scripts/ci/postgres-proofs.txt):
// a worker's tool call is admitted, dispatched and read back by the gateway,
// and its outcome commits with a signed receipt that chains after the
// decision's and verifies offline under the gateway's key alone.
//
// quantum_posture: verifies classical Ed25519 test receipts; no post-quantum
// claim.

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// storedEnvelopes reads a chain's receipt envelopes and bindings in sequence
// order, as the owner bound to tenant.
func (e *env) storedEnvelopes(tenant, chain string) (envelopes, bindings [][]byte) {
	e.t.Helper()
	tx, err := e.owner.Begin()
	must(e.t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT set_config('app.current_tenant', $1, true)`, tenant)
	must(e.t, err)
	rows, err := tx.Query(`SELECT envelope, binding FROM authority_receipts WHERE tenant_id = $1 AND chain_id = $2 ORDER BY seq`, tenant, chain)
	must(e.t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var envelope, binding []byte
		must(e.t, rows.Scan(&envelope, &binding))
		envelopes, bindings = append(envelopes, envelope), append(bindings, binding)
	}
	must(e.t, rows.Err())
	return envelopes, bindings
}

// wantOutcomeReceipts checks an attempt read through the gateway carries
// exactly states as receipts, and that its outcome receipt binds the outcome
// the attempt records.
func (e *env) wantOutcomeReceipts(a admission.Attempt, states ...string) {
	e.t.Helper()
	var got []string
	for _, r := range a.Receipts {
		got = append(got, r.State)
	}
	if !slices.Equal(got, states) {
		e.t.Fatalf("attempt %s (%s) has receipts %v, want %v", a.ID, a.State, got, states)
	}
	if last := a.Receipts[len(a.Receipts)-1]; last.AttemptVersion != a.Version || last.Seq <= a.Receipts[0].Seq {
		e.t.Fatalf("attempt %s at version %d: its last receipt %+v does not describe it after its decision", a.ID, a.Version, last)
	}
	envelopes, bindings := e.storedEnvelopes(tenantA, a.Receipts[0].ChainID)
	last := a.Receipts[len(a.Receipts)-1]
	var binding struct {
		State        string `json:"state"`
		Outcome      string `json:"outcome"`
		OutcomeBasis string `json:"outcome_basis"`
		PermitID     string `json:"permit_id"`
	}
	must(e.t, json.Unmarshal(bindings[last.Seq-1], &binding))
	if binding.State != a.State || binding.Outcome != a.Outcome || binding.OutcomeBasis != a.OutcomeBasis || binding.PermitID != a.Permit.ID {
		e.t.Fatalf("the outcome receipt of %s binds %+v, the attempt is %s(%s) %s", a.ID, binding, a.State, a.Outcome, a.OutcomeBasis)
	}
	bundle, err := receiptverify.ParseBundle(envelopes[last.Seq-1])
	must(e.t, err)
	if digest, err := contracts.ReceiptChainHash(bundle.Receipts[0]); err != nil || digest != last.Digest {
		e.t.Fatalf("the receipt ref %+v does not name the stored receipt (%v)", last, err)
	}
}

func TestPostgresMCPToolOutcomesAreReceipted(t *testing.T) {
	e := newEnv(t)

	// A tool call that succeeds: admitted, dispatched and observed.
	content, isError := e.callTool(t, tokenSeat1Ep1, "receipt-1", "github_repository_get", getArgs(repoA)).structured(t)
	if isError || content["status"] != "succeeded" {
		t.Fatalf("call = %v (error %v)", content, isError)
	}
	e.wantOutcomeReceipts(e.attempt(tenantA, content["attempt_id"].(string)), "ADMITTED", "OBSERVED")

	// A call whose outcome is not known yet is not receipted until the same
	// call finds it.
	e.adapter.script(
		func(adapters.Effect) adapters.DispatchResult {
			return adapters.DispatchResult{Status: adapters.DispatchIndefinite, Reason: "PROVIDER_ERROR"}
		},
		func(adapters.Effect) adapters.ObserveResult {
			return adapters.ObserveResult{Outcome: adapters.OutcomeUnknown}
		})
	unknown := map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "later"}}
	content, _ = e.callTool(t, tokenSeat1Ep1, "receipt-2", "github_repository_get", unknown).structured(t)
	id := content["attempt_id"].(string)
	if a := e.attempt(tenantA, id); a.State != "UNKNOWN" || len(a.Receipts) != 1 {
		t.Fatalf("an unknown outcome = %s with receipts %+v", a.State, a.Receipts)
	}
	e.adapter.script(nil, nil)
	content, _ = e.callTool(t, tokenSeat1Ep1, "receipt-2", "github_repository_get", unknown).structured(t)
	if content["state"] != "RECONCILED" {
		t.Fatalf("the reconciled call = %v", content)
	}
	e.wantOutcomeReceipts(e.attempt(tenantA, id), "ADMITTED", "RECONCILED")

	// A call the provider refuses is a receipted failure.
	e.adapter.script(func(adapters.Effect) adapters.DispatchResult {
		return adapters.DispatchResult{Status: adapters.DispatchNotSent, Reason: "PRECONDITION_FAILED", Detail: "no"}
	}, nil)
	refused := map[string]any{"target": repoA, "arguments": map[string]any{"schema": "helm.github.repository.get.v1", "branch": "blocked"}}
	content, isError = e.callTool(t, tokenSeat1Ep1, "receipt-3", "github_repository_get", refused).structured(t)
	if !isError || content["status"] != "failed" {
		t.Fatalf("a refused call = %v", content)
	}
	e.wantOutcomeReceipts(e.attempt(tenantA, content["attempt_id"].(string)), "ADMITTED", "OBSERVED")

	// The workspace's chain, three decisions and three outcomes, verifies
	// offline under the gateway key alone.
	envelopes, _ := e.storedEnvelopes(tenantA, e.attempt(tenantA, id).Receipts[0].ChainID)
	if len(envelopes) != 6 {
		t.Fatalf("the chain holds %d receipts, want 6", len(envelopes))
	}
	raw := []byte("[")
	for i, envelope := range envelopes {
		if i > 0 {
			raw = append(raw, ',')
		}
		raw = append(raw, envelope...)
	}
	raw = append(raw, ']')
	bundle, err := receiptverify.ParseBundle(raw)
	must(t, err)
	trust := receiptverify.TrustRoot{Keys: map[string]string{testReceiptSigner.GetKeyID(): testReceiptSigner.PublicKey()}}
	if result := receiptverify.VerifyBundle(bundle, trust); !result.Valid {
		t.Fatalf("the MCP chain does not verify offline: %+v", result)
	}
}
