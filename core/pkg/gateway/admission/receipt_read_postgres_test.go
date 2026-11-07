package admission

// CTL-059 read surface against real PostgreSQL 16 (listed in
// scripts/ci/postgres-proofs.txt): an exported range of a workspace's receipt
// chain verifies offline with its bindings under the gateway key alone, an
// attempt's receipts come back as the exact stored bytes, and neither read
// crosses the token's tenant or workspace.
//
// quantum_posture: verifies classical Ed25519 test receipts and recomputes
// SHA-256 digests; no post-quantum claim.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func trustRootJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"keys": map[string]string{testReceiptSigner.GetKeyID(): testReceiptSigner.PublicKey()}})
	must(t, err)
	return raw
}

func checkStatus(res receiptverify.Result, name receiptverify.CheckName) receiptverify.Status {
	for _, c := range res.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

func wantReadRefusal(t *testing.T, what string, err error, code Code) {
	t.Helper()
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Code != code {
		t.Fatalf("%s: err = %v, want code %d", what, err, code)
	}
}

func TestPostgresReceiptExportVerifiesOfflineWithBindings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.propose(human, note("export-1"))
	f.propose(human, proposal("export-2", effectargs.GitHubBranchCreateFromChanges, "github.com/Mindburn-Labs/other", branchArgs("helm/x")))
	escalated := f.escalated("export-draft")
	approved, _, err := f.svc.Approve(ctx, approverB, decideToken("helm.gateway.decide"), approval(escalated, "ok"))
	must(t, err)
	rows := f.wantContiguousChain(tenantA, workspace, 5)

	// Known good: the whole chain exports as the stored bytes, and the export
	// verifies offline, bindings included, under the gateway key alone.
	export, err := f.svc.ExportReceiptChain(ctx, human, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 5})
	must(t, err)
	if export.ChainID != receiptChainID(tenantA, workspace) || export.HeadSeq != 5 || len(export.Receipts) != 5 {
		t.Fatalf("export = chain %q head %d receipts %d", export.ChainID, export.HeadSeq, len(export.Receipts))
	}
	for i, r := range export.Receipts {
		if r.Ref.Seq != uint64(i+1) || r.Ref.ReceiptID != rows[i].receiptID || r.Ref.Digest != rows[i].digest ||
			!bytes.Equal(r.Envelope, rows[i].envelope) || !bytes.Equal(r.Binding, rows[i].binding) {
			t.Fatalf("exported receipt %d is not the stored row", i)
		}
		if !bytes.Contains(export.Bundle, rows[i].envelope) {
			t.Fatalf("the bundle does not hold receipt %d's exact bytes", i)
		}
	}
	got := receiptverify.VerifyJSON(export.Bundle, trustRootJSON(t))
	if got.Verdict != receiptverify.VerdictVerified || got.Verification.BindingsChecked != 5 ||
		checkStatus(got.Verification, receiptverify.CheckBinding) != receiptverify.StatusPass ||
		checkStatus(got.Verification, receiptverify.CheckClosure) != receiptverify.StatusPass {
		t.Fatalf("the export does not verify offline: %+v", got)
	}

	// A segment verifies on its own: its first receipt links to a
	// predecessor outside it, which closure does not need.
	segment, err := f.svc.ExportReceiptChain(ctx, human, ExportInput{WorkspaceID: workspace, FromSeq: 2, ToSeq: 4})
	must(t, err)
	if got := receiptverify.VerifyJSON(segment.Bundle, trustRootJSON(t)); got.Verdict != receiptverify.VerdictVerified || len(segment.Receipts) != 3 {
		t.Fatalf("segment 2..4: %+v", got)
	}

	// An attempt's receipts are its stored rows, each verifying with its
	// binding.
	receipts, err := f.svc.GetReceipts(ctx, human, approved.ID)
	must(t, err)
	if len(receipts) != 2 || receipts[0].Ref.State != "ESCALATED" || receipts[1].Ref.State != "ADMITTED" {
		t.Fatalf("approved attempt receipts = %+v", receipts)
	}
	for _, r := range receipts {
		row := rows[r.Ref.Seq-1]
		if !bytes.Equal(r.Envelope, row.envelope) || !bytes.Equal(r.Binding, row.binding) || r.Ref.AttemptVersion != row.version {
			t.Fatalf("receipt %d is not the stored row", r.Ref.Seq)
		}
		bundle, err := receiptverify.ParseBundle(r.Envelope)
		must(t, err)
		bundle.GatewayBindings = map[string][]byte{r.Ref.ReceiptID: r.Binding}
		if res := receiptverify.VerifyBundle(bundle, trustTestKey()); !res.Valid || checkStatus(res, receiptverify.CheckBinding) != receiptverify.StatusPass {
			t.Fatalf("receipt %d with its binding: %+v", r.Ref.Seq, res)
		}
	}

	// Known bad, offline: a tampered binding and a gap in the range.
	var document map[string]json.RawMessage
	must(t, json.Unmarshal(export.Bundle, &document))
	var bindings map[string]string
	must(t, json.Unmarshal(document["gateway_bindings"], &bindings))
	first, err := base64.StdEncoding.DecodeString(bindings[rows[0].receiptID])
	must(t, err)
	bindings[rows[0].receiptID] = base64.StdEncoding.EncodeToString(bytes.Replace(first, []byte(`"state":"ADMITTED"`), []byte(`"state":"DENIED"`), 1))
	document["gateway_bindings"], err = json.Marshal(bindings)
	must(t, err)
	tampered, err := json.Marshal(document)
	must(t, err)
	if got := receiptverify.VerifyJSON(tampered, trustRootJSON(t)); got.Verdict != receiptverify.VerdictFailed ||
		checkStatus(got.Verification, receiptverify.CheckBinding) != receiptverify.StatusFail {
		t.Fatalf("a tampered binding verified: %+v", got)
	}
	var receiptsArray []json.RawMessage
	must(t, json.Unmarshal(document["receipts"], &receiptsArray))
	delete(bindings, rows[2].receiptID)
	bindings[rows[0].receiptID] = base64.StdEncoding.EncodeToString(rows[0].binding)
	document["gateway_bindings"], err = json.Marshal(bindings)
	must(t, err)
	document["receipts"], err = json.Marshal(append(append([]json.RawMessage{}, receiptsArray[:2]...), receiptsArray[3:]...))
	must(t, err)
	gap, err := json.Marshal(document)
	must(t, err)
	if got := receiptverify.VerifyJSON(gap, trustRootJSON(t)); got.Verdict != receiptverify.VerdictFailed ||
		checkStatus(got.Verification, receiptverify.CheckClosure) != receiptverify.StatusFail {
		t.Fatalf("a range with a gap verified: %+v", got)
	}

	// A range that runs past the head reads up to it, whole, and says so.
	tail, err := f.svc.ExportReceiptChain(ctx, human, ExportInput{WorkspaceID: workspace, FromSeq: 4, ToSeq: 4 + MaxExportReceipts - 1})
	must(t, err)
	if tail.HeadSeq != 5 || len(tail.Receipts) != 2 || tail.Receipts[0].Ref.Seq != 4 || tail.Receipts[1].Ref.Seq != 5 {
		t.Fatalf("export 4.. = head %d, %d receipts", tail.HeadSeq, len(tail.Receipts))
	}
	if got := receiptverify.VerifyJSON(tail.Bundle, trustRootJSON(t)); got.Verdict != receiptverify.VerdictVerified {
		t.Fatalf("export 4..: %+v", got)
	}

	// Ranges that start outside the chain or exceed the cap are refused.
	for name, test := range map[string]struct {
		in   ExportInput
		code Code
	}{
		"from zero":              {ExportInput{WorkspaceID: workspace, FromSeq: 0, ToSeq: 1}, CodeInvalidArgument},
		"reversed":               {ExportInput{WorkspaceID: workspace, FromSeq: 3, ToSeq: 2}, CodeInvalidArgument},
		"over the cap":           {ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: MaxExportReceipts + 1}, CodeInvalidArgument},
		"starting past the head": {ExportInput{WorkspaceID: workspace, FromSeq: 6, ToSeq: 6}, CodeNotFound},
		"no workspace":           {ExportInput{FromSeq: 1, ToSeq: 1}, CodeInvalidArgument},
		"other workspace":        {ExportInput{WorkspaceID: "ws-b", FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
	} {
		_, err := f.svc.ExportReceiptChain(ctx, human, test.in)
		wantReadRefusal(t, name, err, test.code)
	}
}

func TestPostgresReceiptReadsStayInTheTokensTenantAndWorkspace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	wsB := Caller{TenantID: tenantA, WorkspaceID: "ws-b", PrincipalID: "human-a", ActorID: actor}
	tenantBCaller := Caller{TenantID: tenantB, WorkspaceID: workspace, PrincipalID: "human-a", ActorID: actor}
	f.rootMandate(tenantB, "human-a", skeletonTerms(f.now))
	f.rootMandate(tenantA, "agent-a", skeletonTerms(f.now))

	a1 := f.propose(human, note("scope-1"))
	f.propose(human, note("scope-2"))
	f.propose(wsB, note("scope-b"))
	f.propose(tenantBCaller, note("scope-1"))
	worker := f.propose(episodeWorker("ep-1", ""), workerNote("scope-worker"))

	// Each caller exports its own chain, whatever workspace name it shares.
	own, err := f.svc.ExportReceiptChain(ctx, tenantBCaller, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: MaxExportReceipts})
	must(t, err)
	parsed, err := receiptverify.ParseBundle(own.Bundle)
	must(t, err)
	if own.ChainID != receiptChainID(tenantB, workspace) || own.HeadSeq != 1 || len(parsed.Receipts) != 1 || parsed.Receipts[0].SessionID != own.ChainID {
		t.Fatalf("tenant B exported %q head %d: %+v", own.ChainID, own.HeadSeq, parsed.Receipts[0])
	}
	binding, err := receiptverify.ParseGatewayBinding(own.Receipts[0].Binding)
	must(t, err)
	if binding.TenantID != tenantB || binding.WorkspaceID != workspace {
		t.Fatalf("tenant B's export binds %s/%s", binding.TenantID, binding.WorkspaceID)
	}
	for name, test := range map[string]struct {
		caller Caller
		in     ExportInput
		code   Code
	}{
		"tenant B past its own head":          {tenantBCaller, ExportInput{WorkspaceID: workspace, FromSeq: 2, ToSeq: 3}, CodeNotFound},
		"workspace B past its own head":       {wsB, ExportInput{WorkspaceID: "ws-b", FromSeq: 2, ToSeq: 3}, CodeNotFound},
		"workspace B naming workspace A":      {wsB, ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
		"workspace A naming workspace B":      {human, ExportInput{WorkspaceID: "ws-b", FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
		"an episode token":                    {episodeWorker("ep-1", ""), ExportInput{WorkspaceID: workspace, FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
		"a workspace with no chain":           {Caller{TenantID: tenantA, WorkspaceID: "ws-empty", PrincipalID: "human-a", ActorID: actor}, ExportInput{WorkspaceID: "ws-empty", FromSeq: 1, ToSeq: 1}, CodeNotFound},
		"tenant B naming tenant A's chain id": {tenantBCaller, ExportInput{WorkspaceID: receiptChainID(tenantA, workspace), FromSeq: 1, ToSeq: 1}, CodePermissionDenied},
	} {
		_, err := f.svc.ExportReceiptChain(ctx, test.caller, test.in)
		wantReadRefusal(t, name, err, test.code)
	}

	// An attempt's receipts are as visible as the attempt: not to another
	// tenant, another workspace or another episode.
	for name, caller := range map[string]Caller{
		"tenant B":         tenantBCaller,
		"workspace B":      wsB,
		"another episode":  episodeWorker("ep-2", ""),
		"the same episode": episodeWorker("ep-1", ""),
	} {
		receipts, err := f.svc.GetReceipts(ctx, caller, a1.ID)
		wantReadRefusal(t, name+" reading workspace A's attempt", err, CodeNotFound)
		if receipts != nil {
			t.Fatalf("%s: receipts returned with a refusal", name)
		}
	}
	if _, err := f.svc.GetReceipts(ctx, episodeWorker("ep-2", ""), worker.ID); err == nil {
		t.Fatal("another episode read the worker's receipts")
	}
	mine, err := f.svc.GetReceipts(ctx, episodeWorker("ep-1", ""), worker.ID)
	must(t, err)
	if len(mine) != 1 || mine[0].Ref.ChainID != receiptChainID(tenantA, workspace) {
		t.Fatalf("the worker's own receipts = %+v", mine)
	}
	if _, err := f.svc.GetReceipts(ctx, human, "not-a-uuid"); err == nil {
		t.Fatal("a malformed attempt id was read")
	}
}
