package server

// CTL-059 on the wire (listed in scripts/ci/postgres-proofs.txt): an attempt
// carries the references of its signed decision receipts, and each reference
// names the stored receipt a reader verifies offline under the gateway's key.
// GetAttemptReceipts and ExportReceiptChain return the stored bytes for that
// offline check, to a helm.gateway.read token of the attempt's tenant and
// workspace only.
//
// quantum_posture: verifies classical Ed25519 test receipts and signs
// classical RS256 test tokens; no post-quantum claim.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

func TestPostgresAttemptReceiptRefsOnTheWire(t *testing.T) {
	client, iss, db := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	read := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)

	admitted, err := client.Propose(ctx, withToken(branchRequest("receipt-wire-1", "helm/receipts"), propose))
	must(t, err)
	denied, err := client.Propose(ctx, withToken(branchRequest("receipt-wire-2", "main"), propose))
	must(t, err)
	if denied.Msg.GetAttempt().GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_DENIED {
		t.Fatalf("head on the default branch = %+v", denied.Msg.GetAttempt())
	}
	chain := "helm-gateway:8:tenant-a:4:ws-a"
	for i, attempt := range []*gatewayv1.EffectAttempt{admitted.Msg.GetAttempt(), denied.Msg.GetAttempt()} {
		got, err := client.GetAttempt(ctx, withToken(&gatewayv1.GetAttemptRequest{AttemptId: attempt.GetAttemptId()}, read))
		must(t, err)
		for _, a := range []*gatewayv1.EffectAttempt{attempt, got.Msg.GetAttempt()} {
			refs := a.GetReceipts()
			if len(refs) != 1 || refs[0].GetChainId() != chain || refs[0].GetSeq() != uint64(i+1) ||
				refs[0].GetKid() != testReceiptSigner.GetKeyID() || len(refs[0].GetReceiptHash()) != 64 {
				t.Fatalf("attempt %s receipts = %v", a.GetAttemptId(), refs)
			}
		}
		// The reference names the stored receipt: its chain hash, signed by
		// the key it names.
		var envelope []byte
		tx, err := db.BeginTx(ctx, nil)
		must(t, err)
		_, err = tx.Exec(`SELECT set_config('app.current_tenant', 'tenant-a', true)`)
		must(t, err)
		err = tx.QueryRow(`SELECT envelope FROM authority_receipts WHERE tenant_id = 'tenant-a' AND chain_id = $1 AND seq = $2`,
			chain, int64(i+1)).Scan(&envelope)
		_ = tx.Rollback()
		if err == sql.ErrNoRows {
			t.Fatalf("no stored receipt at %s/%d", chain, i+1)
		}
		must(t, err)
		bundle, err := receiptverify.ParseBundle(envelope)
		must(t, err)
		digest, err := contracts.ReceiptChainHash(bundle.Receipts[0])
		must(t, err)
		ref := got.Msg.GetAttempt().GetReceipts()[0]
		trust := receiptverify.TrustRoot{Keys: map[string]string{ref.GetKid(): testReceiptSigner.PublicKey()}}
		if digest != ref.GetReceiptHash() || bundle.Receipts[0].EffectID != attempt.GetAttemptId() ||
			!receiptverify.Verify(bundle.Receipts, trust).Valid {
			t.Fatalf("receipt %s/%d does not match its reference %v", chain, i+1, ref)
		}
	}
}

func TestPostgresReceiptReadsOnTheWire(t *testing.T) {
	client, iss, _ := newWire(t)
	ctx := context.Background()
	propose := iss.token(t, testAudience, "tenant-a", "human-a", ScopePropose)
	read := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead)
	admitted, err := client.Propose(ctx, withToken(branchRequest("receipt-read-1", "helm/receipts"), propose))
	must(t, err)
	_, err = client.Propose(ctx, withToken(branchRequest("receipt-read-2", "main"), propose))
	must(t, err)
	trust, err := json.Marshal(map[string]any{"keys": map[string]string{testReceiptSigner.GetKeyID(): testReceiptSigner.PublicKey()}})
	must(t, err)

	// GetAttemptReceipts: the exact stored bytes, each verifying offline with
	// its binding under the published key.
	got, err := client.GetAttemptReceipts(ctx, withToken(&gatewayv1.GetAttemptReceiptsRequest{AttemptId: admitted.Msg.GetAttempt().GetAttemptId()}, read))
	must(t, err)
	receipts := got.Msg.GetReceipts()
	if got.Msg.GetAttemptId() != admitted.Msg.GetAttempt().GetAttemptId() || len(receipts) != 1 || receipts[0].GetFormat() != contracts.ReceiptSignatureV5 ||
		receipts[0].GetRef().GetSeq() != 1 || receipts[0].GetRef().GetReceiptHash() != admitted.Msg.GetAttempt().GetReceipts()[0].GetReceiptHash() {
		t.Fatalf("GetAttemptReceipts = %v", got.Msg)
	}
	bundle, err := receiptverify.ParseBundle(receipts[0].GetReceipt())
	must(t, err)
	bundle.GatewayBindings = map[string][]byte{receipts[0].GetReceiptId(): receipts[0].GetBinding()}
	if res := receiptverify.VerifyBundle(bundle, receiptverify.TrustRoot{Keys: map[string]string{receipts[0].GetRef().GetKid(): testReceiptSigner.PublicKey()}}); !res.Valid || res.Bindings != 1 {
		t.Fatalf("the read receipt does not verify with its binding: %+v", res)
	}

	// ExportReceiptChain: the token's chain as one document receipt_verify
	// checks offline.
	export, err := client.ExportReceiptChain(ctx, withToken(&gatewayv1.ExportReceiptChainRequest{WorkspaceId: "ws-a", FromSeq: 1, ToSeq: 2}, read))
	must(t, err)
	if export.Msg.GetChainId() != "helm-gateway:8:tenant-a:4:ws-a" || export.Msg.GetHeadSeq() != 2 || len(export.Msg.GetReceipts()) != 2 ||
		!bytes.Contains([]byte(export.Msg.GetBundle()), receipts[0].GetReceipt()) {
		t.Fatalf("ExportReceiptChain = %v", export.Msg)
	}
	if res := receiptverify.VerifyJSON([]byte(export.Msg.GetBundle()), trust); res.Verdict != receiptverify.VerdictVerified || res.Verification.Bindings != 2 {
		t.Fatalf("the export does not verify offline: %+v", res)
	}

	// Refused: another scope, another tenant's token, another workspace, and
	// an episode token's export.
	other := iss.token(t, testAudience, "tenant-b", "human-a", ScopeRead)
	otherWorkspace := iss.token(t, testAudience, "tenant-a", "human-a", ScopeRead, func(c *tokenClaims) { c.WorkspaceID = "ws-b" })
	for name, test := range map[string]struct {
		call func() error
		code connect.Code
	}{
		"a propose token reading receipts": {func() error {
			_, err := client.GetAttemptReceipts(ctx, withToken(&gatewayv1.GetAttemptReceiptsRequest{AttemptId: admitted.Msg.GetAttempt().GetAttemptId()}, propose))
			return err
		}, connect.CodePermissionDenied},
		"a propose token exporting": {func() error {
			_, err := client.ExportReceiptChain(ctx, withToken(&gatewayv1.ExportReceiptChainRequest{WorkspaceId: "ws-a", FromSeq: 1, ToSeq: 1}, propose))
			return err
		}, connect.CodePermissionDenied},
		"no token": {func() error {
			_, err := client.ExportReceiptChain(ctx, connect.NewRequest(&gatewayv1.ExportReceiptChainRequest{WorkspaceId: "ws-a", FromSeq: 1, ToSeq: 1}))
			return err
		}, connect.CodeUnauthenticated},
		"tenant b reading tenant a's attempt": {func() error {
			_, err := client.GetAttemptReceipts(ctx, withToken(&gatewayv1.GetAttemptReceiptsRequest{AttemptId: admitted.Msg.GetAttempt().GetAttemptId()}, other))
			return err
		}, connect.CodeNotFound},
		"tenant b exporting its own empty chain": {func() error {
			_, err := client.ExportReceiptChain(ctx, withToken(&gatewayv1.ExportReceiptChainRequest{WorkspaceId: "ws-a", FromSeq: 1, ToSeq: 1}, other))
			return err
		}, connect.CodeNotFound},
		"workspace b naming workspace a": {func() error {
			_, err := client.ExportReceiptChain(ctx, withToken(&gatewayv1.ExportReceiptChainRequest{WorkspaceId: "ws-a", FromSeq: 1, ToSeq: 1}, otherWorkspace))
			return err
		}, connect.CodePermissionDenied},
		"workspace b reading workspace a's attempt": {func() error {
			_, err := client.GetAttemptReceipts(ctx, withToken(&gatewayv1.GetAttemptReceiptsRequest{AttemptId: admitted.Msg.GetAttempt().GetAttemptId()}, otherWorkspace))
			return err
		}, connect.CodeNotFound},
		"a range over the cap": {func() error {
			_, err := client.ExportReceiptChain(ctx, withToken(&gatewayv1.ExportReceiptChainRequest{WorkspaceId: "ws-a", FromSeq: 1, ToSeq: 257}, read))
			return err
		}, connect.CodeInvalidArgument},
	} {
		if err := test.call(); connect.CodeOf(err) != test.code {
			t.Errorf("%s: %v, want %v", name, err, test.code)
		}
	}
}
