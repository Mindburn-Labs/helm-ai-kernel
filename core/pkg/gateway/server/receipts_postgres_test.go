package server

// CTL-059 on the wire (listed in scripts/ci/postgres-proofs.txt): an attempt
// carries the references of its signed decision receipts, and each reference
// names the stored receipt a reader verifies offline under the gateway's key.
//
// quantum_posture: verifies classical Ed25519 test receipts and signs
// classical RS256 test tokens; no post-quantum claim.

import (
	"context"
	"database/sql"
	"testing"

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
