package admission

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
)

// A TON mainnet effect is refused at Propose with a registered reason code, before
// any database use, whatever adapters are configured (helm-tracker#266).
func TestTONMainnetEffectsAreRefusedBeforeAnyDatabaseUse(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{ReceiptSigner: testReceiptSigner, Adapters: []adapters.Adapter{argumentAdapter{declaration: noteArgumentDeclaration()}}})
	must(t, err)
	for _, effectType := range []string{"ton.acton.script.mainnet", "ton.acton.library.publish_mainnet",
		"ton.acton.library.topup_mainnet", "ton.acton.source.verify_mainnet"} {
		in := note("mainnet")
		in.EffectType = effectType
		in.Target = "ton-acton:demo"
		in.Arguments = []byte(`{}`)
		_, _, err := svc.Propose(context.Background(), human, in)
		wantRefusal(t, effectType, err, CodePermissionDenied, contracts.ReasonTONMainnetRefused)
	}
	must(t, mock.ExpectationsWereMet())
}

// The testnet and fork effect types are not caught by that refusal: it names
// mainnet operations only.
func TestTONNonMainnetEffectsPassTheMainnetRefusal(t *testing.T) {
	for _, effectType := range []string{"ton.acton.script.testnet", "ton.acton.script.fork_mainnet", "ton.acton.contract.build"} {
		in := note("ok")
		in.EffectType = effectType
		in.Target = "ton-acton:demo"
		_, err := validateProposal(in)
		if e, ok := err.(*Error); ok && e.Reason == contracts.ReasonTONMainnetRefused {
			t.Fatalf("%s was refused as mainnet", effectType)
		}
	}
}
