package admission

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestPostgresDeclaredArgumentsRejectBeforeReservationAndPermit(t *testing.T) {
	f := newFixture(t)
	f.notesLimit(2)
	svc := f.withAdapter(argumentAdapter{scripted: &scripted{}, declaration: noteArgumentDeclaration()})
	for name, raw := range invalidDeclaredArguments() {
		t.Run(name, func(t *testing.T) {
			in := note("invalid-input-" + name)
			in.Arguments = []byte(raw)
			in.Quote = []Amount{{Unit: "notes", Amount: 1}}
			_, _, err := svc.Propose(context.Background(), human, in)
			wantRefusal(t, name, err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
		})
	}
	for _, table := range []string{"authority_effect_attempts", "authority_permits", "authority_exposures", "authority_postings"} {
		if n := f.count(tenantA, "SELECT count(*) FROM "+table); n != 0 {
			t.Fatalf("invalid input left %d rows in %s", n, table)
		}
	}
	valid := note("valid-input")
	valid.Arguments = []byte(`{"text":"hello","metadata":{"priority":2}}`)
	valid.Quote = []Amount{{Unit: "notes", Amount: 1}}
	a, existing, err := svc.Propose(context.Background(), human, valid)
	must(t, err)
	if existing {
		t.Fatal("first valid proposal was treated as replay")
	}
	wantState(t, "valid custom input", a, "ADMITTED", "")
	if n := f.count(tenantA, `SELECT count(*) FROM authority_permits WHERE attempt_id=$1`, a.ID); n != 1 {
		t.Fatal("valid input did not receive exactly one permit")
	}
	if n := f.count(tenantA, `SELECT count(*) FROM authority_exposures WHERE attempt_id=$1 AND kind='held' AND amount=1`, a.ID); n != 1 {
		t.Fatal("valid input did not reserve its fixed quote")
	}
	replayed, existing, err := svc.Propose(context.Background(), human, valid)
	must(t, err)
	if !existing || replayed.ID != a.ID {
		t.Fatal("valid input replay created a different attempt")
	}
	f.ledgerBalances()
}
