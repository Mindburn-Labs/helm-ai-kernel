package admission

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/reassignment"
)

// The custom effect intentionally has no effectargs switch case. Its exact
// input contract must come from the registered adapter, including nested input.
const noteArgumentSchema = `{"type":"object","additionalProperties":false,"required":["text","metadata"],"properties":{"text":{"type":"string","minLength":1},"metadata":{"type":"object","additionalProperties":false,"required":["priority"],"properties":{"priority":{"type":"integer","minimum":1,"maximum":3}}}}}`

type argumentAdapter struct {
	*scripted
	declaration adapters.Declaration
}

func (a argumentAdapter) Declarations() []adapters.Declaration {
	return []adapters.Declaration{a.declaration}
}

func noteArgumentDeclaration() adapters.Declaration {
	return adapters.Declaration{EffectType: noteType, ArgumentSchema: []byte(noteArgumentSchema),
		Quote: []adapters.Amount{{Unit: "notes", Amount: 1}}}
}

func invalidDeclaredArguments() map[string]string {
	return map[string]string{
		"extra field":        `{"text":"hello","metadata":{"priority":2},"grant":"all"}`,
		"missing field":      `{"text":"hello"}`,
		"wrong type":         `{"text":7,"metadata":{"priority":2}}`,
		"nested extra field": `{"text":"hello","metadata":{"priority":2,"grant":"all"}}`,
		"nested missing":     `{"text":"hello","metadata":{}}`,
		"nested wrong type":  `{"text":"hello","metadata":{"priority":"2"}}`,
		"duplicate root":     `{"text":7,"text":"hello","metadata":{"priority":2}}`,
		"duplicate nested":   `{"text":"hello","metadata":{"priority":4,"priority":2}}`,
	}
}

func TestDeclaredArgumentsAreRefusedBeforeAnyDatabaseUse(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{Adapters: []adapters.Adapter{argumentAdapter{declaration: noteArgumentDeclaration()}}})
	must(t, err)
	for name, raw := range invalidDeclaredArguments() {
		t.Run(name, func(t *testing.T) {
			in := note("invalid-input")
			in.Arguments = []byte(raw)
			in.Quote = []Amount{{Unit: "notes", Amount: 1}}
			_, _, err := svc.Propose(context.Background(), human, in)
			wantRefusal(t, name, err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
		})
	}
	// No Begin or query is expected. A schema refusal must precede all durable
	// admission, even when the database itself is unavailable.
	must(t, mock.ExpectationsWereMet())
}

func TestInvalidArgumentContractPreventsServiceRegistration(t *testing.T) {
	db, _, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	for _, raw := range []string{`{"type":"object"}`, `{`, `{"type":"object","additionalProperties":false,"properties":{"x":{"$ref":"file:///etc/passwd"}}}`} {
		d := noteArgumentDeclaration()
		d.ArgumentSchema = []byte(raw)
		if _, err := New(db, Config{Adapters: []adapters.Adapter{argumentAdapter{declaration: d}}}); err == nil {
			t.Fatalf("invalid argument declaration was registered: %s", raw)
		}
	}
}

func TestDeclaredBuiltinSchemaPreservesSemanticRefusals(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	svc, err := New(db, Config{Adapters: []adapters.Adapter{github.New()}})
	must(t, err)
	for name, in := range map[string]ProposeInput{
		"invalid git ref":    proposal("bad-ref", github.EffectBranchCreateFromChanges, repo, branchArgs("helm/../unsafe")),
		"substituted target": proposal("bad-target", github.EffectBranchCreateFromChanges, "github.com/owner/repo/other", branchArgs("helm/valid")),
	} {
		_, _, err := svc.Propose(context.Background(), human, in)
		wantRefusal(t, name, err, CodeInvalidArgument, contracts.ReasonSchemaViolation)
	}
	must(t, mock.ExpectationsWereMet())
}

func TestCurrentBuiltinAdaptersRegisterWithoutChangingTheirContracts(t *testing.T) {
	db, mock, err := sqlmock.New()
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	p, err := provision.New(db)
	must(t, err)
	r, err := reassignment.New(db)
	must(t, err)
	_, err = New(db, Config{Adapters: []adapters.Adapter{github.New(), p, r}})
	must(t, err)
	must(t, mock.ExpectationsWereMet())
}
