package cedar

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Synthetic policies covering the same logical rule used by the Rego
// equivalence test, expressed in Cedar's entity-shape model.
const (
	cedarPolicyAllowAdminDelete = `
// Anyone may view.
permit(
    principal,
    action == Action::"view",
    resource
);

// Only admins may delete.
permit(
    principal,
    action == Action::"delete",
    resource
)
when { principal in Role::"admin" };
`

	cedarEntitiesAlice = `[
  {
    "uid":   { "type": "Role", "id": "admin" },
    "attrs": {},
    "parents": []
  },
  {
    "uid":   { "type": "User", "id": "alice" },
    "attrs": {},
    "parents": [{ "type": "Role", "id": "admin" }]
  },
  {
    "uid":   { "type": "User", "id": "bob" },
    "attrs": {},
    "parents": []
  },
  {
    "uid":   { "type": "Document", "id": "doc-1" },
    "attrs": {},
    "parents": []
  }
]`
)

func fixedNow() time.Time { return time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC) }

func TestCompile_Succeeds(t *testing.T) {
	b, err := Compile(cedarPolicyAllowAdminDelete, CompileOptions{
		BundleID:    "cedar-test-1",
		Name:        "Cedar Allow Admin Delete",
		EntitiesDoc: cedarEntitiesAlice,
		Now:         fixedNow,
	})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if b.Language != Language {
		t.Errorf("language = %q, want %q", b.Language, Language)
	}
	if !strings.HasPrefix(b.Hash, "sha256:") {
		t.Errorf("hash = %q, want sha256: prefix", b.Hash)
	}
	if b.Version != 1 {
		t.Errorf("version = %d, want 1", b.Version)
	}
	if b.CompiledAt.IsZero() {
		t.Error("compiled_at zero")
	}
}

func TestCompile_DeterministicHash(t *testing.T) {
	opts := CompileOptions{
		BundleID:    "cedar-deterministic",
		Name:        "Cedar Deterministic Hash",
		EntitiesDoc: cedarEntitiesAlice,
		Now:         fixedNow,
	}
	a, err := Compile(cedarPolicyAllowAdminDelete, opts)
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	b, err := Compile(cedarPolicyAllowAdminDelete, opts)
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if a.Hash != b.Hash {
		t.Errorf("hash drift: %s vs %s", a.Hash, b.Hash)
	}
}

func TestCompile_RejectsEmpty(t *testing.T) {
	_, err := Compile("", CompileOptions{Now: fixedNow})
	if err == nil {
		t.Fatal("expected empty policy set to fail")
	}
}

func TestCompile_RejectsBadEntities(t *testing.T) {
	_, err := Compile(cedarPolicyAllowAdminDelete, CompileOptions{
		EntitiesDoc: `not-a-valid-cedar-entity-doc`,
		Now:         fixedNow,
	})
	if err == nil {
		t.Fatal("expected malformed entities doc to fail")
	}
}

func TestEvaluate_AllowAdminDelete(t *testing.T) {
	b, err := Compile(cedarPolicyAllowAdminDelete, CompileOptions{
		BundleID:    "cedar-eval-1",
		Name:        "Cedar Eval",
		EntitiesDoc: cedarEntitiesAlice,
		Now:         fixedNow,
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ev, err := NewEvaluator(context.Background(), b)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}

	cases := []struct {
		name      string
		req       *DecisionRequest
		wantAllow bool
	}{
		{
			name: "alice can view",
			req: &DecisionRequest{
				Principal: `User::"alice"`,
				Action:    `Action::"view"`,
				Resource:  `Document::"doc-1"`,
			},
			wantAllow: true,
		},
		{
			name: "bob can view",
			req: &DecisionRequest{
				Principal: `User::"bob"`,
				Action:    `Action::"view"`,
				Resource:  `Document::"doc-1"`,
			},
			wantAllow: true,
		},
		{
			name: "alice can delete (admin)",
			req: &DecisionRequest{
				Principal: `User::"alice"`,
				Action:    `Action::"delete"`,
				Resource:  `Document::"doc-1"`,
			},
			wantAllow: true,
		},
		{
			name: "bob cannot delete (not admin)",
			req: &DecisionRequest{
				Principal: `User::"bob"`,
				Action:    `Action::"delete"`,
				Resource:  `Document::"doc-1"`,
			},
			wantAllow: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ev.Evaluate(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			gotAllow := d.Verdict == "ALLOW"
			if gotAllow != tc.wantAllow {
				t.Errorf("verdict = %s, wantAllow=%v", d.Verdict, tc.wantAllow)
			}
		})
	}
}

func TestEvaluate_RejectsNilRequest(t *testing.T) {
	b, err := Compile(cedarPolicyAllowAdminDelete, CompileOptions{
		EntitiesDoc: cedarEntitiesAlice,
		Now:         fixedNow,
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ev, err := NewEvaluator(context.Background(), b)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	if _, err := ev.Evaluate(context.Background(), nil); err == nil {
		t.Fatal("expected nil request to fail")
	}
}
