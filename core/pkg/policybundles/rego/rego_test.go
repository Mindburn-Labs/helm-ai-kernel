package rego

import (
	"context"
	"strings"
	"testing"
	"time"
)

const allowAdminDeleteRego = `package helm.policy

import rego.v1

default decision := {"verdict": "DENY", "reason": "default deny"}

decision := {"verdict": "ALLOW"} if {
	input.action == "view"
}

decision := {"verdict": "ALLOW"} if {
	input.action == "delete"
	input.context.role == "admin"
}
`

func TestCompile_Succeeds(t *testing.T) {
	bundle, err := Compile(allowAdminDeleteRego, CompileOptions{
		BundleID: "rego-test-1",
		Name:     "Rego Test",
		Now:      func() time.Time { return time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if bundle.Language != Language {
		t.Errorf("language = %q, want %q", bundle.Language, Language)
	}
	if !strings.HasPrefix(bundle.Hash, "sha256:") {
		t.Errorf("hash = %q, want sha256: prefix", bundle.Hash)
	}
	if bundle.Query != "data.helm.policy.decision" {
		t.Errorf("default query mismatch: %q", bundle.Query)
	}
}

func TestCompile_DeterministicHash(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC) }
	a, err := Compile(allowAdminDeleteRego, CompileOptions{BundleID: "x", Name: "x", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(allowAdminDeleteRego, CompileOptions{BundleID: "x", Name: "x", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Errorf("hashes differ: %s vs %s", a.Hash, b.Hash)
	}
}

func TestCompile_RejectsHTTPSend(t *testing.T) {
	module := `package helm.policy
import rego.v1
decision := {"verdict": "ALLOW"} if {
	resp := http.send({"method": "GET", "url": "https://example.com"})
	resp.status_code == 200
}
`
	_, err := Compile(module, CompileOptions{BundleID: "bad", Name: "bad"})
	if err == nil {
		t.Fatal("Compile should reject http.send")
	}
	if !strings.Contains(err.Error(), "http.send") {
		t.Errorf("error should mention http.send, got %v", err)
	}
}

func TestCompile_RejectsTimeNowNs(t *testing.T) {
	module := `package helm.policy
import rego.v1
decision := {"verdict": "ALLOW"} if {
	time.now_ns() > 0
}
`
	_, err := Compile(module, CompileOptions{BundleID: "bad", Name: "bad"})
	if err == nil {
		t.Fatal("Compile should reject time.now_ns")
	}
	if !strings.Contains(err.Error(), "time.now_ns") {
		t.Errorf("error should mention time.now_ns, got %v", err)
	}
}

func TestCompile_RejectsRandIntn(t *testing.T) {
	module := `package helm.policy
import rego.v1
decision := {"verdict": "ALLOW"} if {
	rand.intn("x", 100) == 42
}
`
	_, err := Compile(module, CompileOptions{BundleID: "bad", Name: "bad"})
	if err == nil {
		t.Fatal("Compile should reject rand.intn")
	}
	if !strings.Contains(err.Error(), "rand.intn") {
		t.Errorf("error should mention rand.intn, got %v", err)
	}
}

func TestCompile_RejectsCryptoX509(t *testing.T) {
	module := `package helm.policy
import rego.v1
decision := {"verdict": "ALLOW"} if {
	certs := crypto.x509.parse_certificates("x")
	count(certs) > 0
}
`
	_, err := Compile(module, CompileOptions{BundleID: "bad", Name: "bad"})
	if err == nil {
		t.Fatal("Compile should reject crypto.x509.parse_certificates")
	}
}

func TestCompile_RejectsEmpty(t *testing.T) {
	if _, err := Compile("   \n  ", CompileOptions{}); err == nil {
		t.Fatal("Compile should reject empty module")
	}
}

func TestEvaluate_AdminCanDelete(t *testing.T) {
	bundle, err := Compile(allowAdminDeleteRego, CompileOptions{BundleID: "id", Name: "name"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ev.Evaluate(context.Background(), &DecisionRequest{
		Principal: "alice",
		Action:    "delete",
		Resource:  "tool:rm",
		Tool:      "rm",
		Context:   map[string]interface{}{"role": "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != VerdictAllow {
		t.Errorf("verdict = %q, want ALLOW; reason=%q", d.Verdict, d.Reason)
	}
}

func TestEvaluate_NonAdminCannotDelete(t *testing.T) {
	bundle, err := Compile(allowAdminDeleteRego, CompileOptions{BundleID: "id", Name: "name"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ev.Evaluate(context.Background(), &DecisionRequest{
		Principal: "bob",
		Action:    "delete",
		Resource:  "tool:rm",
		Tool:      "rm",
		Context:   map[string]interface{}{"role": "user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != VerdictDeny {
		t.Errorf("verdict = %q, want DENY", d.Verdict)
	}
}

func TestEvaluate_NilRequest(t *testing.T) {
	bundle, err := Compile(allowAdminDeleteRego, CompileOptions{BundleID: "id", Name: "name"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(context.Background(), nil); err == nil {
		t.Fatal("Evaluate(nil) should error")
	}
}

func TestNewEvaluator_NilBundle(t *testing.T) {
	if _, err := NewEvaluator(context.Background(), nil); err == nil {
		t.Fatal("NewEvaluator(nil) should error")
	}
}
