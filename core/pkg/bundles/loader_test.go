package bundles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromBytes(t *testing.T) {
	yaml := `
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  name: test-bundle
  version: "1.0.0"
rules:
  - id: deny-writes
    action: "write.*"
    expression: "true"
    verdict: BLOCK
    reason: "No writes allowed"
  - id: allow-reads
    action: "read.*"
    expression: "true"
    verdict: ALLOW
    reason: "Reads are permitted"
`
	bundle, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if bundle.Metadata.Name != "test-bundle" {
		t.Fatalf("expected test-bundle, got %s", bundle.Metadata.Name)
	}
	if len(bundle.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(bundle.Rules))
	}
	if bundle.Metadata.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestLoadFromFile(t *testing.T) {
	yaml := `
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  name: file-bundle
  version: "1.0.0"
rules:
  - id: rate-limit
    action: "*"
    expression: "state.calls_per_minute < 100"
    verdict: BLOCK
    reason: "Rate limit exceeded"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	bundle, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if bundle.Metadata.Name != "file-bundle" {
		t.Fatalf("expected file-bundle, got %s", bundle.Metadata.Name)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	_, err := LoadFromBytes([]byte("not: [yaml: {{"))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadMissingName(t *testing.T) {
	yaml := `
apiVersion: helm.mindburn.run/v1
kind: PolicyBundle
metadata:
  version: "1.0.0"
rules:
  - id: r1
    action: "*"
    verdict: BLOCK
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestLoadInvalidVerdict(t *testing.T) {
	yaml := `
apiVersion: helm.mindburn.run/v1
metadata:
  name: bad
rules:
  - id: r1
    action: "*"
    verdict: MAYBE
`
	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid verdict")
	}
}

func TestVerify(t *testing.T) {
	yaml := `
apiVersion: helm.mindburn.run/v1
metadata:
  name: verified
  version: "1.0.0"
rules:
  - id: r1
    action: "*"
    verdict: BLOCK
    reason: "test"
`
	bundle, _ := LoadFromBytes([]byte(yaml))
	hash := bundle.Metadata.Hash

	if err := Verify(bundle, hash); err != nil {
		t.Fatalf("verify should pass: %v", err)
	}
	if err := Verify(bundle, "wrong"); err == nil {
		t.Fatal("verify should fail for wrong hash")
	}
}

func TestCompose(t *testing.T) {
	b1 := &Bundle{
		Metadata: BundleMetadata{Name: "b1", Version: "1.0"},
		Rules: []Rule{
			{ID: "r1", Action: "write.*", Verdict: "BLOCK", Reason: "no writes"},
		},
	}
	b2 := &Bundle{
		Metadata: BundleMetadata{Name: "b2", Version: "1.0"},
		Rules: []Rule{
			{ID: "r2", Action: "read.*", Verdict: "ALLOW", Reason: "reads ok"},
		},
	}

	composed, err := Compose(b1, b2)
	if err != nil {
		t.Fatal(err)
	}
	if composed.RuleCount != 2 {
		t.Fatalf("expected 2 rules, got %d", composed.RuleCount)
	}
	if len(composed.Conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %v", composed.Conflicts)
	}
}

func TestComposeConflict(t *testing.T) {
	b1 := &Bundle{
		Metadata: BundleMetadata{Name: "b1", Version: "1.0"},
		Rules: []Rule{
			{ID: "shared", Action: "*", Verdict: "BLOCK", Reason: "block all"},
		},
	}
	b2 := &Bundle{
		Metadata: BundleMetadata{Name: "b2", Version: "1.0"},
		Rules: []Rule{
			{ID: "shared", Action: "*", Verdict: "ALLOW", Reason: "allow all"},
		},
	}

	composed, err := Compose(b1, b2)
	if err != nil {
		t.Fatal(err)
	}
	if len(composed.Conflicts) == 0 {
		t.Fatal("expected conflict for same rule ID with different verdicts")
	}
	// First bundle wins
	if composed.RuleCount != 1 {
		t.Fatalf("expected 1 rule (first wins), got %d", composed.RuleCount)
	}
}

func TestInspect(t *testing.T) {
	bundle := &Bundle{
		Metadata: BundleMetadata{Name: "inspected", Version: "2.0", Hash: "abc"},
		Rules: []Rule{
			{ID: "r1", Action: "write.*", Verdict: "BLOCK", Reason: "n"},
			{ID: "r2", Action: "read.*", Verdict: "ALLOW", Reason: "y"},
		},
	}

	info := Inspect(bundle)
	if info.Name != "inspected" {
		t.Fatalf("expected inspected, got %s", info.Name)
	}
	if info.RuleCount != 2 {
		t.Fatalf("expected 2 rules, got %d", info.RuleCount)
	}
	if len(info.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(info.Actions))
	}
}

func TestComposeEmpty(t *testing.T) {
	composed, err := Compose()
	if err != nil {
		t.Fatal(err)
	}
	if composed.RuleCount != 0 {
		t.Fatalf("expected 0 rules, got %d", composed.RuleCount)
	}
}

func TestHashDeterminism(t *testing.T) {
	yaml := `
metadata:
  name: det
  version: "1.0"
rules:
  - id: r1
    action: "*"
    verdict: BLOCK
    reason: test
`
	b1, _ := LoadFromBytes([]byte(yaml))
	b2, _ := LoadFromBytes([]byte(yaml))

	if b1.Metadata.Hash != b2.Metadata.Hash {
		t.Fatalf("hash not deterministic: %q vs %q", b1.Metadata.Hash, b2.Metadata.Hash)
	}
}
