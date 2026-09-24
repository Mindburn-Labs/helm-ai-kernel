package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

// Activation compiles the policy through the authority core and refuses a
// version with a rule that cannot be decided, rather than installing it.
func TestCompileServePolicySnapshotRefusesUndecidableRules(t *testing.T) {
	cases := map[string]string{
		"invalid CEL":                   `{"action": "EXECUTE_TOOL", "expression": "input.x =="}`,
		"requirement with no condition": `{"action": "EXECUTE_TOOL", "requirement_set": {"requirements": [{"id": "open"}]}}`,
	}
	for name, action := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			refBytes := []byte(`{"pack_id": "runtime-pack", "version": 1, "runtime_actions": [` + action + `]}`)
			refPath := filepath.Join(dir, "runtime.json")
			if err := os.WriteFile(refPath, refBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			policyPath := filepath.Join(dir, "policy.toml")
			policyBytes := []byte(`
name = "runtime"
profile = "test"
reference_pack = "./runtime.json"

[server]
bind = "127.0.0.1"
port = 7714

[receipts]
store = "sqlite"
path = "./data/receipts.db"
`)
			if err := os.WriteFile(policyPath, policyBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			sourceRefs := []string{policyPath, "reference_pack:" + refPath + "@" + policyreconcile.HashBytes(refBytes)}
			head := policyreconcile.PolicyHead{
				Scope:       policyreconcile.DefaultScope,
				PolicyEpoch: 1,
				PolicyHash:  policyreconcile.PolicyHashWithSourceRefs(policyBytes, sourceRefs),
				BundleRef:   policyPath,
				SourceRefs:  sourceRefs,
			}

			_, err := compileServePolicySnapshot(context.Background(), head, policyBytes)
			if err == nil || !strings.Contains(err.Error(), "action EXECUTE_TOOL") {
				t.Fatalf("expected activation to refuse the rule, got %v", err)
			}
		})
	}
}
