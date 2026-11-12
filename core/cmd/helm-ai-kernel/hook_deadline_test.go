// quantum_posture: these tests exercise hook and enforce receipts signed with
// the classical Ed25519 workstation seed; no post-quantum primitive is involved.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/shellscan"
)

// A call the hook cannot classify before its deadline is refused, well
// before the client gives up on the hook and decides without it.
func TestHookDeniesACallItCannotClassifyInTime(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	if hookClassificationDeadline <= 0 || hookClassificationDeadline > 15*time.Second {
		t.Fatalf("classification deadline %s, want one well under the 30 s hook timeout setup installs", hookClassificationDeadline)
	}
	originalDeadline, originalClassify := hookClassificationDeadline, hookClassify
	release := make(chan struct{})
	hookClassificationDeadline = 50 * time.Millisecond
	hookClassify = func(payload preToolPayload, guard *shellscan.PathGuard) []hookClassification {
		<-release
		return nil
	}
	t.Cleanup(func() {
		close(release)
		hookClassificationDeadline, hookClassify = originalDeadline, originalClassify
	})
	start := time.Now()
	denied, stdout, receipts := env.runAt(t, "/repo", "Grep", map[string]any{"glob": "*.go", "pattern": "TODO"})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the hook answered after %s, want soon after its deadline", elapsed)
	}
	if !denied || len(receipts) != 1 || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") || !strings.Contains(stdout, "did not finish classifying") {
		t.Fatalf("denied=%v receipts=[%s] stdout=%s, want one denial that says the call was not classified in time", denied, describeReceipts(receipts), stdout)
	}
}

// enforce creates each receipt file new: a receipt already on disk is never
// replaced, whatever its name.
func TestEnforceReceiptWriteNeverReplacesAFile(t *testing.T) {
	dir := t.TempDir()
	receipt := &contracts.WorkstationPolicyDecisionReceipt{DecisionID: "wpd_fixed", Verdict: contracts.WorkstationVerdictAllow}
	existing := filepath.Join(dir, receipt.DecisionID+".json")
	if err := os.WriteFile(existing, []byte("earlier run"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeNewDecisionReceipt("", dir, receipt); err == nil {
		t.Fatal("a receipt was written over an existing file")
	}
	if data, _ := os.ReadFile(existing); string(data) != "earlier run" {
		t.Fatalf("the existing receipt was replaced: %q", data)
	}
	path, err := writeNewDecisionReceipt("", dir, &contracts.WorkstationPolicyDecisionReceipt{DecisionID: "wpd_other"})
	if err != nil || !strings.HasSuffix(path, "wpd_other.json") {
		t.Fatalf("a new receipt was not written: %q, %v", path, err)
	}
}
