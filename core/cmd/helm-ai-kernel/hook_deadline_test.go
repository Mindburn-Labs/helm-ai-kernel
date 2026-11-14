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
	denied, stdout, receipts := env.runAt(t, "/repo", "Grep", map[string]any{"glob": "*.go", "pattern": "needle"})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the hook answered after %s, want soon after its deadline", elapsed)
	}
	if !denied || len(receipts) != 1 || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") || !strings.Contains(stdout, "did not finish classifying") {
		t.Fatalf("denied=%v receipts=[%s] stdout=%s, want one denial that says the call was not classified in time", denied, describeReceipts(receipts), stdout)
	}
}

// Past its deadline the hook stops the classifier: the guard it classifies
// with refuses everything from then on, so the work ends instead of running
// on beside the decision the hook has already made.
func TestHookStopsTheClassifierAtItsDeadline(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	originalDeadline, originalClassify := hookClassificationDeadline, hookClassify
	stopped, quit := make(chan struct{}), make(chan struct{})
	hookClassificationDeadline = 50 * time.Millisecond
	hookClassify = func(payload preToolPayload, guard *shellscan.PathGuard) []hookClassification {
		defer close(stopped)
		for {
			// A path far from the signer's files matches only once the
			// guard has been stopped.
			if _, matched := guard.Match("/nonexistent/src/main.go", "/"); matched {
				return nil
			}
			select {
			case <-quit:
				return nil
			default:
			}
		}
	}
	t.Cleanup(func() {
		close(quit)
		hookClassificationDeadline, hookClassify = originalDeadline, originalClassify
	})
	denied, stdout, receipts := env.runAt(t, "/repo", "Grep", map[string]any{"glob": "*.go", "pattern": "needle"})
	if !denied || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") {
		t.Fatalf("denied=%v receipts=[%s] stdout=%s, want the call refused at the deadline", denied, describeReceipts(receipts), stdout)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the classifier was still running two seconds after the hook answered")
	}
}

// A classifier that panics does not take the hook down without a decision:
// the call is refused as reaching trust material, with a signed receipt.
func TestHookRefusesACallWhoseClassifierPanics(t *testing.T) {
	env := newHookBypassEnv(t, "observe_draft.v1.allow.json")
	originalClassify := hookClassify
	hookClassify = func(payload preToolPayload, guard *shellscan.PathGuard) []hookClassification {
		var parts []string
		return []hookClassification{{Target: parts[len(parts)-1]}}
	}
	t.Cleanup(func() { hookClassify = originalClassify })
	denied, stdout, receipts := env.runAt(t, "/repo", "Bash", map[string]any{"command": "echo ok"})
	if !denied || len(receipts) != 1 || !hasDenial(receipts, "TRUST_MATERIAL_ACCESS_DENIED") || !strings.Contains(stdout, "panicked") {
		t.Fatalf("denied=%v receipts=[%s] stdout=%s, want one signed denial that says the classifier panicked", denied, describeReceipts(receipts), stdout)
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
