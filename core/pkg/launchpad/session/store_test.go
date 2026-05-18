package session

import "testing"

func TestDeletedRequiresTeardownReceipt(t *testing.T) {
	store := NewStore(t.TempDir())
	err := store.Save(LaunchRun{LaunchID: "launch-1", State: StateDeleted})
	if err == nil {
		t.Fatal("expected deleted without teardown receipt to fail")
	}
}

func TestRunningRequiresReceiptAndSandbox(t *testing.T) {
	store := NewStore(t.TempDir())
	err := store.Save(LaunchRun{LaunchID: "launch-1", State: StateRunning})
	if err == nil {
		t.Fatal("expected running without refs to fail")
	}
}

func TestRunningAllowsLaunchHealthcheckAndSandboxRefs(t *testing.T) {
	store := NewStore(t.TempDir())
	err := store.Save(LaunchRun{
		LaunchID:          "launch-1",
		State:             StateRunning,
		KernelVerdict:     "ALLOW",
		LaunchReceiptRefs: []string{"launch"},
		HealthcheckRefs:   []string{"healthcheck"},
		SandboxGrantRefs:  []string{"sandbox"},
	})
	if err != nil {
		t.Fatalf("expected running with required refs to save: %v", err)
	}
}

func TestSideEffectStateRequiresAllowVerdict(t *testing.T) {
	store := NewStore(t.TempDir())
	err := store.Save(LaunchRun{
		LaunchID:      "launch-1",
		State:         StateInstalling,
		KernelVerdict: "ESCALATE",
	})
	if err == nil {
		t.Fatal("expected side-effect state without ALLOW to fail")
	}
}

func TestUnknownVerdictRejected(t *testing.T) {
	store := NewStore(t.TempDir())
	err := store.Save(LaunchRun{
		LaunchID:      "launch-1",
		State:         StateEscalated,
		KernelVerdict: "WAIT",
	})
	if err == nil {
		t.Fatal("expected unknown verdict to fail")
	}
}
