package kernel

import (
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAgentKillSwitch_KillAndCheck(t *testing.T) {
	ks := NewAgentKillSwitch()

	if ks.IsKilled("agent-1") {
		t.Error("agent should not be killed initially")
	}

	receipt, err := ks.Kill("agent-1", "operator", "compromised")
	if err != nil {
		t.Fatalf("Kill failed: %v", err)
	}
	if !ks.IsKilled("agent-1") {
		t.Error("agent should be killed after Kill()")
	}
	if receipt.Action != "KILL" {
		t.Errorf("receipt action = %s, want KILL", receipt.Action)
	}
	if receipt.AgentID != "agent-1" {
		t.Errorf("receipt agent_id = %s, want agent-1", receipt.AgentID)
	}
	if receipt.Principal != "operator" {
		t.Errorf("receipt principal = %s, want operator", receipt.Principal)
	}
	if receipt.Reason != "compromised" {
		t.Errorf("receipt reason = %s, want compromised", receipt.Reason)
	}
}

func TestAgentKillSwitch_ReviveAndCheck(t *testing.T) {
	ks := NewAgentKillSwitch()

	if _, err := ks.Kill("agent-1", "operator", "test"); err != nil {
		t.Fatalf("Kill failed: %v", err)
	}
	if !ks.IsKilled("agent-1") {
		t.Error("agent should be killed")
	}

	receipt, err := ks.Revive("agent-1", "admin")
	if err != nil {
		t.Fatalf("Revive failed: %v", err)
	}
	if ks.IsKilled("agent-1") {
		t.Error("agent should not be killed after Revive()")
	}
	if receipt.Action != "REVIVE" {
		t.Errorf("receipt action = %s, want REVIVE", receipt.Action)
	}
	if receipt.AgentID != "agent-1" {
		t.Errorf("receipt agent_id = %s, want agent-1", receipt.AgentID)
	}
	if receipt.Principal != "admin" {
		t.Errorf("receipt principal = %s, want admin", receipt.Principal)
	}
}

func TestAgentKillSwitch_DoubleKill(t *testing.T) {
	ks := NewAgentKillSwitch()

	if _, err := ks.Kill("agent-1", "op1", "first"); err != nil {
		t.Fatalf("first Kill should succeed: %v", err)
	}

	_, err := ks.Kill("agent-1", "op2", "second")
	if err == nil {
		t.Error("second Kill should return error")
	}
	if !strings.Contains(err.Error(), "already killed") {
		t.Errorf("error should mention 'already killed', got: %v", err)
	}
}

func TestAgentKillSwitch_ReviveNotKilled(t *testing.T) {
	ks := NewAgentKillSwitch()

	_, err := ks.Revive("agent-1", "admin")
	if err == nil {
		t.Error("Revive on non-killed agent should return error")
	}
	if !strings.Contains(err.Error(), "not killed") {
		t.Errorf("error should mention 'not killed', got: %v", err)
	}
}

func TestAgentKillSwitch_ListKilled(t *testing.T) {
	ks := NewAgentKillSwitch()

	ks.Kill("agent-a", "op", "reason-a")
	ks.Kill("agent-b", "op", "reason-b")
	ks.Kill("agent-c", "op", "reason-c")

	killed := ks.ListKilled()
	if len(killed) != 3 {
		t.Fatalf("want 3 killed agents, got %d", len(killed))
	}

	sort.Strings(killed)
	expected := []string{"agent-a", "agent-b", "agent-c"}
	for i, id := range expected {
		if killed[i] != id {
			t.Errorf("killed[%d] = %s, want %s", i, killed[i], id)
		}
	}
}

func TestAgentKillSwitch_Receipts(t *testing.T) {
	ks := NewAgentKillSwitch()

	ks.Kill("agent-1", "op1", "reason1")
	ks.Revive("agent-1", "op2")
	ks.Kill("agent-2", "op3", "reason2")

	receipts := ks.Receipts()
	if len(receipts) != 3 {
		t.Fatalf("want 3 receipts, got %d", len(receipts))
	}

	// Verify all receipts have content hashes
	for i, r := range receipts {
		if r.ContentHash == "" {
			t.Errorf("receipt[%d] content hash must not be empty", i)
		}
	}

	if receipts[0].Action != "KILL" || receipts[0].AgentID != "agent-1" {
		t.Errorf("receipts[0] = %+v, want KILL agent-1", receipts[0])
	}
	if receipts[1].Action != "REVIVE" || receipts[1].AgentID != "agent-1" {
		t.Errorf("receipts[1] = %+v, want REVIVE agent-1", receipts[1])
	}
	if receipts[2].Action != "KILL" || receipts[2].AgentID != "agent-2" {
		t.Errorf("receipts[2] = %+v, want KILL agent-2", receipts[2])
	}
}

func TestAgentKillSwitch_Concurrency(t *testing.T) {
	ks := NewAgentKillSwitch()
	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ks.IsKilled("agent-1")
			_ = ks.ListKilled()
		}()
	}

	// Concurrent writers
	for i := 0; i < 50; i++ {
		agentID := "agent-concurrent"
		wg.Add(1)
		go func() {
			defer wg.Done()
			ks.Kill(agentID, "op", "test")
			ks.Revive(agentID, "op")
		}()
	}

	wg.Wait()
	// No panics or races — test passes if we reach here
}

func TestAgentKillSwitch_Clock(t *testing.T) {
	ts := time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)
	ks := NewAgentKillSwitch().WithKillSwitchClock(fixedClock(ts))

	receipt, err := ks.Kill("agent-1", "operator", "test")
	if err != nil {
		t.Fatalf("Kill failed: %v", err)
	}
	if receipt.Timestamp != ts {
		t.Errorf("receipt timestamp = %v, want %v", receipt.Timestamp, ts)
	}

	// Deterministic hash: same clock, same inputs → same hash
	ks2 := NewAgentKillSwitch().WithKillSwitchClock(fixedClock(ts))
	receipt2, _ := ks2.Kill("agent-1", "operator", "test")
	if receipt.ContentHash != receipt2.ContentHash {
		t.Errorf("deterministic hashes should match: %s != %s", receipt.ContentHash, receipt2.ContentHash)
	}
}
