package delegation

import (
	"context"
	"testing"
	"time"
)

func TestDelegationManager_CreateDelegation(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	grant, err := dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:   "agent-root",
		DelegateeID:   "agent-worker",
		Capabilities:  []string{"E0", "E1"},
		MaxChainDepth: 2,
		TTL:           1 * time.Hour,
	}, []string{"E0", "E1", "E2"}) // delegator has E0-E2

	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantID == "" {
		t.Error("GrantID should be generated")
	}
	if grant.DelegateeID != "agent-worker" {
		t.Error("DelegateeID mismatch")
	}
	if grant.ChainDepth != 0 {
		t.Error("initial ChainDepth should be 0")
	}
	if grant.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestDelegationManager_CapabilityAttenuation(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	// Try to delegate E3 when delegator only has E0, E1
	_, err := dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:  "root",
		DelegateeID:  "worker",
		Capabilities: []string{"E0", "E3"}, // E3 exceeds
	}, []string{"E0", "E1"})

	if err == nil {
		t.Error("expected error: E3 exceeds delegator's capabilities")
	}
}

func TestDelegationManager_CheckAuthorization(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:  "root",
		DelegateeID:  "worker",
		Capabilities: []string{"E0", "E1"},
		AllowedTools: []string{"read_file", "list_dir"},
		TTL:          1 * time.Hour,
	}, []string{"E0", "E1", "E2"})

	// Authorized: E0 + read_file
	v := dm.CheckAuthorization(ctx, "worker", "read_file", "E0")
	if !v.Authorized {
		t.Error("expected authorized for E0 read_file")
	}

	// Unauthorized: E2 (not in granted capabilities)
	v = dm.CheckAuthorization(ctx, "worker", "read_file", "E2")
	if v.Authorized {
		t.Error("expected unauthorized for E2 (not delegated)")
	}

	// Unauthorized: tool not in allowlist
	v = dm.CheckAuthorization(ctx, "worker", "delete_file", "E0")
	if v.Authorized {
		t.Error("expected unauthorized for delete_file (not in allowlist)")
	}

	// Unknown agent
	v = dm.CheckAuthorization(ctx, "unknown", "read_file", "E0")
	if v.Authorized {
		t.Error("expected unauthorized for unknown agent")
	}
}

func TestDelegationManager_ReDelegate(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	parent, _ := dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:   "root",
		DelegateeID:   "manager",
		Capabilities:  []string{"E0", "E1"},
		MaxChainDepth: 2,
		TTL:           2 * time.Hour,
	}, []string{"E0", "E1", "E2"})

	child, err := dm.ReDelegate(ctx, parent.GrantID, DelegationRequest{
		DelegatorID:  "manager",
		DelegateeID:  "worker",
		Capabilities: []string{"E0"}, // attenuated
		TTL:          30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if child.ChainDepth != 1 {
		t.Errorf("expected ChainDepth 1, got %d", child.ChainDepth)
	}
	if child.ParentGrantID != parent.GrantID {
		t.Error("ParentGrantID should point to parent")
	}
}

func TestDelegationManager_ReDelegate_ExceedsDepth(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	parent, _ := dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:   "root",
		DelegateeID:   "a",
		Capabilities:  []string{"E0"},
		MaxChainDepth: 0, // cannot re-delegate
		TTL:           1 * time.Hour,
	}, []string{"E0"})

	_, err := dm.ReDelegate(ctx, parent.GrantID, DelegationRequest{
		DelegatorID:  "a",
		DelegateeID:  "b",
		Capabilities: []string{"E0"},
		TTL:          30 * time.Minute,
	})
	if err == nil {
		t.Error("expected error: max chain depth reached")
	}
}

func TestDelegationManager_ReDelegate_CapsExceedParent(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	parent, _ := dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:   "root",
		DelegateeID:   "a",
		Capabilities:  []string{"E0"},
		MaxChainDepth: 2,
		TTL:           1 * time.Hour,
	}, []string{"E0", "E1"})

	_, err := dm.ReDelegate(ctx, parent.GrantID, DelegationRequest{
		DelegatorID:  "a",
		DelegateeID:  "b",
		Capabilities: []string{"E0", "E1"}, // E1 exceeds parent's E0
		TTL:          30 * time.Minute,
	})
	if err == nil {
		t.Error("expected error: E1 exceeds parent grant")
	}
}

func TestDelegationManager_RevokeCascade(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	parent, _ := dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:   "root",
		DelegateeID:   "a",
		Capabilities:  []string{"E0"},
		MaxChainDepth: 3,
		TTL:           1 * time.Hour,
	}, []string{"E0"})

	child, _ := dm.ReDelegate(ctx, parent.GrantID, DelegationRequest{
		DelegatorID:  "a",
		DelegateeID:  "b",
		Capabilities: []string{"E0"},
		TTL:          30 * time.Minute,
	})

	// Revoke parent → should cascade to child
	err := dm.RevokeDelegation(ctx, parent.GrantID)
	if err != nil {
		t.Fatal(err)
	}

	// Check parent is revoked
	v := dm.CheckAuthorization(ctx, "a", "read_file", "E0")
	if v.Authorized {
		t.Error("parent delegation should be revoked")
	}

	// Check child is revoked (cascade)
	dm.mu.RLock()
	childGrant := dm.grants[child.GrantID]
	dm.mu.RUnlock()
	if !childGrant.Revoked {
		t.Error("child delegation should be cascade-revoked")
	}
}

func TestDelegationManager_ActiveGrants(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	dm.CreateDelegation(ctx, DelegationRequest{
		DelegatorID:  "root",
		DelegateeID:  "worker",
		Capabilities: []string{"E0"},
		TTL:          1 * time.Hour,
	}, []string{"E0"})

	active := dm.ActiveGrants(ctx, "worker")
	if len(active) != 1 {
		t.Errorf("expected 1 active grant, got %d", len(active))
	}

	active = dm.ActiveGrants(ctx, "unknown")
	if len(active) != 0 {
		t.Errorf("expected 0 active grants for unknown agent, got %d", len(active))
	}
}

func TestDelegationManager_TTLEnforcement(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	dm.mu.Lock()
	expired := &DelegationGrant{
		GrantID:      "expired-001",
		DelegatorID:  "root",
		DelegateeID:  "worker",
		Capabilities: []string{"E0"},
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // already expired
	}
	dm.grants[expired.GrantID] = expired
	dm.byAgent["worker"] = []string{expired.GrantID}
	dm.mu.Unlock()

	v := dm.CheckAuthorization(ctx, "worker", "read_file", "E0")
	if v.Authorized {
		t.Error("expected unauthorized for expired delegation")
	}
}
