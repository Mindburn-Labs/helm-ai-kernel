package firewall

import (
	"context"
	"strings"
	"testing"
)

// Chaos tests for the fail-closed firewall invariant.
//
// These tests are named TestChaos_<scenario> to match the chaos-drill.yml
// workflow's matrix entries. Each test asserts a specific invariant that,
// if broken, constitutes a P0 fail-closed regression.
//
// The chaos-drill runs on PRs touching the firewall package and weekly
// against main to catch drift.

// TestChaos_firewall_nil_dispatcher_denies asserts that a firewall with a
// nil Dispatcher must never silently pass a tool call — it must return a
// fail-closed error. A regression here would mean tools are dispatched to a
// nil pointer (panic) or, worse, silently succeed.
func TestChaos_firewall_nil_dispatcher_denies(t *testing.T) {
	fw := NewPolicyFirewall(nil) // nil dispatcher — the key test condition
	if err := fw.AllowTool("noop", ""); err != nil {
		t.Fatalf("AllowTool setup failed: %v", err)
	}

	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "noop", map[string]any{})
	if err == nil {
		t.Fatal("CHAOS INVARIANT BROKEN: nil dispatcher did not fail-closed")
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("CHAOS INVARIANT BROKEN: expected error to mention 'fail-closed', got: %v", err)
	}
}

// TestChaos_firewall_empty_allowlist_denies asserts that a firewall with an
// empty tool allowlist must deny every tool call, regardless of whether a
// Dispatcher is wired. This is the headline HELM vs AGT architectural
// invariant — empty-allowlist-denies is the difference between an advisory
// governance layer and a fail-closed substrate.
func TestChaos_firewall_empty_allowlist_denies(t *testing.T) {
	// A dispatcher that would succeed if reached.
	dispatcher := &stubDispatcher{}
	fw := NewPolicyFirewall(dispatcher)
	// NOTE: intentionally NOT calling AllowTool — allowlist stays empty.

	_, err := fw.CallTool(context.Background(), PolicyInputBundle{}, "any_tool", map[string]any{})
	if err == nil {
		t.Fatal("CHAOS INVARIANT BROKEN: empty allowlist did not deny")
	}
	if !strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("CHAOS INVARIANT BROKEN: expected error to mention 'not in allowlist', got: %v", err)
	}
	if dispatcher.dispatched {
		t.Fatal("CHAOS INVARIANT BROKEN: dispatcher was reached despite empty allowlist")
	}
}

// stubDispatcher is a test double that flags whether it was ever called.
// If the firewall's allowlist check is bypassed, this records the leak.
type stubDispatcher struct {
	dispatched bool
}

func (s *stubDispatcher) Dispatch(_ context.Context, _ string, _ map[string]any) (any, error) {
	s.dispatched = true
	return "UNREACHABLE", nil
}
