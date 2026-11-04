// quantum_posture: test fixtures use classical Ed25519/SHA-256 only; no post-quantum assurance.

package trust

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust/registry"
)

// ─── 1: Registry Reduce DID register ─────────────────────────────

func TestExt2_RegistryReduceDIDRegister(t *testing.T) {
	s := registry.NewTrustState()
	err := s.Reduce([]*registry.TrustEvent{{
		ID: "e1", Lamport: 1, EventType: registry.EventDIDRegister,
		SubjectID: "did:helm:alice", SubjectType: "did",
		Payload: json.RawMessage(`{"did":"did:helm:alice"}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.DIDs["did:helm:alice"]; !ok {
		t.Fatal("DID should be registered")
	}
}

// ─── 2: Registry Reduce Key publish ──────────────────────────────

func TestExt2_RegistryReduceKeyPublish(t *testing.T) {
	s := registry.NewTrustState()
	s.Reduce([]*registry.TrustEvent{{
		ID: "e1", Lamport: 1, EventType: registry.EventKeyPublish,
		Payload: json.RawMessage(`{"kid":"k1","algorithm":"ed25519","public_key_hash":"abc","owner_did":"did:helm:bob"}`),
	}})
	if _, ok := s.Keys["k1"]; !ok {
		t.Fatal("key should be published")
	}
}

// ─── 3: Registry Reduce Key revoke ──────────────────────────────

func TestExt2_RegistryReduceKeyRevoke(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventKeyPublish,
		Payload: json.RawMessage(`{"kid":"k1","algorithm":"ed25519","public_key_hash":"abc","owner_did":"d1"}`)})
	s.Apply(&registry.TrustEvent{ID: "e2", Lamport: 2, EventType: registry.EventKeyRevoke,
		Payload: json.RawMessage(`{"kid":"k1"}`)})
	if s.Keys["k1"].IsActive(2) {
		t.Fatal("key should be revoked at lamport 2")
	}
}

// ─── 4: Registry Reduce Policy activate ──────────────────────────

func TestExt2_RegistryReducePolicyActivate(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventPolicyActivate,
		Payload: json.RawMessage(`{"policy_id":"pol-1","version":"v1","hash":"sha256:abc"}`)})
	if s.Policies["pol-1"].Version != "v1" {
		t.Fatalf("expected policy version v1, got %s", s.Policies["pol-1"].Version)
	}
}

// ─── 5: Registry Reduce Role grant ──────────────────────────────

func TestExt2_RegistryReduceRoleGrant(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventRoleGrant,
		Payload: json.RawMessage(`{"subject_id":"alice","role":"admin"}`)})
	if len(s.Roles["alice"]) != 1 || s.Roles["alice"][0].Role != "admin" {
		t.Fatal("role should be granted")
	}
}

// ─── 6: Registry Reduce Role revoke ─────────────────────────────

func TestExt2_RegistryReduceRoleRevoke(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventRoleGrant,
		Payload: json.RawMessage(`{"subject_id":"alice","role":"admin"}`)})
	s.Apply(&registry.TrustEvent{ID: "e2", Lamport: 2, EventType: registry.EventRoleRevoke,
		Payload: json.RawMessage(`{"subject_id":"alice","role":"admin"}`)})
	if s.Roles["alice"][0].RevokedAtLamport == nil {
		t.Fatal("role should be revoked")
	}
}

// ─── 7: Registry Reduce Tenant register ──────────────────────────

func TestExt2_RegistryReduceTenantRegister(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventTenantRegister,
		Payload: json.RawMessage(`{"tenant_id":"t1"}`)})
	if _, ok := s.Tenants["t1"]; !ok {
		t.Fatal("tenant should be registered")
	}
}

// ─── 8: Registry Reduce Tenant suspend ───────────────────────────

func TestExt2_RegistryReduceTenantSuspend(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventTenantRegister,
		Payload: json.RawMessage(`{"tenant_id":"t1"}`)})
	s.Apply(&registry.TrustEvent{ID: "e2", Lamport: 2, EventType: registry.EventTenantSuspend,
		Payload: json.RawMessage(`{"tenant_id":"t1"}`)})
	if s.Tenants["t1"].SuspendedAtLamport == nil {
		t.Fatal("tenant should be suspended")
	}
}

// ─── 9: Registry Reduce TrustScore update ────────────────────────

func TestExt2_RegistryReduceTrustScoreUpdate(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventTrustScoreUpdate,
		Payload: json.RawMessage(`{"agent_id":"a1","score":800,"tier":"TRUSTED","score_event_type":"COMPLY","delta":50}`)})
	if s.BehavioralScores["a1"].Score != 800 {
		t.Fatalf("expected score 800, got %d", s.BehavioralScores["a1"].Score)
	}
}

// ─── 10: Registry Reduce OrgTrust skipped (forward compat) ──────

func TestExt2_RegistryReduceOrgTrustSkipped(t *testing.T) {
	s := registry.NewTrustState()
	err := s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventOrgTrustEstablish,
		Payload: json.RawMessage(`{"org_id":"org-1"}`)})
	if err != nil {
		t.Fatalf("OrgTrust should be silently skipped in non-strict mode, got %v", err)
	}
}

// ─── 11: Registry point-in-time key active ───────────────────────

func TestExt2_RegistryPointInTimeKeyActive(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: registry.EventKeyPublish,
		Payload: json.RawMessage(`{"kid":"k1","algorithm":"ed25519","public_key_hash":"abc","owner_did":"d1"}`)})
	s.Apply(&registry.TrustEvent{ID: "e2", Lamport: 10, EventType: registry.EventKeyRevoke,
		Payload: json.RawMessage(`{"kid":"k1"}`)})
	if !s.Keys["k1"].IsActive(5) {
		t.Fatal("key should be active at lamport 5")
	}
	if s.Keys["k1"].IsActive(10) {
		t.Fatal("key should be revoked at lamport 10")
	}
}

// ─── 12: Registry strict mode rejects unknown event type ─────────

func TestExt2_RegistryStrictModeRejects(t *testing.T) {
	s := registry.NewStrictTrustState()
	err := s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: "CUSTOM_UNKNOWN",
		Payload: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("strict mode should reject unknown event type")
	}
}

// ─── 13: Registry non-strict mode skips unknown ──────────────────

func TestExt2_RegistryNonStrictSkips(t *testing.T) {
	s := registry.NewTrustState()
	err := s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 1, EventType: "FUTURE_EVENT",
		Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("non-strict should skip unknown, got %v", err)
	}
}

// ─── 14: Registry out-of-order lamport rejected ──────────────────

func TestExt2_RegistryOutOfOrderLamport(t *testing.T) {
	s := registry.NewTrustState()
	s.Apply(&registry.TrustEvent{ID: "e1", Lamport: 10, EventType: registry.EventTenantRegister,
		Payload: json.RawMessage(`{"tenant_id":"t1"}`)})
	err := s.Apply(&registry.TrustEvent{ID: "e2", Lamport: 5, EventType: registry.EventTenantRegister,
		Payload: json.RawMessage(`{"tenant_id":"t2"}`)})
	if err == nil {
		t.Fatal("out-of-order lamport should be rejected")
	}
}

// ─── 15: ComplianceMatrix add framework and control ──────────────

// ─── 16: ComplianceMatrix hash changes with new control ──────────

// ─── 17: Pack scoring perfect score ──────────────────────────────

// ─── 18: Pack scoring zero metrics ───────────────────────────────

// ─── 19: TUF client requires remote URL ─────────────────────────

// ─── 20: TUF client requires root keys ──────────────────────────

// ─── 21: SLSA verifier validates correct statement ───────────────

// ─── 22: SLSA verifier rejects unknown builder ──────────────────

// ─── 23: SLSA VerifySubjectHash matches ──────────────────────────

// ─── 24: Upgrade registry records and retrieves ──────────────────

// ─── 25: Upgrade registry breaking without schema check fails ───

// helper to avoid unused import warning
var _ = time.Now
