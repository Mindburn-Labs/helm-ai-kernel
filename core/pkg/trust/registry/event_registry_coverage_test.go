package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestTrustEventComputeHashAndKeyActivity(t *testing.T) {
	event := trustRegistryEvent("ev-1", 1, EventDIDRegister, `{"did":"did:example:alice"}`)
	hash, err := event.ComputeHash()
	if err != nil {
		t.Fatalf("ComputeHash() error = %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("ComputeHash() = %q, want sha256 prefix", hash)
	}

	event.Payload = json.RawMessage(`{`)
	if _, err := event.ComputeHash(); err == nil {
		t.Fatal("ComputeHash() expected invalid JSON error")
	}

	revokedAt := uint64(7)
	key := KeyEntry{RevokedAtLamport: &revokedAt}
	if !key.IsActive(6) {
		t.Fatal("key should be active before revoke lamport")
	}
	if key.IsActive(7) {
		t.Fatal("key should be inactive at revoke lamport")
	}
	if !(KeyEntry{}).IsActive(100) {
		t.Fatal("key without revoke lamport should stay active")
	}
}

func TestTrustStateReduceLifecycle(t *testing.T) {
	state := NewTrustState()
	events := []*TrustEvent{
		trustRegistryEvent("did-register", 1, EventDIDRegister, `{"did":"did:example:alice"}`),
		trustRegistryEvent("key-publish-1", 2, EventKeyPublish, `{"kid":"kid-1","algorithm":"ed25519","public_key_hash":"sha256:key1","owner_did":"did:example:alice"}`),
		trustRegistryEvent("key-publish-2", 3, EventKeyPublish, `{"kid":"kid-2","algorithm":"ed25519","public_key_hash":"sha256:key2","owner_did":"did:example:alice"}`),
		trustRegistryEvent("key-rotate", 4, EventKeyRotate, `{"old_kid":"kid-1","new_kid":"kid-2"}`),
		trustRegistryEvent("key-revoke", 5, EventKeyRevoke, `{"kid":"kid-2"}`),
		trustRegistryEvent("policy-activate", 6, EventPolicyActivate, `{"policy_id":"policy-1","version":"v1","hash":"sha256:policy"}`),
		trustRegistryEvent("policy-revoke", 7, EventPolicyRevoke, `{"policy_id":"policy-1"}`),
		trustRegistryEvent("role-grant", 8, EventRoleGrant, `{"subject_id":"did:example:alice","role":"admin"}`),
		trustRegistryEvent("role-revoke", 9, EventRoleRevoke, `{"subject_id":"did:example:alice","role":"admin"}`),
		trustRegistryEvent("tenant-register", 10, EventTenantRegister, `{"tenant_id":"tenant-1"}`),
		trustRegistryEvent("tenant-suspend", 11, EventTenantSuspend, `{"tenant_id":"tenant-1"}`),
		trustRegistryEvent("trust-score", 12, EventTrustScoreUpdate, `{"agent_id":"agent-1","score":900,"tier":"TRUSTED","score_event_type":"POLICY_COMPLY","delta":20}`),
		trustRegistryEvent("did-deactivate", 13, EventDIDDeactivate, `{"did":"did:example:alice"}`),
		trustRegistryEvent("future-event", 14, EventType("FUTURE_EVENT"), `{}`),
	}

	if err := state.Reduce(events); err != nil {
		t.Fatalf("Reduce() error = %v", err)
	}

	if state.Lamport != 14 {
		t.Fatalf("state lamport = %d, want 14", state.Lamport)
	}
	did := state.DIDs["did:example:alice"]
	if did.DeactivatedAt == nil || *did.DeactivatedAt != 13 {
		t.Fatalf("DID deactivate lamport = %v, want 13", did.DeactivatedAt)
	}
	if len(did.Keys) != 2 {
		t.Fatalf("DID keys = %v, want both published keys", did.Keys)
	}
	if state.Keys["kid-1"].RevokedAtLamport == nil || *state.Keys["kid-1"].RevokedAtLamport != 4 {
		t.Fatalf("rotated key revoke lamport = %v, want 4", state.Keys["kid-1"].RevokedAtLamport)
	}
	if state.Keys["kid-2"].RevokedAtLamport == nil || *state.Keys["kid-2"].RevokedAtLamport != 5 {
		t.Fatalf("revoked key lamport = %v, want 5", state.Keys["kid-2"].RevokedAtLamport)
	}
	if state.Policies["policy-1"].RevokedAtLamport == nil || *state.Policies["policy-1"].RevokedAtLamport != 7 {
		t.Fatalf("policy revoke lamport = %v, want 7", state.Policies["policy-1"].RevokedAtLamport)
	}
	if got := state.Roles["did:example:alice"]; len(got) != 1 || got[0].RevokedAtLamport == nil || *got[0].RevokedAtLamport != 9 {
		t.Fatalf("role entries = %+v, want one revoked admin role", got)
	}
	if state.Tenants["tenant-1"].SuspendedAtLamport == nil || *state.Tenants["tenant-1"].SuspendedAtLamport != 11 {
		t.Fatalf("tenant suspend lamport = %v, want 11", state.Tenants["tenant-1"].SuspendedAtLamport)
	}
	if got := state.BehavioralScores["agent-1"]; got.Score != 900 || got.UpdatedLamport != 12 {
		t.Fatalf("behavioral score = %+v, want score 900 at lamport 12", got)
	}
}

func TestTrustStateApplyErrors(t *testing.T) {
	t.Run("out of order", func(t *testing.T) {
		state := NewTrustState()
		if err := state.Apply(trustRegistryEvent("first", 2, EventDIDRegister, `{"did":"did:example:first"}`)); err != nil {
			t.Fatalf("seed Apply() error = %v", err)
		}
		if err := state.Apply(trustRegistryEvent("old", 1, EventDIDRegister, `{"did":"did:example:old"}`)); err == nil {
			t.Fatal("Apply() expected out-of-order error")
		}
	})

	t.Run("strict unknown", func(t *testing.T) {
		state := NewStrictTrustState()
		if err := state.Apply(trustRegistryEvent("unknown", 1, EventType("UNKNOWN"), `{}`)); err == nil {
			t.Fatal("Apply() expected strict unknown event error")
		}
	})

	t.Run("invalid JSON payloads", func(t *testing.T) {
		for _, eventType := range []EventType{
			EventDIDRegister,
			EventDIDDeactivate,
			EventKeyPublish,
			EventKeyRevoke,
			EventKeyRotate,
			EventPolicyActivate,
			EventPolicyRevoke,
			EventRoleGrant,
			EventRoleRevoke,
			EventTenantRegister,
			EventTenantSuspend,
			EventTrustScoreUpdate,
		} {
			state := NewTrustState()
			if err := state.Apply(trustRegistryEvent(string(eventType), 1, eventType, `{`)); err == nil {
				t.Fatalf("Apply(%s) expected invalid payload error", eventType)
			}
		}
	})

	t.Run("domain validation", func(t *testing.T) {
		cases := []struct {
			name   string
			state  *TrustState
			event  *TrustEvent
			errSub string
		}{
			{
				name: "duplicate did",
				state: trustRegistryStateWithEvents(t,
					trustRegistryEvent("did-register", 1, EventDIDRegister, `{"did":"did:example:alice"}`),
				),
				event:  trustRegistryEvent("did-register-again", 2, EventDIDRegister, `{"did":"did:example:alice"}`),
				errSub: "already registered",
			},
			{
				name:   "missing did deactivate",
				state:  NewTrustState(),
				event:  trustRegistryEvent("did-deactivate", 1, EventDIDDeactivate, `{"did":"did:example:missing"}`),
				errSub: "not found",
			},
			{
				name: "duplicate key",
				state: trustRegistryStateWithEvents(t,
					trustRegistryEvent("key-publish", 1, EventKeyPublish, `{"kid":"kid-1","algorithm":"ed25519","public_key_hash":"sha256:key","owner_did":"did:example:alice"}`),
				),
				event:  trustRegistryEvent("key-publish-again", 2, EventKeyPublish, `{"kid":"kid-1","algorithm":"ed25519","public_key_hash":"sha256:key","owner_did":"did:example:alice"}`),
				errSub: "already published",
			},
			{
				name:   "missing key revoke",
				state:  NewTrustState(),
				event:  trustRegistryEvent("key-revoke", 1, EventKeyRevoke, `{"kid":"kid-missing"}`),
				errSub: "not found",
			},
			{
				name: "missing new rotation key",
				state: trustRegistryStateWithEvents(t,
					trustRegistryEvent("key-publish", 1, EventKeyPublish, `{"kid":"kid-1","algorithm":"ed25519","public_key_hash":"sha256:key","owner_did":"did:example:alice"}`),
				),
				event:  trustRegistryEvent("key-rotate", 2, EventKeyRotate, `{"old_kid":"kid-1","new_kid":"kid-2"}`),
				errSub: "must be published",
			},
			{
				name:   "missing policy revoke",
				state:  NewTrustState(),
				event:  trustRegistryEvent("policy-revoke", 1, EventPolicyRevoke, `{"policy_id":"missing"}`),
				errSub: "not found",
			},
			{
				name: "duplicate tenant",
				state: trustRegistryStateWithEvents(t,
					trustRegistryEvent("tenant-register", 1, EventTenantRegister, `{"tenant_id":"tenant-1"}`),
				),
				event:  trustRegistryEvent("tenant-register-again", 2, EventTenantRegister, `{"tenant_id":"tenant-1"}`),
				errSub: "already registered",
			},
			{
				name:   "missing tenant suspend",
				state:  NewTrustState(),
				event:  trustRegistryEvent("tenant-suspend", 1, EventTenantSuspend, `{"tenant_id":"tenant-missing"}`),
				errSub: "not found",
			},
			{
				name:   "trust score missing agent",
				state:  NewTrustState(),
				event:  trustRegistryEvent("trust-score", 1, EventTrustScoreUpdate, `{"score":1,"tier":"SUSPECT","score_event_type":"POLICY_VIOLATE","delta":-1}`),
				errSub: "requires agent_id",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.state.Apply(tc.event)
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("Apply() error = %v, want containing %q", err, tc.errSub)
				}
			})
		}
	})

	t.Run("reduce wraps event errors", func(t *testing.T) {
		state := NewTrustState()
		err := state.Reduce([]*TrustEvent{
			trustRegistryEvent("bad-deactivate", 1, EventDIDDeactivate, `{"did":"did:example:missing"}`),
		})
		if err == nil || !strings.Contains(err.Error(), "bad-deactivate") {
			t.Fatalf("Reduce() error = %v, want event id context", err)
		}
	})
}

func TestSnapshots(t *testing.T) {
	ctx := context.Background()
	events := []*TrustEvent{
		trustRegistryEvent("did-register", 1, EventDIDRegister, `{"did":"did:example:alice"}`),
		trustRegistryEvent("tenant-register", 2, EventTenantRegister, `{"tenant_id":"tenant-1"}`),
	}
	store := &trustRegistryMemoryStore{events: events}

	snapshot, err := Snapshot(ctx, store, 2)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.Lamport != 2 || snapshot.State.Lamport != 2 {
		t.Fatalf("snapshot lamports = (%d,%d), want 2", snapshot.Lamport, snapshot.State.Lamport)
	}
	if !strings.HasPrefix(snapshot.SnapshotHash, "sha256:") {
		t.Fatalf("snapshot hash = %q, want sha256 prefix", snapshot.SnapshotHash)
	}

	exported, err := Export(snapshot)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	imported, err := Import(exported)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if imported.SnapshotHash != snapshot.SnapshotHash {
		t.Fatalf("imported hash = %q, want %q", imported.SnapshotHash, snapshot.SnapshotHash)
	}

	ok, err := VerifySnapshot(ctx, store, snapshot)
	if err != nil {
		t.Fatalf("VerifySnapshot() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifySnapshot() = false, want true")
	}

	tampered := *snapshot
	tampered.SnapshotHash = "sha256:tampered"
	ok, err = VerifySnapshot(ctx, store, &tampered)
	if err != nil {
		t.Fatalf("VerifySnapshot(tampered) error = %v", err)
	}
	if ok {
		t.Fatal("VerifySnapshot(tampered) = true, want false")
	}

	tamperedState := *snapshot
	tamperedState.State.Lamport = 99
	data, err := json.Marshal(tamperedState)
	if err != nil {
		t.Fatalf("marshal tampered snapshot: %v", err)
	}
	if _, err := Import(data); err == nil {
		t.Fatal("Import() expected hash mismatch")
	}
	if _, err := Import([]byte(`{`)); err == nil {
		t.Fatal("Import() expected JSON error")
	}
}

func TestSnapshotErrorsAndRegistrySnapshot(t *testing.T) {
	ctx := context.Background()

	if _, err := Snapshot(ctx, &trustRegistryMemoryStore{getUpToErr: errors.New("store down")}, 4); err == nil {
		t.Fatal("Snapshot() expected store error")
	}
	if _, err := Snapshot(ctx, &trustRegistryMemoryStore{
		events: []*TrustEvent{trustRegistryEvent("bad", 1, EventDIDDeactivate, `{"did":"missing"}`)},
	}, 1); err == nil {
		t.Fatal("Snapshot() expected reducer error")
	}

	reg := NewRegistry(&trustRegistryMemoryStore{})
	reg.state = trustRegistryStateWithEvents(t,
		trustRegistryEvent("did-register", 1, EventDIDRegister, `{"did":"did:example:registry"}`),
	)
	snapshot, err := SnapshotFromRegistry(reg)
	if err != nil {
		t.Fatalf("SnapshotFromRegistry() error = %v", err)
	}
	if snapshot.Lamport != 1 {
		t.Fatalf("registry snapshot lamport = %d, want 1", snapshot.Lamport)
	}

	if _, err := VerifySnapshot(ctx, &trustRegistryMemoryStore{getUpToErr: errors.New("store down")}, snapshot); err == nil {
		t.Fatal("VerifySnapshot() expected rebuild error")
	}
}

func TestRegistryService(t *testing.T) {
	ctx := context.Background()
	fixed := time.Unix(1700000000, 123).UTC()
	prior := trustRegistryEvent("did-register", 1, EventDIDRegister, `{"did":"did:example:alice"}`)
	prior.Hash = mustTrustRegistryHash(t, prior)
	store := &trustRegistryMemoryStore{events: []*TrustEvent{prior}}
	reg := NewRegistry(store)
	reg.clock = func() time.Time { return fixed }

	if err := reg.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if reg.CurrentLamport() != 1 {
		t.Fatalf("CurrentLamport() = %d, want 1", reg.CurrentLamport())
	}

	next := trustRegistryEvent("key-publish", 0, EventKeyPublish, `{"kid":"kid-1","algorithm":"ed25519","public_key_hash":"sha256:key","owner_did":"did:example:alice"}`)
	if err := reg.AppendEvent(ctx, next); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	if next.Lamport != 2 {
		t.Fatalf("appended lamport = %d, want 2", next.Lamport)
	}
	if !next.CreatedAt.Equal(fixed) {
		t.Fatalf("CreatedAt = %s, want %s", next.CreatedAt, fixed)
	}
	if next.PrevHash != prior.Hash {
		t.Fatalf("PrevHash = %q, want %q", next.PrevHash, prior.Hash)
	}
	if next.Hash == "" {
		t.Fatal("AppendEvent() did not compute hash")
	}
	if reg.State().Keys["kid-1"].KID != "kid-1" {
		t.Fatalf("registry state missing appended key: %+v", reg.State().Keys)
	}

	all, err := reg.ListEvents(ctx, 0)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListEvents(0) = (%d,%v), want 2,nil", len(all), err)
	}
	since, err := reg.ListEvents(ctx, 1)
	if err != nil || len(since) != 1 || since[0].ID != "key-publish" {
		t.Fatalf("ListEvents(1) = (%v,%v), want key-publish,nil", since, err)
	}
	bySubject, err := reg.ListEventsBySubject(ctx, next.SubjectID)
	if err != nil || len(bySubject) != 1 {
		t.Fatalf("ListEventsBySubject() = (%d,%v), want 1,nil", len(bySubject), err)
	}
	upTo, err := reg.ListEventsUpTo(ctx, 1)
	if err != nil || len(upTo) != 1 || upTo[0].ID != "did-register" {
		t.Fatalf("ListEventsUpTo() = (%v,%v), want did-register,nil", upTo, err)
	}
}

func TestRegistryServiceErrors(t *testing.T) {
	ctx := context.Background()

	if err := NewRegistry(&trustRegistryMemoryStore{getAllErr: errors.New("load failed")}).Initialize(ctx); err == nil {
		t.Fatal("Initialize() expected load error")
	}
	if err := NewRegistry(&trustRegistryMemoryStore{
		events: []*TrustEvent{trustRegistryEvent("bad", 1, EventDIDDeactivate, `{"did":"missing"}`)},
	}).Initialize(ctx); err == nil {
		t.Fatal("Initialize() expected reduce error")
	}

	cases := []struct {
		name  string
		store *trustRegistryMemoryStore
		event *TrustEvent
	}{
		{
			name:  "latest lamport error",
			store: &trustRegistryMemoryStore{latestErr: errors.New("latest failed")},
			event: trustRegistryEvent("did-register", 0, EventDIDRegister, `{"did":"did:example:alice"}`),
		},
		{
			name: "previous event lookup error",
			store: &trustRegistryMemoryStore{
				events:     []*TrustEvent{trustRegistryEvent("prior", 1, EventDIDRegister, `{"did":"did:example:prior"}`)},
				getUpToErr: errors.New("history failed"),
			},
			event: trustRegistryEvent("did-register", 0, EventDIDRegister, `{"did":"did:example:alice"}`),
		},
		{
			name:  "hash error",
			store: &trustRegistryMemoryStore{},
			event: trustRegistryEvent("bad-json", 0, EventDIDRegister, `{`),
		},
		{
			name:  "apply error",
			store: &trustRegistryMemoryStore{},
			event: trustRegistryEvent("did-deactivate", 0, EventDIDDeactivate, `{"did":"missing"}`),
		},
		{
			name:  "persist error",
			store: &trustRegistryMemoryStore{appendErr: errors.New("persist failed")},
			event: trustRegistryEvent("did-register", 0, EventDIDRegister, `{"did":"did:example:alice"}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry(tc.store)
			if err := reg.AppendEvent(ctx, tc.event); err == nil {
				t.Fatal("AppendEvent() expected error")
			}
		})
	}
}

func TestTrustRegistryLegacyEdges(t *testing.T) {
	reg := NewTrustRegistry()

	if err := reg.Apply(LegacyTrustEvent{EventType: "KEY_ADDED", TenantID: "tenant-1", KeyID: "key-1"}); err == nil {
		t.Fatal("KEY_ADDED without public key expected error")
	}
	if err := reg.Apply(LegacyTrustEvent{EventType: "KEY_ROTATED", TenantID: "tenant-1", KeyID: "key-1"}); err == nil {
		t.Fatal("KEY_ROTATED without public key expected error")
	}
	if reg.IsAuthorized("missing-tenant", "key-1") {
		t.Fatal("missing tenant key should not be authorized")
	}
	keys, err := reg.ResolveAuthorizedKeys("missing-tenant", 0)
	if err != nil {
		t.Fatalf("ResolveAuthorizedKeys(missing tenant) error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ResolveAuthorizedKeys(missing tenant) returned %d keys, want 0", len(keys))
	}

	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err := reg.Apply(LegacyTrustEvent{EventType: "KEY_ADDED", TenantID: "tenant-1", KeyID: "key-a", PublicKey: keyA, Lamport: 1}); err != nil {
		t.Fatalf("Apply tenant-1 key error = %v", err)
	}
	if err := reg.Apply(LegacyTrustEvent{EventType: "KEY_ADDED", TenantID: "tenant-2", KeyID: "key-b", PublicKey: keyB, Lamport: 2}); err != nil {
		t.Fatalf("Apply tenant-2 key error = %v", err)
	}
	keys, err = reg.ResolveAuthorizedKeys("tenant-1", 3)
	if err != nil {
		t.Fatalf("ResolveAuthorizedKeys(point in time) error = %v", err)
	}
	if len(keys) != 1 || string(keys[0]) != string(keyA) {
		t.Fatalf("ResolveAuthorizedKeys(point in time) = %v, want tenant-1 key only", keys)
	}
}

func TestPostgresEventStoreExecAndQueryMethods(t *testing.T) {
	ctx := context.Background()
	event := trustRegistryEvent("ev-1", 12, EventDIDRegister, `{"did":"did:example:alice"}`)
	event.Hash = "sha256:event"

	t.Run("ensure table success and error", func(t *testing.T) {
		db, mock, cleanup := newTrustRegistrySQLMock(t)
		defer cleanup()
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS trust_events").WillReturnResult(sqlmock.NewResult(0, 0))
		if err := NewPostgresEventStore(db).EnsureTable(ctx); err != nil {
			t.Fatalf("EnsureTable() error = %v", err)
		}

		mock.ExpectExec("CREATE TABLE IF NOT EXISTS trust_events").WillReturnError(errors.New("ddl failed"))
		if err := NewPostgresEventStore(db).EnsureTable(ctx); err == nil {
			t.Fatal("EnsureTable() expected error")
		}
	})

	t.Run("append success and error", func(t *testing.T) {
		db, mock, cleanup := newTrustRegistrySQLMock(t)
		defer cleanup()
		mock.ExpectExec("INSERT INTO trust_events").
			WithArgs(event.ID, event.Lamport, event.EventType, event.SubjectID, event.SubjectType, event.Payload, event.Hash, event.PrevHash, event.AuthorKID, event.AuthorSig, event.CreatedAt).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if err := NewPostgresEventStore(db).Append(ctx, event); err != nil {
			t.Fatalf("Append() error = %v", err)
		}

		mock.ExpectExec("INSERT INTO trust_events").
			WithArgs(event.ID, event.Lamport, event.EventType, event.SubjectID, event.SubjectType, event.Payload, event.Hash, event.PrevHash, event.AuthorKID, event.AuthorSig, event.CreatedAt).
			WillReturnError(errors.New("insert failed"))
		if err := NewPostgresEventStore(db).Append(ctx, event); err == nil {
			t.Fatal("Append() expected error")
		}
	})

	t.Run("list queries", func(t *testing.T) {
		db, mock, cleanup := newTrustRegistrySQLMock(t)
		defer cleanup()
		store := NewPostgresEventStore(db)

		mock.ExpectQuery("SELECT id, lamport, event_type").
			WillReturnRows(trustRegistrySQLRows(event))
		got, err := store.GetAll(ctx)
		if err != nil || len(got) != 1 || got[0].ID != event.ID {
			t.Fatalf("GetAll() = (%v,%v), want event,nil", got, err)
		}

		mock.ExpectQuery("SELECT id, lamport, event_type").
			WithArgs(uint64(5)).
			WillReturnRows(trustRegistrySQLRows(event))
		got, err = store.GetSince(ctx, 5)
		if err != nil || len(got) != 1 || got[0].ID != event.ID {
			t.Fatalf("GetSince() = (%v,%v), want event,nil", got, err)
		}

		mock.ExpectQuery("SELECT id, lamport, event_type").
			WithArgs(uint64(12)).
			WillReturnRows(trustRegistrySQLRows(event))
		got, err = store.GetUpTo(ctx, 12)
		if err != nil || len(got) != 1 || got[0].ID != event.ID {
			t.Fatalf("GetUpTo() = (%v,%v), want event,nil", got, err)
		}

		mock.ExpectQuery("SELECT id, lamport, event_type").
			WithArgs(event.SubjectID).
			WillReturnRows(trustRegistrySQLRows(event))
		got, err = store.GetBySubject(ctx, event.SubjectID)
		if err != nil || len(got) != 1 || got[0].ID != event.ID {
			t.Fatalf("GetBySubject() = (%v,%v), want event,nil", got, err)
		}
	})

	t.Run("query errors", func(t *testing.T) {
		db, mock, cleanup := newTrustRegistrySQLMock(t)
		defer cleanup()
		store := NewPostgresEventStore(db)

		mock.ExpectQuery("SELECT id, lamport, event_type").WillReturnError(errors.New("query failed"))
		if _, err := store.GetAll(ctx); err == nil {
			t.Fatal("GetAll() expected query error")
		}

		mock.ExpectQuery("SELECT id, lamport, event_type").WillReturnRows(trustRegistryBadSQLRows())
		if _, err := store.GetAll(ctx); err == nil {
			t.Fatal("GetAll() expected scan error")
		}

		rows := trustRegistrySQLRows(event)
		rows.RowError(0, errors.New("row failed"))
		mock.ExpectQuery("SELECT id, lamport, event_type").WillReturnRows(rows)
		if _, err := store.GetAll(ctx); err == nil {
			t.Fatal("GetAll() expected rows error")
		}
	})
}

func TestPostgresEventStoreLatestLamport(t *testing.T) {
	ctx := context.Background()

	t.Run("valid null and error", func(t *testing.T) {
		db, mock, cleanup := newTrustRegistrySQLMock(t)
		defer cleanup()
		store := NewPostgresEventStore(db)

		mock.ExpectQuery(`SELECT MAX\(lamport\) FROM trust_events`).
			WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(int64(42)))
		got, err := store.LatestLamport(ctx)
		if err != nil || got != 42 {
			t.Fatalf("LatestLamport() = (%d,%v), want 42,nil", got, err)
		}

		mock.ExpectQuery(`SELECT MAX\(lamport\) FROM trust_events`).
			WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(nil))
		got, err = store.LatestLamport(ctx)
		if err != nil || got != 0 {
			t.Fatalf("LatestLamport(null) = (%d,%v), want 0,nil", got, err)
		}

		mock.ExpectQuery(`SELECT MAX\(lamport\) FROM trust_events`).WillReturnError(errors.New("select failed"))
		if _, err := store.LatestLamport(ctx); err == nil {
			t.Fatal("LatestLamport() expected query error")
		}
	})
}

type trustRegistryMemoryStore struct {
	events      []*TrustEvent
	appendErr   error
	getAllErr   error
	getSinceErr error
	getUpToErr  error
	subjectErr  error
	latestErr   error
}

func (s *trustRegistryMemoryStore) Append(_ context.Context, event *TrustEvent) error {
	if s.appendErr != nil {
		return s.appendErr
	}
	s.events = append(s.events, event)
	return nil
}

func (s *trustRegistryMemoryStore) GetAll(context.Context) ([]*TrustEvent, error) {
	if s.getAllErr != nil {
		return nil, s.getAllErr
	}
	return append([]*TrustEvent(nil), s.events...), nil
}

func (s *trustRegistryMemoryStore) GetSince(_ context.Context, afterLamport uint64) ([]*TrustEvent, error) {
	if s.getSinceErr != nil {
		return nil, s.getSinceErr
	}
	var out []*TrustEvent
	for _, event := range s.events {
		if event.Lamport > afterLamport {
			out = append(out, event)
		}
	}
	return out, nil
}

func (s *trustRegistryMemoryStore) GetUpTo(_ context.Context, upToLamport uint64) ([]*TrustEvent, error) {
	if s.getUpToErr != nil {
		return nil, s.getUpToErr
	}
	var out []*TrustEvent
	for _, event := range s.events {
		if event.Lamport <= upToLamport {
			out = append(out, event)
		}
	}
	return out, nil
}

func (s *trustRegistryMemoryStore) GetBySubject(_ context.Context, subjectID string) ([]*TrustEvent, error) {
	if s.subjectErr != nil {
		return nil, s.subjectErr
	}
	var out []*TrustEvent
	for _, event := range s.events {
		if event.SubjectID == subjectID {
			out = append(out, event)
		}
	}
	return out, nil
}

func (s *trustRegistryMemoryStore) LatestLamport(context.Context) (uint64, error) {
	if s.latestErr != nil {
		return 0, s.latestErr
	}
	var latest uint64
	for _, event := range s.events {
		if event.Lamport > latest {
			latest = event.Lamport
		}
	}
	return latest, nil
}

func trustRegistryStateWithEvents(t *testing.T, events ...*TrustEvent) *TrustState {
	t.Helper()
	state := NewTrustState()
	if err := state.Reduce(events); err != nil {
		t.Fatalf("seed state Reduce() error = %v", err)
	}
	return state
}

func trustRegistryEvent(id string, lamport uint64, eventType EventType, payload string) *TrustEvent {
	return &TrustEvent{
		ID:          id,
		Lamport:     lamport,
		EventType:   eventType,
		SubjectID:   id,
		SubjectType: "test",
		Payload:     json.RawMessage(payload),
		PrevHash:    "",
		AuthorKID:   "kid:author",
		AuthorSig:   "sig",
		CreatedAt:   time.Unix(int64(lamport), 0).UTC(),
	}
}

func mustTrustRegistryHash(t *testing.T, event *TrustEvent) string {
	t.Helper()
	hash, err := event.ComputeHash()
	if err != nil {
		t.Fatalf("ComputeHash() error = %v", err)
	}
	return hash
}

func newTrustRegistrySQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	return db, mock, func() {
		t.Helper()
		mock.ExpectClose()
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close() error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("sql expectations: %v", err)
		}
	}
}

func trustRegistrySQLRows(event *TrustEvent) *sqlmock.Rows {
	return sqlmock.NewRows(trustRegistrySQLColumns()).
		AddRow(
			event.ID,
			event.Lamport,
			event.EventType,
			event.SubjectID,
			event.SubjectType,
			[]byte(event.Payload),
			event.Hash,
			event.PrevHash,
			event.AuthorKID,
			event.AuthorSig,
			event.CreatedAt,
		)
}

func trustRegistryBadSQLRows() *sqlmock.Rows {
	return sqlmock.NewRows(trustRegistrySQLColumns()).
		AddRow(
			"bad",
			"not-a-lamport",
			EventDIDRegister,
			"subject",
			"test",
			[]byte(`{}`),
			"sha256:bad",
			"",
			"kid:author",
			"sig",
			time.Unix(1, 0).UTC(),
		)
}

func trustRegistrySQLColumns() []string {
	return []string{
		"id",
		"lamport",
		"event_type",
		"subject_id",
		"subject_type",
		"payload",
		"hash",
		"prev_hash",
		"author_kid",
		"author_sig",
		"created_at",
	}
}
