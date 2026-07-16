package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestServiceFailsClosedBeforePersistingUntrustedOrUnrandomizedHold(t *testing.T) {
	hold, _, _, grant := ceremonyFixtures(t)
	signer := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
		"approval-test",
	)
	config := serviceTestConfig(hold.Spec, grant)

	t.Run("binding scope substitution", func(t *testing.T) {
		store := &serviceTestStore{}
		substituted := hold.Spec
		substituted.TenantID = "tenant-b"
		authority := &serviceTestAuthority{store: authorityMetadata(hold.Spec)}
		service, err := newService(
			store, &serviceTestBinding{spec: substituted}, authority,
			&serviceTestControl{identity: controlForSpec(hold.Spec)},
			&serviceTestConsumer{identity: consumerForSpec(hold.Spec)},
			signer, time.Now, bytes.NewReader(make([]byte, 64)), config,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.BeginHold(context.Background(), hold.Spec.BindingRef); !errors.Is(err, ErrBindingUnavailable) {
			t.Fatalf("BeginHold() error = %v, want ErrBindingUnavailable", err)
		}
		if authority.calls != 0 || store.createCalls != 0 {
			t.Fatalf("substituted binding reached authority=%d or persistence=%d", authority.calls, store.createCalls)
		}
	})

	t.Run("authority metadata substitution", func(t *testing.T) {
		store := &serviceTestStore{}
		authority := approvalverify.TrustStore{
			AuthoritySource: hold.Spec.AuthoritySource, AuthorityVersion: "substituted",
			AuthoritySnapshotHash: hold.Spec.AuthoritySnapshotHash,
		}
		service, err := newService(
			store, &serviceTestBinding{spec: hold.Spec}, &serviceTestAuthority{store: authority},
			&serviceTestControl{identity: controlForSpec(hold.Spec)},
			&serviceTestConsumer{identity: consumerForSpec(hold.Spec)},
			signer, time.Now, bytes.NewReader(make([]byte, 64)), config,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.BeginHold(context.Background(), hold.Spec.BindingRef); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatalf("BeginHold() error = %v, want ErrAuthorityUnavailable", err)
		}
		if store.createCalls != 0 {
			t.Fatalf("untrusted hold reached persistence %d times", store.createCalls)
		}
	})

	t.Run("randomness unavailable", func(t *testing.T) {
		store := &serviceTestStore{}
		service, err := newService(
			store, &serviceTestBinding{spec: hold.Spec},
			&serviceTestAuthority{store: authorityMetadata(hold.Spec)},
			&serviceTestControl{identity: controlForSpec(hold.Spec)},
			&serviceTestConsumer{identity: consumerForSpec(hold.Spec)}, signer,
			time.Now, failingReader{}, config,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.BeginHold(context.Background(), hold.Spec.BindingRef); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("BeginHold() error = %v, want randomness failure", err)
		}
		if store.createCalls != 0 {
			t.Fatalf("unrandomized hold reached persistence %d times", store.createCalls)
		}
	})
}

func TestServiceRejectsExpiredHoldBeforeAuthorityOrRandomness(t *testing.T) {
	hold, _, _, grant := ceremonyFixtures(t)
	store := &serviceTestStore{record: hold}
	authority := &serviceTestAuthority{store: authorityMetadata(hold.Spec)}
	signer := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
		"approval-test",
	)
	config := serviceTestConfig(hold.Spec, grant)
	now := hold.HoldStartedAt.Add(config.MaxChallengeLifetime)
	service, err := newService(
		store, &serviceTestBinding{spec: hold.Spec}, authority,
		&serviceTestControl{identity: controlForSpec(hold.Spec)},
		&serviceTestConsumer{identity: consumerForSpec(hold.Spec)}, signer,
		func() time.Time { return now }, failingReader{}, config,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueChallenge(context.Background(), hold.ApprovalID); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("IssueChallenge() error = %v, want ErrTransitionConflict", err)
	}
	if authority.calls != 0 || store.issueChallengeCalls != 0 {
		t.Fatalf("expired hold reached authority=%d or persistence=%d", authority.calls, store.issueChallengeCalls)
	}
}

func TestServiceRejectsUnsafeLifetimeConfig(t *testing.T) {
	hold, _, _, grant := ceremonyFixtures(t)
	base := serviceTestConfig(hold.Spec, grant)
	tests := map[string]func(*ServiceConfig){
		"lifetime not above hold": func(config *ServiceConfig) {
			config.MaxChallengeLifetime = config.MinHoldDuration
		},
		"active ttl exceeds remaining lifetime": func(config *ServiceConfig) {
			config.ChallengeTTL = config.MaxChallengeLifetime
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := newService(
				&serviceTestStore{}, &serviceTestBinding{spec: hold.Spec},
				&serviceTestAuthority{store: authorityMetadata(hold.Spec)},
				&serviceTestControl{identity: controlForSpec(hold.Spec)},
				&serviceTestConsumer{identity: consumerForSpec(hold.Spec)},
				crypto.NewEd25519SignerFromKey(
					ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
					"approval-test",
				),
				time.Now, bytes.NewReader(make([]byte, 64)), config,
			); err == nil {
				t.Fatal("newService() accepted unsafe lifetime configuration")
			}
		})
	}
}

func TestServiceRejectsUnverifiedConsumerBeforePersistence(t *testing.T) {
	hold, _, _, grant := ceremonyFixtures(t)
	store := &serviceTestStore{}
	service, err := newService(
		store, &serviceTestBinding{spec: hold.Spec},
		&serviceTestAuthority{store: authorityMetadata(hold.Spec)},
		&serviceTestControl{identity: controlForSpec(hold.Spec)},
		&serviceTestConsumer{err: errors.New("mTLS identity missing")},
		crypto.NewEd25519SignerFromKey(
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
			"approval-test",
		),
		time.Now, bytes.NewReader(make([]byte, 64)), serviceTestConfig(hold.Spec, grant),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConsumeGrant(
		context.Background(), hold.ApprovalID,
		"grant-a", shaRef("a"), string(bytes.Repeat([]byte{'b'}, 64)),
	); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("ConsumeGrant() error = %v, want ErrConsumerUnavailable", err)
	}
	if store.consumeCalls != 0 {
		t.Fatalf("unverified consumer reached persistence %d times", store.consumeCalls)
	}
}

func TestServiceClockMatchesPostgresMicrosecondPrecision(t *testing.T) {
	hold, _, _, grant := ceremonyFixtures(t)
	clockValue := time.Date(2026, 7, 16, 12, 0, 0, 123456789, time.FixedZone("offset", 2*60*60))
	service, err := newService(
		&serviceTestStore{}, &serviceTestBinding{spec: hold.Spec},
		&serviceTestAuthority{store: authorityMetadata(hold.Spec)},
		&serviceTestControl{identity: controlForSpec(hold.Spec)},
		&serviceTestConsumer{identity: consumerForSpec(hold.Spec)},
		crypto.NewEd25519SignerFromKey(
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
			"approval-test",
		),
		func() time.Time { return clockValue }, bytes.NewReader(make([]byte, 64)),
		serviceTestConfig(hold.Spec, grant),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := clockValue.UTC().Truncate(time.Microsecond)
	if got := service.now(); !got.Equal(want) || got.Nanosecond()%1_000 != 0 {
		t.Fatalf("service.now() = %s, want %s at microsecond precision", got, want)
	}
}

func TestPostgresStoreRejectsCallerFabricatedTransitionTimes(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	store := NewPostgresStore(nil, nil)
	ctx := context.Background()
	if _, err := store.createHold(ctx, func() Record {
		mutated := hold
		mutated.UpdatedAt = mutated.UpdatedAt.Add(time.Second)
		return mutated
	}()); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("createHold() error = %v, want ErrInvalidRecord", err)
	}
	if _, err := store.issueChallenge(ctx, hold.TenantID, hold.WorkspaceID, hold.ApprovalID, challenge, challenge.IssuedAt.Add(time.Second)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("issueChallenge() error = %v, want ErrInvalidRecord", err)
	}
	if _, err := store.recordQuorum(ctx, hold.TenantID, hold.WorkspaceID, hold.ApprovalID, verified, verified.VerifiedAt.Add(time.Second)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("recordQuorum() error = %v, want ErrInvalidRecord", err)
	}
	if _, err := store.issueGrant(
		ctx, hold.TenantID, hold.WorkspaceID, hold.ApprovalID, grant,
		GrantSignatureEd25519, string(make([]byte, 128)), grant.IssuedAt.Add(time.Second),
	); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("issueGrant() error = %v, want ErrInvalidRecord", err)
	}
}

type serviceTestAuthority struct {
	store approvalverify.TrustStore
	calls int
}

type serviceTestBinding struct {
	spec  ChallengeSpec
	err   error
	calls int
}

type serviceTestConsumer struct {
	identity ConsumerIdentity
	err      error
}

type serviceTestControl struct {
	identity ControlIdentity
	err      error
}

func (p *serviceTestControl) LoadControlIdentity(context.Context) (ControlIdentity, error) {
	return p.identity, p.err
}

func (p *serviceTestConsumer) LoadConsumerIdentity(context.Context) (ConsumerIdentity, error) {
	return p.identity, p.err
}

func (p *serviceTestBinding) LoadApprovalBinding(_ context.Context, _, _, _ string) (ChallengeSpec, error) {
	p.calls++
	return p.spec, p.err
}

func (p *serviceTestAuthority) LoadApprovalAuthority(_ context.Context, _, _, _, _, _ string) (approvalverify.TrustStore, error) {
	p.calls++
	return p.store, nil
}

type serviceTestStore struct {
	record              Record
	createCalls         int
	issueChallengeCalls int
	consumeCalls        int
}

func (s *serviceTestStore) createHold(_ context.Context, record Record) (Record, error) {
	s.createCalls++
	s.record = record
	return record, nil
}

func (s *serviceTestStore) Get(context.Context, string, string, string) (Record, error) {
	if s.record.ApprovalID == "" {
		return Record{}, ErrNotFound
	}
	return s.record, nil
}

func (s *serviceTestStore) issueChallenge(context.Context, string, string, string, contracts.ApprovalChallenge, time.Time) (Record, error) {
	s.issueChallengeCalls++
	return Record{}, errors.New("unexpected issueChallenge call")
}

func (*serviceTestStore) recordQuorum(context.Context, string, string, string, approvalverify.VerifiedApprovalRef, time.Time) (Record, error) {
	return Record{}, errors.New("unexpected recordQuorum call")
}

func (*serviceTestStore) issueGrant(context.Context, string, string, string, contracts.ApprovalGrant, string, string, time.Time) (Record, error) {
	return Record{}, errors.New("unexpected issueGrant call")
}

func (s *serviceTestStore) consumeGrant(context.Context, string, string, string, string, string, string, string, string, time.Time) (Record, error) {
	s.consumeCalls++
	return Record{}, errors.New("unexpected consumeGrant call")
}

func (*serviceTestStore) deny(context.Context, string, string, string, time.Time) (Record, error) {
	return Record{}, errors.New("unexpected deny call")
}

func (*serviceTestStore) expire(context.Context, string, string, string, time.Time) (Record, error) {
	return Record{}, errors.New("unexpected expire call")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func authorityMetadata(spec ChallengeSpec) approvalverify.TrustStore {
	return approvalverify.TrustStore{
		AuthoritySource: spec.AuthoritySource, AuthorityVersion: spec.AuthorityVersion,
		AuthoritySnapshotHash: spec.AuthoritySnapshotHash,
	}
}

func serviceTestConfig(spec ChallengeSpec, grant contracts.ApprovalGrant) ServiceConfig {
	return ServiceConfig{
		MinHoldDuration: 5 * time.Minute, ChallengeTTL: 10 * time.Minute,
		MaxChallengeLifetime: 20 * time.Minute, GrantTTL: 5 * time.Minute,
		MaxAssertions: 4, ServerIdentity: spec.ServerIdentity,
		KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
	}
}

func consumerForSpec(spec ChallengeSpec) ConsumerIdentity {
	return ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: spec.TenantID,
		WorkspaceID: spec.WorkspaceID, Audience: spec.Audience,
	}
}

func controlForSpec(spec ChallengeSpec) ControlIdentity {
	return ControlIdentity{
		Subject: "spiffe://helm/control-plane-a", TenantID: spec.TenantID, WorkspaceID: spec.WorkspaceID,
	}
}
