package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestContextConsumerIdentityProviderRequiresVerifiedContext(t *testing.T) {
	provider := ContextConsumerIdentityProvider{}
	if _, err := provider.LoadConsumerIdentity(context.Background()); err == nil {
		t.Fatal("LoadConsumerIdentity() accepted a context without verified identity")
	}
	want := ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-a", TenantID: "tenant-a",
		WorkspaceID: "workspace-a", Audience: "helm-data-plane",
	}
	got, err := provider.LoadConsumerIdentity(WithConsumerIdentity(context.Background(), want))
	if err != nil {
		t.Fatalf("LoadConsumerIdentity() error = %v", err)
	}
	if got != want {
		t.Fatalf("LoadConsumerIdentity() = %+v, want %+v", got, want)
	}
}

func TestGrantConsumerConsumesOnlyWithVerifiedContextIdentity(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	granted := withGrant(withVerified(withChallenge(hold, challenge), verified), grant)
	store := &serviceTestStore{record: granted}
	now := grant.IssuedAt.Add(1)
	signer := crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)),
		"approval-test",
	)
	consumer, err := newGrantConsumer(store, ContextConsumerIdentityProvider{}, signer, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.ConsumeGrant(context.Background(), grant.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("ConsumeGrant() without verified identity error = %v, want ErrConsumerUnavailable", err)
	}
	identity := consumerForSpec(hold.Spec)
	ctx := WithConsumerIdentity(context.Background(), identity)
	consumed, err := consumer.ConsumeGrant(ctx, grant.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce)
	if err != nil {
		t.Fatalf("ConsumeGrant() error = %v", err)
	}
	if consumed.GrantConsumption == nil || consumed.GrantConsumption.ConsumedBy != identity.Subject || store.consumeCalls != 1 {
		t.Fatalf("consumed record = %+v, calls = %d", consumed, store.consumeCalls)
	}
	if _, err := consumer.RecoverGrantConsumption(ctx, grant.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); err != nil {
		t.Fatalf("RecoverGrantConsumption() error = %v", err)
	}
}

func TestGrantConsumerRejectsMissingDependencies(t *testing.T) {
	if _, err := newGrantConsumer(nil, ContextConsumerIdentityProvider{}, nil, nil); err == nil {
		t.Fatal("newGrantConsumer() accepted missing dependencies")
	}
	var consumer *GrantConsumer
	if _, err := consumer.ConsumeGrant(context.Background(), "approval-a", "grant-a", shaRef("a"), string(bytes.Repeat([]byte{'b'}, 64))); err == nil {
		t.Fatal("nil GrantConsumer accepted consumption")
	}
}
