package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestDispatchAdmitterBindsPostLockTimeAndExactRetry(t *testing.T) {
	_, _, _, grant := ceremonyFixtures(t)
	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	transitionAt := grant.ExpiresAt.Add(-10 * time.Second)
	store := &dispatchAdmissionTestStore{consumption: consumption, transitionAt: transitionAt}
	consumer := dispatchStaticConsumer{identity: ConsumerIdentity{
		Subject: consumption.ConsumedBy, TenantID: consumption.TenantID,
		WorkspaceID: consumption.WorkspaceID, Audience: consumption.Audience,
	}}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, "dispatch-test")
	admitter, err := newDispatchAdmitter(
		store, consumer, signer, func() time.Time { return consumption.ConsumedAt },
		bytes.NewReader(bytes.Repeat([]byte{3}, 64)), 30*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := dispatchAdmissionRequestForConsumption(consumption)
	first, err := admitter.Claim(context.Background(), request)
	if err != nil {
		t.Fatalf("Claim(): %v", err)
	}
	if !first.Admission.IssuedAt.Equal(transitionAt) || !first.Admission.ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("admission lifetime = %s..%s, want post-lock %s..%s",
			first.Admission.IssuedAt, first.Admission.ExpiresAt, transitionAt, grant.ExpiresAt)
	}
	verifier, err := NewEd25519GrantSignatureVerifier(
		signer.PublicKeyBytes(), grant.SigningKeyRef, grant.KernelTrustRootID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyDispatchAdmissionSignature(first.Admission, first.SignatureAlgorithm, first.Signature); err != nil {
		t.Fatalf("VerifyDispatchAdmissionSignature(): %v", err)
	}

	admitter.random = dispatchFailingReader{}
	second, err := admitter.Claim(context.Background(), request)
	if err != nil || !reflect.DeepEqual(second, first) {
		t.Fatalf("exact retry = %+v, error = %v", second, err)
	}
	recovered, err := admitter.Recover(context.Background(), request)
	if err != nil || !reflect.DeepEqual(recovered, first) {
		t.Fatalf("Recover() = %+v, error = %v", recovered, err)
	}
	changed := request
	changed.ConnectorID = "connector-b"
	if _, err := admitter.Claim(context.Background(), changed); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("changed retry error = %v, want ErrTransitionConflict", err)
	}
	if store.sealCalls != 1 {
		t.Fatalf("exact retry resealed admission: calls = %d", store.sealCalls)
	}
}

func TestDispatchAdmitterFailsClosedOnIdentityAndTTL(t *testing.T) {
	_, _, _, grant := ceremonyFixtures(t)
	consumption := consumptionForGrant(t, grant, "spiffe://helm/data-plane-a", grant.IssuedAt.Add(time.Minute))
	store := &dispatchAdmissionTestStore{consumption: consumption, transitionAt: consumption.ConsumedAt.Add(time.Second)}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(privateKey, "dispatch-test")
	if _, err := newDispatchAdmitter(store, dispatchStaticConsumer{}, signer, time.Now, bytes.NewReader(nil), 0); err == nil {
		t.Fatal("zero ttl must fail")
	}
	consumer := dispatchStaticConsumer{identity: ConsumerIdentity{
		Subject: "spiffe://helm/data-plane-b", TenantID: consumption.TenantID,
		WorkspaceID: consumption.WorkspaceID, Audience: consumption.Audience,
	}}
	admitter, err := newDispatchAdmitter(
		store, consumer, signer, time.Now, bytes.NewReader(bytes.Repeat([]byte{4}, 32)), time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.Claim(context.Background(), dispatchAdmissionRequestForConsumption(consumption)); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("consumer substitution error = %v, want ErrTransitionConflict", err)
	}
}

type dispatchStaticConsumer struct {
	identity ConsumerIdentity
}

type dispatchFailingReader struct{}

func (dispatchFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func (p dispatchStaticConsumer) LoadConsumerIdentity(context.Context) (ConsumerIdentity, error) {
	return p.identity, nil
}

type dispatchAdmissionTestStore struct {
	consumption  contracts.ApprovalGrantConsumption
	transitionAt time.Time
	record       *DispatchAdmissionRecord
	request      DispatchAdmissionRequest
	identity     ConsumerIdentity
	sealCalls    int
}

func (s *dispatchAdmissionTestStore) claimDispatchAdmission(_ context.Context, identity ConsumerIdentity, request DispatchAdmissionRequest, seal dispatchAdmissionSealer, _ time.Time) (DispatchAdmissionRecord, error) {
	if s.record != nil {
		if err := dispatchAdmissionMatches(s.record.Admission, identity, request); err != nil {
			return DispatchAdmissionRecord{}, err
		}
		return *s.record, nil
	}
	s.sealCalls++
	admission, algorithm, signature, err := seal(s.consumption, s.transitionAt)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	record := DispatchAdmissionRecord{
		Admission: admission, SignatureAlgorithm: algorithm, Signature: signature,
		CreatedAt: admission.IssuedAt, UpdatedAt: admission.IssuedAt,
	}
	s.record = &record
	s.request = request
	s.identity = identity
	return record, nil
}

func (s *dispatchAdmissionTestStore) recoverDispatchAdmission(_ context.Context, identity ConsumerIdentity, request DispatchAdmissionRequest) (DispatchAdmissionRecord, error) {
	if s.record == nil {
		return DispatchAdmissionRecord{}, ErrNotFound
	}
	if err := dispatchAdmissionMatches(s.record.Admission, identity, request); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	return *s.record, nil
}

func dispatchAdmissionRequestForConsumption(consumption contracts.ApprovalGrantConsumption) DispatchAdmissionRequest {
	return DispatchAdmissionRequest{
		ApprovalID: consumption.ApprovalID, AttemptID: "attempt-a",
		ConsumptionHash:    consumption.ConsumptionHash,
		IdempotencyKeyHash: "sha256:" + strings.Repeat("a", 64),
		EffectHash:         consumption.EffectHash, ConnectorID: "connector-a", Action: consumption.Action,
	}
}
