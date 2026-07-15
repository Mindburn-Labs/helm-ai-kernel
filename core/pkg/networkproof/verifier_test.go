package networkproof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func testAttestation(binding string, now time.Time) DependencyAttestation {
	return DependencyAttestation{
		DecisionRef: "decision:test", BindingDigest: binding, SnapshotDigest: digestString("snapshot:" + binding),
		Generation: "generation-1", CheckedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute),
	}
}

type testKeys struct {
	mu         sync.RWMutex
	methods    map[string]VerificationMethod
	clock      func() time.Time
	err        error
	badBinding bool
	hook       func(KeyRequest)
}

func (r *testKeys) ResolveVerificationMethod(_ context.Context, request KeyRequest) (VerificationMethod, error) {
	if r.hook != nil {
		r.hook(request)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.err != nil {
		return VerificationMethod{}, r.err
	}
	method, ok := r.methods[request.MethodID]
	if !ok {
		return VerificationMethod{}, errors.New("key not found")
	}
	binding, _ := KeyBindingDigest(request)
	if r.badBinding {
		binding = digestString("wrong-key-binding")
	}
	method.Attestation = testAttestation(binding, r.clock())
	return method, nil
}

type testSchemas struct {
	clock           func() time.Time
	allowed         bool
	rejectPredicate string
	err             error
	badBinding      bool
}

func (r *testSchemas) AuthorizeClaimSchema(_ context.Context, request ClaimSchemaRequest) (ClaimSchemaResult, error) {
	if r.err != nil {
		return ClaimSchemaResult{}, r.err
	}
	binding, _ := ClaimSchemaBindingDigest(request)
	if r.badBinding {
		binding = digestString("wrong-schema-binding")
	}
	return ClaimSchemaResult{
		Allowed: r.allowed && request.Predicate != r.rejectPredicate, SchemaDigest: digestString(request.SchemaID + "@" + request.SchemaVersion),
		Attestation: testAttestation(binding, r.clock()),
	}, nil
}

type testAuthority struct {
	clock      func() time.Time
	authorized bool
	state      TrustState
	err        error
	badBinding bool
}

func (r *testAuthority) AuthorizeIssuer(_ context.Context, request AuthorityRequest) (AuthorityResult, error) {
	if r.err != nil {
		return AuthorityResult{}, r.err
	}
	binding, _ := AuthorityBindingDigest(request)
	if r.badBinding {
		binding = digestString("wrong-authority-binding")
	}
	return AuthorityResult{Authorized: r.authorized, State: r.state, Attestation: testAttestation(binding, r.clock())}, nil
}

type testStatuses struct {
	clock      func() time.Time
	status     CredentialStatus
	err        error
	badBinding bool
}

func (r *testStatuses) ResolveCredentialStatus(_ context.Context, request StatusRequest) (StatusResult, error) {
	if r.err != nil {
		return StatusResult{}, r.err
	}
	binding, _ := StatusBindingDigest(request)
	if r.badBinding {
		binding = digestString("wrong-status-binding")
	}
	return StatusResult{Status: r.status, Attestation: testAttestation(binding, r.clock())}, nil
}

type testEvidence struct {
	clock        func() time.Time
	state        TrustState
	err          error
	badBinding   bool
	hook         func(EvidenceRequest)
	postHook     func()
	expiresAfter time.Duration
}

func (r *testEvidence) VerifyEvidence(_ context.Context, request EvidenceRequest) (EvidenceResult, error) {
	if r.hook != nil {
		r.hook(request)
	}
	if r.err != nil {
		return EvidenceResult{}, r.err
	}
	binding, _ := EvidenceBindingDigest(request)
	if r.badBinding {
		binding = digestString("wrong-evidence-binding")
	}
	attestation := testAttestation(binding, r.clock())
	if r.expiresAfter != 0 {
		attestation.ExpiresAt = r.clock().Add(r.expiresAfter)
	}
	result := EvidenceResult{
		State:            r.state,
		Attestation:      attestation,
		ProofGraphRoot:   ArtifactReference{ID: "proofgraph:root:1", Digest: digestString("proofgraph-root")},
		EvidencePackRoot: ArtifactReference{ID: "evidencepack:root:1", Digest: digestString("evidencepack-root")},
	}
	if r.postHook != nil {
		r.postHook()
	}
	return result, nil
}

type testChallengeStore struct {
	mu          sync.Mutex
	records     map[string]ChallengeRecord
	clock       func() time.Time
	failCommit  bool
	commitCount int
}

func (s *testChallengeStore) Issue(challenge Challenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[challenge.ID] = ChallengeRecord{Challenge: cloneChallenge(challenge)}
}

func (s *testChallengeStore) LoadChallenge(_ context.Context, challengeID string) (ChallengeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[challengeID]
	if !ok {
		return ChallengeRecord{}, ErrChallengeNotFound
	}
	return cloneChallengeRecord(record), nil
}

func (s *testChallengeStore) CommitDecision(_ context.Context, challengeID, requestBinding, decisionInput string, decision VerificationReceipt) (ChallengeCommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failCommit {
		return ChallengeCommitResult{}, errors.New("commit unavailable")
	}
	record, ok := s.records[challengeID]
	if !ok {
		return ChallengeCommitResult{}, ErrChallengeNotFound
	}
	if record.Challenge.RequestBindingDigest != requestBinding {
		return ChallengeCommitResult{}, ErrChallengeConflict
	}
	if record.Decision != nil {
		if record.Decision.DecisionInputDigest != decisionInput {
			return ChallengeCommitResult{}, ErrChallengeConflict
		}
		return ChallengeCommitResult{Decision: *cloneReceipt(record.Decision), Existing: true}, nil
	}
	if !s.clock().Before(record.Challenge.ExpiresAt) {
		return ChallengeCommitResult{}, ErrChallengeConflict
	}
	stored := cloneReceipt(&decision)
	record.Decision = stored
	s.records[challengeID] = record
	s.commitCount++
	return ChallengeCommitResult{Decision: *cloneReceipt(stored)}, nil
}

func (s *testChallengeStore) Decision(challengeID string) *VerificationReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneReceipt(s.records[challengeID].Decision)
}

type testReceiptSigner struct {
	mu        sync.RWMutex
	signer    *crypto.Ed25519Signer
	fail      bool
	badOutput bool
	hook      func()
}

func (s *testReceiptSigner) KeyID() string     { return "did:helm:verifier:network#receipt-1" }
func (s *testReceiptSigner) Algorithm() string { return AlgorithmEd25519 }
func (s *testReceiptSigner) PublicKey() []byte { return s.signer.PublicKeyBytes() }
func (s *testReceiptSigner) Sign(payload []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.hook != nil {
		s.hook()
	}
	if s.fail {
		return "", errors.New("signer unavailable")
	}
	if s.badOutput {
		return strings.Repeat("00", 64), nil
	}
	return s.signer.Sign(payload)
}

func (s *testReceiptSigner) SetFailure(fail, bad bool) {
	s.mu.Lock()
	s.fail, s.badOutput = fail, bad
	s.mu.Unlock()
}

func (s *testReceiptSigner) SetHook(hook func()) {
	s.mu.Lock()
	s.hook = hook
	s.mu.Unlock()
}

type fixture struct {
	clock         *testClock
	request       VerificationRequest
	presentation  *Presentation
	profile       AssuranceProfile
	profileDigest string
	verifier      *Verifier
	holder        *crypto.Ed25519Signer
	issuer        *crypto.Ed25519Signer
	receiptKey    *crypto.Ed25519Signer
	keys          *testKeys
	schemas       *testSchemas
	authority     *testAuthority
	statuses      *testStatuses
	evidence      *testEvidence
	challenges    *testChallengeStore
	signer        *testReceiptSigner
}

func newFixture(t *testing.T, actorType ActorType) *fixture {
	t.Helper()
	now := time.Date(2026, 7, 15, 14, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	holder := mustSigner(t, "holder")
	issuer := mustSigner(t, "issuer")
	receiptKey := mustSigner(t, "receipt")
	profile := AssuranceProfile{
		ID: "helm-network-claim", Version: "1.0.0", VerifierVersion: "networkproof-test",
		HolderBinding:     HolderBindingSubjectKeyV1,
		AllowedActorTypes: []ActorType{ActorPerson, ActorOrganization, ActorAgent, ActorService},
		MaxCredentialAge:  24 * time.Hour, MaxPresentationAge: 5 * time.Minute, MaxDependencyAge: 10 * time.Minute,
		ClockSkew: 30 * time.Second, AllowedCredentialProofs: []string{ProofTypeHELMJCS2026},
		AllowedPresentationProofs: []string{ProofTypeHELMJCS2026},
		AllowedCredentialStatuses: []string{"BitstringStatusListEntry"}, AllowedEvidenceKinds: []string{"registry_record"},
	}
	profileDigest, err := AssuranceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	subjectID := "did:helm:" + string(actorType) + ":subject-1"
	request := VerificationRequest{
		RequestID: "verify-request-1", ChallengeID: "challenge-1", SubjectID: subjectID, ActorType: actorType,
		ClaimID: "claim-1", Predicate: "organization.authorization.eu", ValueDigest: digestString("licensed-in-eu"),
		Scope: []string{"capability:invoice.read", "jurisdiction:EU"}, Audience: []string{"https://network.example/client"},
		Nonce: "nonce-with-256-bits-of-source-randomness", Purpose: "vendor due diligence", TransactionID: "transaction-1",
		SchemaID: "helm.network.claim", SchemaVersion: "1.0.0", DisclosureDigest: digestString("claim-fields-v1"),
		ExpectedProfileDigest: profileDigest,
	}
	credential := Credential{
		Context: []string{ContextW3CCredentials, ContextNetworkClaim}, ID: "urn:uuid:credential-1",
		Type: []string{TypeVerifiableCredential, TypeNetworkClaimCredential}, SchemaID: request.SchemaID,
		SchemaVersion: request.SchemaVersion, Issuer: "did:web:issuer.example", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
		CredentialSubject: ClaimSubject{
			ID: subjectID, ActorType: actorType, ClaimID: request.ClaimID, Predicate: request.Predicate,
			ValueDigest: request.ValueDigest, Scope: append([]string(nil), request.Scope...), Audience: append([]string(nil), request.Audience...),
			Purpose: request.Purpose, IssuedAt: now.Add(-time.Hour),
		},
		CredentialStatus: CredentialStatusReference{ID: "https://issuer.example/status/7#42", Type: "BitstringStatusListEntry"},
		Evidence:         []EvidenceReference{{ID: "https://registry.example/records/7", Kind: "registry_record", Digest: digestString("registry-record-v7")}},
		Proof:            &Proof{Type: ProofTypeHELMJCS2026, Created: now.Add(-time.Hour), VerificationMethod: "did:web:issuer.example#assert-1", ProofPurpose: ProofPurposeAssertion},
	}
	signCredential(t, &credential, issuer)
	presentation := &Presentation{
		Context: []string{ContextW3CCredentials, ContextNetworkClaim}, ID: "urn:uuid:presentation-1",
		Type: []string{TypeVerifiablePresentation, TypeNetworkClaimPresentation}, Holder: subjectID,
		Audience: append([]string(nil), request.Audience...), Nonce: request.Nonce, Purpose: request.Purpose,
		TransactionID: request.TransactionID, IssuedAt: now.Add(-time.Minute), Credentials: []Credential{credential},
		Proof: &Proof{Type: ProofTypeHELMJCS2026, Created: now.Add(-time.Minute), VerificationMethod: subjectID + "#auth-1", ProofPurpose: ProofPurposeAuthentication},
	}
	signPresentation(t, presentation, holder)
	keys := &testKeys{clock: clock.Now, methods: map[string]VerificationMethod{
		presentation.Proof.VerificationMethod: {
			ID: presentation.Proof.VerificationMethod, Controller: subjectID, Algorithm: AlgorithmEd25519,
			Purposes: []string{ProofPurposeAuthentication}, PublicKey: holder.PublicKeyBytes(), State: TrustActive,
			ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(24 * time.Hour),
		},
		credential.Proof.VerificationMethod: {
			ID: credential.Proof.VerificationMethod, Controller: credential.Issuer, Algorithm: AlgorithmEd25519,
			Purposes: []string{ProofPurposeAssertion}, PublicKey: issuer.PublicKeyBytes(), State: TrustActive,
			ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(24 * time.Hour),
		},
	}}
	schemas := &testSchemas{clock: clock.Now, allowed: true}
	authority := &testAuthority{clock: clock.Now, authorized: true, state: TrustActive}
	statuses := &testStatuses{clock: clock.Now, status: CredentialStatusValid}
	evidence := &testEvidence{clock: clock.Now, state: TrustActive}
	challenges := &testChallengeStore{clock: clock.Now, records: map[string]ChallengeRecord{}}
	binding, err := VerificationRequestBindingDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	challenges.Issue(Challenge{
		ID: request.ChallengeID, RequestBindingDigest: binding, ProfileDigest: profileDigest,
		NonceDigest: digestString(request.Nonce), Audience: append([]string(nil), request.Audience...), TransactionID: request.TransactionID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute), Generation: "challenge-generation-1",
	})
	signer := &testReceiptSigner{signer: receiptKey}
	var receiptIDs atomic.Int64
	verifier, err := NewVerifier(profile, Dependencies{
		Keys: keys, Schemas: schemas, Authority: authority, Statuses: statuses, Evidence: evidence,
		Challenges: challenges, Signer: signer, Clock: clock.Now,
		NewID: func() string { return fmt.Sprintf("verification-receipt-%d", receiptIDs.Add(1)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		clock: clock, request: request, presentation: presentation, profile: profile, profileDigest: profileDigest,
		verifier: verifier, holder: holder, issuer: issuer, receiptKey: receiptKey, keys: keys, schemas: schemas,
		authority: authority, statuses: statuses, evidence: evidence, challenges: challenges, signer: signer,
	}
}

func mustSigner(t *testing.T, keyID string) *crypto.Ed25519Signer {
	t.Helper()
	signer, err := crypto.NewEd25519Signer(keyID)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func signCredential(t *testing.T, credential *Credential, signer *crypto.Ed25519Signer) {
	t.Helper()
	bytes, err := CredentialSigningBytes(credential)
	if err != nil {
		t.Fatal(err)
	}
	credential.Proof.ProofValue, err = signer.Sign(bytes)
	if err != nil {
		t.Fatal(err)
	}
}

func signPresentation(t *testing.T, presentation *Presentation, signer *crypto.Ed25519Signer) {
	t.Helper()
	bytes, err := PresentationSigningBytes(presentation)
	if err != nil {
		t.Fatal(err)
	}
	presentation.Proof.ProofValue, err = signer.Sign(bytes)
	if err != nil {
		t.Fatal(err)
	}
}

func verifyFixture(t *testing.T, f *fixture) *VerificationReceipt {
	t.Helper()
	receipt, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyReceiptSignature(receipt, f.receiptKey.PublicKeyBytes()); err != nil {
		t.Fatalf("receipt signature: %v", err)
	}
	return receipt
}

func cloneChallenge(value Challenge) Challenge {
	value.Audience = append([]string(nil), value.Audience...)
	return value
}

func cloneChallengeRecord(value ChallengeRecord) ChallengeRecord {
	value.Challenge = cloneChallenge(value.Challenge)
	value.Decision = cloneReceipt(value.Decision)
	return value
}

func issueFixtureChallenge(t *testing.T, f *fixture) {
	t.Helper()
	binding, err := VerificationRequestBindingDigest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	now := f.clock.Now()
	f.challenges.Issue(Challenge{
		ID: f.request.ChallengeID, RequestBindingDigest: binding, ProfileDigest: f.request.ExpectedProfileDigest,
		NonceDigest: digestString(f.request.Nonce), Audience: append([]string(nil), f.request.Audience...),
		TransactionID: f.request.TransactionID, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute),
		Generation: "challenge-generation-1",
	})
}

func replaceFixtureProfile(t *testing.T, f *fixture, profile AssuranceProfile) {
	t.Helper()
	digest, err := AssuranceProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	f.profile, f.profileDigest, f.request.ExpectedProfileDigest = cloneProfile(profile), digest, digest
	issueFixtureChallenge(t, f)
	verifier, err := NewVerifier(profile, f.verifier.deps)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier = verifier
}

func TestVerifiedDecisionBindsExactEvidenceAndCurrentAppraisal(t *testing.T) {
	f := newFixture(t, ActorPerson)
	receipt := verifyFixture(t, f)
	if receipt.DecisionStatusAtEvaluation != StatusVerified || receipt.ReasonCode != "verified_exact_claim" {
		t.Fatalf("decision = %s/%s", receipt.DecisionStatusAtEvaluation, receipt.ReasonCode)
	}
	if receipt.CanonicalCredentialDigest == "" || receipt.CanonicalPresentationDigest == "" || receipt.CredentialSchemaDigest == "" ||
		len(receipt.Dependencies) != 6 || len(receipt.ProofGraphRoots) != 1 || len(receipt.EvidencePackRoots) != 1 {
		t.Fatalf("exact dependency evidence missing: %#v", receipt)
	}
	resolver := newAppraisalResolver(f)
	appraiser, err := NewReceiptAppraiser(resolver, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	appraisal := appraiser.Appraise(context.Background(), receipt, expectationFor(f, receipt))
	if !appraisal.CanRenderVerified() {
		t.Fatalf("current appraisal = %s/%s", appraisal.Status, appraisal.ReasonCode)
	}
}

func TestFourActorTypesUseSubjectHeldKeysAndRejectDelegation(t *testing.T) {
	for _, actorType := range []ActorType{ActorPerson, ActorOrganization, ActorAgent, ActorService} {
		t.Run(string(actorType), func(t *testing.T) {
			f := newFixture(t, actorType)
			if got := verifyFixture(t, f).DecisionStatusAtEvaluation; got != StatusVerified {
				t.Fatalf("actor %s = %s", actorType, got)
			}
		})
	}
	t.Run("delegated presenter rejected by v1", func(t *testing.T) {
		f := newFixture(t, ActorOrganization)
		f.presentation.Holder = "did:helm:person:controller"
		f.presentation.Proof.VerificationMethod = "did:helm:person:controller#auth-1"
		controller := mustSigner(t, "controller")
		f.keys.methods[f.presentation.Proof.VerificationMethod] = VerificationMethod{
			ID: f.presentation.Proof.VerificationMethod, Controller: f.presentation.Holder, Algorithm: AlgorithmEd25519,
			Purposes: []string{ProofPurposeAuthentication}, PublicKey: controller.PublicKeyBytes(), State: TrustActive,
			ValidFrom: f.clock.Now().Add(-time.Hour), ValidUntil: f.clock.Now().Add(time.Hour),
		}
		signPresentation(t, f.presentation, controller)
		receipt := verifyFixture(t, f)
		if receipt.DecisionStatusAtEvaluation == StatusVerified {
			t.Fatal("delegated presenter bypassed subject-held-key v1")
		}
	})
}

func TestChallengeAtomicityOriginalReplayAndConflict(t *testing.T) {
	t.Run("exact original presentation returns exact original", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		first := verifyFixture(t, f)
		second := verifyFixture(t, f)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("exact replay did not return original receipt\nfirst=%#v\nsecond=%#v", first, second)
		}
	})

	t.Run("changed presentation ID conflicts", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		_ = verifyFixture(t, f)
		f.presentation.ID = "urn:uuid:presentation-retry"
		f.presentation.IssuedAt = f.clock.Now()
		f.presentation.Proof.Created = f.clock.Now()
		signPresentation(t, f.presentation, f.holder)
		_, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		if !errors.Is(err, ErrChallengeConflict) {
			t.Fatalf("changed presentation ID error = %v", err)
		}
	})

	t.Run("forged rotated holder proof cannot retrieve original", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		_ = verifyFixture(t, f)
		f.presentation.ID = "urn:uuid:forged-rotation"
		f.presentation.IssuedAt = f.clock.Now()
		f.presentation.Proof.Created = f.clock.Now()
		f.presentation.Proof.ProofValue = strings.Repeat("0", 128)
		_, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		if !errors.Is(err, ErrChallengeConflict) {
			t.Fatalf("forged rotated proof error = %v", err)
		}
	})

	t.Run("restart and expiry preserve exact stored bytes", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		first := verifyFixture(t, f)
		firstBytes, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		f.clock.Set(f.clock.Now().Add(11 * time.Minute))
		restarted, err := NewVerifier(f.profile, f.verifier.deps)
		if err != nil {
			t.Fatal(err)
		}
		second, err := restarted.Verify(context.Background(), f.request, f.presentation)
		if err != nil {
			t.Fatal(err)
		}
		secondBytes, err := json.Marshal(second)
		if err != nil {
			t.Fatal(err)
		}
		if string(firstBytes) != string(secondBytes) {
			t.Fatalf("restart replay bytes changed\nfirst=%s\nsecond=%s", firstBytes, secondBytes)
		}
	})

	t.Run("changed credential conflicts", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		_ = verifyFixture(t, f)
		f.presentation.Credentials[0].Evidence[0].Digest = digestString("different-evidence")
		signCredential(t, &f.presentation.Credentials[0], f.issuer)
		signPresentation(t, f.presentation, f.holder)
		_, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		if !errors.Is(err, ErrChallengeConflict) {
			t.Fatalf("conflicting input error = %v", err)
		}
	})

	t.Run("malformed retry envelope cannot retrieve original", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		_ = verifyFixture(t, f)
		f.presentation.Context[0], f.presentation.Context[1] = f.presentation.Context[1], f.presentation.Context[0]
		signPresentation(t, f.presentation, f.holder)
		_, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		if !errors.Is(err, ErrChallengeConflict) {
			t.Fatalf("malformed replay error = %v", err)
		}
	})

	t.Run("different request-bound presentation conflicts", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		_ = verifyFixture(t, f)
		f.presentation.Audience = []string{"https://other.example/client"}
		signPresentation(t, f.presentation, f.holder)
		_, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		if !errors.Is(err, ErrChallengeConflict) {
			t.Fatalf("different presentation error = %v", err)
		}
	})

	t.Run("expired challenge cannot receive a first decision", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		f.clock.Set(f.clock.Now().Add(11 * time.Minute))
		receipt, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.DecisionStatusAtEvaluation == StatusVerified || f.challenges.Decision(f.request.ChallengeID) != nil {
			t.Fatalf("expired challenge decision = %s stored=%#v", receipt.DecisionStatusAtEvaluation, f.challenges.Decision(f.request.ChallengeID))
		}
		if err := VerifyReceiptSignature(receipt, f.receiptKey.PublicKeyBytes()); err != nil {
			t.Fatalf("expired challenge receipt signature/schema = %v", err)
		}
	})

	t.Run("store rejects first decision that expires after load", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		start := f.clock.Now()
		record, err := f.challenges.LoadChallenge(context.Background(), f.request.ChallengeID)
		if err != nil {
			t.Fatal(err)
		}
		record.Challenge.ExpiresAt = start.Add(time.Minute)
		f.challenges.Issue(record.Challenge)
		f.evidence.postHook = func() { f.clock.Set(start.Add(2 * time.Minute)) }
		_, err = f.verifier.Verify(context.Background(), f.request, f.presentation)
		if !errors.Is(err, ErrChallengeConflict) {
			t.Fatalf("post-load expiry error = %v", err)
		}
		if f.challenges.Decision(f.request.ChallengeID) != nil {
			t.Fatal("store committed a first decision after authoritative expiry")
		}
	})

	t.Run("concurrent exact submissions commit once", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		const workers = 64
		results := make(chan *VerificationReceipt, workers)
		errs := make(chan error, workers)
		var group sync.WaitGroup
		for range workers {
			group.Add(1)
			go func() {
				defer group.Done()
				receipt, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
				if err != nil {
					errs <- err
					return
				}
				results <- receipt
			}()
		}
		group.Wait()
		close(results)
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		var first *VerificationReceipt
		for receipt := range results {
			if first == nil {
				first = receipt
			} else if !reflect.DeepEqual(first, receipt) {
				t.Fatal("concurrent retry returned a different receipt")
			}
		}
		if f.challenges.commitCount != 1 {
			t.Fatalf("commit count = %d", f.challenges.commitCount)
		}
	})
}

func TestSignerAndCommitFailuresNeverConsumeChallenge(t *testing.T) {
	t.Run("signer error", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		f.signer.SetFailure(true, false)
		if _, err := f.verifier.Verify(context.Background(), f.request, f.presentation); err == nil {
			t.Fatal("expected signer failure")
		}
		if f.challenges.Decision(f.request.ChallengeID) != nil {
			t.Fatal("signer failure consumed challenge")
		}
		f.signer.SetFailure(false, false)
		if got := verifyFixture(t, f).DecisionStatusAtEvaluation; got != StatusVerified {
			t.Fatalf("retry = %s", got)
		}
	})
	t.Run("unverifiable signer output", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		f.signer.SetFailure(false, true)
		if _, err := f.verifier.Verify(context.Background(), f.request, f.presentation); err == nil {
			t.Fatal("expected self-verification failure")
		}
		if f.challenges.Decision(f.request.ChallengeID) != nil {
			t.Fatal("bad signer output consumed challenge")
		}
	})
	t.Run("commit error", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		f.challenges.failCommit = true
		if _, err := f.verifier.Verify(context.Background(), f.request, f.presentation); err == nil {
			t.Fatal("expected commit failure")
		}
		if f.challenges.Decision(f.request.ChallengeID) != nil {
			t.Fatal("commit failure consumed challenge")
		}
		f.challenges.failCommit = false
		if got := verifyFixture(t, f).DecisionStatusAtEvaluation; got != StatusVerified {
			t.Fatalf("retry = %s", got)
		}
	})
	t.Run("canceled during signing", func(t *testing.T) {
		f := newFixture(t, ActorPerson)
		ctx, cancel := context.WithCancel(context.Background())
		f.signer.SetHook(cancel)
		if _, err := f.verifier.Verify(ctx, f.request, f.presentation); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
		if f.challenges.Decision(f.request.ChallengeID) != nil {
			t.Fatal("canceled verification consumed challenge")
		}
		f.signer.SetHook(nil)
		if got := verifyFixture(t, f).DecisionStatusAtEvaluation; got != StatusVerified {
			t.Fatalf("retry = %s", got)
		}
	})
}

func TestEverySuccessfullyReturnedHistoricalStatusSelfVerifies(t *testing.T) {
	tests := map[string]struct {
		mutate func(*fixture)
		want   VerificationStatus
	}{
		"invalid request": {func(f *fixture) { f.request.ValueDigest = "not-a-sha256-digest" }, StatusInvalid},
		"challenge unavailable": {func(f *fixture) {
			f.challenges.mu.Lock()
			delete(f.challenges.records, f.request.ChallengeID)
			f.challenges.mu.Unlock()
		}, StatusUnknown},
		"holder key unavailable": {func(f *fixture) { f.keys.err = errors.New("key resolver unavailable") }, StatusUnknown},
		"schema unavailable after authentication": {func(f *fixture) {
			f.schemas.err = errors.New("schema registry unavailable")
		}, StatusUnknown},
		"credential revoked": {func(f *fixture) { f.statuses.status = CredentialStatusRevoked }, StatusRevoked},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, ActorPerson)
			test.mutate(f)
			receipt, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.DecisionStatusAtEvaluation != test.want {
				t.Fatalf("status = %s, want %s", receipt.DecisionStatusAtEvaluation, test.want)
			}
			if err := VerifyReceiptSignature(receipt, f.receiptKey.PublicKeyBytes()); err != nil {
				t.Fatalf("historical receipt signature/schema = %v", err)
			}
		})
	}
}

func TestImmutableSnapshotPreventsConcurrentInputSwap(t *testing.T) {
	f := newFixture(t, ActorPerson)
	entered := make(chan struct{})
	release := make(chan struct{})
	f.keys.hook = func(request KeyRequest) {
		if request.Purpose == ProofPurposeAuthentication {
			close(entered)
			<-release
		}
	}
	result := make(chan *VerificationReceipt, 1)
	errResult := make(chan error, 1)
	go func() {
		receipt, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
		result <- receipt
		errResult <- err
	}()
	<-entered
	f.presentation.Credentials[0].Evidence[0].Digest = digestString("swapped-after-snapshot")
	f.request.Scope[0] = "capability:invoice.write"
	close(release)
	receipt := <-result
	if err := <-errResult; err != nil {
		t.Fatal(err)
	}
	if receipt.DecisionStatusAtEvaluation != StatusVerified || receipt.ValueDigest != digestString("licensed-in-eu") ||
		receipt.Scope[0] == "capability:invoice.write" {
		t.Fatalf("mutable input crossed snapshot boundary: %#v", receipt)
	}
}

func TestProfileIsFrozenAndPinnedByDigest(t *testing.T) {
	f := newFixture(t, ActorPerson)
	f.profile.AllowedEvidenceKinds[0] = "attacker_kind"
	if got := verifyFixture(t, f).DecisionStatusAtEvaluation; got != StatusVerified {
		t.Fatalf("post-construction alias mutation changed verifier: %s", got)
	}

	weak := f.verifier.profile
	weak.MaxDependencyAge = 24 * time.Hour
	digest, err := AssuranceProfileDigest(weak)
	if err != nil {
		t.Fatal(err)
	}
	if digest == f.profileDigest {
		t.Fatal("weaker same-name profile retained the same digest")
	}
	overflow := cloneProfile(f.profile)
	overflow.MaxDependencyAge = time.Duration(1<<63 - 1)
	if _, err := NewVerifier(overflow, f.verifier.deps); err == nil {
		t.Fatal("overflowing profile freshness window accepted")
	}
}

func TestEveryRequestFieldAffectsBindingExceptSetOrder(t *testing.T) {
	f := newFixture(t, ActorPerson)
	base, err := VerificationRequestBindingDigest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*VerificationRequest){
		"request":        func(r *VerificationRequest) { r.RequestID += "x" },
		"challenge":      func(r *VerificationRequest) { r.ChallengeID += "x" },
		"subject":        func(r *VerificationRequest) { r.SubjectID += "x" },
		"actor":          func(r *VerificationRequest) { r.ActorType = ActorAgent },
		"claim":          func(r *VerificationRequest) { r.ClaimID += "x" },
		"predicate":      func(r *VerificationRequest) { r.Predicate += "x" },
		"value":          func(r *VerificationRequest) { r.ValueDigest = digestString("x") },
		"scope":          func(r *VerificationRequest) { r.Scope[0] += "x" },
		"audience":       func(r *VerificationRequest) { r.Audience[0] += "/x" },
		"nonce":          func(r *VerificationRequest) { r.Nonce += "x" },
		"purpose":        func(r *VerificationRequest) { r.Purpose += "x" },
		"transaction":    func(r *VerificationRequest) { r.TransactionID += "x" },
		"schema":         func(r *VerificationRequest) { r.SchemaID += "x" },
		"schema version": func(r *VerificationRequest) { r.SchemaVersion += "x" },
		"disclosure":     func(r *VerificationRequest) { r.DisclosureDigest = digestString("x") },
		"profile":        func(r *VerificationRequest) { r.ExpectedProfileDigest = digestString("x") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := cloneRequest(f.request)
			mutate(&copy)
			digest, err := VerificationRequestBindingDigest(copy)
			if err != nil {
				t.Fatal(err)
			}
			if digest == base {
				t.Fatalf("%s did not affect binding", name)
			}
		})
	}
	ordered := cloneRequest(f.request)
	ordered.Scope[0], ordered.Scope[1] = ordered.Scope[1], ordered.Scope[0]
	digest, _ := VerificationRequestBindingDigest(ordered)
	if digest != base {
		t.Fatal("set order changed request binding")
	}
}

func TestSchemaContextAudienceKeyAndFreshnessFailuresFailClosed(t *testing.T) {
	tests := map[string]func(*fixture){
		"reversed context": func(f *fixture) {
			f.presentation.Context[0], f.presentation.Context[1] = f.presentation.Context[1], f.presentation.Context[0]
			signPresentation(t, f.presentation, f.holder)
		},
		"broad audience": func(f *fixture) {
			f.request.Audience = []string{"all"}
		},
		"unknown schema": func(f *fixture) { f.schemas.allowed = false },
		"unknown predicate": func(f *fixture) {
			f.request.Predicate = "unknown.predicate"
			f.presentation.Credentials[0].CredentialSubject.Predicate = f.request.Predicate
			f.schemas.rejectPredicate = f.request.Predicate
			signCredential(t, &f.presentation.Credentials[0], f.issuer)
			signPresentation(t, f.presentation, f.holder)
			issueFixtureChallenge(t, f)
		},
		"schema binding":    func(f *fixture) { f.schemas.badBinding = true },
		"status binding":    func(f *fixture) { f.statuses.badBinding = true },
		"evidence binding":  func(f *fixture) { f.evidence.badBinding = true },
		"authority binding": func(f *fixture) { f.authority.badBinding = true },
		"key binding":       func(f *fixture) { f.keys.badBinding = true },
		"proof before key validity": func(f *fixture) {
			method := f.keys.methods[f.presentation.Proof.VerificationMethod]
			method.ValidFrom = f.presentation.Proof.Created.Add(time.Second)
			f.keys.methods[method.ID] = method
		},
		"old proof fresh subject": func(f *fixture) {
			credential := &f.presentation.Credentials[0]
			credential.ValidFrom = f.clock.Now().Add(-48 * time.Hour)
			credential.Proof.Created = f.clock.Now().Add(-48 * time.Hour)
			credential.CredentialSubject.IssuedAt = f.clock.Now()
			signCredential(t, credential, f.issuer)
			signPresentation(t, f.presentation, f.holder)
		},
		"credential proof from the future": func(f *fixture) {
			credential := &f.presentation.Credentials[0]
			credential.ValidUntil = f.clock.Now().Add(2 * time.Hour)
			credential.CredentialSubject.IssuedAt = f.clock.Now().Add(time.Hour)
			credential.Proof.Created = f.clock.Now().Add(time.Hour)
			signCredential(t, credential, f.issuer)
			signPresentation(t, f.presentation, f.holder)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, ActorPerson)
			mutate(f)
			receipt, err := f.verifier.Verify(context.Background(), f.request, f.presentation)
			if err != nil && errors.Is(err, ErrChallengeConflict) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if receipt.DecisionStatusAtEvaluation == StatusVerified {
				t.Fatalf("%s rendered VERIFIED", name)
			}
			if err := VerifyReceiptSignature(receipt, f.receiptKey.PublicKeyBytes()); err != nil {
				t.Fatalf("%s returned an unverifiable historical receipt: %v", name, err)
			}
		})
	}
}

func TestFinalFreshnessRecheckDowngradesElapsedDependency(t *testing.T) {
	f := newFixture(t, ActorPerson)
	start := f.clock.Now()
	f.evidence.expiresAfter = time.Minute
	f.evidence.postHook = func() { f.clock.Set(start.Add(2 * time.Minute)) }
	receipt := verifyFixture(t, f)
	if receipt.DecisionStatusAtEvaluation != StatusUnknown || receipt.ReasonCode != "dependency_expired_during_verification" {
		t.Fatalf("decision = %s/%s", receipt.DecisionStatusAtEvaluation, receipt.ReasonCode)
	}
}

func TestStrictJSONBoundaryRejectsDuplicateUnknownDeepAndOversizedInput(t *testing.T) {
	f := newFixture(t, ActorPerson)
	data, err := json.Marshal(f.presentation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePresentationJSON(data); err != nil {
		t.Fatalf("valid JSON rejected: %v", err)
	}
	duplicate := strings.Replace(string(data), `"id":"urn:uuid:presentation-1"`, `"id":"one","id":"two"`, 1)
	if _, err := ParsePresentationJSON([]byte(duplicate)); err == nil {
		t.Fatal("duplicate member accepted")
	}
	unknown := strings.Replace(string(data), `{`, `{"unknown":true,`, 1)
	if _, err := ParsePresentationJSON([]byte(unknown)); err == nil {
		t.Fatal("unknown member accepted")
	}
	deep := strings.Repeat(`{"x":`, maxJSONDepth+2) + `0` + strings.Repeat(`}`, maxJSONDepth+2)
	if _, err := ParsePresentationJSON([]byte(deep)); err == nil {
		t.Fatal("deep JSON accepted")
	}
	if _, err := ParsePresentationJSON(make([]byte, maxCanonicalBytes+1)); err == nil {
		t.Fatal("oversized JSON accepted")
	}
	tooMany := clonePresentation(f.presentation)
	tooMany.Credentials = make([]Credential, 10_000)
	receipt, err := f.verifier.Verify(context.Background(), f.request, tooMany)
	if err == nil || receipt != nil {
		t.Fatalf("oversized typed presentation crossed preflight: receipt=%#v err=%v", receipt, err)
	}
	tooManyRequest := cloneRequest(f.request)
	tooManyRequest.Scope = make([]string, maxSetItems+1)
	if receipt, err := f.verifier.Verify(context.Background(), tooManyRequest, f.presentation); err == nil || receipt != nil {
		t.Fatalf("oversized server request crossed preflight: receipt=%#v err=%v", receipt, err)
	}
	invalidUTF8 := clonePresentation(f.presentation)
	invalidUTF8.ID = string([]byte{0xff})
	if receipt, err := f.verifier.Verify(context.Background(), f.request, invalidUTF8); err == nil || receipt != nil {
		t.Fatalf("invalid UTF-8 crossed preflight: receipt=%#v err=%v", receipt, err)
	}
}

func TestRFC8785CanonicalVectorsAndStableNetworkGolden(t *testing.T) {
	canonical, err := canonicalJCS(map[string]any{"\ue000": 2, "😀": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"😀":1,"":2}` {
		t.Fatalf("UTF-16 property order = %s", canonical)
	}
	canonical, err = canonicalJCS(json.RawMessage(`{"negativeZero":-0,"one":1.0}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"negativeZero":0,"one":1}` {
		t.Fatalf("ECMAScript number canonicalization = %s", canonical)
	}
	canonical, err = canonicalJCS(json.RawMessage(`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`))
	if err != nil {
		t.Fatal(err)
	}
	const rfc8785Sample = `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	if string(canonical) != rfc8785Sample {
		t.Fatalf("RFC 8785 sample vector = %s", canonical)
	}
	f := newFixture(t, ActorPerson)
	credentialBytes, err := CredentialSigningBytes(&f.presentation.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	const credentialGolden = "sha256:b943899a016ce630a4fbe0163ed79ae296ee7d45997f9504fada7c399f8a3271"
	if got := digestBytes(credentialBytes); got != credentialGolden {
		t.Fatalf("credential golden = %s", got)
	}
	presentation := clonePresentation(f.presentation)
	presentation.Credentials[0].Proof.ProofValue = strings.Repeat("a", 128)
	presentationBytes, err := PresentationSigningBytes(presentation)
	if err != nil {
		t.Fatal(err)
	}
	const presentationGolden = "sha256:14283cbd8f79bdace8357acff5c22450b5489f79fdfa4b958e57cd924b994885"
	if got := digestBytes(presentationBytes); got != presentationGolden {
		t.Errorf("presentation golden = %s", got)
	}
	fixedCredential := cloneCredential(&f.presentation.Credentials[0])
	fixedCredential.Proof.ProofValue = strings.Repeat("a", 128)
	credentialArtifactDigest, err := CanonicalCredentialDigest(fixedCredential)
	if err != nil {
		t.Fatal(err)
	}
	const credentialArtifactGolden = "sha256:0390c8c82e882d92648301197997835cd1bf10300ea5afe60c0bd6331235f06d"
	if credentialArtifactDigest != credentialArtifactGolden {
		t.Errorf("credential artifact golden = %s", credentialArtifactDigest)
	}
	presentation.Proof.ProofValue = strings.Repeat("b", 128)
	presentationArtifactDigest, err := CanonicalPresentationDigest(presentation)
	if err != nil {
		t.Fatal(err)
	}
	const presentationArtifactGolden = "sha256:47764d8163b1e3593ca543233a649bec08cc8201a916805ce30231745d333683"
	if presentationArtifactDigest != presentationArtifactGolden {
		t.Errorf("presentation artifact golden = %s", presentationArtifactDigest)
	}
	receipt := verifyFixture(t, f)
	receipt.CanonicalPresentationDigest = digestString("golden-presentation")
	receipt.CanonicalCredentialDigest = digestString("golden-credential")
	receipt.DecisionInputDigest = digestString("golden-decision-input")
	for i := range receipt.Dependencies {
		receipt.Dependencies[i].Attestation.BindingDigest = digestString(fmt.Sprintf("golden-binding-%d", i))
		receipt.Dependencies[i].Attestation.SnapshotDigest = digestString(fmt.Sprintf("golden-snapshot-%d", i))
	}
	receipt.DependencySnapshotDigest, err = dependencySnapshotDigest(receipt.Dependencies)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := ReceiptSigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	const receiptGolden = "sha256:d04f3124acec5ab930203991411e596b179b2cc5eb9ff7f262c128056f4ef230"
	if got := digestBytes(receiptBytes); got != receiptGolden {
		t.Errorf("receipt golden = %s", got)
	}
}

func TestVerifiedReceiptSchemaRejectsAmbiguousOrStaleEvidence(t *testing.T) {
	f := newFixture(t, ActorPerson)
	valid := verifyFixture(t, f)
	if err := validateReceiptSchema(valid); err != nil {
		t.Fatalf("valid receipt schema: %v", err)
	}
	tests := map[string]func(*VerificationReceipt){
		"noncanonical dependency order": func(receipt *VerificationReceipt) {
			receipt.Dependencies[0], receipt.Dependencies[1] = receipt.Dependencies[1], receipt.Dependencies[0]
		},
		"duplicate dependency identity": func(receipt *VerificationReceipt) {
			receipt.Dependencies = append(receipt.Dependencies, receipt.Dependencies[0])
			sortReceiptDependencies(receipt.Dependencies)
		},
		"missing required dependency class": func(receipt *VerificationReceipt) {
			receipt.Dependencies[0].Kind = "unrecognized_dependency"
			sortReceiptDependencies(receipt.Dependencies)
		},
		"inactive historical dependency": func(receipt *VerificationReceipt) {
			receipt.Dependencies[0].State = TrustRevoked
		},
		"dependency checked after decision": func(receipt *VerificationReceipt) {
			receipt.Dependencies[0].Attestation.CheckedAt = receipt.EvaluatedAt.Add(time.Second)
			receipt.Dependencies[0].Attestation.ExpiresAt = receipt.FreshUntil.Add(time.Minute)
		},
		"dependency expired at decision": func(receipt *VerificationReceipt) {
			receipt.Dependencies[0].Attestation.ExpiresAt = receipt.EvaluatedAt
		},
		"receipt freshness exceeds dependency": func(receipt *VerificationReceipt) {
			receipt.FreshUntil = receipt.FreshUntil.Add(time.Second)
		},
		"duplicate proof graph root": func(receipt *VerificationReceipt) {
			receipt.ProofGraphRoots = append(receipt.ProofGraphRoots, receipt.ProofGraphRoots[0])
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := cloneReceipt(valid)
			mutate(receipt)
			digest, err := dependencySnapshotDigest(receipt.Dependencies)
			if err != nil {
				t.Fatal(err)
			}
			receipt.DependencySnapshotDigest = digest
			if err := validateReceiptSchema(receipt); err == nil {
				t.Fatal("tampered receipt schema accepted")
			}
		})
	}
}

func TestCurrentAppraisalNeverReusesHistoricalVerifiedAfterRevocationOrStaleness(t *testing.T) {
	f := newFixture(t, ActorPerson)
	receipt := verifyFixture(t, f)
	expectation := expectationFor(f, receipt)
	tests := map[string]struct {
		mutate func(*testAppraisalResolver, *AppraisalExpectation)
		want   AppraisalStatus
	}{
		"wrong audience": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.Audience = []string{"https://other.example/client"}
		}, AppraisalInvalid},
		"wrong request binding": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.RequestBindingDigest = digestString("other-request")
		}, AppraisalInvalid},
		"wrong subject": {func(_ *testAppraisalResolver, e *AppraisalExpectation) { e.SubjectID += "-other" }, AppraisalInvalid},
		"wrong actor":   {func(_ *testAppraisalResolver, e *AppraisalExpectation) { e.ActorType = ActorAgent }, AppraisalInvalid},
		"wrong claim":   {func(_ *testAppraisalResolver, e *AppraisalExpectation) { e.ClaimID += "-other" }, AppraisalInvalid},
		"wrong predicate": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.Predicate = "other.predicate"
		}, AppraisalInvalid},
		"wrong value": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.ValueDigest = digestString("other-value")
		}, AppraisalInvalid},
		"wrong scope": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.Scope = []string{"capability:invoice.write", "jurisdiction:EU"}
		}, AppraisalInvalid},
		"wrong purpose": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.Purpose = "other purpose"
		}, AppraisalInvalid},
		"wrong transaction": {func(_ *testAppraisalResolver, e *AppraisalExpectation) { e.TransactionID += "-other" }, AppraisalInvalid},
		"wrong disclosure": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.DisclosureDigest = digestString("other-disclosure")
		}, AppraisalInvalid},
		"wrong profile": {func(_ *testAppraisalResolver, e *AppraisalExpectation) {
			e.ProfileDigest = digestString("other-profile")
		}, AppraisalInvalid},
		"revoked dependency":  {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.states["issuer_key"] = TrustRevoked }, AppraisalRevoked},
		"disputed dependency": {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.states["issuer_authority"] = TrustDisputed }, AppraisalWarning},
		"compromised signer":  {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.states["receipt_signer"] = TrustCompromised }, AppraisalWarning},
		"unknown signer":      {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.states["receipt_signer"] = TrustUnknown }, AppraisalWarning},
		"signer key substitution": {func(r *testAppraisalResolver, _ *AppraisalExpectation) {
			r.signerKey = mustSigner(t, "substitute").PublicKeyBytes()
		}, AppraisalInvalid},
		"retired profile": {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.states["assurance_profile"] = TrustRevoked }, AppraisalRevoked},
		"stale resolver":  {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.stale = true }, AppraisalWarning},
		"future signer attestation": {func(r *testAppraisalResolver, _ *AppraisalExpectation) {
			r.future["receipt_signer"] = time.Minute
		}, AppraisalWarning},
		"dependency generation changed": {func(r *testAppraisalResolver, _ *AppraisalExpectation) {
			r.generations["issuer_key"] = "generation-2"
		}, AppraisalWarning},
		"resolver outage": {func(r *testAppraisalResolver, _ *AppraisalExpectation) { r.errKind = "issuer_authority" }, AppraisalWarning},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			resolver := newAppraisalResolver(f)
			expected := expectation
			test.mutate(resolver, &expected)
			appraiser, err := NewReceiptAppraiser(resolver, f.clock.Now)
			if err != nil {
				t.Fatal(err)
			}
			appraisal := appraiser.Appraise(context.Background(), receipt, expected)
			if appraisal.Status != test.want || appraisal.CanRenderVerified() {
				t.Fatalf("appraisal = %s/%s", appraisal.Status, appraisal.ReasonCode)
			}
		})
	}
}

func TestCurrentAppraisalRejectsReceiptEvaluatedBeyondClockSkew(t *testing.T) {
	f := newFixture(t, ActorPerson)
	receipt := verifyFixture(t, f)
	resolver := newAppraisalResolver(f)
	appraisalNow := f.clock.Now().Add(-time.Minute)
	appraiser, err := NewReceiptAppraiser(resolver, func() time.Time { return appraisalNow })
	if err != nil {
		t.Fatal(err)
	}
	appraisal := appraiser.Appraise(context.Background(), receipt, expectationFor(f, receipt))
	if appraisal.Status != AppraisalWarning || appraisal.CanRenderVerified() {
		t.Fatalf("future receipt appraisal = %s/%s", appraisal.Status, appraisal.ReasonCode)
	}
}

func TestCurrentAppraisalAppliesProfileFreshnessToReceiptSigner(t *testing.T) {
	f := newFixture(t, ActorPerson)
	profile := cloneProfile(f.profile)
	profile.MaxDependencyAge = time.Minute
	replaceFixtureProfile(t, f, profile)
	receipt := verifyFixture(t, f)
	resolver := newAppraisalResolver(f)
	resolver.ages["receipt_signer"] = 5 * time.Minute
	appraiser, err := NewReceiptAppraiser(resolver, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	appraisal := appraiser.Appraise(context.Background(), receipt, expectationFor(f, receipt))
	if appraisal.Status != AppraisalWarning || appraisal.ReasonCode != "receipt_signer_stale" || appraisal.CanRenderVerified() {
		t.Fatalf("appraisal = %s/%s", appraisal.Status, appraisal.ReasonCode)
	}
}

type testAppraisalResolver struct {
	clock       func() time.Time
	profile     AssuranceProfile
	signerKey   []byte
	states      map[string]TrustState
	ages        map[string]time.Duration
	future      map[string]time.Duration
	generations map[string]string
	stale       bool
	errKind     string
}

func newAppraisalResolver(f *fixture) *testAppraisalResolver {
	return &testAppraisalResolver{
		clock: f.clock.Now, profile: f.verifier.profile, signerKey: f.receiptKey.PublicKeyBytes(),
		states: map[string]TrustState{}, ages: map[string]time.Duration{}, future: map[string]time.Duration{}, generations: map[string]string{},
	}
}

func (r *testAppraisalResolver) ResolveCurrentTrust(_ context.Context, request AppraisalBindingRequest) (CurrentTrustResult, error) {
	if request.Kind == r.errKind {
		return CurrentTrustResult{}, errors.New("resolver unavailable")
	}
	state := r.states[request.Kind]
	if state == "" {
		state = TrustActive
	}
	binding, _ := AppraisalTrustBindingDigest(request)
	now := r.clock()
	attestation := testAttestation(binding, now)
	if age := r.ages[request.Kind]; age > 0 {
		attestation.CheckedAt = now.Add(-age)
	}
	if future := r.future[request.Kind]; future > 0 {
		attestation.CheckedAt = now.Add(future)
	}
	if generation := r.generations[request.Kind]; generation != "" {
		attestation.Generation = generation
	}
	if r.stale {
		attestation.CheckedAt = now.Add(-time.Hour)
	}
	result := CurrentTrustResult{State: state, Attestation: attestation}
	switch request.Kind {
	case "receipt_signer":
		result.PublicKey, result.Algorithm = append([]byte(nil), r.signerKey...), AlgorithmEd25519
	case "assurance_profile":
		profile := cloneProfile(r.profile)
		result.Profile = &profile
	}
	return result, nil
}

func expectationFor(f *fixture, receipt *VerificationReceipt) AppraisalExpectation {
	return AppraisalExpectation{
		RequestBindingDigest: receipt.RequestBindingDigest, SubjectID: f.request.SubjectID, ActorType: f.request.ActorType,
		ClaimID: f.request.ClaimID, Predicate: f.request.Predicate, ValueDigest: f.request.ValueDigest,
		Scope: append([]string(nil), f.request.Scope...), Audience: append([]string(nil), f.request.Audience...),
		Purpose: f.request.Purpose, TransactionID: f.request.TransactionID,
		DisclosureDigest: f.request.DisclosureDigest, ProfileDigest: f.profileDigest,
	}
}
