package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	_ "github.com/lib/pq"
)

// TestPostgresLifecycleSingleIssueAndConsume is the source-owned real-Postgres
// concurrency proof. It is opt-in locally and mandatory in the production
// approval gate through HELM_TEST_POSTGRES_URL.
func TestPostgresLifecycleSingleIssueAndConsume(t *testing.T) {
	postgresURL := os.Getenv("HELM_TEST_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("set HELM_TEST_POSTGRES_URL to run approval ceremony concurrency proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	schema := fmt.Sprintf("helm_approval_%d", time.Now().UnixNano())
	db := openApprovalTestPostgres(t, postgresURL, schema)
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		t.Fatalf("create approval test schema: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	}()

	fixtureHold, _, _, fixtureGrant := ceremonyFixtures(t)
	grantPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signer := crypto.NewEd25519SignerFromKey(grantPrivateKey, "approval-test")
	grantVerifier, err := NewEd25519GrantSignatureVerifier(
		signer.PublicKeyBytes(), fixtureGrant.SigningKeyRef, fixtureGrant.KernelTrustRootID,
	)
	if err != nil {
		t.Fatalf("NewEd25519GrantSignatureVerifier(): %v", err)
	}
	store := NewPostgresStore(db, grantVerifier)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("Init(): %v", err)
	}
	clockNow := fixtureHold.HoldStartedAt
	config := ServiceConfig{
		MinHoldDuration: 5 * time.Minute, ChallengeTTL: 10 * time.Minute,
		MaxChallengeLifetime: 20 * time.Minute, GrantTTL: 5 * time.Minute,
		MaxAssertions: 4, ServerIdentity: fixtureHold.Spec.ServerIdentity,
		KernelTrustRootID: fixtureGrant.KernelTrustRootID, SigningKeyRef: fixtureGrant.SigningKeyRef,
	}
	authority, approverKeys := approvalTestAuthority(fixtureHold.Spec, fixtureHold.HoldStartedAt)
	service, err := newService(
		store, staticBindingProvider{spec: fixtureHold.Spec},
		staticAuthorityProvider{store: authority},
		staticConsumerProvider{identity: consumerForSpec(fixtureHold.Spec)}, signer,
		func() time.Time { return clockNow }, cryptorand.Reader, config,
	)
	if err != nil {
		t.Fatalf("newService(): %v", err)
	}
	hold, err := service.BeginHold(ctx, requestForSpec(fixtureHold.Spec))
	if err != nil {
		t.Fatalf("BeginHold(): %v", err)
	}
	if _, err := service.IssueChallenge(ctx, hold.TenantID, hold.ApprovalID); !errors.Is(err, ErrHoldPending) {
		t.Fatalf("early IssueChallenge() error = %v, want ErrHoldPending", err)
	}
	clockNow = hold.HoldStartedAt.Add(config.MinHoldDuration)
	challenged, err := service.IssueChallenge(ctx, hold.TenantID, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge(): %v", err)
	}
	if challenged.Challenge == nil || challenged.Challenge.ExpiresAt.Sub(challenged.HoldStartedAt) > config.MaxChallengeLifetime {
		t.Fatalf("challenge lifetime exceeds source-owned ceiling: %+v", challenged.Challenge)
	}
	assertions := approvalTestAssertions(t, *challenged.Challenge, approverKeys)
	clockNow = clockNow.Add(time.Minute)
	verified, err := service.VerifyQuorum(ctx, hold.TenantID, hold.ApprovalID, assertions)
	if err != nil {
		t.Fatalf("VerifyQuorum(): %v", err)
	}
	if verified.VerifiedRef == nil || !verified.VerifiedRef.VerifiedAt.Equal(clockNow) {
		t.Fatalf("verified record = %+v", verified)
	}

	clockNow = clockNow.Add(time.Minute)
	issued := make(chan Record, 2)
	errorsCh := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, issueErr := service.IssueGrant(ctx, hold.TenantID, hold.ApprovalID)
			if issueErr != nil {
				errorsCh <- issueErr
				return
			}
			issued <- record
		}()
	}
	wg.Wait()
	close(issued)
	close(errorsCh)
	issuedRecords := collectRecords(issued)
	issueErrors := collectErrors(errorsCh)
	if len(issuedRecords) != 1 || len(issueErrors) != 1 || !errors.Is(issueErrors[0], ErrTransitionConflict) {
		t.Fatalf("concurrent issuance results = %d success, %v errors", len(issuedRecords), issueErrors)
	}
	winner := issuedRecords[0]
	if winner.State != StateGrantIssued || winner.Grant == nil {
		t.Fatalf("winning grant record = %+v", winner)
	}

	consumed := make(chan Record, 2)
	consumeErrors := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record, consumeErr := service.ConsumeGrant(
				ctx, hold.ApprovalID, winner.Grant.GrantID,
				winner.Grant.GrantHash, winner.Grant.Nonce,
			)
			if consumeErr != nil {
				consumeErrors <- consumeErr
				return
			}
			consumed <- record
		}()
	}
	wg.Wait()
	close(consumed)
	close(consumeErrors)
	consumedRecords := collectRecords(consumed)
	consumptionErrors := collectErrors(consumeErrors)
	if len(consumedRecords) != 1 || len(consumptionErrors) != 1 || !errors.Is(consumptionErrors[0], ErrTransitionConflict) {
		t.Fatalf("concurrent consumption results = %d success, %v errors", len(consumedRecords), consumptionErrors)
	}
	final := consumedRecords[0]
	if final.State != StateConsumed || final.Version != 5 || final.ConsumedAt == nil {
		t.Fatalf("final record = %+v", final)
	}
	if _, err := store.Get(ctx, "tenant-b", hold.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get() error = %v, want ErrNotFound", err)
	}

	deniedHold, err := service.BeginHold(ctx, requestForSpec(fixtureHold.Spec))
	if err != nil {
		t.Fatalf("BeginHold() for denial: %v", err)
	}
	denied, err := service.Deny(ctx, deniedHold.TenantID, deniedHold.ApprovalID)
	if err != nil || denied.State != StateDenied {
		t.Fatalf("Deny() record = %+v, error = %v", denied, err)
	}
	if _, err := service.Deny(ctx, deniedHold.TenantID, deniedHold.ApprovalID); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second Deny() error = %v, want ErrTransitionConflict", err)
	}

	tampered := issueApprovalTestGrant(t, ctx, service, fixtureHold.Spec, approverKeys, &clockNow, config)
	result, err := db.ExecContext(ctx, `UPDATE approval_ceremonies
		SET grant_signature = $1
		WHERE tenant_id = $2 AND approval_id = $3`,
		strings.Repeat("0", 128), tampered.TenantID, tampered.ApprovalID,
	)
	if err != nil {
		t.Fatalf("tamper persisted signature: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		t.Fatalf("tamper persisted signature affected %d rows, error = %v", rows, err)
	}
	if _, err := service.ConsumeGrant(
		ctx, tampered.ApprovalID, tampered.Grant.GrantID,
		tampered.Grant.GrantHash, tampered.Grant.Nonce,
	); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("ConsumeGrant() tampered signature error = %v, want ErrGrantSignatureRejected", err)
	}
	if _, err := service.Get(ctx, tampered.TenantID, tampered.ApprovalID); !errors.Is(err, ErrGrantSignatureRejected) {
		t.Fatalf("Get() tampered signature error = %v, want ErrGrantSignatureRejected", err)
	}
	var persistedState string
	var persistedConsumedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT state, consumed_at
		FROM approval_ceremonies WHERE tenant_id = $1 AND approval_id = $2`,
		tampered.TenantID, tampered.ApprovalID,
	).Scan(&persistedState, &persistedConsumedAt); err != nil {
		t.Fatalf("read tampered grant state: %v", err)
	}
	if persistedState != string(StateGrantIssued) || persistedConsumedAt.Valid {
		t.Fatalf("tampered grant changed state: state = %s, consumed = %v", persistedState, persistedConsumedAt)
	}

	expiringHold, err := service.BeginHold(ctx, requestForSpec(fixtureHold.Spec))
	if err != nil {
		t.Fatalf("BeginHold() for expiration: %v", err)
	}
	clockNow = expiringHold.HoldStartedAt.Add(config.MinHoldDuration)
	expiring, err := service.IssueChallenge(ctx, expiringHold.TenantID, expiringHold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge() for expiration: %v", err)
	}
	clockNow = expiring.Challenge.ExpiresAt
	expired, err := service.Expire(ctx, expiring.TenantID, expiring.ApprovalID)
	if err != nil || expired.State != StateExpired {
		t.Fatalf("Expire() record = %+v, error = %v", expired, err)
	}
}

func issueApprovalTestGrant(
	t *testing.T,
	ctx context.Context,
	service *Service,
	spec ChallengeSpec,
	approverKeys map[string]ed25519.PrivateKey,
	clockNow *time.Time,
	config ServiceConfig,
) Record {
	t.Helper()
	hold, err := service.BeginHold(ctx, requestForSpec(spec))
	if err != nil {
		t.Fatalf("BeginHold(): %v", err)
	}
	*clockNow = hold.HoldStartedAt.Add(config.MinHoldDuration)
	challenged, err := service.IssueChallenge(ctx, hold.TenantID, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge(): %v", err)
	}
	assertions := approvalTestAssertions(t, *challenged.Challenge, approverKeys)
	*clockNow = clockNow.Add(time.Minute)
	if _, err := service.VerifyQuorum(ctx, hold.TenantID, hold.ApprovalID, assertions); err != nil {
		t.Fatalf("VerifyQuorum(): %v", err)
	}
	*clockNow = clockNow.Add(time.Minute)
	granted, err := service.IssueGrant(ctx, hold.TenantID, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant(): %v", err)
	}
	return granted
}

type staticAuthorityProvider struct {
	store approvalverify.TrustStore
}

type staticBindingProvider struct {
	spec ChallengeSpec
}

type staticConsumerProvider struct {
	identity ConsumerIdentity
}

func (p staticConsumerProvider) LoadConsumerIdentity(context.Context) (ConsumerIdentity, error) {
	return p.identity, nil
}

func (p staticBindingProvider) LoadApprovalBinding(_ context.Context, _, _, _ string) (ChallengeSpec, error) {
	return p.spec, nil
}

func (p staticAuthorityProvider) LoadApprovalAuthority(_ context.Context, _, _, _, _, _ string) (approvalverify.TrustStore, error) {
	return p.store, nil
}

func approvalTestAuthority(spec ChallengeSpec, holdStarted time.Time) (approvalverify.TrustStore, map[string]ed25519.PrivateKey) {
	privateKeys := map[string]ed25519.PrivateKey{
		"key-a": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)),
		"key-b": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize)),
	}
	keys := make(map[string]approvalverify.TrustedApproverKey, len(privateKeys))
	for index, keyID := range []string{"key-a", "key-b"} {
		suffix := string(rune('a' + index))
		keys[keyID] = approvalverify.TrustedApproverKey{
			KeyID: keyID, TenantID: spec.TenantID, PrincipalID: "principal-" + suffix,
			CredentialID: "credential-" + suffix, DeviceID: "device-" + suffix,
			PublicKey:    privateKeys[keyID].Public().(ed25519.PublicKey),
			WorkspaceIDs: []string{spec.WorkspaceID}, Roles: []string{spec.RequiredRole},
			Actions: []string{spec.Action}, Audiences: []string{spec.Audience}, Enabled: true,
			NotBefore: holdStarted.Add(-time.Hour), NotAfter: holdStarted.Add(time.Hour),
		}
	}
	return approvalverify.TrustStore{
		AuthoritySource: spec.AuthoritySource, AuthorityVersion: spec.AuthorityVersion,
		AuthoritySnapshotHash: spec.AuthoritySnapshotHash, Keys: keys,
	}, privateKeys
}

func approvalTestAssertions(t *testing.T, challenge contracts.ApprovalChallenge, privateKeys map[string]ed25519.PrivateKey) []contracts.ApprovalAssertion {
	t.Helper()
	assertions := make([]contracts.ApprovalAssertion, 0, len(privateKeys))
	for _, keyID := range []string{"key-a", "key-b"} {
		assertion := contracts.ApprovalAssertion{
			Domain: contracts.ApprovalAssertionDomainV1, SchemaVersion: contracts.ApprovalAssertionSchemaV1,
			ContractVersion: contracts.ApprovalAssertionContractV1,
			ChallengeID:     challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash,
			KeyID: keyID, Algorithm: contracts.ApprovalAssertionEd25519,
		}
		digest, err := assertion.SigningDigest()
		if err != nil {
			t.Fatalf("ApprovalAssertion.SigningDigest(): %v", err)
		}
		assertion.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKeys[keyID], digest))
		assertions = append(assertions, assertion)
	}
	return assertions
}

func openApprovalTestPostgres(t *testing.T, rawURL, schema string) *sql.DB {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		t.Fatalf("HELM_TEST_POSTGRES_URL must be a URL-style Postgres DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatalf("open Postgres: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	return db
}

func collectRecords(channel <-chan Record) []Record {
	result := make([]Record, 0)
	for record := range channel {
		result = append(result, record)
	}
	return result
}

func collectErrors(channel <-chan error) []error {
	result := make([]error, 0)
	for err := range channel {
		result = append(result, err)
	}
	return result
}
