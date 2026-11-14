package server

// The owner's passkey as the root of authority (helm-tracker#334) on the wire,
// against real PostgreSQL 16 (listed in scripts/ci/postgres-proofs.txt):
// EnsurePrincipals enrols the owner's passkey at the tenant's genesis with a
// self-signed assertion and adds no human afterwards; an approval of an
// authority widening carries the owner's own WebAuthn assertion over
// pending_approval.owner_challenge, which the gateway verifies; and with
// HELM_GATEWAY_OWNER_ASSERTION_REQUIRED on, the Control Plane's issuer alone
// widens nothing. TestPostgresIssuerAloneWidensNothingOnTheWire replays the
// mission check's self-grant probe, which on main widened a tenant's limit
// twice with issuer-minted tokens.
//
// quantum_posture: signs classical RS256 test tokens and ES256 or Ed25519 test
// assertions; no post-quantum claim.

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/passkey"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

const ownerRPID = "app.helm.example"

// ownerSpec is a human with its passkeys.
func ownerSpec(id string, keys ...*passkey.Authenticator) *gatewayv1.PrincipalSpec {
	spec := humanSpec(id, id)
	for _, k := range keys {
		spec.Credentials = append(spec.Credentials, &gatewayv1.PrincipalCredential{
			CredentialId: k.ID, Alg: int32(k.Alg), PublicKeySpki: k.SPKI, RpId: k.RPID}) // #nosec G115 -- -7 or -8
	}
	return spec
}

func wireAssertion(a passkey.Assertion) *gatewayv1.OwnerAssertion {
	return &gatewayv1.OwnerAssertion{CredentialId: a.CredentialID, AuthenticatorData: a.AuthenticatorData,
		ClientDataJson: a.ClientDataJSON, Signature: a.Signature}
}

// genesis registers a tenant's first principals with the owner's passkey and
// a genesis assertion by signer over challenge (nil: the genesis challenge).
func (w *adminWire) genesis(tenant string, signer *passkey.Authenticator, challenge []byte, specs ...*gatewayv1.PrincipalSpec) (*gatewayv1.EnsurePrincipalsResponse, error) {
	var owner string
	for _, s := range specs {
		if len(s.GetCredentials()) > 0 {
			owner = s.GetPrincipalId()
		}
	}
	if challenge == nil {
		challenge = admission.GenesisChallengeV1(tenant, owner, signer.ID)
	}
	resp, err := w.client.EnsurePrincipals(context.Background(), withToken(&gatewayv1.EnsurePrincipalsRequest{
		Principals: specs, GenesisAssertion: wireAssertion(signer.Assert(w.t, challenge)),
	}, w.token(tenant, adminRegistrar, ScopeProvision)))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// credentials counts the tenant's enrolled passkeys of kind ('genesis' or
// 'plan').
func (w *adminWire) credentials(tenant, kind string) int {
	w.t.Helper()
	var n int
	must(w.t, w.rows.InTenant(context.Background(), tenant, func(tx *authorityrows.Tx) error {
		return tx.SQL().QueryRowContext(context.Background(), `SELECT count(*) FROM authority_principal_credentials
			WHERE tenant_id = $1 AND enrolled_by = $2`, tenant, kind).Scan(&n)
	}))
	return n
}

func (w *adminWire) tenantExists(tenant string) bool {
	w.t.Helper()
	var ok bool
	must(w.t, w.rows.InTenant(context.Background(), tenant, func(tx *authorityrows.Tx) error {
		return tx.SQL().QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM authority_tenants WHERE tenant_id = $1)`, tenant).Scan(&ok)
	}))
	return ok
}

// The owner's passkey is enrolled at genesis only, by a genesis assertion that
// verifies; afterwards no human and no passkey joins through EnsurePrincipals,
// and a repeated request changes nothing.
func TestPostgresGenesisEnrolsTheOwnersPasskeyOnTheWire(t *testing.T) {
	for _, required := range []bool{false, true} {
		w := newAdminWireWith(t, required)
		owner := passkey.New(t, passkey.ES256, ownerRPID)
		stranger := passkey.New(t, passkey.EdDSA, ownerRPID)

		// Known bad first, each on a tenant the call would create: nothing is
		// created, the tenant included.
		bad := []struct {
			name   string
			call   func() error
			code   connect.Code
			reason contracts.ReasonCode
		}{
			{"a genesis assertion by another passkey", func() error {
				_, err := w.genesis("tenant-g", stranger, admission.GenesisChallengeV1("tenant-g", adminOwner, owner.ID),
					serviceSpec(adminProvision), ownerSpec(adminOwner, owner))
				return err
			}, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
			{"a genesis assertion over another challenge", func() error {
				_, err := w.genesis("tenant-g", owner, admission.GenesisChallengeV1("tenant-other", adminOwner, owner.ID),
					serviceSpec(adminProvision), ownerSpec(adminOwner, owner))
				return err
			}, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
			{"a passkey without a genesis assertion", func() error {
				_, err := w.ensure("tenant-g", serviceSpec(adminProvision), ownerSpec(adminOwner, owner))
				return err
			}, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
			{"a second human at genesis", func() error {
				_, err := w.genesis("tenant-g", owner, nil, ownerSpec(adminOwner, owner), humanSpec("usr_second", "usr_second"))
				return err
			}, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation},
			{"two passkeys at genesis", func() error {
				_, err := w.genesis("tenant-g", owner, nil, ownerSpec(adminOwner, owner, stranger))
				return err
			}, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation},
			{"a passkey on a service", func() error {
				spec := ownerSpec(adminProvision, owner)
				spec.Kind, spec.ExternalSubject = gatewayv1.PrincipalKind_PRINCIPAL_KIND_SERVICE, nil
				_, err := w.genesis("tenant-g", owner, nil, spec)
				return err
			}, connect.CodeInvalidArgument, contracts.ReasonSchemaViolation},
		}
		if required {
			bad = append(bad, struct {
				name   string
				call   func() error
				code   connect.Code
				reason contracts.ReasonCode
			}{"a genesis without a passkey owner", func() error {
				_, err := w.ensure("tenant-g", serviceSpec(adminProvision), humanSpec(adminOwner, adminOwner))
				return err
			}, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired})
		}
		for _, c := range bad {
			wantRPCError(t, c.name, c.call(), c.code, c.reason)
			if w.tenantExists("tenant-g") {
				t.Fatalf("%s: the refused genesis created the tenant", c.name)
			}
		}

		// Known good: the owner with its passkey, and the services it works
		// with, in one genesis.
		first, err := w.genesis("tenant-g", owner, nil, serviceSpec(adminProvision), serviceSpec(testActor), ownerSpec(adminOwner, owner))
		must(t, err)
		if !first.GetTenantCreated() || len(first.GetPrincipals()) != 3 || w.credentials("tenant-g", "genesis") != 1 {
			t.Fatalf("genesis = %+v, %d genesis passkeys", first, w.credentials("tenant-g", "genesis"))
		}
		// A repeated genesis request answers the same principals and enrols
		// nothing.
		again, err := w.genesis("tenant-g", owner, nil, serviceSpec(adminProvision), serviceSpec(testActor), ownerSpec(adminOwner, owner))
		must(t, err)
		if again.GetTenantCreated() || w.credentials("tenant-g", "genesis") != 1 {
			t.Fatalf("repeated genesis = %+v", again)
		}

		// On the tenant that exists: no new human, no new passkey, whatever
		// the flag; services and agents still register.
		_, err = w.ensure("tenant-g", humanSpec("usr_puppet", "usr_puppet"))
		wantRPCError(t, "a new human on a tenant that exists", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
		_, err = w.genesis("tenant-g", stranger, nil, ownerSpec(adminOwner, stranger))
		wantRPCError(t, "a new passkey for the owner", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
		_, err = w.genesis("tenant-g", stranger, nil, ownerSpec("usr_puppet", stranger))
		wantRPCError(t, "a new human with its own passkey", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
		if _, err := w.stored("tenant-g", "usr_puppet"); err == nil {
			t.Fatal("a refused request registered usr_puppet")
		}
		_, err = w.ensure("tenant-g", principal("agt:new", gatewayv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "", ""), serviceSpec("svc:new"))
		must(t, err)
		// The owner presented without its passkey: answered as it is without
		// the flag, and refused with it, where only the owner's repeated
		// genesis request presents a human.
		_, err = w.ensure("tenant-g", humanSpec(adminOwner, adminOwner))
		if required {
			wantRPCError(t, "a human on a tenant that exists, flag on", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
		} else {
			must(t, err)
		}
		if w.credentials("tenant-g", "genesis") != 1 || w.credentials("tenant-g", "plan") != 0 {
			t.Fatal("a refused request enrolled a passkey")
		}
	}
}

// approveAsOwner approves attempt as adminOwner with an assertion by signer
// over challenge (nil: the owner_challenge the owner reads on the attempt),
// and optionally an issuer-minted step-up proof.
func (w *adminWire) approveAsOwner(attempt *gatewayv1.EffectAttempt, signer *passkey.Authenticator, challenge []byte, proof bool, jti string) (*gatewayv1.EffectAttempt, error) {
	w.t.Helper()
	id, digest := attempt.GetAttemptId(), attempt.GetPendingApproval().GetApprovalDigest()
	req := &gatewayv1.ApproveRequest{AttemptId: id, ApprovalDigest: digest, Reason: "the owner approves"}
	if signer != nil {
		if challenge == nil {
			read, err := get2(w, id, w.token("tenant-a", adminOwner, ScopeRead))
			must(w.t, err)
			challenge = read.GetPendingApproval().GetOwnerChallenge()
		}
		req.OwnerAssertion = wireAssertion(signer.Assert(w.t, challenge))
	}
	if proof {
		req.StepUpProof = w.iss.token(w.t, testAudience, "tenant-a", adminOwner, ScopeStepUp, jtiOf("proof-"+jti), binding(id, digest, "webauthn"))
	}
	decide := w.iss.token(w.t, testAudience, "tenant-a", adminOwner, ScopeDecide, decision(id, "approve"), jtiOf("decide-"+jti))
	resp, err := w.effects.Approve(context.Background(), withToken(req, decide))
	if err != nil {
		return nil, err
	}
	return resp.Msg.GetAttempt(), nil
}

func (w *adminWire) proposePlan(key string, plan []byte) *gatewayv1.EffectAttempt {
	w.t.Helper()
	proposed, err := w.effects.Propose(context.Background(), withToken(&gatewayv1.ProposeRequest{
		IdempotencyKey: key, WorkRef: &gatewayv1.ProposeRequest_CommitmentId{CommitmentId: "owner-wire"},
		Effect: &gatewayv1.EffectDescriptor{EffectType: effectargs.AuthorityProvision, Target: adminOrg, Arguments: plan},
	}, w.token("tenant-a", adminProvision, ScopePropose)))
	must(w.t, err)
	a := proposed.Msg.GetAttempt()
	if a.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED {
		w.t.Fatalf("Propose = %s", a.GetState())
	}
	return a
}

func (w *adminWire) wantEscalated(what, attemptID string) {
	w.t.Helper()
	got, err := get2(w, attemptID, w.token("tenant-a", adminProvision, ScopeRead))
	must(w.t, err)
	if got.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ESCALATED || got.GetApproval() != nil {
		w.t.Fatalf("%s changed the attempt: %s", what, got.GetState())
	}
}

// Mission probe 3: the Control Plane's issuer, holding only its own signing
// key, widened a tenant with a real owner twice on main: a puppet human added
// through EnsurePrincipals approved with an issuer-minted step-up proof, then
// issuer-minted tokens for the owner's own principal id. With
// HELM_GATEWAY_OWNER_ASSERTION_REQUIRED on, neither path widens anything, and
// the owner's own passkey assertion does.
func TestPostgresIssuerAloneWidensNothingOnTheWire(t *testing.T) {
	w := newAdminWireWith(t, true)
	ctx := context.Background()
	owner := passkey.New(t, passkey.ES256, ownerRPID)
	_, err := w.genesis("tenant-a", owner, nil, serviceSpec(adminProvision), serviceSpec(testActor), ownerSpec(adminOwner, owner))
	must(t, err)

	// Step 1 of the probe: the registrar adds a person to the existing tenant.
	_, err = w.ensure("tenant-a", humanSpec("usr_puppet", "usr_puppet"))
	wantRPCError(t, "the puppet human", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)

	// Steps 2 and 5: a widening plan, approved with issuer-minted tokens for
	// the owner's principal id and no act of the owner. It stays ESCALATED.
	a := w.proposePlan("widen-1", e2ePlan(t, effectargs.AuthorityProvision, "", "v1", 1_000_000_000, 900_000_000, time.Now()))
	if len(a.GetPendingApproval().GetOwnerChallenge()) != 32 {
		t.Fatalf("pending approval = %+v", a.GetPendingApproval())
	}
	_, err = w.approveAsOwner(a, nil, nil, true, "issuer-only")
	wantRPCError(t, "an issuer-minted step-up proof alone", err, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
	w.wantEscalated("the refused approval", a.GetAttemptId())

	// The owner's own assertion over the challenge it reads widens, once.
	admitted, err := w.approveAsOwner(a, owner, nil, false, "owner-1")
	must(t, err)
	if admitted.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED ||
		string(admitted.GetApproval().GetOwnerCredentialId()) != string(owner.ID) {
		t.Fatalf("Approve = %+v", admitted)
	}
	execute := w.iss.token(t, testAudience, "tenant-a", testActor, ScopeExecute, func(c *tokenClaims) { c.Act = nil })
	dispatched, err := w.effects.Dispatch(ctx, withToken(&gatewayv1.DispatchRequest{AttemptId: a.GetAttemptId()}, execute))
	must(t, err)
	if dispatched.Msg.GetAttempt().GetOutcome() != gatewayv1.EffectOutcome_EFFECT_OUTCOME_SUCCEEDED {
		t.Fatalf("Dispatch = %+v", dispatched.Msg.GetAttempt())
	}
}

// The approval's assertion is the approver's act over exactly this attempt:
// a forged, replayed, misbound or foreign one leaves the attempt ESCALATED,
// with or without the flag; without the flag a step-up proof still works,
// and a present assertion that does not verify is refused rather than
// ignored.
func TestPostgresOwnerAssertionRefusalsOnTheWire(t *testing.T) {
	w := newAdminWireWith(t, false)
	owner := passkey.New(t, passkey.EdDSA, ownerRPID)
	other := passkey.New(t, passkey.EdDSA, ownerRPID)
	_, err := w.genesis("tenant-a", owner, nil, serviceSpec(adminProvision), serviceSpec(testActor), ownerSpec(adminOwner, owner))
	must(t, err)
	a := w.proposePlan("widen-1", e2ePlan(t, effectargs.AuthorityProvision, "", "v1", 100, 80, time.Now()))
	read, err := get2(w, a.GetAttemptId(), w.token("tenant-a", adminOwner, ScopeRead))
	must(t, err)
	challenge := read.GetPendingApproval().GetOwnerChallenge()
	if string(challenge) != string(admission.OwnerChallengeV1("tenant-a", adminOwner, a.GetAttemptId(), a.GetPendingApproval().GetApprovalDigest())) {
		t.Fatal("owner_challenge is not OwnerChallengeV1 for the reader")
	}
	// The challenge is the reader's: the provisioner reads another one.
	if string(a.GetPendingApproval().GetOwnerChallenge()) == string(challenge) {
		t.Fatal("owner_challenge does not move with the reading principal")
	}

	foreign := passkey.New(t, passkey.EdDSA, ownerRPID)
	foreign.ID = owner.ID // a key that claims the owner's credential id
	for i, c := range []struct {
		name      string
		signer    *passkey.Authenticator
		challenge []byte
	}{
		{"another key under the owner's credential id", foreign, challenge},
		{"a passkey the tenant never enrolled", other, challenge},
		{"an assertion over another attempt's challenge", owner, admission.OwnerChallengeV1("tenant-a", adminOwner, "another-attempt", a.GetPendingApproval().GetApprovalDigest())},
		{"an assertion over another approver's challenge", owner, admission.OwnerChallengeV1("tenant-a", adminProvision, a.GetAttemptId(), a.GetPendingApproval().GetApprovalDigest())},
	} {
		// A valid step-up proof rides along: a present assertion that does not
		// verify is refused, never passed over for the proof.
		_, err := w.approveAsOwner(a, c.signer, c.challenge, true, "bad-"+string(rune('a'+i)))
		wantRPCError(t, c.name, err, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
		w.wantEscalated(c.name, a.GetAttemptId())
	}
	// A replay: the owner's counter moves on, so its earlier assertion, signed
	// again for the same challenge with the old counter, is refused.
	owner.Counter += 10
	_, err = w.approveAsOwner(a, owner, challenge, false, "ahead")
	must(t, err)
	b := w.proposePlan("widen-2", e2ePlan(t, effectargs.AuthorityProvision, "", "v2", 90, 70, time.Now()))
	owner.Counter -= 5
	_, err = w.approveAsOwner(b, owner, nil, false, "behind")
	wantRPCError(t, "a counter that went backwards", err, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
	w.wantEscalated("the replay", b.GetAttemptId())
	// Without the flag, the issuer's step-up proof alone still approves.
	approved, err := w.approveAsOwner(b, nil, nil, true, "legacy")
	must(t, err)
	if approved.GetState() != gatewayv1.EffectAttemptState_EFFECT_ATTEMPT_STATE_ADMITTED || len(approved.GetApproval().GetOwnerCredentialId()) != 0 {
		t.Fatalf("legacy approval = %+v", approved)
	}
}
