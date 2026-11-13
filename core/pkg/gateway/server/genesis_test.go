package server

// The owner rules of EnsurePrincipals (helm-tracker#334) as pure rules: who a
// genesis enrols, and which human a tenant that exists still answers. The
// wire proofs against PostgreSQL are in owner_passkey_postgres_test.go.
//
// quantum_posture: signs classical ES256 and Ed25519 test assertions; no
// post-quantum claim.

import (
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/internal/testkit/passkey"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
)

func requested(id string, kind authorityrows.PrincipalKind, keys ...*passkey.Authenticator) requestedPrincipal {
	p := requestedPrincipal{spec: authorityrows.PrincipalSpec{ID: id, Kind: kind}}
	for _, k := range keys {
		p.credentials = append(p.credentials, effectargs.Credential{ID: k.ID, Alg: k.Alg, PublicKeySPKI: k.SPKI, RPID: k.RPID})
	}
	return p
}

func genesisAssertion(t *testing.T, k *passkey.Authenticator, challenge []byte) *admission.OwnerAssertion {
	a := k.Assert(t, challenge)
	return &admission.OwnerAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}
}

func wantAdminRefusal(t *testing.T, what string, err error, code connect.Code, reason contracts.ReasonCode) {
	t.Helper()
	var r *adminRefusal
	if !errors.As(err, &r) || r.code != code || r.reason != reason {
		t.Fatalf("%s: err = %v, want %v %s", what, err, code, reason)
	}
}

func TestOwnerGenesisEnrolsExactlyTheOwnersSelfSignedPasskey(t *testing.T) {
	owner := passkey.New(t, passkey.ES256, ownerRPID)
	other := passkey.New(t, passkey.EdDSA, ownerRPID)
	service := requested("svc:helm-org", authorityrows.PrincipalService)
	good := []requestedPrincipal{service, requested("usr_owner", authorityrows.PrincipalHuman, owner)}
	challenge := admission.GenesisChallengeV1("tenant-a", "usr_owner", owner.ID)

	for _, required := range []bool{false, true} {
		g, err := ownerGenesis("tenant-a", true, required, good, genesisAssertion(t, owner, challenge))
		if err != nil || g == nil || g.principalID != "usr_owner" || string(g.credential.ID) != string(owner.ID) || g.proof.SignCount == 0 {
			t.Fatalf("required=%v: genesis = %+v, %v", required, g, err)
		}
	}
	// Without the requirement, a legacy genesis without a passkey still
	// registers; with it, a new tenant needs its passkey owner.
	legacy := []requestedPrincipal{service, requested("usr_owner", authorityrows.PrincipalHuman)}
	if g, err := ownerGenesis("tenant-a", true, false, legacy, nil); g != nil || err != nil {
		t.Fatalf("legacy genesis = %+v, %v", g, err)
	}
	_, err := ownerGenesis("tenant-a", true, true, legacy, nil)
	wantAdminRefusal(t, "a genesis without a passkey owner, required", err, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)
	_, err = ownerGenesis("tenant-a", true, true, []requestedPrincipal{service}, nil)
	wantAdminRefusal(t, "a genesis without an owner, required", err, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired)

	for name, c := range map[string]struct {
		principals []requestedPrincipal
		assertion  *admission.OwnerAssertion
		code       connect.Code
		reason     contracts.ReasonCode
	}{
		"no genesis assertion":    {good, nil, connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
		"another key's assertion": {good, genesisAssertion(t, other, challenge), connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
		"another tenant's challenge": {good, genesisAssertion(t, owner, admission.GenesisChallengeV1("tenant-b", "usr_owner", owner.ID)),
			connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
		"another owner's challenge": {good, genesisAssertion(t, owner, admission.GenesisChallengeV1("tenant-a", "usr_other", owner.ID)),
			connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
		"an approval challenge": {good, genesisAssertion(t, owner, admission.OwnerChallengeV1("tenant-a", "usr_owner", "attempt-1", make([]byte, 32))),
			connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired},
		"an assertion without a passkey": {legacy, genesisAssertion(t, owner, challenge), connect.CodeInvalidArgument, contracts.ReasonSchemaViolation},
		"a second human": {append([]requestedPrincipal{requested("usr_two", authorityrows.PrincipalHuman)}, good...), genesisAssertion(t, owner, challenge),
			connect.CodeInvalidArgument, contracts.ReasonSchemaViolation},
		"two passkeys": {[]requestedPrincipal{requested("usr_owner", authorityrows.PrincipalHuman, owner, other)}, genesisAssertion(t, owner, challenge),
			connect.CodeInvalidArgument, contracts.ReasonSchemaViolation},
	} {
		_, err := ownerGenesis("tenant-a", true, false, c.principals, c.assertion)
		wantAdminRefusal(t, name, err, c.code, c.reason)
	}
	// On a tenant that exists nothing is enrolled; an assertion alone is
	// refused.
	if g, err := ownerGenesis("tenant-a", false, true, good, genesisAssertion(t, owner, challenge)); g != nil || err != nil {
		t.Fatalf("a repeated genesis on a tenant that exists = %+v, %v", g, err)
	}
	_, err = ownerGenesis("tenant-a", false, false, legacy, genesisAssertion(t, owner, challenge))
	wantAdminRefusal(t, "an assertion on a tenant that exists", err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
}

// On a tenant that exists, no human and no passkey joins through
// EnsurePrincipals; what is there is answered as it is, and with the
// requirement only the owner's repeated genesis request presents a human.
func TestHumanAfterGenesisAddsNoHumanAndNoPasskey(t *testing.T) {
	for _, c := range []struct {
		name              string
		created, required bool
		h                 presentedHuman
		ok                bool
	}{
		{"a genesis", true, true, presentedHuman{}, true},
		{"a new human", false, false, presentedHuman{}, false},
		{"a new human, required", false, true, presentedHuman{}, false},
		{"a registered human as it is", false, false, presentedHuman{registered: true}, true},
		{"a registered human as it is, required", false, true, presentedHuman{registered: true}, false},
		{"a new passkey", false, false, presentedHuman{registered: true, passkeys: true}, false},
		{"the owner's repeated genesis", false, true, presentedHuman{registered: true, passkeys: true, enrolled: true, genesis: true}, true},
		{"a plan-enrolled passkey, required", false, true, presentedHuman{registered: true, passkeys: true, enrolled: true}, false},
		{"a plan-enrolled passkey", false, false, presentedHuman{registered: true, passkeys: true, enrolled: true}, true},
	} {
		err := humanAfterGenesis(c.created, c.required, c.h)
		if c.ok {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		wantAdminRefusal(t, c.name, err, connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege)
	}
}
