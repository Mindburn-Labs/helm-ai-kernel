package server

// The owner rules of EnsurePrincipals (helm-tracker#334): humans come from the
// tenant's owner. The owner's passkey is enrolled once, at the tenant's genesis,
// with a self-signed genesis assertion the gateway verifies; every later human
// and passkey comes through a provision plan a distinct human approved.
//
// quantum_posture: verifies classical ECDSA P-256 or Ed25519 WebAuthn
// assertions (admission.VerifyAssertion); no post-quantum claim.

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel/authority/authorityrows"
	gatewayv1 "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/gen/helm/gateway/v1"
)

// adminRefusal is a refusal of an admin RPC with its Connect code and reason.
type adminRefusal struct {
	code   connect.Code
	reason contracts.ReasonCode
	err    error
}

func (r *adminRefusal) Error() string { return r.err.Error() }

func refuseAdmin(code connect.Code, reason contracts.ReasonCode, format string, args ...any) error {
	return &adminRefusal{code: code, reason: reason, err: fmt.Errorf(format, args...)}
}

// requestedPrincipal is one principal of an EnsurePrincipals request, with the
// passkeys it carries.
type requestedPrincipal struct {
	spec        authorityrows.PrincipalSpec
	credentials []effectargs.Credential
}

// genesisEnrolment is the owner's passkey a tenant's genesis enrols, verified.
type genesisEnrolment struct {
	principalID string
	credential  effectargs.Credential
	proof       provision.GenesisProof
}

// ownerGenesis applies the owner rules that read nothing but the request and
// whether the call creates the tenant. It is pure. On a tenant the call
// creates, a request that carries a passkey or a genesis assertion names
// exactly one human, the owner, with exactly one passkey, and a genesis
// assertion by that passkey over GenesisChallengeV1 of the tenant, the owner
// and the credential id, which must verify; the enrolment is returned. With
// required (HELM_GATEWAY_OWNER_ASSERTION_REQUIRED) a new tenant needs that
// owner. On a tenant that exists nothing is enrolled: a passkey there is
// accepted only as already enrolled (humanAfterGenesis), and a genesis
// assertion without one is refused.
func ownerGenesis(tenantID string, created, required bool, principals []requestedPrincipal, assertion *admission.OwnerAssertion) (*genesisEnrolment, error) {
	var humans, keyed []requestedPrincipal
	for _, p := range principals {
		if p.spec.Kind == authorityrows.PrincipalHuman {
			humans = append(humans, p)
		}
		if len(p.credentials) > 0 {
			keyed = append(keyed, p)
		}
	}
	if !created {
		if len(keyed) == 0 && assertion != nil {
			return nil, refuseAdmin(connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege,
				"the tenant exists: its genesis is over, and a passkey is enrolled through an approved provision plan")
		}
		return nil, nil
	}
	if len(keyed) == 0 && assertion == nil {
		if required {
			return nil, refuseAdmin(connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired,
				"a new tenant's genesis registers its owner, one human with one passkey and a genesis_assertion signed by it")
		}
		return nil, nil // without the requirement, humans without passkeys may still be registered
	}
	switch {
	case len(humans) != 1 || len(keyed) != 1:
		return nil, refuseAdmin(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"a genesis names exactly one human, the owner, with its passkey: later humans come through an approved provision plan")
	case len(keyed[0].credentials) != 1:
		return nil, refuseAdmin(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation,
			"the owner enrols exactly one passkey at genesis; more come through an approved provision plan")
	case assertion == nil:
		return nil, refuseAdmin(connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired,
			"the owner's passkey needs a genesis_assertion signed by it")
	}
	owner, cred := keyed[0].spec.ID, keyed[0].credentials[0]
	counter, err := admission.VerifyAssertion(cred, 0, *assertion, admission.GenesisChallengeV1(tenantID, owner, cred.ID))
	if err != nil {
		return nil, refuseAdmin(connect.CodePermissionDenied, contracts.ReasonOwnerAssertionRequired, "the genesis assertion does not verify: %v", err)
	}
	return &genesisEnrolment{principalID: owner, credential: cred, proof: provision.GenesisProof{
		AuthenticatorData: assertion.AuthenticatorData, ClientDataJSON: assertion.ClientDataJSON,
		Signature: assertion.Signature, SignCount: counter,
	}}, nil
}

// errHumanAfterGenesis refuses a human EnsurePrincipals may not register.
var errHumanAfterGenesis = errors.New("a human joins a tenant that exists only through an approved provision plan")

// presentedHuman is what the tenant's rows say of a human a request presents
// to a tenant that exists.
type presentedHuman struct {
	// registered: the tenant has the principal.
	registered bool
	// passkeys: the request carries passkeys for it; enrolled: every one is
	// enrolled for it exactly as presented; genesis: one of them is the
	// owner's genesis passkey.
	passkeys, enrolled, genesis bool
}

// humanAfterGenesis applies the owner rules that read the tenant's rows, on a
// tenant that exists. A human that is not registered is refused whatever
// required says, and so is a passkey not already enrolled exactly as
// presented: humans and passkeys come only through an approved provision plan.
// What is already there is answered as it is, so a repeated request changes
// nothing. With required, only the owner's repeated genesis request (the owner
// with its genesis passkey) presents a human at all.
func humanAfterGenesis(created, required bool, h presentedHuman) error {
	refused := func(err error) error {
		return refuseAdmin(connect.CodePermissionDenied, contracts.ReasonInsufficientPrivilege, "%v", err)
	}
	switch {
	case created:
		return nil
	case !h.registered:
		return refused(errHumanAfterGenesis)
	case h.passkeys && !h.enrolled:
		return refused(errors.New("a passkey is enrolled at genesis or through an approved provision plan, never on a tenant that exists"))
	case required && !(h.passkeys && h.enrolled && h.genesis):
		return refused(errors.New("with owner assertions required, a tenant that exists takes no human here; only its owner's repeated genesis request is answered"))
	}
	return nil
}

// requestCredentials reads a principal's passkeys from the wire: only a human
// carries them, at most effectargs.MaxPrincipalCredentials, each one a
// credential the gateway can verify with, and no credential id twice in the
// request.
func requestCredentials(p *gatewayv1.PrincipalSpec, kind authorityrows.PrincipalKind, seen map[string]bool) ([]effectargs.Credential, error) {
	in := p.GetCredentials()
	if len(in) == 0 {
		return nil, nil
	}
	bad := func(format string, args ...any) error {
		return rpcError(connect.CodeInvalidArgument, contracts.ReasonSchemaViolation, false, fmt.Errorf(format, args...))
	}
	if kind != authorityrows.PrincipalHuman {
		return nil, bad("principal %q: only a human has passkeys", p.GetPrincipalId())
	}
	if len(in) > effectargs.MaxPrincipalCredentials {
		return nil, bad("principal %q carries more than %d passkeys", p.GetPrincipalId(), effectargs.MaxPrincipalCredentials)
	}
	out := make([]effectargs.Credential, 0, len(in))
	for i, c := range in {
		cred := effectargs.Credential{ID: c.GetCredentialId(), Alg: int(c.GetAlg()), PublicKeySPKI: c.GetPublicKeySpki(), RPID: c.GetRpId()}
		if err := effectargs.CheckCredential(cred); err != nil {
			return nil, bad("principal %q credentials[%d]: %v", p.GetPrincipalId(), i, err)
		}
		if seen[string(cred.ID)] {
			return nil, bad("a credential id is listed twice")
		}
		seen[string(cred.ID)] = true
		out = append(out, cred)
	}
	return out, nil
}
