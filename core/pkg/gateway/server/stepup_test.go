package server

// quantum_posture: exercises the step-up proof's claim checks with a fake
// validator and computes SHA-256 test digests; signs nothing, and makes no
// post-quantum claim.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth/jwks"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

// The step-up proof is verified before Approve's transaction: whatever fails,
// the approval carries no proof, so admission refuses an effect that needs
// one and ignores it for one that needs none.
func TestStepUpProofIsBoundToTheApproval(t *testing.T) {
	const attempt = "0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d"
	digest := bytes.Repeat([]byte{0xab}, 32)
	hexDigest := hex.EncodeToString(digest)
	// entry is the helm_step_up entry; verified is the JSON of user_verified,
	// or "" to leave it out.
	entry := func(attemptID, approvalDigest, method, verified string) json.RawMessage {
		userVerified := ""
		if verified != "" {
			userVerified = `,"user_verified":` + verified
		}
		return json.RawMessage(`[{"type":"helm_step_up","attempt_id":"` + attemptID + `","approval_digest":"` + approvalDigest +
			`","method":"` + method + `"` + userVerified + `}]`)
	}
	issued := time.Now().Truncate(time.Second)
	// good is a fresh proof of human-b, the decide token's approver, in
	// tenant-a: issued now, valid for two minutes.
	good := func(edit ...func(*jwks.OAuthTokenClaims)) *jwks.OAuthTokenClaims {
		c := goodClaims()
		c.Scopes = []string{ScopeStepUp}
		c.RegisteredClaims.Subject = "human-b"
		c.RegisteredClaims.Issuer = "https://control-plane.test"
		c.RegisteredClaims.ID = "proof-1"
		c.RegisteredClaims.IssuedAt = jwt.NewNumericDate(issued)
		c.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(issued.Add(2 * time.Minute))
		c.AuthorizationDetails = entry(attempt, hexDigest, "webauthn", "true")
		for _, e := range edit {
			e(c)
		}
		return c
	}
	decide := Identity{
		Caller: admission.Caller{TenantID: "tenant-a", WorkspaceID: "ws-a", PrincipalID: "human-b", ActorID: testActor},
		Scope:  ScopeDecide, Issuer: "https://control-plane.test", TokenID: "decide-1",
	}
	stepUp := func(v fakeValidator, proof string) *admission.StepUp {
		return (&Authenticator{Validator: v, Actor: testActor}).stepUp(context.Background(), decide, attempt, digest, proof)
	}

	// Known good: what admission uses up is the proof's own iss, jti, scope
	// and exp, the method the entry names, and the compact token as received.
	got := stepUp(fakeValidator{claims: good()}, "a.b.c")
	if got == nil || got.Method != "webauthn" || got.Raw != "a.b.c" || got.Token.Scope != ScopeStepUp || got.Token.ID != "proof-1" ||
		got.Token.Issuer != "https://control-plane.test" || !got.Token.ExpiresAt.Equal(issued.Add(2*time.Minute)) {
		t.Fatalf("a proof bound to this approval = %+v", got)
	}
	// The longest lifetime, 300 seconds, and the longest proof kept are fine.
	if stepUp(fakeValidator{claims: good(func(c *jwks.OAuthTokenClaims) {
		c.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(issued.Add(300 * time.Second))
	})}, "a.b.c") == nil {
		t.Error("a proof of 300 seconds was refused")
	}
	if stepUp(fakeValidator{claims: good()}, strings.Repeat("a", admission.MaxStepUpProofBytes)) == nil {
		t.Error("a proof of the longest kept size was refused")
	}

	other := "0192f0c4-7a1e-7c3b-9d2a-000000000000"
	claims := func(edit func(*jwks.OAuthTokenClaims)) fakeValidator { return fakeValidator{claims: good(edit)} }
	details := func(raw json.RawMessage) func(*jwks.OAuthTokenClaims) {
		return func(c *jwks.OAuthTokenClaims) { c.AuthorizationDetails = raw }
	}
	lifetime := func(d time.Duration) func(*jwks.OAuthTokenClaims) {
		return func(c *jwks.OAuthTokenClaims) { c.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(issued.Add(d)) }
	}
	for name, test := range map[string]struct {
		validator fakeValidator
		proof     string
	}{
		"no proof":                     {fakeValidator{claims: good()}, ""},
		"an invalid token":             {fakeValidator{err: &jwks.JWKSValidationError{Kind: jwks.JWKSErrInvalidSignature}}, "a.b.c"},
		"keys unavailable":             {fakeValidator{err: &jwks.JWKSValidationError{Kind: jwks.JWKSErrFetchFailed}}, "a.b.c"},
		"longer than the record keeps": {fakeValidator{claims: good()}, strings.Repeat("a", admission.MaxStepUpProofBytes+1)},
		"a decide token":               {claims(func(c *jwks.OAuthTokenClaims) { c.Scopes = []string{ScopeDecide} }), "a.b.c"},
		"a propose token":              {claims(func(c *jwks.OAuthTokenClaims) { c.Scopes = []string{ScopePropose} }), "a.b.c"},
		"two scopes":                   {claims(func(c *jwks.OAuthTokenClaims) { c.Scopes = []string{ScopeStepUp, ScopeDecide} }), "a.b.c"},
		"two audiences": {claims(func(c *jwks.OAuthTokenClaims) {
			c.RegisteredClaims.Audience = append(c.RegisteredClaims.Audience, "helm-kernel:qa")
		}), "a.b.c"},
		"another actor":    {claims(func(c *jwks.OAuthTokenClaims) { c.Actor = "spiffe://evil" }), "a.b.c"},
		"another approver": {claims(func(c *jwks.OAuthTokenClaims) { c.RegisteredClaims.Subject = "human-c" }), "a.b.c"},
		"another tenant":   {claims(func(c *jwks.OAuthTokenClaims) { c.TenantID = "tenant-b" }), "a.b.c"},

		"no details":           {claims(details(nil)), "a.b.c"},
		"another attempt":      {claims(details(entry(other, hexDigest, "webauthn", "true"))), "a.b.c"},
		"another digest":       {claims(details(entry(attempt, hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), "webauthn", "true"))), "a.b.c"},
		"an upper-case digest": {claims(details(entry(attempt, strings.ToUpper(hexDigest), "webauthn", "true"))), "a.b.c"},
		"a base64 digest":      {claims(details(entry(attempt, "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=", "webauthn", "true"))), "a.b.c"},
		"another method":       {claims(details(entry(attempt, hexDigest, "totp", "true"))), "a.b.c"},
		"a decision entry": {claims(details(json.RawMessage(
			`[{"type":"helm_effect_decision","attempt_id":"` + attempt + `","action":"approve"}]`))), "a.b.c"},
		"two entries": {claims(func(c *jwks.OAuthTokenClaims) {
			one := string(entry(attempt, hexDigest, "webauthn", "true"))
			c.AuthorizationDetails = json.RawMessage(one[:len(one)-1] + "," + one[1:])
		}), "a.b.c"},

		// User verification is stated, and stated as boolean true.
		"user verification not stated":  {claims(details(entry(attempt, hexDigest, "webauthn", ""))), "a.b.c"},
		"user verification false":       {claims(details(entry(attempt, hexDigest, "webauthn", "false"))), "a.b.c"},
		"user verification as a string": {claims(details(entry(attempt, hexDigest, "webauthn", `"true"`))), "a.b.c"},
		"user verification as a number": {claims(details(entry(attempt, hexDigest, "webauthn", "1"))), "a.b.c"},
		"user verification null":        {claims(details(entry(attempt, hexDigest, "webauthn", "null"))), "a.b.c"},

		// Freshness: an iat, and an exp within 300 seconds after it.
		"no iat":                {claims(func(c *jwks.OAuthTokenClaims) { c.RegisteredClaims.IssuedAt = nil }), "a.b.c"},
		"a lifetime of 301 s":   {claims(lifetime(301 * time.Second)), "a.b.c"},
		"a lifetime of an hour": {claims(lifetime(time.Hour)), "a.b.c"},
		"exp equal to iat":      {claims(lifetime(0)), "a.b.c"},
		"exp before iat":        {claims(lifetime(-time.Minute)), "a.b.c"},
	} {
		if got := stepUp(test.validator, test.proof); got != nil {
			t.Errorf("%s: a proof was accepted: %+v", name, got)
		}
	}
}
