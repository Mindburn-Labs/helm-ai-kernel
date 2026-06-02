package extauthz

import (
	"strings"
	"testing"
	"time"
)

type fakeGatewayFixture struct {
	store  TrustStore
	now    time.Time
	opts   VerifyOptions
	ledger PermitConsumer
}

func newFakeGatewayFixture(store TrustStore, now time.Time, ledger PermitConsumer) fakeGatewayFixture {
	opts := fixtureVerifyOptions(ledger)
	return fakeGatewayFixture{
		store:  store,
		now:    now,
		opts:   opts,
		ledger: ledger,
	}
}

func (g fakeGatewayFixture) handle(req AuthorizationRequest, resp AuthorizationResponse) (Evaluation, *DispatchRecord, error) {
	if resp.Verdict == VerdictAllow {
		return EvaluateAndConsumeGatewayResponse(req, resp, g.store, g.opts, g.now)
	}
	eval, err := EvaluateGatewayResponse(req, resp, g.store, g.opts, g.now)
	return eval, nil, err
}

func TestFakeGatewayFixtureAllowsOnlyDurablePermitBackedAllow(t *testing.T) {
	req, resp, store, _, now := signedFixture(t, VerdictAllow)
	gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})

	eval, record, err := gateway.handle(req, resp)
	if err != nil {
		t.Fatalf("expected ALLOW dispatch through durable permit consumer: eval=%+v record=%+v err=%v", eval, record, err)
	}
	if !eval.DispatchAuthorized || eval.Verdict != VerdictAllow || record == nil || record.ProofState != ProofStateAuthorized {
		t.Fatalf("expected authorized dispatch, eval=%+v record=%+v", eval, record)
	}
	if record.KernelVerdictRef != resp.KernelVerdictRef || record.EffectPermitRef != resp.EffectPermitRef {
		t.Fatalf("dispatch record not bound to verdict/permit: record=%+v resp=%+v", record, resp)
	}
}

func TestFakeGatewayFixtureNoDispatchForDenyAndEscalate(t *testing.T) {
	for _, tc := range []struct {
		verdict string
		reason  string
	}{
		{verdict: VerdictDeny, reason: ReasonDenyNoDispatch},
		{verdict: VerdictEscalate, reason: ReasonEscalateNoDispatch},
	} {
		t.Run(tc.verdict, func(t *testing.T) {
			req, resp, store, _, now := signedFixture(t, tc.verdict)
			gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})

			eval, record, err := gateway.handle(req, resp)
			if err != nil {
				t.Fatalf("expected verified no-dispatch response: eval=%+v err=%v", eval, err)
			}
			if eval.DispatchAuthorized || eval.Verdict != tc.verdict || eval.ReasonCode != tc.reason || record != nil {
				t.Fatalf("expected no dispatch for %s, eval=%+v record=%+v", tc.verdict, eval, record)
			}
		})
	}
}

func TestFakeGatewayFixtureFailsClosedForMalformedMissingStaleAndUnsignedVerdicts(t *testing.T) {
	t.Run("missing kernel trust root context", func(t *testing.T) {
		req, resp, store, _, now := signedFixture(t, VerdictAllow)
		gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})
		gateway.opts.ExpectedKernelTrustRootID = ""

		assertFakeGatewayFailClosed(t, gateway, req, resp, "expected kernel trust root")
	})

	t.Run("missing policy epoch context", func(t *testing.T) {
		req, resp, store, _, now := signedFixture(t, VerdictAllow)
		gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})
		gateway.opts.ExpectedPolicyEpoch = ""

		assertFakeGatewayFailClosed(t, gateway, req, resp, "expected policy epoch")
	})

	t.Run("unavailable kernel signing key", func(t *testing.T) {
		req, resp, _, _, now := signedFixture(t, VerdictAllow)
		gateway := newFakeGatewayFixture(TrustStore{Keys: map[string]TrustedKey{}}, now, durableLedger{NewPermitLedger()})

		assertFakeGatewayFailClosed(t, gateway, req, resp, "unknown or disabled signing key")
	})

	t.Run("unsigned verdict", func(t *testing.T) {
		req, resp, store, _, now := signedFixture(t, VerdictAllow)
		resp.KernelVerdictSignature = ""
		gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})

		assertFakeGatewayFailClosed(t, gateway, req, resp, "missing response kernel_verdict_signature")
	})

	t.Run("stale policy epoch", func(t *testing.T) {
		req, resp, store, _, now := signedFixture(t, VerdictAllow)
		gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})
		gateway.opts.ExpectedPolicyEpoch = "epoch-10"

		assertFakeGatewayFailClosed(t, gateway, req, resp, "stale policy epoch")
	})

	t.Run("expired verdict", func(t *testing.T) {
		req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)
		resp.KernelVerdictExpiresAt = now.Add(-time.Second).UTC().Format(time.RFC3339Nano)
		resp = resign(t, resp, privateKey)
		gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})

		assertFakeGatewayFailClosed(t, gateway, req, resp, "stale verdict")
	})

	t.Run("cacheable allow", func(t *testing.T) {
		req, resp, store, privateKey, now := signedFixture(t, VerdictAllow)
		resp.CachePolicy = "public"
		resp = resign(t, resp, privateKey)
		gateway := newFakeGatewayFixture(store, now, durableLedger{NewPermitLedger()})

		assertFakeGatewayFailClosed(t, gateway, req, resp, "no_store")
	})

	t.Run("non durable permit consumer", func(t *testing.T) {
		req, resp, store, _, now := signedFixture(t, VerdictAllow)
		gateway := newFakeGatewayFixture(store, now, NewPermitLedger())

		assertFakeGatewayFailClosed(t, gateway, req, resp, ReasonDurablePermitStoreRequired)
	})
}

func assertFakeGatewayFailClosed(t *testing.T, gateway fakeGatewayFixture, req AuthorizationRequest, resp AuthorizationResponse, want string) {
	t.Helper()
	eval, record, err := gateway.handle(req, resp)
	if err == nil {
		t.Fatalf("expected fail-closed error containing %q, eval=%+v record=%+v", want, eval, record)
	}
	if record != nil || eval.DispatchAuthorized {
		t.Fatalf("fail-closed path must not dispatch, eval=%+v record=%+v err=%v", eval, record, err)
	}
	if !strings.Contains(err.Error(), want) && !strings.Contains(eval.ReasonCode, want) {
		t.Fatalf("expected error/reason to contain %q, eval=%+v err=%v", want, eval, err)
	}
}
