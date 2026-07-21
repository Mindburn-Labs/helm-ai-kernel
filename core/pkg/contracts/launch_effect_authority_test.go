// quantum_posture: these authorization fixtures exercise classical Ed25519
// signatures only and make no hybrid or post-quantum protection claim.
package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalceremony"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

func TestLaunchEffectAuthorizationEnvelopeVerifiesAuthorityBoundary(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
		t.Fatalf("signed launch authorization envelope rejected by schema: %v", err)
	}
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("signed launch authorization envelope rejected: %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopePreflightGrantsNoNetworkAuthority(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	var finalized atomic.Bool
	var networkStarted atomic.Bool
	ctx.FinalizeAndStartDispatch = func(
		contracts.LaunchEffectDispatchFinalization,
		func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
		func() error,
	) error {
		finalized.Store(true)
		return nil
	}
	ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error {
		networkStarted.Store(true)
		return nil
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("launch authorization preflight rejected: %v", err)
	}
	if finalized.Load() || networkStarted.Load() {
		t.Fatal("non-authorizing preflight finalized or started a connector effect")
	}
}

func TestLaunchEffectAuthorizationEnvelopeVerifiesProviderAuthorityBranches(t *testing.T) {
	for fixtureIndex := 0; fixtureIndex < 5; fixtureIndex++ {
		fixtureIndex := fixtureIndex
		fixture := launchInputFixtures()[fixtureIndex]
		t.Run(fixture.effectID, func(t *testing.T) {
			envelope, ctx, _, _, _ := launchEffectAuthorizationFixtureAt(t, fixtureIndex)
			if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
				t.Fatalf("provider authority envelope rejected: %v", err)
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsProviderAuthorityDrift(t *testing.T) {
	tests := []struct {
		name         string
		fixtureIndex int
		mutateInput  func(map[string]any)
		mutate       func(*contracts.LaunchEffectEnvelopeVerificationContext)
		expect       string
	}{
		{
			name:         "provider route resolver missing",
			fixtureIndex: 0,
			mutate: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
				ctx.ResolveRouteBinding = nil
			},
			expect: "source-owned route binding",
		},
		{
			name:         "provider certification changed",
			fixtureIndex: 0,
			mutateInput: func(input map[string]any) {
				input["provider_certification_hash"] = launchHash("f")
			},
			expect: "provider_certification_hash",
		},
		{
			name:         "commercial quote changed",
			fixtureIndex: 2,
			mutateInput: func(input map[string]any) {
				input["base_provider_cost_minor"] = 999
				input["gross_exposure_minor"] = 1199
				input["expected_cash_minor"] = 999
			},
			expect: "approval-bound route quote",
		},
		{
			name:         "provider mutation action changed",
			fixtureIndex: 0,
			mutateInput: func(input map[string]any) {
				input["provider_payload_hash"] = launchHash("f")
			},
			expect: "exact provider payload",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _, _ := launchEffectAuthorizationFixtureAtWithInputMutation(t, test.fixtureIndex, test.mutateInput)
			if test.mutate != nil {
				test.mutate(&ctx)
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("provider authority drift error = %v, want %q", err, test.expect)
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeBindsVerdictKeyToTrustRoot(t *testing.T) {
	envelope, ctx, privateKey, _ := launchArtifactAuthorizationFixture(t)
	envelope.KernelTrustRootID = "kernel-root-colliding-key-id"
	ctx.Permit.KernelTrustRootID = envelope.KernelTrustRootID
	var err error
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "verdict key") {
		t.Fatalf("colliding signer key ID under another trust root error = %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsTamperedVerdictProof(t *testing.T) {
	tests := []struct {
		name   string
		expect string
		mutate func(*contracts.LaunchEffectAuthorizationEnvelope)
	}{
		{
			name:   "verdict hash",
			expect: "verdict hash mismatch",
			mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope) {
				envelope.KernelVerdictHash = launchHash("f")
			},
		},
		{
			name:   "verdict signature",
			expect: "verdict signature verification failed",
			mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope) {
				replacement := "0"
				if strings.HasSuffix(envelope.KernelVerdictSignature, replacement) {
					replacement = "1"
				}
				envelope.KernelVerdictSignature = envelope.KernelVerdictSignature[:len(envelope.KernelVerdictSignature)-1] + replacement
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
			test.mutate(&envelope)
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("tampered %s error = %v, want %q", test.name, err, test.expect)
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsInvalidTimeWindowsAndPermitBinding(t *testing.T) {
	tests := []struct {
		name   string
		expect string
		mutate func(*contracts.LaunchEffectAuthorizationEnvelope, *contracts.LaunchEffectEnvelopeVerificationContext)
	}{
		{
			name:   "permit escapes verdict",
			expect: "permit escapes its verdict validity window",
			mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
				verdictExpiry, _ := time.Parse(time.RFC3339Nano, envelope.KernelVerdictExpiry)
				permitExpiry := verdictExpiry.Add(time.Second)
				envelope.PermitExpiry = permitExpiry.Format(time.RFC3339Nano)
				ctx.Permit.PermitExpiry = permitExpiry
			},
		},
		{
			name:   "permit TTL",
			expect: "permit lifetime exceeds the source-owned maximum",
			mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
				permitIssuedAt, _ := time.Parse(time.RFC3339Nano, envelope.PermitIssuedAt)
				permitExpiry := permitIssuedAt.Add(ctx.MaximumPermitTTL + time.Second)
				envelope.PermitExpiry = permitExpiry.Format(time.RFC3339Nano)
				ctx.Permit.PermitExpiry = permitExpiry
			},
		},
		{
			name:   "deadline exceeds permit",
			expect: "dispatch deadline exceeds permit expiry",
			mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
				permitExpiry, _ := time.Parse(time.RFC3339Nano, envelope.PermitExpiry)
				deadline := permitExpiry.Add(time.Nanosecond)
				envelope.DispatchDeadline = deadline.Format(time.RFC3339Nano)
				ctx.Permit.DispatchDeadline = deadline
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, privateKey, _ := launchArtifactAuthorizationFixture(t)
			test.mutate(&envelope, &ctx)
			resigned, err := contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(resigned, ctx); err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("invalid %s error = %v, want %q", test.name, err, test.expect)
			}
		})
	}

	t.Run("permit field mismatch", func(t *testing.T) {
		envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
		ctx.Permit.DependencySetHash = launchHash("f")
		if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "permit binding mismatch for dependency_set_hash") {
			t.Fatalf("permit field mismatch error = %v", err)
		}
	})
}

func TestLaunchEffectAuthorizationEnvelopeRejectsFenceReplay(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(contracts.LaunchEffectAuthorizationEnvelope, *contracts.LaunchEffectEnvelopeVerificationContext)
	}{
		{name: "missing source", mutate: func(_ contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = nil
		}},
		{name: "active", mutate: func(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{TenantID: envelope.TenantID, WorkspaceID: envelope.WorkspaceID, EffectiveEpoch: envelope.EmergencyFenceEpoch, Active: true}, nil
			}
		}},
		{name: "stop clear epoch", mutate: func(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{TenantID: envelope.TenantID, WorkspaceID: envelope.WorkspaceID, EffectiveEpoch: envelope.EmergencyFenceEpoch + 2}, nil
			}
		}},
		{name: "scope substitution", mutate: func(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{TenantID: envelope.TenantID, WorkspaceID: "workspace-other", EffectiveEpoch: envelope.EmergencyFenceEpoch}, nil
			}
		}},
		{name: "source unavailable", mutate: func(_ contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveEmergencyFence = func(string, string) (contracts.LaunchEmergencyFenceSnapshot, error) {
				return contracts.LaunchEmergencyFenceSnapshot{}, fmt.Errorf("fence store unavailable")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
			test.mutate(envelope, &ctx)
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
				t.Fatal("stale or unavailable emergency fence state was accepted")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeConsumesPermitOnce(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatal(err)
	}
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("single-use permit was consumed twice")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsStartWithoutPermitCAS(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	var networkStarted atomic.Bool
	ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error {
		networkStarted.Store(true)
		return nil
	}
	ctx.FinalizeAndStartDispatch = func(
		_ contracts.LaunchEffectDispatchFinalization,
		validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
		start func() error,
	) error {
		if _, err := validate(); err != nil {
			return err
		}
		// Intentionally omit both the permit CAS and durable STARTED reservation.
		return start()
	}
	err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx)
	if err == nil || !strings.Contains(err.Error(), "permit consumption or STARTED reservation not found") {
		t.Fatalf("missing permit CAS error = %v", err)
	}
	if networkStarted.Load() {
		t.Fatal("dispatch without a proven permit CAS crossed the network seam")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsDispatchByteDriftAtConnectorSeam(t *testing.T) {
	tests := []struct {
		name         string
		fixtureIndex int
		expect       string
		mutate       func(*contracts.LaunchEffectDispatchRequest)
	}{
		{
			name:         "request body",
			fixtureIndex: 5,
			expect:       "exact dispatch body",
			mutate: func(request *contracts.LaunchEffectDispatchRequest) {
				request.RequestBody[0] ^= 1
			},
		},
		{
			name:         "canonical arguments",
			fixtureIndex: 5,
			expect:       "exact dispatch arguments",
			mutate: func(request *contracts.LaunchEffectDispatchRequest) {
				request.ArgsC14N[0] ^= 1
			},
		},
		{
			name:         "provider payload",
			fixtureIndex: 0,
			expect:       "exact provider payload",
			mutate: func(request *contracts.LaunchEffectDispatchRequest) {
				request.ProviderPayload[0] ^= 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _, _ := launchEffectAuthorizationFixtureAt(t, test.fixtureIndex)
			request, err := ctx.ResolveDispatchRequest(ctx.Permit)
			if err != nil {
				t.Fatal(err)
			}
			ctx.ResolveDispatchRequest = func(contracts.LaunchEffectPermitBinding) (contracts.LaunchEffectDispatchRequest, error) {
				return request, nil
			}
			var networkStarted atomic.Bool
			ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error {
				networkStarted.Store(true)
				return nil
			}
			ctx.FinalizeAndStartDispatch = func(
				_ contracts.LaunchEffectDispatchFinalization,
				validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
				start func() error,
			) error {
				if _, err := validate(); err != nil {
					return err
				}
				test.mutate(&request)
				return start()
			}
			err = contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx)
			if err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("dispatch %s drift error = %v, want %q", test.name, err, test.expect)
			}
			if networkStarted.Load() {
				t.Fatal("changed dispatch bytes crossed the network seam")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopePassesVerifiedPrivateDispatchCopy(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	source, err := ctx.ResolveDispatchRequest(ctx.Permit)
	if err != nil {
		t.Fatal(err)
	}
	expectedBody := append([]byte(nil), source.RequestBody...)
	ctx.ResolveDispatchRequest = func(contracts.LaunchEffectPermitBinding) (contracts.LaunchEffectDispatchRequest, error) {
		return source, nil
	}
	ctx.StartDispatch = func(_ contracts.LaunchEffectPermitBinding, request contracts.LaunchEffectDispatchRequest) error {
		source.RequestBody[0] ^= 1
		if !bytes.Equal(request.RequestBody, expectedBody) {
			return fmt.Errorf("verified dispatch request aliased its mutable source buffer")
		}
		return nil
	}
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("verified private dispatch copy rejected: %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsExpiryBeforeAtomicFinalization(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	var consumed atomic.Bool
	observedAt := ctx.Now
	ctx.ResolveDispatchTime = func() (time.Time, error) { return observedAt, nil }
	ctx.FinalizeAndStartDispatch = func(
		expected contracts.LaunchEffectDispatchFinalization,
		validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
		start func() error,
	) error {
		observedAt = expected.MustStartBefore
		if _, err := validate(); err != nil {
			return err
		}
		consumed.Store(true)
		return start()
	}
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "expired before atomic dispatch finalization") {
		t.Fatalf("dispatch expiry race error = %v", err)
	}
	if consumed.Load() {
		t.Fatal("expired finalization consumed the single-use permit")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsPolicyChangeBeforeAtomicFinalization(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	var consumed atomic.Bool
	policyEpoch := envelope.PolicyEpoch
	ctx.ResolvePolicyEpoch = func(string, string) (string, error) { return policyEpoch, nil }
	ctx.FinalizeAndStartDispatch = func(
		_ contracts.LaunchEffectDispatchFinalization,
		validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
		start func() error,
	) error {
		policyEpoch = "epoch-2"
		if _, err := validate(); err != nil {
			return err
		}
		consumed.Store(true)
		return start()
	}
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "policy epoch changed before atomic dispatch finalization") {
		t.Fatalf("policy epoch race error = %v", err)
	}
	if consumed.Load() {
		t.Fatal("stale policy finalization consumed the single-use permit")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsStaleConnectorStartObservation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(contracts.LaunchEffectDispatchFinalization, *string, *time.Time)
		expect string
	}{
		{
			name: "policy changed after permit consumption",
			mutate: func(_ contracts.LaunchEffectDispatchFinalization, policyEpoch *string, _ *time.Time) {
				*policyEpoch = "epoch-2"
			},
			expect: "policy epoch changed before atomic dispatch finalization",
		},
		{
			name: "authority expired after permit consumption",
			mutate: func(expected contracts.LaunchEffectDispatchFinalization, _ *string, observedAt *time.Time) {
				*observedAt = expected.MustStartBefore
			},
			expect: "expired before atomic dispatch finalization",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
			var consumed atomic.Bool
			var networkStarted atomic.Bool
			policyEpoch := envelope.PolicyEpoch
			observedAt := ctx.Now
			ctx.ResolvePolicyEpoch = func(string, string) (string, error) { return policyEpoch, nil }
			ctx.ResolveDispatchTime = func() (time.Time, error) { return observedAt, nil }
			ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error {
				networkStarted.Store(true)
				return nil
			}
			ctx.FinalizeAndStartDispatch = func(
				expected contracts.LaunchEffectDispatchFinalization,
				validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
				start func() error,
			) error {
				if _, err := validate(); err != nil {
					return err
				}
				consumed.Store(true)
				test.mutate(expected, &policyEpoch, &observedAt)
				return start()
			}
			err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx)
			if err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("stale connector start error = %v, want %q", err, test.expect)
			}
			if !consumed.Load() {
				t.Fatal("test did not cross the permit CAS boundary")
			}
			if networkStarted.Load() {
				t.Fatal("stale connector authority crossed the network seam")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRechecksRevocableStateAtConnectorSeam(t *testing.T) {
	tests := []struct {
		name   string
		expect string
		stale  func(*contracts.LaunchEffectEnvelopeVerificationContext, *atomic.Bool)
	}{
		{
			name:   "emergency fence",
			expect: "emergency fence is active",
			stale: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext, stale *atomic.Bool) {
				resolve := ctx.ResolveEmergencyFence
				ctx.ResolveEmergencyFence = func(tenantID, workspaceID string) (contracts.LaunchEmergencyFenceSnapshot, error) {
					snapshot, err := resolve(tenantID, workspaceID)
					snapshot.Active = stale.Load()
					return snapshot, err
				}
			},
		},
		{
			name:   "approval consumption",
			expect: "resolve canonical launch approval authority",
			stale: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext, stale *atomic.Bool) {
				resolve := ctx.ResolveApprovalAuthority
				ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
					if stale.Load() {
						return contracts.LaunchEffectApprovalAuthority{}, fmt.Errorf("approval consumption revoked")
					}
					return resolve(grantRef, grantHash, consumptionRef, consumptionHash)
				}
			},
		},
		{
			name:   "dependency state",
			expect: "dependency state changed before atomic dispatch finalization",
			stale: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext, stale *atomic.Bool) {
				verify := ctx.VerifyDependencyState
				ctx.VerifyDependencyState = func(ref, hash string) error {
					if stale.Load() {
						return fmt.Errorf("predecessor receipt no longer dispatchable")
					}
					return verify(ref, hash)
				}
			},
		},
		{
			name:   "connector release",
			expect: "resolve current launch connector release",
			stale: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext, stale *atomic.Bool) {
				resolve := ctx.ResolveCurrentConnectorRelease
				ctx.ResolveCurrentConnectorRelease = func(authority contracts.ApprovalConnectorAuthority) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
					if stale.Load() {
						return contracts.ConnectorReleaseAuthorityEnvelope{}, fmt.Errorf("connector release revoked")
					}
					return resolve(authority)
				}
			},
		},
		{
			name:   "connector release signature",
			expect: "verify current launch connector release",
			stale: func(ctx *contracts.LaunchEffectEnvelopeVerificationContext, stale *atomic.Bool) {
				resolve := ctx.ResolveCurrentConnectorRelease
				ctx.ResolveCurrentConnectorRelease = func(authority contracts.ApprovalConnectorAuthority) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
					release, err := resolve(authority)
					if err == nil && stale.Load() {
						replacement := byte('0')
						if release.Signature[len(release.Signature)-1] == replacement {
							replacement = '1'
						}
						release.Signature = release.Signature[:len(release.Signature)-1] + string(replacement)
					}
					return release, err
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
			var stale atomic.Bool
			var consumed atomic.Bool
			var networkStarted atomic.Bool
			test.stale(&ctx, &stale)
			ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error {
				networkStarted.Store(true)
				return nil
			}
			ctx.FinalizeAndStartDispatch = func(
				_ contracts.LaunchEffectDispatchFinalization,
				validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
				start func() error,
			) error {
				if _, err := validate(); err != nil {
					return err
				}
				consumed.Store(true)
				stale.Store(true)
				return start()
			}
			err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx)
			if err == nil || !strings.Contains(err.Error(), test.expect) {
				t.Fatalf("revocable %s error = %v, want %q", test.name, err, test.expect)
			}
			if !consumed.Load() {
				t.Fatal("test did not cross the permit CAS boundary")
			}
			if networkStarted.Load() {
				t.Fatal("stale revocable authority crossed the network seam")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRechecksProviderCertificationAtConnectorSeam(t *testing.T) {
	envelope, ctx, _, _, routeFixture := launchEffectAuthorizationFixtureAt(t, 0)
	var consumed atomic.Bool
	var networkStarted atomic.Bool
	ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error {
		networkStarted.Store(true)
		return nil
	}
	ctx.FinalizeAndStartDispatch = func(
		_ contracts.LaunchEffectDispatchFinalization,
		validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
		start func() error,
	) error {
		if _, err := validate(); err != nil {
			return err
		}
		consumed.Store(true)
		routeFixture.resolver.current[routeFixture.certification.CertificationID] = "revoked"
		return start()
	}
	err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx)
	if err == nil || !strings.Contains(err.Error(), "provider route changed before atomic dispatch finalization") {
		t.Fatalf("revoked provider certification error = %v", err)
	}
	if !consumed.Load() {
		t.Fatal("test did not cross the permit CAS boundary")
	}
	if networkStarted.Load() {
		t.Fatal("revoked provider certification crossed the network seam")
	}
}

func TestLaunchEffectAuthorizationEnvelopeAcceptsEquivalentAtomicTimestamps(t *testing.T) {
	envelope, ctx, _, _ := launchArtifactAuthorizationFixture(t)
	var committed atomic.Bool
	observed := ctx.Permit
	zone := time.FixedZone("equivalent-instant", 0)
	observed.PermitIssuedAt = observed.PermitIssuedAt.In(zone)
	observed.PermitExpiry = observed.PermitExpiry.In(zone)
	observed.KernelVerdictIssuedAt = observed.KernelVerdictIssuedAt.In(zone)
	observed.KernelVerdictExpiry = observed.KernelVerdictExpiry.In(zone)
	observed.DispatchDeadline = observed.DispatchDeadline.In(zone)
	ctx.ResolvePermitBinding = func(string, string) (contracts.LaunchEffectPermitBinding, error) { return observed, nil }
	ctx.VerifyDispatchCommit = func(contracts.LaunchEffectDispatchFinalization, contracts.LaunchEffectDispatchFinalizationObservation) error {
		if !committed.Load() {
			return fmt.Errorf("dispatch commit missing")
		}
		return nil
	}
	ctx.StartDispatch = func(contracts.LaunchEffectPermitBinding, contracts.LaunchEffectDispatchRequest) error { return nil }
	ctx.FinalizeAndStartDispatch = func(
		_ contracts.LaunchEffectDispatchFinalization,
		validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
		start func() error,
	) error {
		if _, err := validate(); err != nil {
			return err
		}
		committed.Store(true)
		return start()
	}
	if err := contracts.StartLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("equivalent source-owned timestamps were rejected: %v", err)
	}
}

func launchArtifactAuthorizationFixture(t *testing.T) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	envelope, ctx, privateKey, publicKey, _ := launchEffectAuthorizationFixtureAt(t, 5)
	return envelope, ctx, privateKey, publicKey
}

func launchEffectAuthorizationFixtureAt(t *testing.T, fixtureIndex int) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey, launchRouteFixture) {
	t.Helper()
	return launchEffectAuthorizationFixtureAtWithInputMutation(t, fixtureIndex, nil)
}

func launchEffectAuthorizationFixtureAtWithInputMutation(t *testing.T, fixtureIndex int, mutateInput func(map[string]any)) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey, launchRouteFixture) {
	t.Helper()
	fixture := launchInputFixtures()[fixtureIndex]
	input := cloneLaunchInput(t, fixture.input)
	contract := contracts.LookupLaunchMissionEffectPreview(fixture.effectID)
	if contract == nil {
		t.Fatalf("missing launch effect contract for %s", fixture.effectID)
	}
	var routeFixture launchRouteFixture
	if launchTestEffectRequiresProviderRoute(fixture.effectID) {
		profile := launchProviderProfile(
			"digitalocean",
			contracts.LaunchConnectorDigitalOcean,
			"fra",
			"app-platform",
			[]string{"http_service", "static_site"},
			[]string{"health-check", "https-endpoint", "stateless-runtime"},
			[]string{contracts.LaunchLifecycleEphemeral},
			"digitalocean",
		)
		profile.Actions[0].ActionURN = contracts.LaunchProviderActionDigitalOceanActivate
		profile.Actions[1].ActionURN = contracts.LaunchProviderActionDigitalOceanProvision
		profile.Actions[2].ActionURN = contracts.LaunchProviderActionDigitalOceanRollback
		profile.Actions[3].ActionURN = contracts.LaunchProviderActionDigitalOceanTeardown
		routeFixture = singleLaunchRouteFixture(t, profile, true)
		bindLaunchInputToRoute(t, input, fixture.effectID, routeFixture)
	}
	if mutateInput != nil {
		mutateInput(input)
	}
	effectHash, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, input)
	if err != nil {
		t.Fatal(err)
	}
	now := launchRoutingNow
	verdictIssuedAt := now.Add(-time.Minute)
	verdictExpiry := now.Add(2 * time.Minute)
	permitIssuedAt := now
	permitExpiry := now.Add(45 * time.Second)
	dispatchDeadline := now.Add(40 * time.Second)
	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "protocols", "json-schemas", filepath.FromSlash(fixture.schema)))
	if err != nil {
		t.Fatal(err)
	}
	principal := "spiffe://helm/data-plane-1"
	audience := "launch.dispatch"
	trustRootID := "kernel-root-1"
	authority, consumptionRef := launchApprovalAuthority(t, fixture.effectID, input, effectHash, now, principal, audience, trustRootID)
	dispatchRequest := contracts.LaunchEffectDispatchRequest{
		RequestBody: []byte(`{"effect_id":"` + fixture.effectID + `","mission_id":"mission-1"}`),
		ArgsC14N:    []byte(`{"effect_id":"` + fixture.effectID + `","workspace_id":"workspace-1"}`),
	}
	if launchTestProviderMutation(fixture.effectID) {
		dispatchRequest.ProviderPayload = launchProviderPayloadFixture(fixture.effectID)
	}
	expectedProviderPayloadHash := ""
	if len(dispatchRequest.ProviderPayload) != 0 {
		expectedProviderPayloadHash = canonicalize.ComputeArtifactHash(dispatchRequest.ProviderPayload)
	}
	envelope := contracts.LaunchEffectAuthorizationEnvelope{
		SchemaVersion:           contracts.LaunchEffectEnvelopeSchemaVersion,
		EffectID:                fixture.effectID,
		TenantID:                "tenant-1",
		WorkspaceID:             "workspace-1",
		MissionID:               "mission-1",
		Principal:               principal,
		Audience:                audience,
		KernelTrustRootID:       trustRootID,
		EffectOrdinal:           input["effect_ordinal"].(int),
		InputSchemaRef:          fixture.schema,
		InputSchemaHash:         canonicalize.ComputeArtifactHash(schemaBytes),
		Input:                   input,
		InputHash:               effectHash,
		IdempotencyKey:          effectHash,
		PlanHash:                input["plan_hash"].(string),
		ApprovalArtifactRef:     authority.Grant.GrantID,
		ApprovalArtifactHash:    authority.Grant.GrantHash,
		ApprovalConsumptionRef:  consumptionRef,
		ApprovalConsumptionHash: authority.Consumption.ConsumptionHash,
		DispatchAdmissionRef:    authority.DispatchAdmission.AdmissionID,
		DispatchAdmissionHash:   authority.DispatchAdmission.AdmissionHash,
		DependencySetRef:        fmt.Sprintf("dependency-set-%d", input["effect_ordinal"].(int)),
		DependencySetHash:       launchHash("7"),
		PolicyEpoch:             "epoch-1",
		EmergencyFenceEpoch:     4,
		Verdict:                 "ALLOW",
		KernelVerdictRef:        "verdict-1",
		KernelVerdictIssuedAt:   verdictIssuedAt.Format(time.RFC3339Nano),
		KernelVerdictExpiry:     verdictExpiry.Format(time.RFC3339Nano),
		KernelVerdictSignerKey:  "kernel-key-1",
		EffectPermitRef:         "permit-1",
		EffectPermitHash:        launchHash("0"),
		PermitNonce:             "0123456789abcdefABCDEF",
		PermitIssuedAt:          permitIssuedAt.Format(time.RFC3339Nano),
		PermitExpiry:            permitExpiry.Format(time.RFC3339Nano),
		ProofSessionRef:         "proof-session-1",
		EvidenceReservationRef:  "evidence-reservation-1",
		ConnectorID:             contract.ConnectorID,
		ConnectorContractHash:   input["connector_contract_hash"].(string),
		ConnectorAuthorityRef:   authority.Grant.ConnectorAuthority.BindingRef,
		ConnectorAuthorityHash:  authority.Grant.ConnectorAuthority.AuthorityHash,
		ActionURN:               contract.ActionURN,
		RequestBodyHash:         canonicalize.ComputeArtifactHash(dispatchRequest.RequestBody),
		ArgsC14NHash:            canonicalize.ComputeArtifactHash(dispatchRequest.ArgsC14N),
		DispatchDeadline:        dispatchDeadline.Format(time.RFC3339Nano),
		ReplayHint:              "single_use_permit",
	}
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := launchPermitBinding(envelope, permitIssuedAt, permitExpiry, verdictIssuedAt, verdictExpiry, dispatchDeadline)
	var consumed atomic.Bool
	approvalPrivateKey := launchApprovalPrivateKey()
	approvalVerifier, err := approvalceremony.NewEd25519GrantSignatureVerifier(approvalPrivateKey.Public().(ed25519.PublicKey), "approval-key-1", trustRootID)
	if err != nil {
		t.Fatal(err)
	}
	releasePublicKey, releasePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	currentRelease := launchCurrentConnectorReleaseFixture(t, authority.Grant.ConnectorAuthority, now, releasePrivateKey)
	releaseVerifier, err := connectorregistry.NewEd25519ReleaseAuthorityVerifier(
		currentRelease.Authority.AuthorityID,
		[]connectorregistry.TrustedReleaseAuthorityKey{{
			AuthorityID: currentRelease.Authority.AuthorityID, SigningKeyRef: currentRelease.Authority.SigningKeyRef,
			PublicKey: releasePublicKey, Enabled: true, NotBefore: now.Add(-10 * time.Minute), NotAfter: now.Add(10 * time.Minute),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := contracts.LaunchEffectEnvelopeVerificationContext{
		Now: now,
		ResolveInputSchema: func(schemaRef string) ([]byte, error) {
			if schemaRef != envelope.InputSchemaRef {
				return nil, fmt.Errorf("unknown schema reference")
			}
			return append([]byte(nil), schemaBytes...), nil
		},
		ValidateInput: func(schemaRef, schemaHash string, candidate map[string]any) error {
			if schemaRef != envelope.InputSchemaRef || schemaHash != envelope.InputSchemaHash {
				return fmt.Errorf("unexpected schema identity")
			}
			return compileSchema(t, schemaRef).Validate(candidate)
		},
		ResolveApprovalAuthority: func(grantRef, grantHash, candidateConsumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
			if grantRef != authority.Grant.GrantID || grantHash != authority.Grant.GrantHash || candidateConsumptionRef != consumptionRef || consumptionHash != authority.Consumption.ConsumptionHash {
				return contracts.LaunchEffectApprovalAuthority{}, fmt.Errorf("approval authority not found")
			}
			return authority, nil
		},
		VerifyApprovalAuthority: func(candidate contracts.LaunchEffectApprovalAuthority) error {
			if err := approvalVerifier.VerifyGrantSignature(candidate.Grant, candidate.GrantSignatureAlgorithm, candidate.GrantSignature); err != nil {
				return err
			}
			if err := approvalVerifier.VerifyGrantConsumptionSignature(candidate.Consumption, candidate.ConsumptionSignatureAlgorithm, candidate.ConsumptionSignature); err != nil {
				return err
			}
			return approvalVerifier.VerifyDispatchAdmissionSignature(candidate.DispatchAdmission, candidate.DispatchSignatureAlgorithm, candidate.DispatchSignature)
		},
		VerifyDependencyState: func(ref, hash string) error {
			if ref != envelope.DependencySetRef || hash != envelope.DependencySetHash {
				return fmt.Errorf("dependency set mismatch")
			}
			return nil
		},
		ExpectedPolicyEpoch: envelope.PolicyEpoch,
		MaximumPermitTTL:    45 * time.Second,
		ResolveVerdictKey: func(kernelTrustRootID, signerKeyID string) (ed25519.PublicKey, error) {
			if kernelTrustRootID != trustRootID || signerKeyID != envelope.KernelVerdictSignerKey {
				return nil, fmt.Errorf("unknown verdict signer key")
			}
			return publicKey, nil
		},
		ResolveEmergencyFence: func(tenantID, workspaceID string) (contracts.LaunchEmergencyFenceSnapshot, error) {
			return contracts.LaunchEmergencyFenceSnapshot{TenantID: tenantID, WorkspaceID: workspaceID, EffectiveEpoch: envelope.EmergencyFenceEpoch}, nil
		},
		ResolveDispatchTime: func() (time.Time, error) { return now, nil },
		ResolvePermitBinding: func(effectPermitRef, effectPermitHash string) (contracts.LaunchEffectPermitBinding, error) {
			if effectPermitRef != permit.EffectPermitRef || effectPermitHash != permit.EffectPermitHash {
				return contracts.LaunchEffectPermitBinding{}, fmt.Errorf("permit binding not found")
			}
			return permit, nil
		},
		ResolveDispatchRequest: func(expected contracts.LaunchEffectPermitBinding) (contracts.LaunchEffectDispatchRequest, error) {
			if expected.EffectPermitRef != permit.EffectPermitRef || expected.EffectPermitHash != permit.EffectPermitHash {
				return contracts.LaunchEffectDispatchRequest{}, fmt.Errorf("dispatch request permit binding mismatch")
			}
			return dispatchRequest, nil
		},
		ResolvePolicyEpoch: func(tenantID, workspaceID string) (string, error) {
			if tenantID != envelope.TenantID || workspaceID != envelope.WorkspaceID {
				return "", fmt.Errorf("policy scope not found")
			}
			return envelope.PolicyEpoch, nil
		},
		ResolveCurrentConnectorRelease: func(candidate contracts.ApprovalConnectorAuthority) (contracts.ConnectorReleaseAuthorityEnvelope, error) {
			if candidate.AuthorityHash != authority.Grant.ConnectorAuthority.AuthorityHash {
				return contracts.ConnectorReleaseAuthorityEnvelope{}, fmt.Errorf("connector release not found")
			}
			return currentRelease, nil
		},
		VerifyCurrentConnectorRelease: func(release contracts.ConnectorReleaseAuthorityEnvelope, observedAt time.Time) error {
			return releaseVerifier.VerifyCurrentCertifiedAt(release, observedAt)
		},
		VerifyDispatchCommit: func(expected contracts.LaunchEffectDispatchFinalization, observation contracts.LaunchEffectDispatchFinalizationObservation) error {
			if !consumed.Load() {
				return fmt.Errorf("permit consumption or STARTED reservation not found")
			}
			if expected.Permit != permit || observation.ObservedAuthority != permit || observation.ObservedAt.Before(now) {
				return fmt.Errorf("dispatch commit binding mismatch")
			}
			if observation.RequestBodyHash != permit.RequestBodyHash || observation.ArgsC14NHash != permit.ArgsC14NHash || observation.ProviderPayloadHash != expectedProviderPayloadHash {
				return fmt.Errorf("dispatch commit payload binding mismatch")
			}
			return nil
		},
		FinalizeAndStartDispatch: func(
			expected contracts.LaunchEffectDispatchFinalization,
			validate func() (contracts.LaunchEffectDispatchFinalizationObservation, error),
			start func() error,
		) error {
			if expected.Permit != permit {
				return fmt.Errorf("permit compare-and-swap binding mismatch")
			}
			if !now.Before(expected.MustStartBefore) {
				return fmt.Errorf("dispatch authority expired")
			}
			observation, err := validate()
			if err != nil {
				return err
			}
			if observation.ObservedAuthority != permit || !observation.ObservedAt.Equal(now) {
				return fmt.Errorf("source-owned validation observation mismatch")
			}
			if !consumed.CompareAndSwap(false, true) {
				return fmt.Errorf("permit already consumed")
			}
			return start()
		},
		StartDispatch: func(expected contracts.LaunchEffectPermitBinding, request contracts.LaunchEffectDispatchRequest) error {
			if expected != permit {
				return fmt.Errorf("connector start permit binding mismatch")
			}
			if !bytes.Equal(request.RequestBody, dispatchRequest.RequestBody) || !bytes.Equal(request.ArgsC14N, dispatchRequest.ArgsC14N) || !bytes.Equal(request.ProviderPayload, dispatchRequest.ProviderPayload) {
				return fmt.Errorf("connector start dispatch bytes mismatch")
			}
			return nil
		},
		Permit: permit,
	}
	if launchTestEffectRequiresProviderRoute(fixture.effectID) {
		ctx.ResolveRouteBinding = func(routeRef string) (contracts.LaunchRouteBinding, error) {
			if routeRef != routeFixture.route.RouteID {
				return contracts.LaunchRouteBinding{}, fmt.Errorf("route not found")
			}
			return routeFixture.route, nil
		}
		ctx.RouteArtifacts = routeFixture.resolver
	}
	return envelope, ctx, privateKey, publicKey, routeFixture
}

func launchPermitBinding(envelope contracts.LaunchEffectAuthorizationEnvelope, issuedAt, expiry, verdictIssuedAt, verdictExpiry, deadline time.Time) contracts.LaunchEffectPermitBinding {
	return contracts.LaunchEffectPermitBinding{
		EffectPermitRef: envelope.EffectPermitRef, EffectPermitHash: envelope.EffectPermitHash, PermitNonce: envelope.PermitNonce,
		ProofSessionRef: envelope.ProofSessionRef, EvidenceReservationRef: envelope.EvidenceReservationRef,
		PermitIssuedAt: issuedAt, PermitExpiry: expiry, KernelVerdictRef: envelope.KernelVerdictRef, KernelVerdictHash: envelope.KernelVerdictHash,
		KernelVerdictIssuedAt: verdictIssuedAt, KernelVerdictExpiry: verdictExpiry,
		EffectID: envelope.EffectID, TenantID: envelope.TenantID, WorkspaceID: envelope.WorkspaceID, MissionID: envelope.MissionID,
		Principal: envelope.Principal, Audience: envelope.Audience, KernelTrustRootID: envelope.KernelTrustRootID, EffectOrdinal: envelope.EffectOrdinal,
		InputSchemaHash: envelope.InputSchemaHash, InputHash: envelope.InputHash, IdempotencyKey: envelope.IdempotencyKey, PlanHash: envelope.PlanHash,
		ApprovalArtifactRef: envelope.ApprovalArtifactRef, ApprovalArtifactHash: envelope.ApprovalArtifactHash,
		ApprovalConsumptionRef: envelope.ApprovalConsumptionRef, ApprovalConsumptionHash: envelope.ApprovalConsumptionHash,
		DispatchAdmissionRef: envelope.DispatchAdmissionRef, DispatchAdmissionHash: envelope.DispatchAdmissionHash,
		DependencySetRef: envelope.DependencySetRef, DependencySetHash: envelope.DependencySetHash,
		ConnectorID: envelope.ConnectorID, ConnectorContractHash: envelope.ConnectorContractHash,
		ConnectorAuthorityRef: envelope.ConnectorAuthorityRef, ConnectorAuthorityHash: envelope.ConnectorAuthorityHash,
		ActionURN: envelope.ActionURN, RequestBodyHash: envelope.RequestBodyHash, ArgsC14NHash: envelope.ArgsC14NHash,
		PolicyEpoch: envelope.PolicyEpoch, EmergencyFenceEpoch: envelope.EmergencyFenceEpoch, DispatchDeadline: deadline, SingleUse: true,
	}
}

func launchApprovalAuthority(t *testing.T, effectID string, input map[string]any, effectHash string, now time.Time, principal, audience, trustRootID string) (contracts.LaunchEffectApprovalAuthority, string) {
	t.Helper()
	planHash := input["plan_hash"].(string)
	policyHash := launchHash("6")
	action := launchTestApprovalAction(effectID)
	contract := contracts.LookupLaunchMissionEffectPreview(effectID)
	if contract == nil {
		t.Fatalf("missing launch effect contract for %s", effectID)
	}
	connectorID := contract.ConnectorID
	connectorAction := contract.ActionURN
	certificationRef := "cert:launch-internal-connector"
	certificationHash := launchHash("8")
	if launchTestProviderMutation(effectID) {
		var ok bool
		connectorID, ok = input["provider_connector_id"].(string)
		if !ok || connectorID == "" {
			t.Fatal("provider mutation fixture has no provider connector ID")
		}
		connectorAction, ok = input["provider_action_urn"].(string)
		if !ok || connectorAction == "" {
			t.Fatal("provider mutation fixture has no provider action")
		}
		certificationRef, ok = input["provider_certification_ref"].(string)
		if !ok || certificationRef == "" {
			t.Fatal("provider mutation fixture has no provider certification ref")
		}
		certificationHash, ok = input["provider_certification_hash"].(string)
		if !ok || certificationHash == "" {
			t.Fatal("provider mutation fixture has no provider certification hash")
		}
	}
	release := launchConnectorReleaseFixture(t, effectID, connectorID, certificationRef, certificationHash, now)
	connectorAuthority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion: contracts.ApprovalConnectorAuthoritySchemaV1, ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State: contracts.ApprovalConnectorAuthorityStateV1, BindingRef: "launch-connector-authority-" + effectID,
		TenantID: "tenant-1", WorkspaceID: "workspace-1", PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion,
		PackManifestHash: planHash, Action: action, ConnectorAction: connectorAction, EffectHash: effectHash, PolicyHash: policyHash,
		ConnectorID: release.ConnectorID, ConnectorVersion: release.ConnectorVersion, ReleaseScopeKind: release.ScopeKind,
		ReleaseAuthorityID: release.AuthorityID, ReleaseRegistryRevision: release.RegistryRevision, ReleaseAuthorityHash: release.AuthorityHash,
		ConnectorExecutorKind: release.ConnectorExecutorKind, ConnectorBinaryHash: release.ConnectorBinaryHash, ConnectorSignatureRef: release.ConnectorSignatureRef,
		ConnectorSignatureHash: release.ConnectorSignatureHash, ConnectorSignerID: release.ConnectorSignerID, ConnectorSandboxProfile: release.ConnectorSandboxProfile,
		ConnectorDriftPolicyRef: release.ConnectorDriftPolicyRef, CertificationRef: release.CertificationRef,
		CertificationHash: release.CertificationHash, CertificationAuthority: release.CertificationAuthority,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := (contracts.ApprovalGrant{
		SchemaVersion: contracts.ApprovalGrantSchemaV1, ContractVersion: contracts.ApprovalGrantContractV1,
		GrantID: "launch-grant-" + effectID, TenantID: "tenant-1", WorkspaceID: "workspace-1", Audience: audience,
		PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion, PackManifestHash: planHash,
		Action: action, ConnectorAuthority: connectorAuthority,
		IntentHash: planHash, EffectHash: effectHash, PlanHash: planHash, Decision: contracts.ApprovalGrantDecisionAllow,
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", PolicyHash: policyHash,
		ApprovalID: "launch-approval-" + effectID, CeremonyHash: launchHash("5"), SignerSetHash: launchHash("4"),
		ServerIdentity: "spiffe://helm/control-plane-1", KernelTrustRootID: trustRootID, SigningKeyRef: "approval-key-1",
		IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(6 * time.Minute), Nonce: strings.Repeat("1", 64),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	consumption, err := (contracts.ApprovalGrantConsumption{
		SchemaVersion: contracts.ApprovalGrantConsumptionSchemaV1, ContractVersion: contracts.ApprovalGrantConsumptionContractV1,
		ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, ConsumedBy: principal,
		PackID: grant.PackID, PackVersion: grant.PackVersion, PackManifestHash: grant.PackManifestHash,
		Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority, IntentHash: grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
		PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: now.Add(-30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion: contracts.ApprovalDispatchAdmissionSchemaV1, ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage: contracts.ApprovalDispatchAdmissionCoverageV1, AdmissionID: "launch-dispatch-" + effectID, AttemptID: "permit-1",
		State: contracts.ApprovalDispatchAdmissionStateV1, ApprovalID: grant.ApprovalID, GrantID: grant.GrantID,
		GrantHash: grant.GrantHash, ConsumptionHash: consumption.ConsumptionHash, TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID,
		Audience: grant.Audience, AdmittedBy: principal, IdempotencyKeyHash: effectHash, EffectHash: effectHash,
		Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority, KernelTrustRootID: trustRootID, SigningKeyRef: grant.SigningKeyRef,
		IssuedAt: now.Add(-15 * time.Second), ExpiresAt: now.Add(45 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := launchApprovalPrivateKey()
	grantPayload, err := approvalceremony.ApprovalGrantSigningPayload(grant, approvalceremony.GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	consumptionPayload, err := approvalceremony.ApprovalGrantConsumptionSigningPayload(consumption, approvalceremony.GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	admissionPayload, err := approvalceremony.ApprovalDispatchAdmissionSigningPayload(admission, approvalceremony.GrantSignatureEd25519)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.LaunchEffectApprovalAuthority{
		Grant: grant, GrantSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, GrantSignature: hex.EncodeToString(ed25519.Sign(privateKey, grantPayload)),
		Consumption: consumption, ConsumptionSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, ConsumptionSignature: hex.EncodeToString(ed25519.Sign(privateKey, consumptionPayload)),
		DispatchAdmission: admission, DispatchSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, DispatchSignature: hex.EncodeToString(ed25519.Sign(privateKey, admissionPayload)),
	}, "approval-consumption:" + grant.GrantID
}

func launchConnectorReleaseFixture(t *testing.T, effectID, connectorID, certificationRef, certificationHash string, now time.Time) contracts.ConnectorReleaseAuthority {
	t.Helper()
	validUntil := now.Add(10 * time.Minute)
	release, err := (contracts.ConnectorReleaseAuthority{
		SchemaVersion: contracts.ConnectorReleaseAuthoritySchemaV1, ContractVersion: contracts.ConnectorReleaseAuthorityContractV1,
		AuthorityID: "launch-release-authority-" + effectID, SigningKeyRef: "connector-release-key-1",
		Algorithm: contracts.ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: 1,
		ScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal, ConnectorID: connectorID, ConnectorVersion: "1.0.0",
		State: contracts.ConnectorReleaseAuthorityStateCertified, ConnectorExecutorKind: "digital",
		ConnectorSandboxProfile: "launch-provider-route-v1", ConnectorDriftPolicyRef: "policy://launch/connector-drift/v1",
		ConnectorBinaryHash: launchHash("a"), ConnectorSignatureRef: "sigstore://launch/connector/1.0.0",
		ConnectorSignatureHash: launchHash("b"), ConnectorSignerID: "mindburn-release",
		CertificationRef: certificationRef, CertificationHash: certificationHash,
		CertificationAuthority: "spiffe://helm/certification-service",
		SignedAt:               now.Add(-5 * time.Minute), ValidFrom: now.Add(-5 * time.Minute), ValidUntil: &validUntil,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func launchCurrentConnectorReleaseFixture(t *testing.T, authority contracts.ApprovalConnectorAuthority, now time.Time, privateKey ed25519.PrivateKey) contracts.ConnectorReleaseAuthorityEnvelope {
	t.Helper()
	validUntil := now.Add(10 * time.Minute)
	release, err := (contracts.ConnectorReleaseAuthority{
		SchemaVersion: contracts.ConnectorReleaseAuthoritySchemaV1, ContractVersion: contracts.ConnectorReleaseAuthorityContractV1,
		AuthorityID: authority.ReleaseAuthorityID, SigningKeyRef: "connector-release-key-1",
		Algorithm: contracts.ConnectorReleaseAuthorityAlgorithmV1, RegistryRevision: authority.ReleaseRegistryRevision,
		ScopeKind: authority.ReleaseScopeKind, ConnectorID: authority.ConnectorID, ConnectorVersion: authority.ConnectorVersion,
		State: contracts.ConnectorReleaseAuthorityStateCertified, ConnectorExecutorKind: authority.ConnectorExecutorKind,
		ConnectorSandboxProfile: authority.ConnectorSandboxProfile, ConnectorDriftPolicyRef: authority.ConnectorDriftPolicyRef,
		ConnectorBinaryHash: authority.ConnectorBinaryHash, ConnectorSignatureRef: authority.ConnectorSignatureRef,
		ConnectorSignatureHash: authority.ConnectorSignatureHash, ConnectorSignerID: authority.ConnectorSignerID,
		CertificationRef: authority.CertificationRef, CertificationHash: authority.CertificationHash,
		CertificationAuthority: authority.CertificationAuthority,
		SignedAt:               now.Add(-5 * time.Minute), ValidFrom: now.Add(-5 * time.Minute), ValidUntil: &validUntil,
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	if release.AuthorityHash != authority.ReleaseAuthorityHash {
		t.Fatalf("connector release fixture hash = %s, approval binds %s", release.AuthorityHash, authority.ReleaseAuthorityHash)
	}
	payload, err := connectorregistry.ConnectorReleaseAuthoritySigningPayload(release)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.ConnectorReleaseAuthorityEnvelope{Authority: release, Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload))}
}

func bindLaunchInputToRoute(t *testing.T, input map[string]any, effectID string, fixture launchRouteFixture) {
	t.Helper()
	placement := fixture.route.Placements[0]
	placementCost := fixture.quote.PlacementCosts[0]
	routeHash, err := contracts.DeriveLaunchRouteBindingHash(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]any{
		"provider":                         placement.ProviderID,
		"provider_account_ref":             placement.ProviderAccountRef,
		"provider_account_hash":            placement.ProviderAccountHash,
		"region":                           placement.RegionID,
		"jurisdiction":                     placement.Jurisdiction,
		"route_binding_ref":                fixture.route.RouteID,
		"route_binding_hash":               routeHash,
		"route_placement_id":               placement.PlacementID,
		"provider_capability_profile_ref":  placement.ProviderProfileRef,
		"provider_capability_profile_hash": placement.ProviderProfileHash,
		"provider_certification_ref":       placement.ProviderCertificationRef,
		"provider_certification_hash":      placement.ProviderCertificationHash,
		"provider_connector_id":            placement.ProviderConnectorID,
		"provider_connector_contract_hash": placement.ProviderConnectorContractHash,
		"repository_analysis_ref":          fixture.route.RepositoryAnalysisRef,
		"repository_analysis_hash":         fixture.route.RepositoryAnalysisHash,
		"workload_graph_ref":               fixture.route.WorkloadGraphRef,
		"workload_graph_hash":              fixture.route.WorkloadGraphHash,
		"resource_graph_ref":               fixture.route.ResourceGraphRef,
		"resource_graph_hash":              fixture.route.ResourceGraphHash,
		"route_quote_ref":                  fixture.route.RouteQuoteRef,
		"route_quote_hash":                 fixture.route.RouteQuoteHash,
		"quote_hash":                       fixture.route.RouteQuoteHash,
		"constraint_set_hash":              fixture.route.ConstraintSetHash,
		"generated_spec_hash":              fixture.route.GeneratedSpecHash,
		"gross_cap_minor":                  fixture.constraints.MaximumGrossMinor,
		"base_provider_cost_minor":         placementCost.BaseCostMinor,
		"tax_fx_reserve_minor":             placementCost.TaxFXReserveMinor,
		"gross_exposure_minor":             placementCost.GrossExposureMinor,
		"verified_credit_minor":            placementCost.VerifiedCreditMinor,
		"expected_cash_minor":              placementCost.ExpectedCashMinor,
		"currency":                         fixture.quote.Currency,
		"gross_cap_currency":               fixture.constraints.MaximumGrossCurrency,
		"credit_status":                    placementCost.CreditStatus,
		"price_snapshot_hash":              placementCost.PriceEvidenceHash,
		"provider_terms_profile_hash":      placementCost.TermsEvidenceHash,
		"credit_snapshot_hash":             placementCost.OfferSnapshotHash,
		"fx_snapshot_hash":                 fixture.quote.FXSnapshotHash,
		"tax_snapshot_hash":                fixture.quote.TaxSnapshotHash,
	} {
		setLaunchInputIfPresent(input, field, value)
	}
	if effectID == contracts.EffectTypeSpendAuthorize {
		return
	}
	for _, action := range placement.ActionBindings {
		if action.EffectID == effectID {
			setLaunchInputIfPresent(input, "provider_action_urn", action.ProviderActionURN)
			setLaunchInputIfPresent(input, "provider_payload_hash", action.ProviderPayloadHash)
			return
		}
	}
	t.Fatalf("route placement has no action binding for %s", effectID)
}

func setLaunchInputIfPresent(input map[string]any, field string, value any) {
	if _, ok := input[field]; ok {
		input[field] = value
	}
}

func launchTestProviderMutation(effectID string) bool {
	switch effectID {
	case contracts.EffectTypeProviderProvision, contracts.EffectTypeDeployProductionActivate, contracts.EffectTypeProviderRollback, contracts.EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}

func launchTestEffectRequiresProviderRoute(effectID string) bool {
	return effectID != contracts.EffectTypeCompanyArtifactUpdate
}

func launchTestApprovalAction(effectID string) string {
	switch effectID {
	case contracts.EffectTypeProviderProvision, contracts.EffectTypeSpendAuthorize:
		return contracts.ApprovalGrantActionInstall
	case contracts.EffectTypeDeployProductionActivate, contracts.EffectTypeCompanyArtifactUpdate:
		return contracts.ApprovalGrantActionUpgrade
	case contracts.EffectTypeProviderRollback:
		return contracts.ApprovalGrantActionRollback
	case contracts.EffectTypeProviderTeardown:
		return contracts.ApprovalGrantActionUninstall
	default:
		panic("unregistered launch effect")
	}
}

// Deterministic reference-pack material only; never register these keys in a
// runtime approval or verdict trust root.
func launchApprovalPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("abcdef0123456789abcdef0123456789"))
}

func launchFixturePrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
}
