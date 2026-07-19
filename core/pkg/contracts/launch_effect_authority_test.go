// quantum_posture: these authorization fixtures exercise classical Ed25519
// signatures only and make no hybrid or post-quantum protection claim.
package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
)

func TestLaunchEffectAuthorizationEnvelopeVerifiesEveryAuthorityBinding(t *testing.T) {
	envelope, ctx, _, publicKey := launchAuthorizationFixture(t)
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
		t.Fatalf("signed launch authorization envelope rejected by schema: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("signed launch authorization envelope rejected: %v", err)
	}
	if envelope.KernelVerdictHash != "sha256:bea40de178e7b5a464932e5a93c55ed6dc74e350d6aa1b781edd65a6a99bcac5" {
		t.Fatalf("launch verdict hash = %s, want committed golden", envelope.KernelVerdictHash)
	}
	if envelope.KernelVerdictSignature != "ed25519:f5cc0062a6ef4c879b1eb5931d52c86c9cb997bf47ae248cbe59af79e56a3c623898a041c672b6cf8de4a91ba2b9f9be4e870e4632e5c6f73cb1dee0c7ed480e" {
		t.Fatalf("launch verdict signature = %s, want committed golden", envelope.KernelVerdictSignature)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("fixture public key is invalid")
	}
}

func TestLaunchEffectAuthorizationEnvelopeFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*contracts.LaunchEffectAuthorizationEnvelope, *contracts.LaunchEffectEnvelopeVerificationContext)
		resign bool
	}{
		{name: "outer input identity", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.TenantID = "tenant-cross-boundary"
		}},
		{name: "principal absent from consumed approval", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.Principal = "spiffe://helm/data-plane-other"
			ctx.Permit.Principal = envelope.Principal
		}},
		{name: "audience absent from approval", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.Audience = "launch.observe"
			ctx.Permit.Audience = envelope.Audience
		}},
		{name: "approval trust root", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelTrustRootID = "kernel-root-other"
			ctx.Permit.KernelTrustRootID = envelope.KernelTrustRootID
		}},
		{name: "input schema hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputSchemaHash = launchHash("0")
		}},
		{name: "uppercase input schema hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputSchemaHash = "sha256:" + strings.Repeat("A", 64)
		}},
		{name: "missing schema validator", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ValidateInput = nil
		}},
		{name: "missing schema resolver", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveInputSchema = nil
		}},
		{name: "missing provider route resolver", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveRouteBinding = nil
		}},
		{name: "missing canonical approval resolver", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveApprovalAuthority = nil
		}},
		{name: "missing canonical approval verifier", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.VerifyApprovalAuthority = nil
		}},
		{name: "invalid canonical approval signature", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			original := ctx.ResolveApprovalAuthority
			ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
				authority, err := original(grantRef, grantHash, consumptionRef, consumptionHash)
				authority.GrantSignature = strings.Repeat("0", 128)
				return authority, err
			}
		}},
		{name: "invalid canonical dispatch admission signature", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			original := ctx.ResolveApprovalAuthority
			ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
				authority, err := original(grantRef, grantHash, consumptionRef, consumptionHash)
				authority.DispatchSignature = strings.Repeat("0", 128)
				return authority, err
			}
		}},
		{name: "connector release authority", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.ConnectorAuthorityHash = launchHash("0")
			ctx.Permit.ConnectorAuthorityHash = envelope.ConnectorAuthorityHash
		}},
		{name: "dispatch admission binding", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.DispatchAdmissionHash = launchHash("0")
			ctx.Permit.DispatchAdmissionHash = envelope.DispatchAdmissionHash
		}},
		{name: "dependency state", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.VerifyDependencyState = func(string, string) error { return fmt.Errorf("predecessor unresolved") }
		}},
		{name: "canonical input hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.InputHash = launchHash("0")
		}},
		{name: "idempotency key", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.IdempotencyKey = launchHash("0")
		}},
		{name: "effect permit hash", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EffectPermitHash = launchHash("9")
		}},
		{name: "canonical request", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.RequestBodyHash = launchHash("0")
		}},
		{name: "connector action", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.ActionURN = contracts.LaunchActionProviderTeardown
		}},
		{name: "permit nonce", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PermitNonce = "different_nonce_0123456789"
		}},
		{name: "noncanonical permit nonce", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PermitNonce = "invalid.nonce.0123456789"
		}},
		{name: "policy epoch", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.PolicyEpoch = "epoch-stale"
		}},
		{name: "emergency fence", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.EmergencyFenceEpoch = 3
		}},
		{name: "dispatch after permit", resign: true, mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.DispatchDeadline = "2026-07-18T12:06:00Z"
		}},
		{name: "permit exceeds source-owned TTL", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.MaximumPermitTTL = 30 * time.Second
		}},
		{name: "expired verdict", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.Now = launchRoutingNow.Add(7 * time.Minute)
		}},
		{name: "untrusted verdict signer", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.ResolveVerdictKey = func(string) (ed25519.PublicKey, error) { return nil, fmt.Errorf("key absent from trust root") }
		}},
		{name: "missing atomic dispatch finalizer", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.FinalizeDispatch = nil
		}},
		{name: "active scoped stop at dispatch", mutate: func(_ *contracts.LaunchEffectAuthorizationEnvelope, ctx *contracts.LaunchEffectEnvelopeVerificationContext) {
			ctx.FinalizeDispatch = func(contracts.LaunchEffectPermitBinding) error { return fmt.Errorf("scoped stop active") }
		}},
		{name: "signature", mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
		}},
		{name: "uppercase signature encoding", mutate: func(envelope *contracts.LaunchEffectAuthorizationEnvelope, _ *contracts.LaunchEffectEnvelopeVerificationContext) {
			envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("A", 128)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope, ctx, privateKey, _ := launchAuthorizationFixture(t)
			test.mutate(&envelope, &ctx)
			if test.resign {
				var err error
				envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
				t.Fatal("authority-binding mutation was accepted")
			}
		})
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsContradictoryApprovedConnectorAction(t *testing.T) {
	envelope, ctx, verdictPrivateKey, _ := launchAuthorizationFixture(t)
	authority, err := ctx.ResolveApprovalAuthority(envelope.ApprovalArtifactRef, envelope.ApprovalArtifactHash, envelope.ApprovalConsumptionRef, envelope.ApprovalConsumptionHash)
	if err != nil {
		t.Fatal(err)
	}

	connectorAuthority := authority.Grant.ConnectorAuthority
	connectorAuthority.ConnectorAction = contracts.LaunchProviderActionDigitalOceanTeardown
	connectorAuthority.AuthorityHash = ""
	connectorAuthority, err = connectorAuthority.Seal()
	if err != nil {
		t.Fatal(err)
	}
	grant := authority.Grant
	grant.ConnectorAuthority = connectorAuthority
	grant.GrantHash = ""
	grant, err = grant.Seal()
	if err != nil {
		t.Fatal(err)
	}
	consumption := authority.Consumption
	consumption.GrantHash = grant.GrantHash
	consumption.ConnectorAuthority = connectorAuthority
	consumption.ConsumptionHash = ""
	consumption, err = consumption.Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission := authority.DispatchAdmission
	admission.GrantHash = grant.GrantHash
	admission.ConsumptionHash = consumption.ConsumptionHash
	admission.ConnectorAuthority = connectorAuthority
	admission.AdmissionHash = ""
	admission, err = admission.Seal()
	if err != nil {
		t.Fatal(err)
	}

	approvalPrivateKey := launchApprovalPrivateKey()
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
	authority = contracts.LaunchEffectApprovalAuthority{
		Grant: grant, GrantSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, GrantSignature: hex.EncodeToString(ed25519.Sign(approvalPrivateKey, grantPayload)),
		Consumption: consumption, ConsumptionSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, ConsumptionSignature: hex.EncodeToString(ed25519.Sign(approvalPrivateKey, consumptionPayload)),
		DispatchAdmission: admission, DispatchSignatureAlgorithm: approvalceremony.GrantSignatureEd25519, DispatchSignature: hex.EncodeToString(ed25519.Sign(approvalPrivateKey, admissionPayload)),
	}

	envelope.ApprovalArtifactHash = grant.GrantHash
	envelope.ApprovalConsumptionHash = consumption.ConsumptionHash
	envelope.DispatchAdmissionHash = admission.AdmissionHash
	envelope.ConnectorAuthorityHash = connectorAuthority.AuthorityHash
	ctx.Permit.ApprovalArtifactHash = grant.GrantHash
	ctx.Permit.ApprovalConsumptionHash = consumption.ConsumptionHash
	ctx.Permit.DispatchAdmissionHash = admission.AdmissionHash
	ctx.Permit.ConnectorAuthorityHash = connectorAuthority.AuthorityHash
	ctx.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
		if grantRef != grant.GrantID || grantHash != grant.GrantHash || consumptionRef != envelope.ApprovalConsumptionRef || consumptionHash != consumption.ConsumptionHash {
			return contracts.LaunchEffectApprovalAuthority{}, fmt.Errorf("approval authority not found")
		}
		return authority, nil
	}
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, verdictPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Permit.KernelVerdictHash = envelope.KernelVerdictHash

	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil || !strings.Contains(err.Error(), "connector action") {
		t.Fatalf("contradictory approved connector action was not rejected precisely: %v", err)
	}
}

func TestLaunchEffectAuthorizationRejectsUnsignedRouteProbes(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	var routeReads atomic.Int32
	originalResolver := ctx.ResolveRouteBinding
	ctx.ResolveRouteBinding = func(routeRef string) (contracts.LaunchRouteBinding, error) {
		routeReads.Add(1)
		return originalResolver(routeRef)
	}
	envelope.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("tampered Kernel verdict unexpectedly verified")
	}
	if routeReads.Load() != 0 {
		t.Fatal("source-owned route registry was queried before Kernel signature verification")
	}
}

func TestLaunchEffectAuthorizationEnvelopeConsumesPermitAtomically(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("first dispatch verification failed: %v", err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("replayed launch effect permit was accepted")
	}
}

func TestLaunchEffectAuthorizationEnvelopeDoesNotConsumeAfterFailedVerification(t *testing.T) {
	envelope, ctx, _, _ := launchAuthorizationFixture(t)
	tampered := envelope
	tampered.KernelVerdictSignature = "ed25519:" + strings.Repeat("0", 128)
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(tampered, ctx); err == nil {
		t.Fatal("tampered verdict unexpectedly verified")
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
		t.Fatalf("failed verification consumed the permit: %v", err)
	}
}

func TestLaunchEffectAuthorizationEnvelopeVerifiesEveryPreviewEffect(t *testing.T) {
	for index, fixture := range launchInputFixtures() {
		index, fixture := index, fixture
		t.Run(fixture.effectID, func(t *testing.T) {
			envelope, ctx, _, _ := launchAuthorizationFixtureAt(t, index)
			if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_envelope.v1.json"), envelope); err != nil {
				t.Fatalf("launch authorization envelope rejected by schema: %v", err)
			}
			if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err != nil {
				t.Fatalf("launch authorization envelope rejected: %v", err)
			}
		})
	}
}

func TestLaunchRollbackEnvelopeConsumesOnlyItsExactPreauthorization(t *testing.T) {
	envelope, ctx, privateKey, _ := launchAuthorizationFixtureAt(t, 3)
	envelope.ApprovalArtifactRef = "different-rollback-permit"
	envelope.ApprovalArtifactHash = launchHash("d")
	ctx.Permit.ApprovalArtifactRef = envelope.ApprovalArtifactRef
	ctx.Permit.ApprovalArtifactHash = envelope.ApprovalArtifactHash
	var err error
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Permit.KernelVerdictHash = envelope.KernelVerdictHash
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("rollback envelope accepted authority other than its exact nested rollback permit")
	}
}

func TestLaunchEffectAuthorizationEnvelopeRejectsSchemaIncompleteCanonicalInput(t *testing.T) {
	envelope, ctx, privateKey, _ := launchAuthorizationFixture(t)
	envelope.Input = cloneLaunchInput(t, envelope.Input)
	delete(envelope.Input, "resource_graph_hash")
	key, err := contracts.DeriveLaunchEffectIdempotencyKey(envelope.EffectID, envelope.Input)
	if err != nil {
		t.Fatal(err)
	}
	envelope.InputHash = key
	envelope.IdempotencyKey = key
	ctx.Permit.InputHash = key
	ctx.Permit.IdempotencyKey = key
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectAuthorizationEnvelope(envelope, ctx); err == nil {
		t.Fatal("schema-incomplete canonical input passed the dispatch verifier")
	}
}

func TestLaunchEffectReceiptSigningRevisionAndStateMachine(t *testing.T) {
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifyContext := launchReceiptVerificationContext(publicKey)
	receipt := launchUnknownReceiptFixture()
	signed, err := contracts.SignLaunchEffectReceipt(receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAgainstSchema(t, compileSchema(t, "effects/launch/launch_effect_receipt.v1.json"), signed); err != nil {
		t.Fatalf("signed receipt rejected by schema: %v", err)
	}
	if err := contracts.VerifyLaunchEffectReceipt(signed, verifyContext); err != nil {
		t.Fatalf("signed receipt rejected: %v", err)
	}
	if signed.ReceiptID != "235b2bcb428ada93c16938a90274c63c9d95c3b8d456bf286ecf45a8521bff10" {
		t.Fatalf("launch receipt ID = %s, want committed golden", signed.ReceiptID)
	}
	if signed.Signature != "41ZfNl5pyyWRWcQtHAoUGkWD/6hqC1FQI0VXTigvkVYEoegteqgTK3X1O+CTb2U312jS94CtSDut0HKJC60cBg==" {
		t.Fatalf("launch receipt signature = %s, want committed golden", signed.Signature)
	}

	reconciled := signed
	reconciled.ReceiptID = ""
	reconciled.Signature = ""
	reconciled.ReceiptRevision = 2
	reconciled.ReconciliationRevision = 1
	reconciled.PreviousReceiptID = signed.ReceiptID
	reconciled.Outcome = "SUCCEEDED"
	reconciled.ReconciliationStatus = "PROVEN_APPLIED"
	reconciled.DependencyState = "RELEASED"
	reconciled.DependencyStateHash = launchHash("a")
	reconciled.ResultHash = launchHash("9")
	reconciled.ProviderOperationRef = "provider-operation-1"
	reconciled.ProviderResourceRefs = []string{"do:app:1", "do:deployment:1"}
	reconciled.EvidencePackRef = "evidencepack:launch:1"
	reconciled.EvidencePackHash = launchHash("8")
	reconciled.ProofGraphNode = launchHash("b")
	reconciled.Timestamp = "2026-07-18T12:04:00Z"
	reconciled.Lamport = 2
	reconciledSigned, err := contracts.SignLaunchEffectReceipt(reconciled, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceipt(reconciledSigned, verifyContext); err != nil {
		t.Fatalf("reconciled receipt rejected: %v", err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(reconciledSigned, signed, verifyContext); err != nil {
		t.Fatalf("receipt revision chain rejected: %v", err)
	}

	conflict := signed
	conflict.ReceiptID = ""
	conflict.Signature = ""
	conflict.ReceiptRevision = 2
	conflict.ReconciliationRevision = 1
	conflict.PreviousReceiptID = signed.ReceiptID
	conflict.Outcome = "UNKNOWN"
	conflict.ReconciliationStatus = "CONFLICT"
	conflict.ResultHash = launchHash("c")
	conflict.Timestamp = "2026-07-18T12:04:00Z"
	conflict.Lamport = 2
	conflictSigned, err := contracts.SignLaunchEffectReceipt(conflict, privateKey)
	if err != nil {
		t.Fatalf("non-terminal provider conflict was rejected: %v", err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(conflictSigned, signed, verifyContext); err != nil {
		t.Fatalf("provider conflict revision was rejected: %v", err)
	}
	resolvedConflict := conflictSigned
	resolvedConflict.ReceiptID = ""
	resolvedConflict.Signature = ""
	resolvedConflict.ReceiptRevision = 3
	resolvedConflict.ReconciliationRevision = 2
	resolvedConflict.PreviousReceiptID = conflictSigned.ReceiptID
	resolvedConflict.Outcome = "FAILED"
	resolvedConflict.ReconciliationStatus = "PROVEN_NOT_APPLIED"
	resolvedConflict.ResultHash = launchHash("d")
	resolvedConflict.EvidencePackRef = "evidencepack:conflict-resolved"
	resolvedConflict.EvidencePackHash = launchHash("e")
	resolvedConflict.Timestamp = "2026-07-18T12:05:00Z"
	resolvedConflict.Lamport = 3
	resolvedConflictSigned, err := contracts.SignLaunchEffectReceipt(resolvedConflict, privateKey)
	if err != nil {
		t.Fatalf("provider conflict could not later reconcile: %v", err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(resolvedConflictSigned, conflictSigned, verifyContext); err != nil {
		t.Fatalf("resolved provider conflict revision was rejected: %v", err)
	}

	tampered := reconciledSigned
	tampered.ResultHash = launchHash("8")
	if err := contracts.VerifyLaunchEffectReceipt(tampered, verifyContext); err == nil {
		t.Fatal("tampered launch effect receipt verified")
	}

	unsafeUnknown := receipt
	unsafeUnknown.DependencyState = "RELEASED"
	if _, err := contracts.SignLaunchEffectReceipt(unsafeUnknown, privateKey); err == nil {
		t.Fatal("UNKNOWN receipt released dependent effects")
	}
	prematureEvidence := receipt
	prematureEvidence.EvidencePackRef = "evidencepack:premature"
	prematureEvidence.EvidencePackHash = launchHash("8")
	if _, err := contracts.SignLaunchEffectReceipt(prematureEvidence, privateKey); err == nil {
		t.Fatal("UNKNOWN receipt claimed a finalized EvidencePack")
	}

	brokenChain := reconciledSigned
	brokenChain.PreviousReceiptID = strings.Repeat("0", 64)
	brokenChain, err = contracts.SignLaunchEffectReceipt(brokenChain, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(brokenChain, signed, verifyContext); err == nil {
		t.Fatal("receipt revision with the wrong predecessor hash verified")
	}

	unreconciledFailure := receipt
	unreconciledFailure.Outcome = "FAILED"
	if _, err := contracts.SignLaunchEffectReceipt(unreconciledFailure, privateKey); err == nil {
		t.Fatal("FAILED receipt without terminal reconciliation proof was signed")
	}

	changedWithoutReconciliation := signed
	changedWithoutReconciliation.ReceiptID = ""
	changedWithoutReconciliation.Signature = ""
	changedWithoutReconciliation.ReceiptRevision = 2
	changedWithoutReconciliation.PreviousReceiptID = signed.ReceiptID
	changedWithoutReconciliation.ResultHash = launchHash("d")
	changedWithoutReconciliation.Timestamp = "2026-07-18T12:04:00Z"
	changedWithoutReconciliation.Lamport = 2
	changedWithoutReconciliationSigned, err := contracts.SignLaunchEffectReceipt(changedWithoutReconciliation, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(changedWithoutReconciliationSigned, signed, verifyContext); err == nil {
		t.Fatal("receipt reconciliation material changed without advancing reconciliation revision")
	}

	changedImmutable := reconciled
	changedImmutable.Principal = "workspace:other"
	changedImmutable.ReceiptChainID = ""
	changedImmutableSigned, err := contracts.SignLaunchEffectReceipt(changedImmutable, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyLaunchEffectReceiptRevision(changedImmutableSigned, signed, verifyContext); err == nil {
		t.Fatal("receipt revision changed immutable principal")
	}
}

func TestLaunchEffectReceiptRejectsNoncanonicalAndUntrustedProof(t *testing.T) {
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)

	unsorted := launchUnknownReceiptFixture()
	unsorted.ProviderResourceRefs = []string{"do:app:2", "do:app:1"}
	if _, err := contracts.SignLaunchEffectReceipt(unsorted, privateKey); err == nil {
		t.Fatal("receipt signed noncanonical provider resource reference order")
	}

	badNonce := launchUnknownReceiptFixture()
	badNonce.PermitNonce = "invalid.nonce.0123456789"
	if _, err := contracts.SignLaunchEffectReceipt(badNonce, privateKey); err == nil {
		t.Fatal("receipt signed a noncanonical permit nonce")
	}

	uppercaseHash := launchUnknownReceiptFixture()
	uppercaseHash.ResultHash = "sha256:" + strings.Repeat("A", 64)
	if _, err := contracts.SignLaunchEffectReceipt(uppercaseHash, privateKey); err == nil {
		t.Fatal("receipt signed an uppercase digest")
	}

	signed, err := contracts.SignLaunchEffectReceipt(launchUnknownReceiptFixture(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := signed
	badSignature.Signature = strings.TrimRight(badSignature.Signature, "=")
	if err := contracts.VerifyLaunchEffectReceipt(badSignature, launchReceiptVerificationContext(publicKey)); err == nil {
		t.Fatal("receipt accepted noncanonical base64 signature")
	}

	untrusted := launchReceiptVerificationContext(publicKey)
	untrusted.ResolveSignerKey = func(string) (ed25519.PublicKey, error) {
		return nil, fmt.Errorf("key absent from trust root")
	}
	if err := contracts.VerifyLaunchEffectReceipt(signed, untrusted); err == nil {
		t.Fatal("receipt accepted signer absent from trust root")
	}

	missingProof := launchReceiptVerificationContext(publicKey)
	missingProof.VerifyProofGraphNode = func(string) error { return fmt.Errorf("node not found") }
	if err := contracts.VerifyLaunchEffectReceipt(signed, missingProof); err == nil {
		t.Fatal("receipt accepted a missing ProofGraph node")
	}

	missingReservation := launchReceiptVerificationContext(publicKey)
	missingReservation.VerifyEffectReservation = nil
	if err := contracts.VerifyLaunchEffectReceipt(signed, missingReservation); err == nil {
		t.Fatal("receipt accepted missing durable effect reservation verification")
	}
	wrongReservation := launchReceiptVerificationContext(publicKey)
	wrongReservation.VerifyEffectReservation = func(string, string, string, string) error { return fmt.Errorf("reservation not found") }
	if err := contracts.VerifyLaunchEffectReceipt(signed, wrongReservation); err == nil {
		t.Fatal("receipt accepted an unproven durable effect reservation")
	}
}

func launchAuthorizationFixture(t *testing.T) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	return launchAuthorizationFixtureAt(t, 0)
}

func launchAuthorizationFixtureAt(t *testing.T, fixtureIndex int) (contracts.LaunchEffectAuthorizationEnvelope, contracts.LaunchEffectEnvelopeVerificationContext, ed25519.PrivateKey, ed25519.PublicKey) {
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
	key, err := contracts.DeriveLaunchEffectIdempotencyKey(fixture.effectID, input)
	if err != nil {
		t.Fatal(err)
	}
	now := launchRoutingNow
	verdictIssuedAt := now.Add(-time.Minute)
	verdictExpiry := now.Add(2 * time.Minute)
	permitIssuedAt := now
	expiry := now.Add(45 * time.Second)
	deadline := now.Add(40 * time.Second)

	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "protocols", "json-schemas", filepath.FromSlash(fixture.schema)))
	if err != nil {
		t.Fatal(err)
	}
	schemaHash := canonicalize.ComputeArtifactHash(schemaBytes)
	principal := "spiffe://helm/data-plane-1"
	audience := "launch.dispatch"
	trustRootID := "kernel-root-1"
	authority, approvalConsumptionRef := launchCanonicalApprovalAuthority(t, fixture.effectID, input, input["plan_hash"].(string), key, now, principal, audience, trustRootID)
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
		InputSchemaHash:         schemaHash,
		Input:                   input,
		InputHash:               key,
		IdempotencyKey:          key,
		PlanHash:                input["plan_hash"].(string),
		ApprovalArtifactRef:     authority.Grant.GrantID,
		ApprovalArtifactHash:    authority.Grant.GrantHash,
		ApprovalConsumptionRef:  approvalConsumptionRef,
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
		PermitExpiry:            expiry.Format(time.RFC3339Nano),
		ProofSessionRef:         "proof-session-1",
		EvidenceReservationRef:  "evidence-reservation-1",
		ConnectorID:             contract.ConnectorID,
		ConnectorContractHash:   input["connector_contract_hash"].(string),
		ConnectorAuthorityRef:   authority.Grant.ConnectorAuthority.BindingRef,
		ConnectorAuthorityHash:  authority.Grant.ConnectorAuthority.AuthorityHash,
		ActionURN:               contract.ActionURN,
		RequestBodyHash:         launchHash("1"),
		ArgsC14NHash:            launchHash("2"),
		DispatchDeadline:        deadline.Format(time.RFC3339Nano),
		ReplayHint:              "single_use_permit",
	}
	privateKey := launchFixturePrivateKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope, err = contracts.SignLaunchEffectAuthorizationEnvelope(envelope, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	permit := contracts.LaunchEffectPermitBinding{
		EffectPermitRef:         envelope.EffectPermitRef,
		EffectPermitHash:        envelope.EffectPermitHash,
		PermitNonce:             envelope.PermitNonce,
		PermitIssuedAt:          permitIssuedAt,
		PermitExpiry:            expiry,
		KernelVerdictRef:        envelope.KernelVerdictRef,
		KernelVerdictHash:       envelope.KernelVerdictHash,
		KernelVerdictIssuedAt:   verdictIssuedAt,
		KernelVerdictExpiry:     verdictExpiry,
		EffectID:                envelope.EffectID,
		TenantID:                envelope.TenantID,
		WorkspaceID:             envelope.WorkspaceID,
		MissionID:               envelope.MissionID,
		Principal:               envelope.Principal,
		Audience:                envelope.Audience,
		KernelTrustRootID:       envelope.KernelTrustRootID,
		EffectOrdinal:           envelope.EffectOrdinal,
		InputSchemaHash:         envelope.InputSchemaHash,
		InputHash:               envelope.InputHash,
		IdempotencyKey:          envelope.IdempotencyKey,
		PlanHash:                envelope.PlanHash,
		ApprovalArtifactRef:     envelope.ApprovalArtifactRef,
		ApprovalArtifactHash:    envelope.ApprovalArtifactHash,
		ApprovalConsumptionRef:  envelope.ApprovalConsumptionRef,
		ApprovalConsumptionHash: envelope.ApprovalConsumptionHash,
		DispatchAdmissionRef:    envelope.DispatchAdmissionRef,
		DispatchAdmissionHash:   envelope.DispatchAdmissionHash,
		DependencySetRef:        envelope.DependencySetRef,
		DependencySetHash:       envelope.DependencySetHash,
		ConnectorID:             envelope.ConnectorID,
		ConnectorContractHash:   envelope.ConnectorContractHash,
		ConnectorAuthorityRef:   envelope.ConnectorAuthorityRef,
		ConnectorAuthorityHash:  envelope.ConnectorAuthorityHash,
		ActionURN:               envelope.ActionURN,
		RequestBodyHash:         envelope.RequestBodyHash,
		ArgsC14NHash:            envelope.ArgsC14NHash,
		PolicyEpoch:             envelope.PolicyEpoch,
		EmergencyFenceEpoch:     envelope.EmergencyFenceEpoch,
		DispatchDeadline:        deadline,
		SingleUse:               true,
	}
	var consumed atomic.Bool
	approvalPrivateKey := launchApprovalPrivateKey()
	approvalPublicKey := approvalPrivateKey.Public().(ed25519.PublicKey)
	approvalVerifier, err := approvalceremony.NewEd25519GrantSignatureVerifier(approvalPublicKey, "approval-key-1", trustRootID)
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
		ResolveApprovalAuthority: func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
			if grantRef != authority.Grant.GrantID || grantHash != authority.Grant.GrantHash || consumptionRef != approvalConsumptionRef || consumptionHash != authority.Consumption.ConsumptionHash {
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
		ExpectedRequestBodyHash: envelope.RequestBodyHash,
		ExpectedArgsC14NHash:    envelope.ArgsC14NHash,
		ExpectedPolicyEpoch:     envelope.PolicyEpoch,
		MaximumPermitTTL:        45 * time.Second,
		ResolveVerdictKey: func(signerKeyID string) (ed25519.PublicKey, error) {
			if signerKeyID != envelope.KernelVerdictSignerKey {
				return nil, fmt.Errorf("unknown verdict signer key")
			}
			return publicKey, nil
		},
		FinalizeDispatch: func(expected contracts.LaunchEffectPermitBinding) error {
			if expected != permit {
				return fmt.Errorf("permit compare-and-swap binding mismatch")
			}
			if !consumed.CompareAndSwap(false, true) {
				return fmt.Errorf("permit already consumed")
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
	return envelope, ctx, privateKey, publicKey
}

func launchCanonicalApprovalAuthority(t *testing.T, effectID string, input map[string]any, planHash, effectHash string, now time.Time, principal, audience, trustRootID string) (contracts.LaunchEffectApprovalAuthority, string) {
	t.Helper()
	action := launchTestApprovalAction(effectID)
	policyHash := launchHash("6")
	connectorAuthority := launchTestConnectorAuthority(t, effectID, input, planHash, effectHash, policyHash)
	grant, err := (contracts.ApprovalGrant{
		SchemaVersion: contracts.ApprovalGrantSchemaV1, ContractVersion: contracts.ApprovalGrantContractV1,
		GrantID: "launch-grant-" + effectID, TenantID: "tenant-1", WorkspaceID: "workspace-1", Audience: audience,
		PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion, PackManifestHash: planHash, Action: action, ConnectorAuthority: connectorAuthority,
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
		PackID: grant.PackID, PackVersion: grant.PackVersion, PackManifestHash: grant.PackManifestHash, Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority,
		IntentHash: grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
		PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: now.Add(-30 * time.Second),
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	admission, err := (contracts.ApprovalDispatchAdmission{
		SchemaVersion: contracts.ApprovalDispatchAdmissionSchemaV1, ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
		Coverage: contracts.ApprovalDispatchAdmissionCoverageV1, AdmissionID: "launch-dispatch-" + effectID, AttemptID: "permit-1", State: contracts.ApprovalDispatchAdmissionStateV1,
		ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, AdmittedBy: principal,
		IdempotencyKeyHash: effectHash, EffectHash: effectHash, Action: grant.Action, ConnectorAuthority: grant.ConnectorAuthority,
		KernelTrustRootID: trustRootID, SigningKeyRef: grant.SigningKeyRef,
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

func launchTestConnectorAuthority(t *testing.T, effectID string, input map[string]any, planHash, effectHash, policyHash string) contracts.ApprovalConnectorAuthority {
	t.Helper()
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
		certificationRef, ok = input["provider_certification_ref"].(string)
		if !ok || certificationRef == "" {
			t.Fatal("provider mutation fixture has no provider certification ref")
		}
		certificationHash, ok = input["provider_certification_hash"].(string)
		if !ok || certificationHash == "" {
			t.Fatal("provider mutation fixture has no provider certification hash")
		}
		connectorAction, ok = input["provider_action_urn"].(string)
		if !ok || connectorAction == "" {
			t.Fatal("provider mutation fixture has no provider connector action")
		}
	}
	authority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion: contracts.ApprovalConnectorAuthoritySchemaV1, ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State: contracts.ApprovalConnectorAuthorityStateV1, BindingRef: "launch-connector-authority-" + effectID,
		TenantID: "tenant-1", WorkspaceID: "workspace-1", PackID: "mission-1", PackVersion: contracts.LaunchEffectCatalogVersion,
		PackManifestHash: planHash, Action: launchTestApprovalAction(effectID), ConnectorAction: connectorAction, EffectHash: effectHash, PolicyHash: policyHash,
		ConnectorID: connectorID, ConnectorVersion: "1.0.0", ReleaseScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal,
		ReleaseAuthorityID: "launch-release-authority-" + effectID, ReleaseRegistryRevision: 1, ReleaseAuthorityHash: launchHash("3"),
		ConnectorExecutorKind: "digital", ConnectorBinaryHash: launchHash("a"),
		ConnectorSignatureRef: "sigstore://launch/connector/1.0.0", ConnectorSignatureHash: launchHash("b"), ConnectorSignerID: "mindburn-release",
		ConnectorSandboxProfile: "launch-provider-route-v1", ConnectorDriftPolicyRef: "policy://launch/connector-drift/v1",
		CertificationRef: certificationRef, CertificationHash: certificationHash, CertificationAuthority: "spiffe://helm/certification-service",
	}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func launchTestProviderMutation(effectID string) bool {
	switch effectID {
	case contracts.EffectTypeProviderProvision, contracts.EffectTypeDeployProductionActivate, contracts.EffectTypeProviderRollback, contracts.EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}

func bindLaunchInputToRoute(t *testing.T, input map[string]any, effectID string, fixture launchRouteFixture) {
	t.Helper()
	placement := fixture.route.Placements[0]
	placementCost := fixture.quote.PlacementCosts[0]
	routeHash, err := contracts.DeriveLaunchRouteBindingHash(fixture.route)
	if err != nil {
		t.Fatal(err)
	}
	setLaunchInputIfPresent(input, "provider", placement.ProviderID)
	setLaunchInputIfPresent(input, "provider_account_ref", placement.ProviderAccountRef)
	setLaunchInputIfPresent(input, "provider_account_hash", placement.ProviderAccountHash)
	setLaunchInputIfPresent(input, "region", placement.RegionID)
	setLaunchInputIfPresent(input, "jurisdiction", placement.Jurisdiction)
	setLaunchInputIfPresent(input, "route_binding_ref", fixture.route.RouteID)
	setLaunchInputIfPresent(input, "route_binding_hash", routeHash)
	setLaunchInputIfPresent(input, "route_placement_id", placement.PlacementID)
	setLaunchInputIfPresent(input, "provider_capability_profile_ref", placement.ProviderProfileRef)
	setLaunchInputIfPresent(input, "provider_capability_profile_hash", placement.ProviderProfileHash)
	setLaunchInputIfPresent(input, "provider_certification_ref", placement.ProviderCertificationRef)
	setLaunchInputIfPresent(input, "provider_certification_hash", placement.ProviderCertificationHash)
	setLaunchInputIfPresent(input, "provider_connector_id", placement.ProviderConnectorID)
	setLaunchInputIfPresent(input, "provider_connector_contract_hash", placement.ProviderConnectorContractHash)
	setLaunchInputIfPresent(input, "repository_analysis_ref", fixture.route.RepositoryAnalysisRef)
	setLaunchInputIfPresent(input, "repository_analysis_hash", fixture.route.RepositoryAnalysisHash)
	setLaunchInputIfPresent(input, "workload_graph_ref", fixture.route.WorkloadGraphRef)
	setLaunchInputIfPresent(input, "workload_graph_hash", fixture.route.WorkloadGraphHash)
	setLaunchInputIfPresent(input, "resource_graph_ref", fixture.route.ResourceGraphRef)
	setLaunchInputIfPresent(input, "resource_graph_hash", fixture.route.ResourceGraphHash)
	setLaunchInputIfPresent(input, "route_quote_ref", fixture.route.RouteQuoteRef)
	setLaunchInputIfPresent(input, "route_quote_hash", fixture.route.RouteQuoteHash)
	setLaunchInputIfPresent(input, "quote_hash", fixture.route.RouteQuoteHash)
	setLaunchInputIfPresent(input, "constraint_set_hash", fixture.route.ConstraintSetHash)
	setLaunchInputIfPresent(input, "generated_spec_hash", fixture.route.GeneratedSpecHash)
	setLaunchInputIfPresent(input, "gross_cap_minor", fixture.constraints.MaximumGrossMinor)
	setLaunchInputIfPresent(input, "base_provider_cost_minor", placementCost.BaseCostMinor)
	setLaunchInputIfPresent(input, "tax_fx_reserve_minor", placementCost.TaxFXReserveMinor)
	setLaunchInputIfPresent(input, "gross_exposure_minor", placementCost.GrossExposureMinor)
	setLaunchInputIfPresent(input, "verified_credit_minor", placementCost.VerifiedCreditMinor)
	setLaunchInputIfPresent(input, "expected_cash_minor", placementCost.ExpectedCashMinor)
	setLaunchInputIfPresent(input, "currency", fixture.quote.Currency)
	setLaunchInputIfPresent(input, "credit_status", placementCost.CreditStatus)
	setLaunchInputIfPresent(input, "price_snapshot_hash", placementCost.PriceEvidenceHash)
	setLaunchInputIfPresent(input, "provider_terms_profile_hash", placementCost.TermsEvidenceHash)
	setLaunchInputIfPresent(input, "credit_snapshot_hash", placementCost.OfferSnapshotHash)
	setLaunchInputIfPresent(input, "fx_snapshot_hash", fixture.quote.FXSnapshotHash)
	setLaunchInputIfPresent(input, "tax_snapshot_hash", fixture.quote.TaxSnapshotHash)
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

func launchApprovalPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("abcdef0123456789abcdef0123456789"))
}

func TestLaunchMissionReferencePackMatchesGoImplementation(t *testing.T) {
	want := launchMissionReferencePackBytes(t)
	path := filepath.Join(repoRoot(t), "reference_packs", "launch-mission-v1", "vectors.json")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Launch Mission reference pack drifted from the Go contracts; regenerate the committed vectors")
	}
}

func TestDumpLaunchMissionReferencePack(t *testing.T) {
	if os.Getenv("HELM_DUMP_LAUNCH_REFERENCE_PACK") != "1" {
		t.Skip("reference-pack generator is opt-in")
	}
	output := os.Getenv("HELM_LAUNCH_REFERENCE_PACK_OUTPUT")
	if output == "" {
		t.Fatal("HELM_LAUNCH_REFERENCE_PACK_OUTPUT is required")
	}
	if err := os.WriteFile(output, launchMissionReferencePackBytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
}

func launchMissionReferencePackBytes(t *testing.T) []byte {
	t.Helper()
	profile := launchProviderProfile("digitalocean", contracts.LaunchConnectorDigitalOcean, "fra", "app-platform", []string{"http_service", "static_site"}, []string{"health-check", "https-endpoint", "stateless-runtime"}, []string{contracts.LaunchLifecycleEphemeral}, "digitalocean")
	profile.Actions[0].ActionURN = contracts.LaunchProviderActionDigitalOceanActivate
	profile.Actions[1].ActionURN = contracts.LaunchProviderActionDigitalOceanProvision
	profile.Actions[2].ActionURN = contracts.LaunchProviderActionDigitalOceanRollback
	profile.Actions[3].ActionURN = contracts.LaunchProviderActionDigitalOceanTeardown
	routeFixture := singleLaunchRouteFixture(t, profile, true)
	routeHash, err := contracts.DeriveLaunchRouteBindingHash(routeFixture.route)
	if err != nil {
		t.Fatal(err)
	}
	universalFixture := multiLaunchRouteFixture(t)
	if err := contracts.ValidateLaunchRouteBinding(universalFixture.route, universalFixture.resolver, launchRoutingNow, false); err != nil {
		t.Fatalf("build universal multi-provider reference vector: %v", err)
	}
	universalRouteHash, err := contracts.DeriveLaunchRouteBindingHash(universalFixture.route)
	if err != nil {
		t.Fatal(err)
	}
	universalProfiles := map[string]any{}
	universalProfileHashes := map[string]string{}
	for _, placement := range universalFixture.route.Placements {
		profile := universalFixture.resolver.profiles[placement.ProviderProfileRef]
		profileHash, hashErr := contracts.DeriveLaunchProviderCapabilityProfileHash(profile)
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		universalProfiles[profile.ProfileID] = profile
		universalProfileHashes[profile.ProfileID] = profileHash
	}
	universalOffers := map[string]any{}
	universalOfferHashes := map[string]string{}
	for _, line := range universalFixture.quote.PlacementCosts {
		offer := universalFixture.resolver.offers[line.OfferSnapshotRef]
		offerHash, hashErr := contracts.DeriveLaunchOfferSnapshotHash(offer)
		if hashErr != nil {
			t.Fatal(hashErr)
		}
		universalOffers[offer.SnapshotID] = offer
		universalOfferHashes[offer.SnapshotID] = offerHash
	}
	envelope, ctx, _, verdictPublicKey := launchAuthorizationFixture(t)
	authority, err := ctx.ResolveApprovalAuthority(envelope.ApprovalArtifactRef, envelope.ApprovalArtifactHash, envelope.ApprovalConsumptionRef, envelope.ApprovalConsumptionHash)
	if err != nil {
		t.Fatal(err)
	}
	receiptInput := launchUnknownReceiptFixture()
	receiptInput.DecisionID = envelope.KernelVerdictRef
	receiptInput.Principal = envelope.Principal
	receiptInput.Audience = envelope.Audience
	receiptInput.KernelTrustRootID = envelope.KernelTrustRootID
	receiptInput.EffectOrdinal = envelope.EffectOrdinal
	receiptInput.InputSchemaHash = envelope.InputSchemaHash
	receiptInput.InputHash = envelope.InputHash
	receiptInput.IdempotencyKey = envelope.IdempotencyKey
	receiptInput.RequestHash = envelope.RequestBodyHash
	receiptInput.PayloadHash = envelope.RequestBodyHash
	receiptInput.KernelVerdictRef = envelope.KernelVerdictRef
	receiptInput.KernelVerdictHash = envelope.KernelVerdictHash
	receiptInput.ApprovalArtifactRef = envelope.ApprovalArtifactRef
	receiptInput.ApprovalArtifactHash = envelope.ApprovalArtifactHash
	receiptInput.ApprovalConsumptionRef = envelope.ApprovalConsumptionRef
	receiptInput.ApprovalConsumptionHash = envelope.ApprovalConsumptionHash
	receiptInput.DispatchAdmissionRef = envelope.DispatchAdmissionRef
	receiptInput.DispatchAdmissionHash = envelope.DispatchAdmissionHash
	receiptInput.EffectReservationRef = "effect-reservation:" + envelope.DispatchAdmissionRef + ":2"
	receiptInput.EffectReservationHash = launchHash("c")
	receiptInput.EffectPermitRef = envelope.EffectPermitRef
	receiptInput.EffectPermitHash = envelope.EffectPermitHash
	receiptInput.PermitNonce = envelope.PermitNonce
	receiptInput.PolicyEpoch = envelope.PolicyEpoch
	receiptInput.EmergencyFenceEpoch = envelope.EmergencyFenceEpoch
	receiptInput.ConnectorContractHash = envelope.ConnectorContractHash
	receiptInput.ConnectorAuthorityRef = envelope.ConnectorAuthorityRef
	receiptInput.ConnectorAuthorityHash = envelope.ConnectorAuthorityHash
	receiptInput.DependencySetRef = envelope.DependencySetRef
	receiptInput.DependencySetHash = envelope.DependencySetHash
	receiptInput.RouteBindingRef = routeFixture.route.RouteID
	receiptInput.RouteBindingHash = routeHash
	receiptInput.RoutePlacementID = routeFixture.route.Placements[0].PlacementID
	receiptInput.ProviderProfileRef = routeFixture.route.Placements[0].ProviderProfileRef
	receiptInput.ProviderProfileHash = routeFixture.route.Placements[0].ProviderProfileHash
	receiptInput.ProviderCertificationRef = routeFixture.route.Placements[0].ProviderCertificationRef
	receiptInput.ProviderCertificationHash = routeFixture.route.Placements[0].ProviderCertificationHash
	receiptInput.OfferSnapshotRef = routeFixture.quote.PlacementCosts[0].OfferSnapshotRef
	receiptInput.OfferSnapshotHash = routeFixture.quote.PlacementCosts[0].OfferSnapshotHash
	receiptInput.PriceEvidenceHash = routeFixture.quote.PlacementCosts[0].PriceEvidenceHash
	receiptInput.TermsEvidenceHash = routeFixture.quote.PlacementCosts[0].TermsEvidenceHash
	receipt, err := contracts.SignLaunchEffectReceipt(receiptInput, launchFixturePrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	effects := make([]map[string]any, 0, len(launchInputFixtures()))
	for _, fixture := range launchInputFixtures() {
		effects = append(effects, map[string]any{"effect_id": fixture.effectID, "input": fixture.input, "idempotency_key": fixture.goldenKey})
	}
	pack := map[string]any{
		"schema_version": "launch-mission-reference-v1", "contract_version": contracts.LaunchEffectCatalogVersion,
		"canonicalization": "RFC8785_JCS_SAFE_INTEGER_INPUTS", "quantum_posture": "classical_ed25519_only",
		"certification_public_key": "ed25519:" + hex.EncodeToString(routeFixture.resolver.keys[routeFixture.certification.SignerKeyID]),
		"artifact_hashes": map[string]string{
			"repository_analysis": routeFixture.route.RepositoryAnalysisHash, "workload_graph": routeFixture.route.WorkloadGraphHash,
			"provider_capability_profile": routeFixture.route.Placements[0].ProviderProfileHash, "provider_certification": routeFixture.certification.RecordHash,
			"offer_snapshot": routeFixture.quote.PlacementCosts[0].OfferSnapshotHash,
			"constraint_set": routeFixture.route.ConstraintSetHash, "route_quote": routeFixture.route.RouteQuoteHash,
			"resource_graph": routeFixture.route.ResourceGraphHash, "provider_payload_set": routeFixture.route.ProviderPayloadSetHash, "route_binding": routeHash,
		},
		"artifacts": map[string]any{
			"repository_analysis": routeFixture.analysis, "workload_graph": routeFixture.graph, "provider_capability_profile": profile,
			"provider_certification": routeFixture.certification, "constraint_set": routeFixture.constraints, "route_quote": routeFixture.quote,
			"offer_snapshot": routeFixture.offer,
			"resource_graph": routeFixture.resources, "provider_payload_set": routeFixture.payloads, "route_binding": routeFixture.route,
		},
		"universal_route": map[string]any{
			"purpose": "provider-neutral multi-placement route for an ephemeral API and stateful database",
			"artifact_hashes": map[string]any{
				"repository_analysis":          universalFixture.route.RepositoryAnalysisHash,
				"workload_graph":               universalFixture.route.WorkloadGraphHash,
				"provider_capability_profiles": universalProfileHashes,
				"offer_snapshots":              universalOfferHashes,
				"constraint_set":               universalFixture.route.ConstraintSetHash,
				"route_quote":                  universalFixture.route.RouteQuoteHash,
				"resource_graph":               universalFixture.route.ResourceGraphHash,
				"provider_payload_set":         universalFixture.route.ProviderPayloadSetHash,
				"route_binding":                universalRouteHash,
			},
			"artifacts": map[string]any{
				"repository_analysis":          universalFixture.analysis,
				"workload_graph":               universalFixture.graph,
				"provider_capability_profiles": universalProfiles,
				"offer_snapshots":              universalOffers,
				"constraint_set":               universalFixture.constraints,
				"route_quote":                  universalFixture.quote,
				"resource_graph":               universalFixture.resources,
				"provider_payload_set":         universalFixture.payloads,
				"route_binding":                universalFixture.route,
			},
		},
		"effect_inputs": effects,
		"authorization": map[string]any{
			"envelope": envelope, "verdict_public_key": "ed25519:" + hex.EncodeToString(verdictPublicKey),
			"approval_authority": authority, "approval_public_key": "ed25519:" + hex.EncodeToString(launchApprovalPrivateKey().Public().(ed25519.PublicKey)),
		},
		"receipt": map[string]any{
			"value": receipt, "public_key": "ed25519:" + hex.EncodeToString(launchFixturePrivateKey().Public().(ed25519.PublicKey)),
		},
		"integer_equivalence": []string{"1", "1.0", "1e0"},
		"negative_vectors": []map[string]string{
			{"id": "route_hash_tamper", "expected_error": "hash_mismatch"},
			{"id": "verdict_signature_tamper", "expected_error": "signature_rejected"},
			{"id": "receipt_result_tamper", "expected_error": "receipt_id_mismatch"},
			{"id": "unsafe_integer", "expected_error": "unsafe_integer"},
		},
	}
	data, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	return data
}

func launchUnknownReceiptFixture() contracts.LaunchEffectReceipt {
	return contracts.LaunchEffectReceipt{
		SchemaVersion:          contracts.LaunchEffectReceiptSchemaVersion,
		ReceiptVersion:         contracts.LaunchEffectReceiptVersion,
		Kind:                   "helm_native_receipt",
		ReceiptRevision:        1,
		ReconciliationRevision: 0,
		DecisionID:             "verdict-1",
		EffectID:               contracts.EffectTypeProviderProvision,
		Verdict:                "ALLOW",
		Principal:              "spiffe://helm/data-plane-1",
		Audience:               "launch.dispatch",
		KernelTrustRootID:      "kernel-root-1",
		Tool:                   contracts.LaunchConnectorProviderRoute,
		Action:                 contracts.LaunchActionProviderProvision,
		Timestamp:              "2026-07-18T12:03:00Z",
		Lamport:                1,
		ProofGraphNode:         launchHash("0"),
		SignerKeyID:            "kernel-key-1",
		PayloadHash:            launchHash("3"),
		Metadata: contracts.LaunchEffectReceiptMetadata{
			Profile:              contracts.LaunchEffectReceiptProfile,
			RedactionProfileHash: launchHash("7"),
		},
		TenantID:                  "tenant-1",
		WorkspaceID:               "workspace-1",
		MissionID:                 "mission-1",
		EffectOrdinal:             1,
		InputSchemaHash:           launchHash("d"),
		InputHash:                 launchHash("1"),
		IdempotencyKey:            launchHash("2"),
		RequestHash:               launchHash("3"),
		ResultHash:                launchHash("4"),
		KernelVerdictRef:          "verdict-1",
		KernelVerdictHash:         launchHash("5"),
		ApprovalArtifactRef:       "commercial-approval-1",
		ApprovalArtifactHash:      launchHash("f"),
		ApprovalConsumptionRef:    "approval-consumption-1",
		ApprovalConsumptionHash:   launchHash("a"),
		DispatchAdmissionRef:      "dispatch-admission-1",
		DispatchAdmissionHash:     launchHash("d"),
		EffectReservationRef:      "effect-reservation:dispatch-admission-1:2",
		EffectReservationHash:     launchHash("c"),
		EffectPermitRef:           "permit-1",
		EffectPermitHash:          launchHash("c"),
		PermitNonce:               "0123456789abcdefABCDEF",
		PermitConsumptionRef:      "permit-consumption-1",
		PermitConsumptionHash:     launchHash("b"),
		PolicyEpoch:               "epoch-1",
		EmergencyFenceEpoch:       4,
		ConnectorContractHash:     launchHash("6"),
		ConnectorAuthorityRef:     "connector-authority-1",
		ConnectorAuthorityHash:    launchHash("f"),
		ReconciliationLocator:     launchHash("e"),
		Outcome:                   "UNKNOWN",
		ReconciliationStatus:      "PENDING",
		DependencyState:           "FROZEN",
		DependencySetRef:          "dependency-set-1",
		DependencySetHash:         launchHash("8"),
		DependencyStateHash:       launchHash("9"),
		RouteBindingRef:           "route-1",
		RouteBindingHash:          launchHash("2"),
		RoutePlacementID:          "placement-1",
		ProviderProfileRef:        "digitalocean-candidate",
		ProviderProfileHash:       launchHash("3"),
		ProviderCertificationRef:  "certification-1",
		ProviderCertificationHash: launchHash("4"),
		OfferSnapshotRef:          "offer-snapshot-1",
		OfferSnapshotHash:         launchHash("7"),
		PriceEvidenceHash:         launchHash("5"),
		TermsEvidenceHash:         launchHash("6"),
	}
}

func launchReceiptVerificationContext(publicKey ed25519.PublicKey) contracts.LaunchEffectReceiptVerificationContext {
	return contracts.LaunchEffectReceiptVerificationContext{
		MinimumLamport: 1,
		ResolveSignerKey: func(signerKeyID string) (ed25519.PublicKey, error) {
			if signerKeyID != "kernel-key-1" {
				return nil, fmt.Errorf("unknown receipt signer key")
			}
			return publicKey, nil
		},
		VerifyEffectReservation: func(reservationRef, reservationHash, dispatchAdmissionRef, dispatchAdmissionHash string) error {
			if reservationRef != "effect-reservation:"+dispatchAdmissionRef+":2" || reservationHash != launchHash("c") || !strings.HasPrefix(dispatchAdmissionHash, "sha256:") {
				return fmt.Errorf("durable effect reservation does not bind dispatch admission")
			}
			return nil
		},
		VerifyProofGraphNode: func(nodeHash string) error {
			if !strings.HasPrefix(nodeHash, "sha256:") {
				return fmt.Errorf("invalid ProofGraph node")
			}
			return nil
		},
	}
}

func launchFixturePrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
}
