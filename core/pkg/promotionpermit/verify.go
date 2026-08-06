package promotionpermit

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type VerificationContext struct {
	PromotionInputRef string
	PromotionInput    Input
	ReleaseManifest   []byte
	PlatformOverlay   []byte
	AppsOverlay       []byte
	Launch            contracts.LaunchEffectEnvelopeVerificationContext
}

// Verify preflights static authority only. It never invokes the launch
// finalizer, consumes a permit, or crosses a connector seam.
func Verify(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx VerificationContext) error {
	if envelope.EffectID != contracts.EffectTypeDeployProductionActivate {
		return errors.New("production promotion requires DEPLOY_PRODUCTION_ACTIVATE")
	}
	if ctx.Launch.ResolveApprovalAuthority == nil {
		return errors.New("production promotion requires source-owned approval authority")
	}

	var approval contracts.LaunchEffectApprovalAuthority
	launch := ctx.Launch
	resolveApproval := launch.ResolveApprovalAuthority
	launch.ResolveApprovalAuthority = func(grantRef, grantHash, consumptionRef, consumptionHash string) (contracts.LaunchEffectApprovalAuthority, error) {
		resolved, err := resolveApproval(grantRef, grantHash, consumptionRef, consumptionHash)
		if err == nil {
			approval = resolved
		}
		return resolved, err
	}
	if err := contracts.PreflightLaunchEffectAuthorizationEnvelope(envelope, launch); err != nil {
		return fmt.Errorf("preflight production promotion authority: %w", err)
	}
	if err := ctx.PromotionInput.VerifyArtifactBytes(ctx.ReleaseManifest, ctx.PlatformOverlay, ctx.AppsOverlay); err != nil {
		return err
	}
	if err := ctx.PromotionInput.VerifyEnvelopeBinding(envelope, ctx.PromotionInputRef); err != nil {
		return err
	}
	if err := verifyCurrentFence(envelope, launch); err != nil {
		return err
	}
	return verifyCurrentConnector(approval.Grant.ConnectorAuthority, launch)
}

func (input Input) VerifyEnvelopeBinding(envelope contracts.LaunchEffectAuthorizationEnvelope, promotionInputRef string) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if envelope.EffectID != contracts.EffectTypeDeployProductionActivate || envelope.Input == nil {
		return errors.New("promotion input requires a DEPLOY_PRODUCTION_ACTIVATE envelope")
	}
	if !canonicalReference(promotionInputRef) {
		return errors.New("promotion input reference must be independently supplied")
	}
	hash, err := input.Hash()
	if err != nil {
		return err
	}
	for field, expected := range map[string]string{
		"promotion_permit_ref":  promotionInputRef,
		"promotion_permit_hash": hash,
		"release_manifest_ref":  input.ReleaseManifestRef,
		"release_manifest_hash": input.ReleaseManifestHash,
	} {
		actual, ok := envelope.Input[field].(string)
		if !ok || subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
			return fmt.Errorf("production promotion envelope input mismatch for %s", field)
		}
	}
	return nil
}

func verifyCurrentFence(envelope contracts.LaunchEffectAuthorizationEnvelope, ctx contracts.LaunchEffectEnvelopeVerificationContext) error {
	if ctx.ResolveEmergencyFence == nil {
		return errors.New("production promotion requires source-owned emergency fence state")
	}
	snapshot, err := ctx.ResolveEmergencyFence(envelope.TenantID, envelope.WorkspaceID)
	if err != nil {
		return fmt.Errorf("resolve production promotion emergency fence: %w", err)
	}
	if snapshot.TenantID != envelope.TenantID || snapshot.WorkspaceID != envelope.WorkspaceID ||
		snapshot.EffectiveEpoch < 0 || snapshot.EffectiveEpoch != envelope.EmergencyFenceEpoch {
		return errors.New("production promotion emergency fence scope or epoch mismatch")
	}
	if snapshot.Active {
		return errors.New("production promotion emergency fence is active")
	}
	return nil
}

func verifyCurrentConnector(authority contracts.ApprovalConnectorAuthority, ctx contracts.LaunchEffectEnvelopeVerificationContext) error {
	if ctx.ResolveCurrentConnectorRelease == nil || ctx.VerifyCurrentConnectorRelease == nil {
		return errors.New("production promotion requires current connector release authority")
	}
	release, err := ctx.ResolveCurrentConnectorRelease(authority)
	if err != nil {
		return fmt.Errorf("resolve production promotion connector release: %w", err)
	}
	if err := ctx.VerifyCurrentConnectorRelease(release, ctx.Now); err != nil {
		return fmt.Errorf("verify production promotion connector release: %w", err)
	}
	if err := authority.ValidateCurrentRelease(release.Authority); err != nil {
		return fmt.Errorf("production promotion connector release is stale: %w", err)
	}
	return nil
}
