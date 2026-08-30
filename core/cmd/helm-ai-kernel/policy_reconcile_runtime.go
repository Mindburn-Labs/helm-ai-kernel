package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

func compileServePolicySnapshot(ctx context.Context, head policyreconcile.PolicyHead, bundle []byte) (*policyreconcile.EffectivePolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if head.BundleRef == "" {
		return nil, fmt.Errorf("policy bundle_ref is required to compile serve policy")
	}
	if strings.HasPrefix(head.BundleRef, "cp-policy-publication:") {
		return compileManagedPolicySnapshot(head, bundle)
	}
	runtimePolicy, err := loadServePolicyRuntimeFromBytes(head.BundleRef, bundle)
	if err != nil {
		return nil, err
	}
	if runtimePolicy.ReferencePackHash != "" && !sourceRefsContainDigest(head.SourceRefs, runtimePolicy.ReferencePackHash) {
		return nil, fmt.Errorf("policy source refs missing reference_pack digest %s", runtimePolicy.ReferencePackHash)
	}
	scope := head.Scope.Normalize()

	shadowMode := os.Getenv("HELM_SHADOW_MODE") == "true" || os.Getenv("HELM_DRY_RUN") == "true"
	innerPDP := pdp.NewHelmPDP(runtimePolicy.Policy.Name, runtimePolicy.AllowMap())
	if runtimePolicy.Graph != nil {
		engine, err := prg.NewPolicyEngine()
		if err != nil {
			return nil, err
		}
		if err := engine.WarmGraph(runtimePolicy.Graph); err != nil {
			return nil, err
		}
	}

	return &policyreconcile.EffectivePolicySnapshot{
		TenantID:        scope.TenantID,
		WorkspaceID:     scope.WorkspaceID,
		PolicyEpoch:     head.PolicyEpoch,
		PolicyHash:      head.PolicyHash,
		P0CeilingsHash:  head.P0CeilingsHash,
		P1BundleHash:    head.P1BundleHash,
		P2OverlayHashes: append([]string(nil), head.P2OverlayHashes...),
		SourceRefs:      append([]string(nil), head.SourceRefs...),
		Validation:      policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive, Hash: head.PolicyHash},
		Graph:           runtimePolicy.Graph,
		PDP:             pdp.NewTelemetryPDP(innerPDP, shadowMode),
	}, nil
}

func compileManagedPolicySnapshot(head policyreconcile.PolicyHead, bundle []byte) (*policyreconcile.EffectivePolicySnapshot, error) {
	rawEpoch := strings.TrimPrefix(head.BundleRef, "cp-policy-publication:")
	epoch, err := strconv.ParseUint(rawEpoch, 10, 64)
	if err != nil || epoch == 0 || strconv.FormatUint(epoch, 10) != rawEpoch || epoch != head.PolicyEpoch {
		return nil, fmt.Errorf("managed policy bundle_ref epoch does not match policy head")
	}
	innerPDP, err := pdp.NewManagedPolicyPDP(bundle, head.SourceRefs)
	if err != nil {
		return nil, err
	}
	p0Hash, p1Hash, p2Hashes := innerPDP.LayerHashes()
	if head.P0CeilingsHash != "" && head.P0CeilingsHash != p0Hash {
		return nil, fmt.Errorf("managed policy P0 hash does not match policy head")
	}
	if head.P1BundleHash != "" && head.P1BundleHash != p1Hash {
		return nil, fmt.Errorf("managed policy P1 hash does not match policy head")
	}
	if len(head.P2OverlayHashes) > 0 && !equalStrings(head.P2OverlayHashes, p2Hashes) {
		return nil, fmt.Errorf("managed policy P2 hashes do not match policy head")
	}
	scope := head.Scope.Normalize()
	shadowMode := os.Getenv("HELM_SHADOW_MODE") == "true" || os.Getenv("HELM_DRY_RUN") == "true"
	return &policyreconcile.EffectivePolicySnapshot{
		TenantID:        scope.TenantID,
		WorkspaceID:     scope.WorkspaceID,
		PolicyEpoch:     head.PolicyEpoch,
		PolicyHash:      head.PolicyHash,
		P0CeilingsHash:  p0Hash,
		P1BundleHash:    p1Hash,
		P2OverlayHashes: p2Hashes,
		SourceRefs:      append([]string(nil), head.SourceRefs...),
		Validation:      policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive, Hash: head.PolicyHash},
		PDP:             pdp.NewTelemetryPDP(innerPDP, shadowMode),
	}, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sourceRefsContainDigest(sourceRefs []string, digest string) bool {
	for _, ref := range sourceRefs {
		if strings.Contains(ref, "@"+digest) {
			return true
		}
	}
	return false
}
