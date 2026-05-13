package main

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

func compileServePolicySnapshot(ctx context.Context, head policyreconcile.PolicyHead, bundle []byte) (*policyreconcile.EffectivePolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if head.BundleRef == "" {
		return nil, fmt.Errorf("policy bundle_ref is required to compile serve policy")
	}
	runtimePolicy, err := loadServePolicyRuntimeFromBytes(head.BundleRef, bundle)
	if err != nil {
		return nil, err
	}
	scope := head.Scope.Normalize()
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
		PDP:             pdp.NewHelmPDP(runtimePolicy.Policy.Name, runtimePolicy.AllowMap()),
	}, nil
}
