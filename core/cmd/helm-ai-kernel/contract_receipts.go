package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func contractReceipts(ctx context.Context, svc *Services, tenantID, sessionID string, limit int) ([]*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	return listReceiptsForCursor(ctx, svc, tenantID, sessionID, store.TenantReceiptCursor{}, store.ReceiptQueryFilter{}, limit)
}

func canonicalContractReceipts(ctx context.Context, svc *Services, tenantID, sessionID string, limit int) ([]*contracts.Receipt, error) {
	receipts, err := contractReceipts(ctx, svc, tenantID, sessionID, limit)
	if err != nil {
		return nil, err
	}
	return canonicalReceiptsForTenant(ctx, svc, tenantID, receipts)
}

func canonicalReceiptsForTenant(ctx context.Context, svc *Services, tenantID string, receipts []*contracts.Receipt) ([]*contracts.Receipt, error) {
	canonical := make([]*contracts.Receipt, 0, len(receipts))
	for _, receipt := range receipts {
		if receipt == nil {
			return nil, fmt.Errorf("receipt store returned nil receipt")
		}
		verified, err := canonicalReceiptForTenant(ctx, svc, tenantID, receipt.ReceiptID)
		if err != nil {
			return nil, err
		}
		canonical = append(canonical, verified)
	}
	return canonical, nil
}

func canonicalReceiptForTenant(ctx context.Context, svc *Services, tenantID, receiptID string) (*contracts.Receipt, error) {
	if svc == nil || svc.ReceiptStore == nil {
		return nil, fmt.Errorf("receipt store unavailable")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedCanonicalReceiptReader)
	if !ok {
		return nil, fmt.Errorf("receipt store lacks canonical evidence reader capability")
	}
	return reader.GetCanonicalReceiptByIDForTenant(ctx, tenantID, receiptID)
}

// authorizeArtifactReceiptReferences ensures a shared boundary artifact cannot
// claim a receipt owned by a different tenant. The registry seals artifact
// content, but tenant-scoped canonical receipt lookup is the authority for
// whether that content may name a receipt at all.
func authorizeArtifactReceiptReferences(ctx context.Context, svc *Services, tenantID string, receiptRefs ...string) error {
	if len(receiptRefs) == 0 {
		return nil
	}
	if svc == nil || svc.ReceiptStore == nil {
		return errors.New("receipt store unavailable for artifact receipt references")
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedCanonicalReceiptReader)
	if !ok {
		return errors.New("receipt store lacks canonical tenant receipt reader capability")
	}
	for _, receiptRef := range receiptRefs {
		receiptRef = strings.TrimSpace(receiptRef)
		if receiptRef == "" {
			return errors.New("artifact receipt references must not contain empty values")
		}
		receipt, err := reader.GetCanonicalReceiptByIDForTenant(ctx, tenantID, receiptRef)
		if err != nil || receipt == nil || strings.TrimSpace(receipt.ReceiptID) != receiptRef {
			return fmt.Errorf("artifact receipt reference %q is not available to authenticated tenant", receiptRef)
		}
	}
	return nil
}
