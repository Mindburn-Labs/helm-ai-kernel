package executor

import (
	"context"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// PackExporter defines the interface for generating and signing proof packs.
type PackExporter interface {
	ExportChangePack(ctx context.Context, input *contracts.ChangePack) (*contracts.ChangePack, error)
	ExportIncidentPack(ctx context.Context, input *contracts.IncidentPack) (*contracts.IncidentPack, error)
	ExportAccessReviewPack(ctx context.Context, input *contracts.AccessReviewPack) (*contracts.AccessReviewPack, error)
	ExportVendorDueDiligencePack(ctx context.Context, input *contracts.VendorDueDiligencePack) (*contracts.VendorDueDiligencePack, error)
}

type packExporter struct {
	signerID string
	signer   crypto.Signer
}
