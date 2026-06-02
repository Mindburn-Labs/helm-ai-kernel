package executor

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestPackExporter_AccessReviewAndVendorExports(t *testing.T) {
	exporter := NewPackExporter("test-signer", mustSigner(t))
	ctx := context.Background()
	reviewedAt := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)

	accessPack, err := exporter.ExportAccessReviewPack(ctx, &contracts.AccessReviewPack{
		PackID:     "access-1",
		PackType:   "ACCESS_REVIEW_PACK",
		Scope:      "prod",
		ReviewedAt: reviewedAt,
		Reviews: []contracts.AccessReviewItem{{
			SubjectID:  "agent-1",
			Resource:   "database",
			Permission: "read",
			Decision:   "APPROVED",
		}},
	})
	if err != nil {
		t.Fatalf("ExportAccessReviewPack: %v", err)
	}
	if accessPack.Attestation.GeneratedAt.IsZero() {
		t.Fatal("access review GeneratedAt should be populated")
	}
	if accessPack.Attestation.PackHash == "" || accessPack.Attestation.Signature == "" {
		t.Fatal("access review attestation should include hash and signature")
	}

	vendorPack, err := exporter.ExportVendorDueDiligencePack(ctx, &contracts.VendorDueDiligencePack{
		PackID:         "vendor-1",
		PackType:       "VENDOR_DUE_DILIGENCE_PACK",
		VendorName:     "Example Vendor",
		AssessmentDate: reviewedAt,
		ComplianceChecks: []contracts.VendorComplianceCheck{{
			Standard: "SOC2",
			Status:   "COMPLIANT",
		}},
	})
	if err != nil {
		t.Fatalf("ExportVendorDueDiligencePack: %v", err)
	}
	if vendorPack.Attestation.GeneratedAt.IsZero() {
		t.Fatal("vendor GeneratedAt should be populated")
	}
	if vendorPack.Attestation.PackHash == "" || vendorPack.Attestation.Signature == "" {
		t.Fatal("vendor attestation should include hash and signature")
	}
}

func TestPackExporter_SignFailures(t *testing.T) {
	exporter := NewPackExporter("test-signer", failingPackSigner{})
	ctx := context.Background()

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "change",
			run: func() error {
				_, err := exporter.ExportChangePack(ctx, &contracts.ChangePack{PackID: "change-1"})
				return err
			},
		},
		{
			name: "incident",
			run: func() error {
				_, err := exporter.ExportIncidentPack(ctx, &contracts.IncidentPack{PackID: "incident-1"})
				return err
			},
		},
		{
			name: "access review",
			run: func() error {
				_, err := exporter.ExportAccessReviewPack(ctx, &contracts.AccessReviewPack{PackID: "access-1"})
				return err
			},
		},
		{
			name: "vendor",
			run: func() error {
				_, err := exporter.ExportVendorDueDiligencePack(ctx, &contracts.VendorDueDiligencePack{PackID: "vendor-1"})
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), "failed to sign pack") {
				t.Fatalf("expected signing failure, got %v", err)
			}
		})
	}
}

func TestPackExporter_ComputePackHashErrors(t *testing.T) {
	exporter := &packExporter{}

	if _, err := exporter.computePackHash(map[string]any{"bad": math.Inf(1)}); err == nil {
		t.Fatal("unsupported JSON values should fail hash computation")
	}
	if _, err := exporter.computePackHash([]string{"not", "an", "object"}); err == nil {
		t.Fatal("non-object JSON should fail map decode")
	}
}

type failingPackSigner struct{}

func (failingPackSigner) Sign([]byte) (string, error) {
	return "", errors.New("sign failed")
}

func (failingPackSigner) PublicKey() string { return "test-key" }

func (failingPackSigner) PublicKeyBytes() []byte { return []byte("test-key") }

func (failingPackSigner) SignDecision(*contracts.DecisionRecord) error { return nil }

func (failingPackSigner) SignIntent(*contracts.AuthorizedExecutionIntent) error { return nil }

func (failingPackSigner) SignReceipt(*contracts.Receipt) error { return nil }
