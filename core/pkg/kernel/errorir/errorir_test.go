package errorir

import (
	"strings"
	"testing"
)

func TestNewErrorIR(t *testing.T) {
	e := NewErrorIR(
		CodeValidationSchemaMismatch,
		"Schema Mismatch",
		"field 'name' is required",
		400,
		ClassificationNonRetryable,
	)

	if e.Title != "Schema Mismatch" {
		t.Errorf("expected title 'Schema Mismatch', got %s", e.Title)
	}
	if e.Status != 400 {
		t.Errorf("expected status 400, got %d", e.Status)
	}
	if e.Detail != "field 'name' is required" {
		t.Errorf("unexpected detail: %s", e.Detail)
	}
	if e.HELM.ErrorCode != CodeValidationSchemaMismatch {
		t.Errorf("expected error code %s, got %s", CodeValidationSchemaMismatch, e.HELM.ErrorCode)
	}
	if e.HELM.Classification != ClassificationNonRetryable {
		t.Errorf("expected classification %s, got %s", ClassificationNonRetryable, e.HELM.Classification)
	}
	if e.HELM.Namespace != "CORE" {
		t.Errorf("expected namespace CORE, got %s", e.HELM.Namespace)
	}
	if !strings.HasPrefix(e.Type, "https://helm.org/errors/") {
		t.Errorf("expected type URI prefix, got %s", e.Type)
	}
}

func TestNamespaceFromErrorCode(t *testing.T) {
	tests := map[string]string{
		"HELM/CORE/VALIDATION/SCHEMA_MISMATCH":    "CORE",
		"HELM/ADAPTER/slack/DELIVERY_FAILED":      "ADAPTER/slack",
		"HELM/ADAPTER/openai/RATE_LIMIT":          "ADAPTER/openai",
		"INVALID/CORE/VALIDATION/SCHEMA_MISMATCH": "UNKNOWN",
		"HELM":                             "UNKNOWN",
		"HELM//VALIDATION/SCHEMA_MISMATCH": "UNKNOWN",
	}

	for code, want := range tests {
		if got := namespaceFromErrorCode(code); got != want {
			t.Fatalf("namespaceFromErrorCode(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestNewErrorIR_Retryable(t *testing.T) {
	e := NewErrorIR(
		CodeEffectTimeout,
		"Effect Timeout",
		"upstream timed out after 30s",
		504,
		ClassificationRetryable,
	)
	if e.HELM.Classification != ClassificationRetryable {
		t.Error("expected retryable classification")
	}
}

func TestNewErrorIR_AllCodes(t *testing.T) {
	codes := []string{
		CodeValidationSchemaMismatch,
		CodeValidationCSNFViolation,
		CodeAuthUnauthorized,
		CodeAuthForbidden,
		CodeEffectTimeout,
		CodeEffectUpstreamError,
		CodeEffectIdempotencyConflict,
		CodePolicyDenied,
		CodeResourceNotFound,
		CodeResourceConflict,
		CodeCELDPError,
	}
	for _, code := range codes {
		e := NewErrorIR(code, "test", "test detail", 500, ClassificationNonRetryable)
		if e.HELM.ErrorCode != code {
			t.Errorf("expected code %s, got %s", code, e.HELM.ErrorCode)
		}
	}
}

func TestClassificationConstants(t *testing.T) {
	if ClassificationRetryable != "RETRYABLE" {
		t.Error("wrong retryable constant")
	}
	if ClassificationNonRetryable != "NON_RETRYABLE" {
		t.Error("wrong non-retryable constant")
	}
	if ClassificationIdempotentSafe != "IDEMPOTENT_SAFE" {
		t.Error("wrong idempotent-safe constant")
	}
	if ClassificationCompensationRequired != "COMPENSATION_REQUIRED" {
		t.Error("wrong compensation-required constant")
	}
}
