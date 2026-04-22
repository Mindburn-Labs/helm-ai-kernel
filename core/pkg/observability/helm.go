// Package observability provides HELM-specific instrumentation helpers.
package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// HELM-specific semantic convention attributes.
var (
	// Entity attributes
	AttrEntityID   = attribute.Key("helm.entity.id")
	AttrEntityType = attribute.Key("helm.entity.type")

	// Governance attributes
	AttrGovernanceState  = attribute.Key("helm.governance.state")
	AttrGovernanceEpoch  = attribute.Key("helm.governance.epoch")
	AttrGovernanceAction = attribute.Key("helm.governance.action")

	// Mutation attributes
	AttrMutationID     = attribute.Key("helm.mutation.id")
	AttrMutationField  = attribute.Key("helm.mutation.field")
	AttrMutationStatus = attribute.Key("helm.mutation.status")

	// PDP/Governance attributes
	AttrPolicyDomain = attribute.Key("helm.policy.domain")
	AttrPolicyAction = attribute.Key("helm.policy.action")
	AttrPDPDecision  = attribute.Key("helm.pdp.decision")
	AttrPDPLatencyMs = attribute.Key("helm.pdp.latency_ms")

	// Compliance attributes
	AttrJurisdiction = attribute.Key("helm.compliance.jurisdiction")
	AttrRegulation   = attribute.Key("helm.compliance.regulation")
	AttrObligationID = attribute.Key("helm.compliance.obligation_id")
	AttrComplianceOK = attribute.Key("helm.compliance.compliant")

	// Crypto attributes
	AttrCryptoAlgorithm = attribute.Key("helm.crypto.algorithm")
	AttrCryptoOperation = attribute.Key("helm.crypto.operation")
	AttrCryptoKeyID     = attribute.Key("helm.crypto.key_id")
)

// GovernanceOperation creates attributes for governance operations.
func GovernanceOperation(entityID, state, action string, epoch int64) []attribute.KeyValue {
	return []attribute.KeyValue{
		AttrEntityID.String(entityID),
		AttrGovernanceState.String(state),
		AttrGovernanceAction.String(action),
		AttrGovernanceEpoch.Int64(epoch),
	}
}

// MutationOperation creates attributes for mutation operations.
func MutationOperation(entityID, mutationID, field, status string) []attribute.KeyValue {
	return []attribute.KeyValue{
		AttrEntityID.String(entityID),
		AttrMutationID.String(mutationID),
		AttrMutationField.String(field),
		AttrMutationStatus.String(status),
	}
}

// PDPOperation creates attributes for PDP evaluation.
func PDPOperation(domain, action, decision string, latencyMs float64) []attribute.KeyValue {
	return []attribute.KeyValue{
		AttrPolicyDomain.String(domain),
		AttrPolicyAction.String(action),
		AttrPDPDecision.String(decision),
		AttrPDPLatencyMs.Float64(latencyMs),
	}
}

// ComplianceOperation creates attributes for compliance checks.
func ComplianceOperation(jurisdiction, regulation, obligationID string, compliant bool) []attribute.KeyValue {
	return []attribute.KeyValue{
		AttrJurisdiction.String(jurisdiction),
		AttrRegulation.String(regulation),
		AttrObligationID.String(obligationID),
		AttrComplianceOK.Bool(compliant),
	}
}

// CryptoOperation creates attributes for cryptographic operations.
func CryptoOperation(algorithm, operation, keyID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		AttrCryptoAlgorithm.String(algorithm),
		AttrCryptoOperation.String(operation),
		AttrCryptoKeyID.String(keyID),
	}
}

// SpanFromContext extracts the span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddSpanEvent adds an event to the current span.
func AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetSpanStatus sets the span status based on error.
func SetSpanStatus(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	if err != nil {
		span.RecordError(err)
	}
}
