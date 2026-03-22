// Package effects defines the public contract for the HELM effects gateway.
//
// Every external side effect in a HELM-governed system MUST flow through the
// effects gateway. There is no other permitted path from agent intent to
// external effect.
//
// This OSS package defines the canonical types and interfaces. The commercial
// HELM Platform provides the full Gateway implementation with PermitGuard,
// PermitIssuer, and connector management.
//
// Architecture: Intent → PEP → KernelVerdict → EffectPermit → Gateway → Connector → Receipt
package effects
