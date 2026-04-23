// Package orgdna defines the public normative types for the HELM OrgDNA standard.
//
// OrgDNA is the declarative organizational genome — a machine-readable description
// of an organization's structure, policies, roles, principals, and governance rules.
// This package contains the canonical public type definitions that any HELM-compatible
// implementation must support.
//
// The commercial HELM Platform extends these types with a full compiler (OrgVM),
// runtime, evolution engine, and synthesis pipeline. This OSS package defines only
// the normative contract surface.
//
// Key types:
//   - OrgGenome: The declarative organizational description
//   - OrgPhenotype: The compiled runtime artifact
//   - OrgPrimitives: Units, Roles, Principals
//   - RegulationConfig: Policy set, control loops, essential variables
//   - PhenotypeContract: Determinism and output guarantees
package orgdna
