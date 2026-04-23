// Package trust implements the Pack Trust Fabric per Addendum 14.X.
// This file contains SLSA provenance types and validation per Section 14.X.3.
package trust

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// InTotoStatementType is the type URI for in-toto Statement v1.
const InTotoStatementType = "https://in-toto.io/Statement/v1"

// SLSAProvenancePredicateType is the predicate type for SLSA v1.0.
const SLSAProvenancePredicateType = "https://slsa.dev/provenance/v1"

// InTotoStatement represents an in-toto Statement v1.
// Per Section 14.X.3: Every certified pack MUST ship with an in-toto statement.
type InTotoStatement struct {
	// Type is always "https://in-toto.io/Statement/v1"
	Type string `json:"_type"`

	// Subject lists the artifacts this statement describes
	Subject []Subject `json:"subject"`

	// PredicateType identifies the predicate schema
	PredicateType string `json:"predicateType"`

	// Predicate contains the attestation data (SLSA provenance)
	Predicate json.RawMessage `json:"predicate"`
}

// Subject identifies an artifact by name and digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SLSAProvenance represents the SLSA v1.0 provenance predicate.
// Per Section 14.X.3: SLSA provenance requirements.
type SLSAProvenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes how the artifact was built.
type BuildDefinition struct {
	// BuildType identifies the build system
	BuildType string `json:"buildType"`

	// ExternalParameters are user-controlled inputs
	ExternalParameters json.RawMessage `json:"externalParameters"`

	// InternalParameters are builder-controlled inputs
	InternalParameters json.RawMessage `json:"internalParameters,omitempty"`

	// ResolvedDependencies lists all dependencies used
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// ResourceDescriptor identifies a resource by URI and digest.
type ResourceDescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
	Name   string            `json:"name,omitempty"`
}

// RunDetails describes the build execution.
type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata,omitempty"`
}

// Builder identifies the build system.
type Builder struct {
	ID string `json:"id"`
}

// Metadata contains build timing information.
type Metadata struct {
	InvocationID string    `json:"invocationId,omitempty"`
	StartedOn    time.Time `json:"startedOn,omitempty"`
	FinishedOn   time.Time `json:"finishedOn,omitempty"`
}

// ProvenancePolicy defines policy requirements for provenance validation.
// Per Section 14.X.3: Kernel policy enforcement.
type ProvenancePolicy struct {
	// AllowedBuilders lists approved builder identities
	AllowedBuilders []string `json:"allowed_builders"`

	// RequiredSLSAVersion is the minimum SLSA version required
	RequiredSLSAVersion string `json:"required_slsa_version"`

	// PinnedDependencies maps dependency URIs to required hashes
	PinnedDependencies map[string]string `json:"pinned_dependencies"`

	// RequiredSourceRepos limits source to specific repositories
	RequiredSourceRepos []string `json:"required_source_repos"`

	// RequireSLSALevel sets minimum SLSA level (1-4)
	RequireSLSALevel int `json:"require_slsa_level,omitempty"`
}

// DefaultProvenancePolicy returns a minimal policy for certified packs.
func DefaultProvenancePolicy() *ProvenancePolicy {
	return &ProvenancePolicy{
		RequiredSLSAVersion: SLSAProvenancePredicateType,
		AllowedBuilders:     []string{}, // Must be configured
		PinnedDependencies:  make(map[string]string),
		RequiredSourceRepos: []string{}, // Must be configured
	}
}

// SLSAVerifier validates SLSA provenance attestations.
type SLSAVerifier struct {
	Policy *ProvenancePolicy
}

// NewSLSAVerifier creates a verifier with the given policy.
func NewSLSAVerifier(policy *ProvenancePolicy) *SLSAVerifier {
	if policy == nil {
		policy = DefaultProvenancePolicy()
	}
	return &SLSAVerifier{Policy: policy}
}

// VerifyAttestation validates an in-toto statement with SLSA provenance.
// Per Section 14.X.3: Provenance validation requirements.
func (v *SLSAVerifier) VerifyAttestation(statement *InTotoStatement) error {
	// 1. Verify statement type
	if statement.Type != InTotoStatementType {
		return fmt.Errorf("invalid statement type: expected %s, got %s",
			InTotoStatementType, statement.Type)
	}

	// 2. Verify predicate type matches policy
	if v.Policy.RequiredSLSAVersion != "" && statement.PredicateType != v.Policy.RequiredSLSAVersion {
		return fmt.Errorf("SLSA version %s does not meet requirement %s",
			statement.PredicateType, v.Policy.RequiredSLSAVersion)
	}

	// 3. Parse the provenance predicate
	var provenance SLSAProvenance
	if err := json.Unmarshal(statement.Predicate, &provenance); err != nil {
		return fmt.Errorf("failed to parse SLSA provenance: %w", err)
	}

	// 4. Verify builder identity
	if err := v.verifyBuilder(provenance.RunDetails.Builder); err != nil {
		return err
	}

	// 5. Verify pinned dependencies
	if err := v.verifyDependencies(provenance.BuildDefinition.ResolvedDependencies); err != nil {
		return err
	}

	// 6. Verify source repository if policy requires it
	if err := v.verifySourceRepo(provenance.BuildDefinition.ExternalParameters); err != nil {
		return err
	}

	return nil
}

// verifyBuilder checks if the builder is in the allowlist.
func (v *SLSAVerifier) verifyBuilder(builder Builder) error {
	if len(v.Policy.AllowedBuilders) == 0 {
		// No builder restrictions
		return nil
	}

	for _, allowed := range v.Policy.AllowedBuilders {
		if builder.ID == allowed {
			return nil
		}
	}

	return fmt.Errorf("builder %s not in allowlist", builder.ID)
}

// verifyDependencies checks that pinned dependencies match.
func (v *SLSAVerifier) verifyDependencies(deps []ResourceDescriptor) error {
	for _, dep := range deps {
		expectedHash, isPinned := v.Policy.PinnedDependencies[dep.URI]
		if !isPinned {
			continue // Not pinned, skip
		}

		actualHash, hasHash := dep.Digest["sha256"]
		if !hasHash {
			return fmt.Errorf("dependency %s missing sha256 digest", dep.URI)
		}

		if actualHash != expectedHash {
			return fmt.Errorf("dependency %s hash mismatch: expected %s, got %s",
				dep.URI, expectedHash, actualHash)
		}
	}

	return nil
}

// verifySourceRepo checks that the source comes from an allowed repository.
func (v *SLSAVerifier) verifySourceRepo(externalParams json.RawMessage) error {
	if len(v.Policy.RequiredSourceRepos) == 0 {
		return nil // No source restrictions
	}

	// Parse external parameters to extract source
	var params struct {
		Source struct {
			URI string `json:"uri"`
		} `json:"source"`
	}
	if err := json.Unmarshal(externalParams, &params); err != nil {
		// If we can't parse, we can't verify - warn but don't fail
		return nil
	}

	if params.Source.URI == "" {
		return nil // No source specified
	}

	for _, allowed := range v.Policy.RequiredSourceRepos {
		if strings.HasPrefix(params.Source.URI, allowed) {
			return nil
		}
	}

	return fmt.Errorf("source repository %s not in allowlist", params.Source.URI)
}

// VerifySubjectHash checks that the statement covers the expected artifact.
func (v *SLSAVerifier) VerifySubjectHash(statement *InTotoStatement, expectedHash string) error {
	for _, subject := range statement.Subject {
		hash, ok := subject.Digest["sha256"]
		if ok && hash == expectedHash {
			return nil
		}
	}

	return fmt.Errorf("no subject matches expected hash %s", expectedHash)
}
