package adversarial

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// DetectorRevision is bumped whenever mandatory adversarial detector or
// mutation semantics change. The runner executable digest remains the exact
// implementation identity; this revision is the source-owned compatibility
// key used by campaign policy.
const DetectorRevision = "kernel-adversarial-detectors/v1.3.0"

// DetectorDefinition is the complete ordered source-owned detector contract.
// It binds each mandatory suite to the deterministic negative mutation and
// exact detector test that must reject it.
type DetectorDefinition struct {
	Revision string                    `json:"revision"`
	Suites   []DetectorSuiteDefinition `json:"suites"`
}

// DetectorSuiteDefinition binds one mandatory suite to its negative control.
type DetectorSuiteDefinition struct {
	SuiteID        string `json:"suite_id"`
	Name           string `json:"name"`
	MutationID     string `json:"mutation_id"`
	ExpectedTestID string `json:"expected_test_id"`
}

// Definition returns a fresh immutable-by-copy view of the detector contract.
// It fails closed when a suite, mutation, or expected detector test is missing
// or duplicated instead of publishing an incomplete compatibility digest.
func Definition() (DetectorDefinition, error) {
	suites := AllSuites()
	mutations := mandatoryCoverageMutations()
	definition := DetectorDefinition{
		Revision: DetectorRevision,
		Suites:   make([]DetectorSuiteDefinition, 0, len(suites)),
	}
	seenSuites := make(map[string]struct{}, len(suites))
	seenMutations := make(map[string]struct{}, len(suites))
	for _, suite := range suites {
		if suite == nil || suite.ID == "" || suite.Name == "" {
			return DetectorDefinition{}, fmt.Errorf("mandatory detector suite has an empty identity")
		}
		if _, exists := seenSuites[suite.ID]; exists {
			return DetectorDefinition{}, fmt.Errorf("mandatory detector suite %q is duplicated", suite.ID)
		}
		mutation, exists := mutations[suite.ID]
		if !exists || mutation.ID == "" || mutation.ExpectedTestID == "" || mutation.Apply == nil {
			return DetectorDefinition{}, fmt.Errorf("mandatory detector suite %q has no complete mutation binding", suite.ID)
		}
		if _, exists := seenMutations[mutation.ID]; exists {
			return DetectorDefinition{}, fmt.Errorf("mandatory detector mutation %q is duplicated", mutation.ID)
		}
		seenSuites[suite.ID] = struct{}{}
		seenMutations[mutation.ID] = struct{}{}
		definition.Suites = append(definition.Suites, DetectorSuiteDefinition{
			SuiteID:        suite.ID,
			Name:           suite.Name,
			MutationID:     mutation.ID,
			ExpectedTestID: mutation.ExpectedTestID,
		})
	}
	if len(mutations) != len(definition.Suites) {
		return DetectorDefinition{}, fmt.Errorf("mutation catalog has %d entries for %d mandatory suites", len(mutations), len(definition.Suites))
	}
	return definition, nil
}

// DefinitionDigest binds the ordered suite, mutation, and expected-test
// catalog plus semantic revision into campaign runner provenance.
func DefinitionDigest() (string, error) {
	definition, err := Definition()
	if err != nil {
		return "", err
	}
	payload, err := canonicalize.JCS(definition)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
