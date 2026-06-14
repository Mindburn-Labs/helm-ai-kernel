// Package trust — Pack Certification Levels.
//
// Per HELM 2030 Spec §4.8 — Factory Framework:
//
//	Conformance suites and certification levels required for install.
package trust

import (
	"fmt"
	"sync"
	"time"
)

// CertificationLevel defines tiered pack certification.
type CertificationLevel string

const (
	CertNone       CertificationLevel = "NONE"
	CertBasic      CertificationLevel = "BASIC"      // Passes basic tests
	CertVerified   CertificationLevel = "VERIFIED"   // Passes conformance suite
	CertProduction CertificationLevel = "PRODUCTION" // Full production hardening
)

var certOrder = map[CertificationLevel]int{
	CertNone: 0, CertBasic: 1, CertVerified: 2, CertProduction: 3,
}

// CertificationRecord records the certification of a pack.
type CertificationRecord struct {
	PackName     string             `json:"pack_name"`
	PackVersion  string             `json:"pack_version"`
	Level        CertificationLevel `json:"level"`
	CertifiedBy  string             `json:"certified_by"`
	CertifiedAt  time.Time          `json:"certified_at"`
	TestSuiteRef string             `json:"test_suite_ref"`
	TestsPassed  int                `json:"tests_passed"`
	TestsTotal   int                `json:"tests_total"`
}

// CertificationGate enforces minimum certification for pack installs.
type CertificationGate struct {
	mu           sync.Mutex
	records      map[string]*CertificationRecord // pack@version → record
	requirements map[string]CertificationLevel   // context → minimum level
}

// NewCertificationGate creates a new gate.
func NewCertificationGate() *CertificationGate {
	return &CertificationGate{
		records:      make(map[string]*CertificationRecord),
		requirements: make(map[string]CertificationLevel),
	}
}

// SetRequirement sets the minimum certification for a context.
func (g *CertificationGate) SetRequirement(context string, level CertificationLevel) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requirements[context] = level
}

// RecordCertification records a pack's certification level.
//
// VERIFIED and higher certifications must carry signed test-suite evidence: a
// non-zero TestsTotal where every test passed. A record that claims VERIFIED or
// PRODUCTION without a clean, non-empty test run is rejected and not stored, so
// CheckInstall can never grant an install on an unsubstantiated certification.
func (g *CertificationGate) RecordCertification(record *CertificationRecord) error {
	if certOrder[record.Level] >= certOrder[CertVerified] {
		if record.TestsTotal == 0 || record.TestsPassed != record.TestsTotal {
			return fmt.Errorf("certification %s for %s@%s requires a complete test suite: %d/%d tests passed",
				record.Level, record.PackName, record.PackVersion, record.TestsPassed, record.TestsTotal)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key := record.PackName + "@" + record.PackVersion
	g.records[key] = record
	return nil
}

// CheckInstall verifies a pack meets the certification requirement for a context.
func (g *CertificationGate) CheckInstall(packName, packVersion, context string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	required, ok := g.requirements[context]
	if !ok {
		required = CertBasic // Default minimum
	}

	key := packName + "@" + packVersion
	record, ok := g.records[key]
	if !ok {
		return fmt.Errorf("pack %s@%s has no certification record", packName, packVersion)
	}

	if certOrder[record.Level] < certOrder[required] {
		return fmt.Errorf("pack %s@%s has certification %s, requires %s for context %q",
			packName, packVersion, record.Level, required, context)
	}
	return nil
}

// GetCertification returns the certification record for a pack.
func (g *CertificationGate) GetCertification(packName, packVersion string) (*CertificationRecord, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := packName + "@" + packVersion
	r, ok := g.records[key]
	if !ok {
		return nil, fmt.Errorf("no certification for %s@%s", packName, packVersion)
	}
	return r, nil
}
