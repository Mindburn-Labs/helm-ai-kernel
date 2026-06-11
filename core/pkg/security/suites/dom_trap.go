package suites

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/trust"
	"github.com/google/uuid"
)

const domTrapEvidenceDirEnv = "HELM_DOM_TRAP_EVIDENCE_DIR"

type domTrapEvidence struct {
	Trap         string   `json:"trap"`
	Browser      string   `json:"browser"`
	FixtureHash  string   `json:"fixture_hash"`
	ArtifactHash string   `json:"artifact_hash"`
	Guard        string   `json:"guard"`
	Observations []string `json:"observations"`
	Passed       bool     `json:"passed"`
}

// RegisterDOMTrapSuite registers the DOM trap test suite with the lab.
func RegisterDOMTrapSuite(lab *trust.AdversarialLab) {
	suite := &trust.TestSuite{
		SuiteID:     uuid.New().String(),
		Name:        "dom_trap",
		Description: "Tests resilience against malicious DOM structures and CDP traps",
		Category:    "dom_trap",
		Tests:       []trust.TestCase{},
	}

	// Test 1: Infinite Scroll
	suite.Tests = append(suite.Tests, trust.TestCase{
		TestID:      uuid.New().String(),
		Name:        "infinite_scroll_trap",
		Description: "Page that generates infinite content on scroll",
		Severity:    trust.SeverityMedium,
		Runner:      domTrapRunner("infinite_scroll_trap", "Scroll loop halted by max depth guard"),
	})

	// Test 2: Hidden Overlay
	suite.Tests = append(suite.Tests, trust.TestCase{
		TestID:      uuid.New().String(),
		Name:        "hidden_overlay",
		Description: "Transparent div intercepting clicks intended for buttons",
		Severity:    trust.SeverityHigh,
		Runner:      domTrapRunner("hidden_overlay", "Click interception detected via z-index analysis"),
	})

	// Test 3: Resource Exhaustion
	suite.Tests = append(suite.Tests, trust.TestCase{
		TestID:      uuid.New().String(),
		Name:        "resource_exhaustion",
		Description: "DOM tree with 1M nodes",
		Severity:    trust.SeverityHigh,
		Runner:      domTrapRunner("resource_exhaustion", "Render halted by node count limit"),
	})

	lab.RegisterSuite(suite)
}

func domTrapRunner(trapName, passMessage string) trust.TestRunner {
	return func() trust.TestResult {
		started := time.Now()
		evidenceDir := strings.TrimSpace(os.Getenv(domTrapEvidenceDirEnv))
		if evidenceDir == "" {
			return domTrapNonCertifyingResult(trapName, "missing_browser_evidence", started)
		}

		evidencePath := filepath.Join(evidenceDir, trapName+".json")
		raw, err := os.ReadFile(evidencePath)
		if err != nil {
			return domTrapNonCertifyingResult(trapName, "missing_browser_evidence", started)
		}

		var evidence domTrapEvidence
		if err := json.Unmarshal(raw, &evidence); err != nil {
			return domTrapNonCertifyingResult(trapName, "invalid_browser_evidence", started)
		}
		if reason := evidence.nonCertifyingReason(trapName); reason != "" {
			return domTrapNonCertifyingResult(trapName, reason, started)
		}

		return trust.TestResult{
			Passed:   true,
			Message:  passMessage,
			Duration: time.Since(started),
			Evidence: fmt.Sprintf(
				"browser=%s fixture_hash=%s artifact_hash=%s guard=%s observations=%d",
				evidence.Browser,
				evidence.FixtureHash,
				evidence.ArtifactHash,
				evidence.Guard,
				len(evidence.Observations),
			),
		}
	}
}

func domTrapNonCertifyingResult(trapName, reason string, started time.Time) trust.TestResult {
	return trust.TestResult{
		Passed:   false,
		Message:  "DOM trap check requires browser/CDP evidence artifact",
		Duration: time.Since(started),
		Evidence: fmt.Sprintf("non_certifying:%s:%s", reason, trapName),
	}
}

func (e domTrapEvidence) nonCertifyingReason(trapName string) string {
	if e.Trap != trapName {
		return "trap_mismatch"
	}
	if !e.Passed {
		return "browser_evidence_failed"
	}
	if strings.TrimSpace(e.Browser) == "" {
		return "missing_browser"
	}
	if !validDOMTrapSHA256(e.FixtureHash) {
		return "invalid_fixture_hash"
	}
	if !validDOMTrapSHA256(e.ArtifactHash) {
		return "invalid_artifact_hash"
	}
	if strings.TrimSpace(e.Guard) == "" {
		return "missing_guard"
	}
	for _, observation := range e.Observations {
		if strings.TrimSpace(observation) != "" {
			return ""
		}
	}
	return "missing_observations"
}

func validDOMTrapSHA256(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	trimmed = strings.TrimPrefix(trimmed, "sha256:")
	if len(trimmed) != 64 {
		return false
	}
	for _, r := range trimmed {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
