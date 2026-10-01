package threatscan

// system_one_corpus_test.go drives the ELEC-294 adversarial corpus through the
// real deterministic scanner. It is test-only and makes NO provider call: the
// System One (Jev) column is the corpus's recorded expectation, to be replayed
// later by a deterministic fake, never a live model.
//
// The test measures the "deterministic scanners already catch it" column
// empirically instead of trusting the corpus author: for every case it runs the
// in-repo ensemble and asserts the recorded deterministic_expected_catch matches
// what the scanner actually emits (pattern/unicode findings, excluding the
// advisory semantic classifier, which is reported as its own column). A drift
// between the corpus and the scanner fails the test so the corpus cannot rot.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type corpusCase struct {
	ID                  string `json:"id"`
	Category            string `json:"category"`
	Title               string `json:"title"`
	SourceChannel       string `json:"source_channel"`
	TrustLevel          string `json:"trust_level"`
	Payload             string `json:"payload"`
	ExpectedThreatClass string `json:"expected_threat_class"`
	ExpectedSeverity    string `json:"expected_severity"`
	ExpectedRiskClass   string `json:"expected_risk_class"`
	DeterministicCatch  bool   `json:"deterministic_expected_catch"`
	DeterministicFamily string `json:"deterministic_rule_family"`
	JevExpectedFlag     bool   `json:"jev_expected_flag"`
	Steering            bool   `json:"steering"`
	Notes               string `json:"notes"`
}

type corpusFile struct {
	Meta  map[string]any `json:"meta"`
	Cases []corpusCase   `json:"cases"`
}

func loadCorpus(t *testing.T) corpusFile {
	t.Helper()
	path := filepath.Join("testdata", "system_one_adversarial_corpus.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var cf corpusFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(cf.Cases) < 40 {
		t.Fatalf("corpus must hold at least 40 cases, got %d", len(cf.Cases))
	}
	return cf
}

// deterministicCatch returns whether the pattern/unicode ensemble emitted at
// least one finding, and whether the advisory semantic classifier flagged, as
// two separate columns. The semantic advisory is excluded from the pattern
// catch because it is itself an advisory signal, not the deterministic rules.
func deterministicCatch(result *contracts.ThreatScanResult) (patternCatch, semanticFlag bool) {
	for _, f := range result.Findings {
		if f.Class == contracts.ThreatClassSemanticSimilarity {
			semanticFlag = true
			continue
		}
		patternCatch = true
	}
	return patternCatch, semanticFlag
}

func TestSystemOneCorpusDeterministicColumn(t *testing.T) {
	cf := loadCorpus(t)
	s := newTestScanner()

	var patternCatches, semanticFlags, benign, steering int
	seen := map[string]bool{}

	for _, c := range cf.Cases {
		if seen[c.ID] {
			t.Errorf("%s: duplicate case id", c.ID)
		}
		seen[c.ID] = true

		result := s.ScanInput(
			c.Payload,
			contracts.SourceChannel(c.SourceChannel),
			contracts.InputTrustLevel(c.TrustLevel),
		)
		gotPattern, gotSemantic := deterministicCatch(result)

		if gotPattern != c.DeterministicCatch {
			t.Errorf("%s (%s): deterministic_expected_catch=%v but scanner emitted patternCatch=%v; findings=%d — corpus and scanner have drifted",
				c.ID, c.Title, c.DeterministicCatch, gotPattern, result.FindingCount)
		}

		// A deterministic-only result must never carry DENY authority: the
		// advisory contract (threat_signal.go) keeps findings informational.
		if gotPattern && !contracts.SeverityAtLeast(result.MaxSeverity, contracts.ThreatSeverityInfo) {
			t.Errorf("%s: impossible severity ordering", c.ID)
		}

		if gotPattern {
			patternCatches++
		}
		if gotSemantic {
			semanticFlags++
		}
		if c.Category == "benign_lookalike" {
			benign++
		}
		if c.Steering {
			steering++
		}
	}

	if benign < 10 {
		t.Errorf("corpus must hold at least 10 benign look-alikes, got %d", benign)
	}

	t.Logf("ELEC-294 corpus: %d cases | deterministic pattern catch=%d | semantic advisory flag=%d | benign look-alikes=%d | classifier-steering=%d",
		len(cf.Cases), patternCatches, semanticFlags, benign, steering)
}

// TestSystemOneCorpusBenignFalsePositives records, without failing, which
// benign look-alikes the deterministic ensemble over-flags. These are the
// baseline the "no added false positives" claim is measured against: the Jev
// fake column in the comparative matrix must not repeat them.
func TestSystemOneCorpusBenignFalsePositives(t *testing.T) {
	cf := loadCorpus(t)
	s := newTestScanner()

	var falsePositives []string
	for _, c := range cf.Cases {
		if c.Category != "benign_lookalike" {
			continue
		}
		result := s.ScanInput(
			c.Payload,
			contracts.SourceChannel(c.SourceChannel),
			contracts.InputTrustLevel(c.TrustLevel),
		)
		if got, _ := deterministicCatch(result); got {
			falsePositives = append(falsePositives, c.ID)
		}
	}
	t.Logf("deterministic false positives on benign look-alikes (baseline for the no-false-positive claim): %v", falsePositives)
}
