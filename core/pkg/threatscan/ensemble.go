// ensemble.go implements multi-scanner voting for defense-in-depth.
// Per arXiv 2509.14285, coordinated specialized scanners achieve 100% mitigation.
// Per arXiv 2512.08417, attention-based detection enhances signal quality.
//
// The ensemble runs multiple independent scanners and aggregates findings
// using a configurable voting strategy.
//
// Design invariants:
//   - Each scanner votes independently
//   - Voting strategies: ANY (one scanner = finding), MAJORITY, UNANIMOUS
//   - Results include per-scanner attribution for debugging
//   - Thread-safe for concurrent scanning
package threatscan

import (
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// VotingStrategy determines how scanner findings are aggregated into consensus.
type VotingStrategy string

const (
	// VotingAny triggers consensus if any single scanner reports a finding.
	VotingAny VotingStrategy = "ANY"
	// VotingMajority triggers consensus if >50% of scanners report findings.
	VotingMajority VotingStrategy = "MAJORITY"
	// VotingUnanimous triggers consensus only if all scanners report findings.
	VotingUnanimous VotingStrategy = "UNANIMOUS"
)

// NamedScanner pairs a descriptive name with a Scanner instance for attribution.
type NamedScanner struct {
	Name    string
	Scanner *Scanner
}

// EnsembleResult is the aggregated output of a multi-scanner voting scan.
type EnsembleResult struct {
	ScanID       string                    `json:"scan_id"`
	Timestamp    time.Time                 `json:"timestamp"`
	Strategy     VotingStrategy            `json:"strategy"`
	Consensus    bool                      `json:"consensus"`
	MaxSeverity  contracts.ThreatSeverity  `json:"max_severity"`
	ScannerVotes []ScannerVote             `json:"scanner_votes"`
	Findings     []contracts.ThreatFinding `json:"findings"`
}

// ScannerVote records the independent result of a single scanner in the ensemble.
type ScannerVote struct {
	ScannerName  string                   `json:"scanner_name"`
	FindingCount int                      `json:"finding_count"`
	MaxSeverity  contracts.ThreatSeverity `json:"max_severity"`
}

// EnsembleOption configures optional behavior for EnsembleScanner.
type EnsembleOption func(*EnsembleScanner)

// EnsembleScanner orchestrates multiple independent scanners and aggregates
// their findings using a configurable voting strategy.
type EnsembleScanner struct {
	scanners []NamedScanner
	strategy VotingStrategy
	clock    func() time.Time
}

// NewEnsembleScanner creates an EnsembleScanner with the given voting strategy
// and scanner set.
func NewEnsembleScanner(strategy VotingStrategy, opts ...EnsembleOption) *EnsembleScanner {
	e := &EnsembleScanner{
		strategy: strategy,
		clock:    time.Now,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// WithEnsembleScanners adds named scanners to the ensemble.
func WithEnsembleScanners(scanners ...NamedScanner) EnsembleOption {
	return func(e *EnsembleScanner) {
		e.scanners = append(e.scanners, scanners...)
	}
}

// WithEnsembleClock overrides the time source for deterministic replay.
func WithEnsembleClock(clock func() time.Time) EnsembleOption {
	return func(e *EnsembleScanner) {
		e.clock = clock
	}
}

// Scan runs all scanners independently on the given input and aggregates
// results using the configured voting strategy.
func (e *EnsembleScanner) Scan(input string, channel contracts.SourceChannel, trust contracts.InputTrustLevel) *EnsembleResult {
	now := e.clock()

	votes := make([]ScannerVote, 0, len(e.scanners))
	var allFindings []contracts.ThreatFinding
	votersWithFindings := 0

	for _, ns := range e.scanners {
		result := ns.Scanner.ScanInput(input, channel, trust)

		vote := ScannerVote{
			ScannerName:  ns.Name,
			FindingCount: result.FindingCount,
			MaxSeverity:  result.MaxSeverity,
		}
		votes = append(votes, vote)

		if result.FindingCount > 0 {
			votersWithFindings++
			allFindings = append(allFindings, result.Findings...)
		}
	}

	consensus := e.computeConsensus(votersWithFindings, len(e.scanners))
	maxSev := contracts.ThreatSeverityInfo
	if consensus && len(allFindings) > 0 {
		maxSev = contracts.MaxSeverityOf(allFindings)
	}

	// When consensus is not reached, do not emit findings.
	var emittedFindings []contracts.ThreatFinding
	if consensus {
		emittedFindings = allFindings
	}

	return &EnsembleResult{
		ScanID:       fmt.Sprintf("ensemble-%d", now.UnixNano()),
		Timestamp:    now,
		Strategy:     e.strategy,
		Consensus:    consensus,
		MaxSeverity:  maxSev,
		ScannerVotes: votes,
		Findings:     emittedFindings,
	}
}

// computeConsensus determines whether the voting threshold is met.
func (e *EnsembleScanner) computeConsensus(votersWithFindings, totalVoters int) bool {
	if totalVoters == 0 {
		return false
	}
	if votersWithFindings == 0 {
		return false
	}

	switch e.strategy {
	case VotingAny:
		return votersWithFindings >= 1
	case VotingMajority:
		return votersWithFindings > totalVoters/2
	case VotingUnanimous:
		return votersWithFindings == totalVoters
	default:
		// Unknown strategy: fail closed — no consensus.
		return false
	}
}
