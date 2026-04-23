// Package governance provides SwarmPDP for parallel policy evaluation.
// Inspired by Kimi K2.5 PARL agent swarm paradigm.
package governance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// SwarmPDPConfig configures the parallel policy decision point.
type SwarmPDPConfig struct {
	// MaxParallelPDPs is the maximum number of parallel evaluators (per K2.5: up to 100)
	MaxParallelPDPs int `json:"max_parallel_pdps"`

	// EnableMetrics enables PARL critical path tracking
	EnableMetrics bool `json:"enable_metrics"`

	// DomainDecomposition enables splitting by policy domain
	DomainDecomposition bool `json:"domain_decomposition"`

	// StrictMerge if true, any DENY wins; if false, uses priority-based merge
	StrictMerge bool `json:"strict_merge"`
}

// DefaultSwarmPDPConfig returns a production-ready configuration.
func DefaultSwarmPDPConfig() *SwarmPDPConfig {
	return &SwarmPDPConfig{
		MaxParallelPDPs:     16,
		EnableMetrics:       true,
		DomainDecomposition: true,
		StrictMerge:         true, // DENY always wins for safety
	}
}

// SwarmPDPMetric tracks PARL critical path for policy evaluation.
type SwarmPDPMetric struct {
	mu                 sync.RWMutex
	StageIndex         int     `json:"stage_index"`
	OrchestrationSteps []int   `json:"orchestration_steps"`
	MaxBranchSteps     []int   `json:"max_branch_steps"`
	TotalCriticalSteps int     `json:"total_critical_steps"`
	TotalRequests      int     `json:"total_requests"`
	TotalBatches       int     `json:"total_batches"`
	AvgParallelism     float64 `json:"avg_parallelism"`
}

// NewSwarmPDPMetric creates a new metric tracker.
func NewSwarmPDPMetric() *SwarmPDPMetric {
	return &SwarmPDPMetric{
		OrchestrationSteps: make([]int, 0),
		MaxBranchSteps:     make([]int, 0),
	}
}

// RecordBatch records T = Σₜ[S_main + max S_sub] for a batch.
func (m *SwarmPDPMetric) RecordBatch(orchestrationSteps int, branchSteps []int, requestCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	maxBranch := 0
	for _, s := range branchSteps {
		if s > maxBranch {
			maxBranch = s
		}
	}

	m.OrchestrationSteps = append(m.OrchestrationSteps, orchestrationSteps)
	m.MaxBranchSteps = append(m.MaxBranchSteps, maxBranch)
	m.StageIndex++
	m.TotalBatches++
	m.TotalRequests += requestCount

	m.TotalCriticalSteps = 0
	for i := range m.OrchestrationSteps {
		m.TotalCriticalSteps += m.OrchestrationSteps[i] + m.MaxBranchSteps[i]
	}

	if m.TotalBatches > 0 {
		m.AvgParallelism = float64(m.TotalRequests) / float64(m.TotalBatches)
	}
}

// PolicyDomain represents a policy evaluation domain.
type PolicyDomain string

const (
	DomainAuthorization PolicyDomain = "authorization"
	DomainCompliance    PolicyDomain = "compliance"
	DomainRisk          PolicyDomain = "risk"
	DomainAudit         PolicyDomain = "audit"
	DomainGeneral       PolicyDomain = "general"
)

// RequestGroup represents a group of requests in the same domain.
type RequestGroup struct {
	Domain   PolicyDomain `json:"domain"`
	Requests []PDPRequest `json:"requests"`
}

// BatchResult contains the result of a batch evaluation.
type BatchResult struct {
	Responses     []*PDPResponse `json:"responses"`
	CriticalSteps int            `json:"critical_steps"`
	ParallelLanes int            `json:"parallel_lanes"`
	Duration      time.Duration  `json:"duration"`
}

// SwarmPDP implements PolicyDecisionPoint with K2.5-style parallel evaluation.
type SwarmPDP struct {
	mu            sync.RWMutex
	config        *SwarmPDPConfig
	basePDP       PolicyDecisionPoint
	metrics       *SwarmPDPMetric
	policyVersion string
}

// NewSwarmPDP creates a new swarm-based PDP.
func NewSwarmPDP(basePDP PolicyDecisionPoint, config *SwarmPDPConfig) *SwarmPDP {
	if config == nil {
		config = DefaultSwarmPDPConfig()
	}

	return &SwarmPDP{
		config:        config,
		basePDP:       basePDP,
		metrics:       NewSwarmPDPMetric(),
		policyVersion: basePDP.PolicyVersion(),
	}
}

// Evaluate implements PolicyDecisionPoint for single requests.
func (s *SwarmPDP) Evaluate(ctx context.Context, req PDPRequest) (*PDPResponse, error) {
	// For single requests, delegate to base PDP
	return s.basePDP.Evaluate(ctx, req)
}

// PolicyVersion implements PolicyDecisionPoint.
func (s *SwarmPDP) PolicyVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policyVersion
}

// EvaluateBatch processes multiple requests with parallel execution.
// Per K2.5 PARL: spawn sub-agents for independent policy domains.
func (s *SwarmPDP) EvaluateBatch(ctx context.Context, requests []PDPRequest) (*BatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := time.Now()

	if len(requests) == 0 {
		return &BatchResult{
			Responses:     []*PDPResponse{},
			CriticalSteps: 0,
			ParallelLanes: 0,
			Duration:      time.Since(start),
		}, nil
	}

	// Decompose by policy domain
	groups := s.decomposeByDomain(requests)

	// Prepare parallel evaluation
	type evalResult struct {
		index    int
		response *PDPResponse
		steps    int
		err      error
	}

	results := make(chan evalResult, len(requests))
	sem := make(chan struct{}, s.config.MaxParallelPDPs)
	var wg sync.WaitGroup

	// Execute groups in parallel
	requestIndex := 0
	branchSteps := make([]int, 0, len(groups))

	for _, group := range groups {
		groupStart := requestIndex
		groupSize := len(group.Requests)

		for i, req := range group.Requests {
			wg.Add(1)
			currentIndex := groupStart + i

			go func(idx int, r PDPRequest) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				resp, err := s.basePDP.Evaluate(ctx, r)
				results <- evalResult{
					index:    idx,
					response: resp,
					steps:    1,
					err:      err,
				}
			}(currentIndex, req)
		}

		requestIndex += groupSize
		branchSteps = append(branchSteps, groupSize)
	}

	// Close results when done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results in order
	responses := make([]*PDPResponse, len(requests))
	for r := range results {
		if r.err != nil {
			return nil, r.err
		}
		responses[r.index] = r.response
	}

	// Record metrics
	if s.config.EnableMetrics {
		s.metrics.RecordBatch(1, branchSteps, len(requests))
	}

	return &BatchResult{
		Responses:     responses,
		CriticalSteps: s.metrics.TotalCriticalSteps,
		ParallelLanes: len(groups),
		Duration:      time.Since(start),
	}, nil
}

// decomposeByDomain groups requests by policy domain for parallel evaluation.
func (s *SwarmPDP) decomposeByDomain(requests []PDPRequest) []*RequestGroup {
	if !s.config.DomainDecomposition {
		// No decomposition, single group
		return []*RequestGroup{{
			Domain:   DomainGeneral,
			Requests: requests,
		}}
	}

	// Group by effect type as domain proxy
	byDomain := make(map[PolicyDomain][]PDPRequest)
	for _, req := range requests {
		domain := classifyDomain(req.Effect.EffectType)
		byDomain[domain] = append(byDomain[domain], req)
	}

	// Convert to groups
	groups := make([]*RequestGroup, 0, len(byDomain))
	for domain, reqs := range byDomain {
		groups = append(groups, &RequestGroup{
			Domain:   domain,
			Requests: reqs,
		})
	}

	// Sort for determinism
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Domain < groups[j].Domain
	})

	return groups
}

// classifyDomain classifies an effect type into a policy domain.
func classifyDomain(effectType string) PolicyDomain {
	switch effectType {
	case "authorize", "grant", "revoke", "delegate":
		return DomainAuthorization
	case "transfer", "payment", "settlement":
		return DomainCompliance
	case "trade", "position", "exposure":
		return DomainRisk
	case "log", "report", "archive":
		return DomainAudit
	default:
		return DomainGeneral
	}
}

// MergeDecisions merges multiple decisions using the configured strategy.
func (s *SwarmPDP) MergeDecisions(decisions []Decision) Decision {
	if len(decisions) == 0 {
		return DecisionDeny // Default deny
	}

	if s.config.StrictMerge {
		// Any DENY wins (fail-closed)
		for _, d := range decisions {
			if d == DecisionDeny {
				return DecisionDeny
			}
		}
		// Any REQUIRE_* takes precedence over ALLOW
		for _, d := range decisions {
			if d == DecisionRequireApproval || d == DecisionRequireEvidence {
				return d
			}
		}
		return DecisionAllow
	}

	// Priority-based merge (more permissive)
	priority := map[Decision]int{
		DecisionDeny:            5,
		DecisionRequireApproval: 4,
		DecisionRequireEvidence: 3,
		DecisionDefer:           2,
		DecisionAllow:           1,
	}

	highest := DecisionAllow
	for _, d := range decisions {
		if priority[d] > priority[highest] {
			highest = d
		}
	}
	return highest
}

// GetMetrics returns the PARL metrics.
func (s *SwarmPDP) GetMetrics() *SwarmPDPMetric {
	return s.metrics
}

// Hash returns a deterministic hash of the swarm state.
func (s *SwarmPDP) Hash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, _ := json.Marshal(struct {
		Config        *SwarmPDPConfig
		PolicyVersion string
		Metrics       *SwarmPDPMetric
	}{
		Config:        s.config,
		PolicyVersion: s.policyVersion,
		Metrics:       s.metrics,
	})

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// StreamEvaluate evaluates requests as a stream with backpressure.
//
//nolint:gocognit // complexity acceptable
func (s *SwarmPDP) StreamEvaluate(ctx context.Context, requests <-chan PDPRequest, batchSize int) (<-chan *PDPResponse, <-chan error) {
	responses := make(chan *PDPResponse, batchSize)
	errors := make(chan error, 1)

	go func() {
		defer close(responses)
		defer close(errors)

		batch := make([]PDPRequest, 0, batchSize)

		for {
			select {
			case req, ok := <-requests:
				if !ok {
					// Channel closed, process remaining batch
					if len(batch) > 0 {
						result, err := s.EvaluateBatch(ctx, batch)
						if err != nil {
							errors <- err
							return
						}
						for _, resp := range result.Responses {
							responses <- resp
						}
					}
					return
				}

				batch = append(batch, req)
				if len(batch) >= batchSize {
					result, err := s.EvaluateBatch(ctx, batch)
					if err != nil {
						errors <- err
						return
					}
					for _, resp := range result.Responses {
						responses <- resp
					}
					batch = batch[:0]
				}

			case <-ctx.Done():
				errors <- ctx.Err()
				return
			}
		}
	}()

	return responses, errors
}

// Compile-time interface check
var _ PolicyDecisionPoint = (*SwarmPDP)(nil)
