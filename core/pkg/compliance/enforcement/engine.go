// Package enforcement integrates SCO with SwarmPDP for policy evaluation.
// Part of the Sovereign Compliance Oracle (SCO).
package enforcement

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/compiler"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// PolicyResult represents the outcome of a policy evaluation.
type PolicyResult string

const (
	Permit        PolicyResult = "PERMIT"         // Compliant
	Deny          PolicyResult = "DENY"           // Non-compliant
	Indeterminate PolicyResult = "INDETERMINATE"  // Error or unknown
	NotApplicable PolicyResult = "NOT_APPLICABLE" // Rule doesn't apply
)

// EnforcementResult represents the outcome of a compliance check.
type EnforcementResult struct {
	RequestID      string                                       `json:"request_id"`
	EntityID       string                                       `json:"entity_id"`
	Timestamp      time.Time                                    `json:"timestamp"`
	Overall        PolicyResult                                 `json:"overall"`
	ByObligation   []*ObligationResult                          `json:"by_obligation"`
	ByJurisdiction map[jkg.JurisdictionCode]*JurisdictionResult `json:"by_jurisdiction"`
	Conflicts      []*ConflictResult                            `json:"conflicts,omitempty"`
	RiskScore      float64                                      `json:"risk_score"`
	EvaluationTime time.Duration                                `json:"evaluation_time"`
	GraphVersion   string                                       `json:"graph_version"`
}

// ObligationResult is the result for a single obligation.
type ObligationResult struct {
	ObligationID string        `json:"obligation_id"`
	Framework    string        `json:"framework"`
	Title        string        `json:"title"`
	Result       PolicyResult  `json:"result"`
	CELExpr      string        `json:"cel_expr,omitempty"`
	RiskLevel    jkg.RiskLevel `json:"risk_level"`
	ErrorMessage string        `json:"error_message,omitempty"`
}

// JurisdictionResult aggregates results by jurisdiction.
type JurisdictionResult struct {
	JurisdictionCode jkg.JurisdictionCode `json:"jurisdiction_code"`
	TotalObligations int                  `json:"total_obligations"`
	Compliant        int                  `json:"compliant"`
	NonCompliant     int                  `json:"non_compliant"`
	NotApplicable    int                  `json:"not_applicable"`
	Errors           int                  `json:"errors"`
}

// ConflictResult describes a detected regulatory conflict.
type ConflictResult struct {
	ObligationA   string               `json:"obligation_a"`
	ObligationB   string               `json:"obligation_b"`
	JurisdictionA jkg.JurisdictionCode `json:"jurisdiction_a"`
	JurisdictionB jkg.JurisdictionCode `json:"jurisdiction_b"`
	Resolution    string               `json:"resolution"`
	Notes         string               `json:"notes,omitempty"`
}

// EnforcementRequest is the input for a compliance check.
type EnforcementRequest struct {
	RequestID     string                 `json:"request_id"`
	EntityID      string                 `json:"entity_id"`
	EntityType    string                 `json:"entity_type"`
	Jurisdictions []jkg.JurisdictionCode `json:"jurisdictions"`
	Frameworks    []string               `json:"frameworks,omitempty"`
	Context       map[string]interface{} `json:"context"`
	AsOfDate      time.Time              `json:"as_of_date,omitempty"`
}

// EnforcementEngine integrates SCO components for compliance evaluation.
type EnforcementEngine struct {
	mu        sync.RWMutex
	graph     *jkg.Graph
	query     *jkg.Query
	compiler  *compiler.Compiler
	evaluator PolicyEvaluator
	config    *EnforcementConfig
	metrics   *EnforcementMetrics
}

// EnforcementConfig configures the enforcement engine.
type EnforcementConfig struct {
	MaxConcurrentEvaluations int           `json:"max_concurrent_evaluations"`
	EvaluationTimeout        time.Duration `json:"evaluation_timeout"`
	CacheEnabled             bool          `json:"cache_enabled"`
	CacheTTL                 time.Duration `json:"cache_ttl"`
}

// DefaultEnforcementConfig returns sensible defaults.
func DefaultEnforcementConfig() *EnforcementConfig {
	return &EnforcementConfig{
		MaxConcurrentEvaluations: 50,
		EvaluationTimeout:        5 * time.Second,
		CacheEnabled:             true,
		CacheTTL:                 5 * time.Minute,
	}
}

// EnforcementMetrics tracks enforcement performance.
type EnforcementMetrics struct {
	mu                sync.RWMutex
	TotalEvaluations  int64                          `json:"total_evaluations"`
	CompliantCount    int64                          `json:"compliant_count"`
	NonCompliantCount int64                          `json:"non_compliant_count"`
	ErrorCount        int64                          `json:"error_count"`
	AvgEvaluationTime time.Duration                  `json:"avg_evaluation_time"`
	ByJurisdiction    map[jkg.JurisdictionCode]int64 `json:"by_jurisdiction"`
	ByFramework       map[string]int64               `json:"by_framework"`
	ConflictsDetected int64                          `json:"conflicts_detected"`
}

// PolicyEvaluator is the interface for evaluating compiled policies.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, expr string, input map[string]interface{}) (PolicyResult, error)
}

// NewEnforcementEngine creates a new enforcement engine.
func NewEnforcementEngine(graph *jkg.Graph, evaluator PolicyEvaluator, config *EnforcementConfig) *EnforcementEngine {
	if config == nil {
		config = DefaultEnforcementConfig()
	}

	return &EnforcementEngine{
		graph:     graph,
		query:     jkg.NewQuery(graph),
		compiler:  compiler.NewCompiler(),
		evaluator: evaluator,
		config:    config,
		metrics: &EnforcementMetrics{
			ByJurisdiction: make(map[jkg.JurisdictionCode]int64),
			ByFramework:    make(map[string]int64),
		},
	}
}

// Check performs a compliance check for the given request.
func (e *EnforcementEngine) Check(ctx context.Context, req *EnforcementRequest) (*EnforcementResult, error) {
	start := time.Now()

	if req == nil {
		return nil, fmt.Errorf("nil request")
	}

	if req.RequestID == "" {
		req.RequestID = generateRequestID()
	}

	// Initialize result
	result := &EnforcementResult{
		RequestID:      req.RequestID,
		EntityID:       req.EntityID,
		Timestamp:      time.Now(),
		Overall:        Permit,
		ByObligation:   make([]*ObligationResult, 0),
		ByJurisdiction: make(map[jkg.JurisdictionCode]*JurisdictionResult),
		Conflicts:      make([]*ConflictResult, 0),
		GraphVersion:   e.graph.Hash(),
	}

	// Find applicable obligations
	applicability := e.query.FindApplicable(&jkg.ApplicabilityRequest{
		EntityID:      req.EntityID,
		EntityType:    req.EntityType,
		Jurisdictions: req.Jurisdictions,
		Frameworks:    req.Frameworks,
		AsOfDate:      req.AsOfDate,
	})

	if len(applicability.Obligations) == 0 {
		result.EvaluationTime = time.Since(start)
		return result, nil
	}

	// Initialize jurisdiction results
	for _, j := range req.Jurisdictions {
		result.ByJurisdiction[j] = &JurisdictionResult{
			JurisdictionCode: j,
		}
	}

	// Evaluate each obligation
	ctx, cancel := context.WithTimeout(ctx, e.config.EvaluationTimeout)
	defer cancel()

	for _, obligation := range applicability.Obligations {
		oblResult := e.evaluateObligation(ctx, obligation, req)
		result.ByObligation = append(result.ByObligation, oblResult)

		// Update jurisdiction stats
		if jr, ok := result.ByJurisdiction[obligation.JurisdictionCode]; ok {
			jr.TotalObligations++
			switch oblResult.Result {
			case Permit:
				jr.Compliant++
			case Deny:
				jr.NonCompliant++
				result.Overall = Deny
			case NotApplicable:
				jr.NotApplicable++
			default:
				jr.Errors++
			}
		}

		// Update metrics
		e.updateMetrics(obligation, oblResult)
	}

	// Check for conflicts
	for _, conflict := range applicability.Conflicts {
		result.Conflicts = append(result.Conflicts, &ConflictResult{
			ObligationA:   conflict.ObligationA.ObligationID,
			ObligationB:   conflict.ObligationB.ObligationID,
			JurisdictionA: conflict.ObligationA.JurisdictionCode,
			JurisdictionB: conflict.ObligationB.JurisdictionCode,
			Resolution:    conflict.Recommendation,
			Notes:         conflict.ConflictReason,
		})
	}

	// Calculate risk score
	result.RiskScore = e.calculateRiskScore(result)
	result.EvaluationTime = time.Since(start)

	// Update global metrics
	e.metrics.mu.Lock()
	e.metrics.TotalEvaluations++
	if result.Overall == Permit {
		e.metrics.CompliantCount++
	} else {
		e.metrics.NonCompliantCount++
	}
	if e.metrics.AvgEvaluationTime == 0 {
		e.metrics.AvgEvaluationTime = result.EvaluationTime
	} else {
		e.metrics.AvgEvaluationTime = (e.metrics.AvgEvaluationTime + result.EvaluationTime) / 2
	}
	e.metrics.ConflictsDetected += int64(len(result.Conflicts))
	e.metrics.mu.Unlock()

	return result, nil
}

// evaluateObligation evaluates a single obligation.
func (e *EnforcementEngine) evaluateObligation(ctx context.Context, obl *jkg.Obligation, req *EnforcementRequest) *ObligationResult {
	oblResult := &ObligationResult{
		ObligationID: obl.ObligationID,
		Framework:    obl.Framework,
		Title:        obl.Title,
		RiskLevel:    obl.RiskLevel,
	}

	// Compile obligation to CEL
	policy, err := e.compiler.CompileFromText(obl.Description, obl.Framework, obl.ArticleRef)
	if err != nil {
		oblResult.Result = Indeterminate
		oblResult.ErrorMessage = fmt.Sprintf("compilation error: %v", err)
		return oblResult
	}

	oblResult.CELExpr = policy.FullExpr

	// Evaluate if we have an evaluator
	if e.evaluator != nil {
		evalResult, err := e.evaluator.Evaluate(ctx, policy.FullExpr, req.Context)
		if err != nil {
			oblResult.Result = Indeterminate
			oblResult.ErrorMessage = fmt.Sprintf("evaluation error: %v", err)
			return oblResult
		}
		oblResult.Result = evalResult
	} else {
		// No evaluator configured — cannot verify compliance.
		// Fail-closed: report as INDETERMINATE, never assume compliant.
		oblResult.Result = Indeterminate
		oblResult.ErrorMessage = "no policy evaluator configured"
	}

	return oblResult
}

// calculateRiskScore computes an aggregate risk score.
func (e *EnforcementEngine) calculateRiskScore(result *EnforcementResult) float64 {
	if len(result.ByObligation) == 0 {
		return 0.0
	}

	totalRisk := 0.0
	nonCompliantWeight := 0.0

	for _, obl := range result.ByObligation {
		weight := riskWeight(obl.RiskLevel)
		if obl.Result == Deny {
			nonCompliantWeight += weight
		}
		totalRisk += weight
	}

	if totalRisk == 0 {
		return 0.0
	}

	return nonCompliantWeight / totalRisk
}

// riskWeight returns the weight for a risk level.
func riskWeight(level jkg.RiskLevel) float64 {
	switch level {
	case jkg.RiskCritical:
		return 4.0
	case jkg.RiskHigh:
		return 3.0
	case jkg.RiskMedium:
		return 2.0
	case jkg.RiskLow:
		return 1.0
	default:
		return 0.5
	}
}

// updateMetrics updates per-obligation metrics.
func (e *EnforcementEngine) updateMetrics(obl *jkg.Obligation, result *ObligationResult) {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	e.metrics.ByJurisdiction[obl.JurisdictionCode]++
	e.metrics.ByFramework[obl.Framework]++

	if result.Result == Indeterminate {
		e.metrics.ErrorCount++
	}
}

// GetMetrics returns current metrics.
func (e *EnforcementEngine) GetMetrics() *EnforcementMetrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()
	return e.metrics
}

// GetGraph returns the underlying JKG graph.
func (e *EnforcementEngine) GetGraph() *jkg.Graph {
	return e.graph
}

// GetQuery returns the query interface.
func (e *EnforcementEngine) GetQuery() *jkg.Query {
	return e.query
}

// RefreshGraph replaces the graph with a new version.
func (e *EnforcementEngine) RefreshGraph(graph *jkg.Graph) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.graph = graph
	e.query = jkg.NewQuery(graph)
}

// Helper functions

func generateRequestID() string {
	randomBytes := make([]byte, 16)
	if _, err := cryptoRand.Read(randomBytes); err != nil {
		// Fallback to time-based ID if crypto/rand fails
		h := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(h[:])[:12]
	}
	h := sha256.Sum256(randomBytes)
	return hex.EncodeToString(h[:])[:12]
}
