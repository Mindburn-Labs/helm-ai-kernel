// Package compiler transforms legal obligations into executable CEL policies.
// Part of the Sovereign Compliance Oracle (SCO).
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// TokenType categorizes legal text tokens.
type TokenType string

const (
	TokenSubject   TokenType = "SUBJECT"   // Who the obligation applies to
	TokenAction    TokenType = "ACTION"    // What action is regulated
	TokenCondition TokenType = "CONDITION" // Under what conditions
	TokenThreshold TokenType = "THRESHOLD" // Numeric thresholds
	TokenTimeframe TokenType = "TIMEFRAME" // Temporal constraints
	TokenPenalty   TokenType = "PENALTY"   // Consequences
	TokenException TokenType = "EXCEPTION" // Carve-outs
	TokenReference TokenType = "REFERENCE" // Cross-references
)

// Token represents a parsed legal text element.
type Token struct {
	Type       TokenType `json:"type"`
	Value      string    `json:"value"`
	Normalized string    `json:"normalized"`
	Position   int       `json:"position"`
	Confidence float64   `json:"confidence"` // 0.0-1.0
}

// ObligationAST is the Abstract Syntax Tree for a parsed obligation.
type ObligationAST struct {
	ObligationID string             `json:"obligation_id"`
	Framework    string             `json:"framework"`
	ArticleRef   string             `json:"article_ref"`
	Type         jkg.ObligationType `json:"type"`
	Tokens       []*Token           `json:"tokens"`
	Subject      *SubjectClause     `json:"subject"`
	Action       *ActionClause      `json:"action"`
	Conditions   []*ConditionClause `json:"conditions"`
	Exceptions   []*ExceptionClause `json:"exceptions"`
	Thresholds   []*ThresholdClause `json:"thresholds"`
	Timeframe    *TimeframeClause   `json:"timeframe,omitempty"`
	ParsedAt     time.Time          `json:"parsed_at"`
	Confidence   float64            `json:"confidence"`
}

// SubjectClause defines who the obligation applies to.
type SubjectClause struct {
	EntityTypes   []string `json:"entity_types"`  // e.g., ["CASP", "credit_institution"]
	Exclusions    []string `json:"exclusions"`    // Entities excluded
	Jurisdictions []string `json:"jurisdictions"` // Applicable jurisdictions
	CELExpr       string   `json:"cel_expr"`      // Compiled CEL expression
}

// ActionClause defines the regulated action.
type ActionClause struct {
	Verb     string `json:"verb"`     // e.g., "provide", "report", "obtain"
	Object   string `json:"object"`   // What is acted upon
	Modality string `json:"modality"` // "must", "must_not", "may"
	CELExpr  string `json:"cel_expr"`
}

// ConditionClause defines triggering conditions.
type ConditionClause struct {
	Type      string `json:"type"`      // "if", "when", "unless"
	Predicate string `json:"predicate"` // Natural language condition
	CELExpr   string `json:"cel_expr"`
}

// ExceptionClause defines carve-outs.
type ExceptionClause struct {
	Description string   `json:"description"`
	AppliesTo   []string `json:"applies_to"` // Entity types
	CELExpr     string   `json:"cel_expr"`
}

// ThresholdClause defines numeric thresholds.
type ThresholdClause struct {
	Name     string  `json:"name"`     // e.g., "transaction_amount"
	Operator string  `json:"operator"` // ">", ">=", "<", "<=", "=="
	Value    float64 `json:"value"`
	Unit     string  `json:"unit"` // e.g., "EUR", "percentage", "days"
	CELExpr  string  `json:"cel_expr"`
}

// TimeframeClause defines temporal constraints.
type TimeframeClause struct {
	Type     string `json:"type"`     // "within", "before", "after", "ongoing"
	Duration string `json:"duration"` // e.g., "30 days", "immediately"
	CELExpr  string `json:"cel_expr"`
}

// CompiledPolicy is the output of the compiler.
type CompiledPolicy struct {
	PolicyID     string `json:"policy_id"`
	ObligationID string `json:"obligation_id"`
	Framework    string `json:"framework"`
	Version      int    `json:"version"`

	// CEL expressions for evaluation
	SubjectExpr   string `json:"subject_expr"`   // Who it applies to
	TriggerExpr   string `json:"trigger_expr"`   // When it triggers
	ActionExpr    string `json:"action_expr"`    // What must/must not happen
	ExceptionExpr string `json:"exception_expr"` // Carve-outs

	// Combined expression for PDP
	FullExpr string `json:"full_expr"`

	// Metadata
	RiskLevel  jkg.RiskLevel `json:"risk_level"`
	CompiledAt time.Time     `json:"compiled_at"`
	Confidence float64       `json:"confidence"`
	Hash       string        `json:"hash"`
}

// Compiler transforms legal text into CEL policies.
type Compiler struct {
	patterns  map[TokenType][]*regexp.Regexp
	entityMap map[string]string // Legal term → CEL entity type
	actionMap map[string]string // Legal verb → CEL action
	metrics   *CompilerMetrics
}

// CompilerMetrics tracks compilation statistics.
type CompilerMetrics struct {
	mu            sync.RWMutex
	TotalCompiled int64                        `json:"total_compiled"`
	SuccessCount  int64                        `json:"success_count"`
	ErrorCount    int64                        `json:"error_count"`
	AvgConfidence float64                      `json:"avg_confidence"`
	ByFramework   map[string]int64             `json:"by_framework"`
	ByType        map[jkg.ObligationType]int64 `json:"by_type"`
}

// NewCompiler creates a new obligation compiler.
func NewCompiler() *Compiler {
	c := &Compiler{
		patterns:  make(map[TokenType][]*regexp.Regexp),
		entityMap: defaultEntityMap(),
		actionMap: defaultActionMap(),
		metrics: &CompilerMetrics{
			ByFramework: make(map[string]int64),
			ByType:      make(map[jkg.ObligationType]int64),
		},
	}
	c.initPatterns()
	return c
}

// initPatterns sets up regex patterns for token extraction.
func (c *Compiler) initPatterns() {
	// Subject patterns
	c.patterns[TokenSubject] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(crypto[- ]?asset service provider|CASP)s?`),
		regexp.MustCompile(`(?i)(credit institution|bank)s?`),
		regexp.MustCompile(`(?i)(e[- ]?money institution|EMI)s?`),
		regexp.MustCompile(`(?i)(investment firm)s?`),
		regexp.MustCompile(`(?i)(issuer)s?`),
		regexp.MustCompile(`(?i)(obliged entit(y|ies))`),
		regexp.MustCompile(`(?i)(financial institution)s?`),
		regexp.MustCompile(`(?i)(money service business|MSB)s?`),
		regexp.MustCompile(`(?i)(AI (system )?provider)s?`),
	}

	// Threshold patterns
	c.patterns[TokenThreshold] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(over|above|exceeding|more than)\s*[€$£]?\s*(\d+(?:,\d{3})*(?:\.\d+)?)\s*(EUR|USD|GBP)?`),
		regexp.MustCompile(`(?i)(under|below|less than)\s*[€$£]?\s*(\d+(?:,\d{3})*(?:\.\d+)?)\s*(EUR|USD|GBP)?`),
		regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*%\s*(of|or)`),
		regexp.MustCompile(`(?i)within\s+(\d+)\s+(days?|hours?|months?)`),
	}

	// Timeframe patterns
	c.patterns[TokenTimeframe] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)within\s+(\d+)\s+(business\s+)?(days?|hours?|weeks?|months?)`),
		regexp.MustCompile(`(?i)(immediately|without delay|forthwith)`),
		regexp.MustCompile(`(?i)(before|prior to|by)\s+(.+)`),
		regexp.MustCompile(`(?i)(ongoing|continuous|periodic)`),
	}

	// Reference patterns
	c.patterns[TokenReference] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Article\s+(\d+)(?:\((\d+)\))?`),
		regexp.MustCompile(`(?i)§\s*(\d+(?:\.\d+)?)`),
		regexp.MustCompile(`(?i)Regulation\s+\(EU\)\s+(\d+/\d+)`),
	}
}

// Parse tokenizes legal text into an AST.
func (c *Compiler) Parse(text string, framework string, articleRef string) (*ObligationAST, error) {
	if text == "" {
		return nil, fmt.Errorf("empty text")
	}

	ast := &ObligationAST{
		ObligationID: generateObligationID(framework, articleRef),
		Framework:    framework,
		ArticleRef:   articleRef,
		Tokens:       make([]*Token, 0),
		Conditions:   make([]*ConditionClause, 0),
		Exceptions:   make([]*ExceptionClause, 0),
		Thresholds:   make([]*ThresholdClause, 0),
		ParsedAt:     time.Now(),
	}

	// Determine obligation type
	ast.Type = c.detectObligationType(text)

	// Extract tokens
	for tokenType, patterns := range c.patterns {
		for _, pattern := range patterns {
			matches := pattern.FindAllStringSubmatchIndex(text, -1)
			for _, match := range matches {
				if len(match) >= 2 {
					token := &Token{
						Type:       tokenType,
						Value:      text[match[0]:match[1]],
						Position:   match[0],
						Confidence: 0.8,
					}
					token.Normalized = c.normalizeToken(token)
					ast.Tokens = append(ast.Tokens, token)
				}
			}
		}
	}

	// Build clauses from tokens
	c.buildClauses(ast, text)

	// Calculate overall confidence
	ast.Confidence = c.calculateConfidence(ast)

	return ast, nil
}

// Compile transforms an AST into a CEL policy.
//
//nolint:gocognit // complexity acceptable
func (c *Compiler) Compile(ast *ObligationAST) (*CompiledPolicy, error) {
	if ast == nil {
		return nil, fmt.Errorf("nil AST")
	}

	policy := &CompiledPolicy{
		PolicyID:     fmt.Sprintf("policy-%s", ast.ObligationID),
		ObligationID: ast.ObligationID,
		Framework:    ast.Framework,
		Version:      1,
		CompiledAt:   time.Now(),
		Confidence:   ast.Confidence,
	}

	// Generate subject expression
	if ast.Subject != nil {
		policy.SubjectExpr = ast.Subject.CELExpr
	} else {
		policy.SubjectExpr = "true" // Applies to all
	}

	// Generate trigger expression from conditions
	if len(ast.Conditions) > 0 {
		exprs := make([]string, 0, len(ast.Conditions))
		for _, cond := range ast.Conditions {
			if cond.CELExpr != "" {
				exprs = append(exprs, cond.CELExpr)
			}
		}
		if len(exprs) > 0 {
			policy.TriggerExpr = strings.Join(exprs, " && ")
		}
	}
	if policy.TriggerExpr == "" {
		policy.TriggerExpr = "true"
	}

	// Generate action expression
	if ast.Action != nil {
		policy.ActionExpr = ast.Action.CELExpr
	} else {
		policy.ActionExpr = c.defaultActionExpr(ast.Type)
	}

	// Generate exception expression
	if len(ast.Exceptions) > 0 {
		exprs := make([]string, 0, len(ast.Exceptions))
		for _, exc := range ast.Exceptions {
			if exc.CELExpr != "" {
				exprs = append(exprs, fmt.Sprintf("!(%s)", exc.CELExpr))
			}
		}
		if len(exprs) > 0 {
			policy.ExceptionExpr = strings.Join(exprs, " && ")
		}
	}
	if policy.ExceptionExpr == "" {
		policy.ExceptionExpr = "true"
	}

	// Combine into full expression
	policy.FullExpr = c.combineExpressions(policy)

	// Determine risk level
	policy.RiskLevel = c.assessRiskLevel(ast)

	// Generate hash
	policy.Hash = c.hashPolicy(policy)

	// Update metrics
	c.updateMetrics(ast, true)

	return policy, nil
}

// CompileFromText is a convenience method that parses and compiles in one step.
func (c *Compiler) CompileFromText(text, framework, articleRef string) (*CompiledPolicy, error) {
	ast, err := c.Parse(text, framework, articleRef)
	if err != nil {
		c.updateMetrics(nil, false)
		return nil, fmt.Errorf("parse error: %w", err)
	}

	policy, err := c.Compile(ast)
	if err != nil {
		c.updateMetrics(ast, false)
		return nil, fmt.Errorf("compile error: %w", err)
	}

	return policy, nil
}

// detectObligationType determines the type of obligation from text.
func (c *Compiler) detectObligationType(text string) jkg.ObligationType {
	lower := strings.ToLower(text)

	if strings.Contains(lower, "shall not") || strings.Contains(lower, "must not") ||
		strings.Contains(lower, "prohibited") || strings.Contains(lower, "forbidden") {
		return jkg.ObligationProhibition
	}

	if strings.Contains(lower, "report") || strings.Contains(lower, "notify") ||
		strings.Contains(lower, "inform") || strings.Contains(lower, "submit") {
		return jkg.ObligationReporting
	}

	if strings.Contains(lower, "register") || strings.Contains(lower, "authoriz") ||
		strings.Contains(lower, "licens") {
		return jkg.ObligationRegistration
	}

	if strings.Contains(lower, "may") || strings.Contains(lower, "permitted") {
		return jkg.ObligationPermission
	}

	return jkg.ObligationRequirement
}

// normalizeToken normalizes a token value.
func (c *Compiler) normalizeToken(token *Token) string {
	normalized := strings.ToLower(token.Value)
	normalized = strings.TrimSpace(normalized)

	// Entity normalization
	if token.Type == TokenSubject {
		if mapped, ok := c.entityMap[normalized]; ok {
			return mapped
		}
	}

	return normalized
}

// buildClauses builds structured clauses from tokens.
func (c *Compiler) buildClauses(ast *ObligationAST, text string) {
	// Build subject clause from subject tokens
	subjectTokens := filterTokens(ast.Tokens, TokenSubject)
	if len(subjectTokens) > 0 {
		entityTypes := make([]string, 0)
		for _, t := range subjectTokens {
			if mapped, ok := c.entityMap[strings.ToLower(t.Value)]; ok {
				entityTypes = append(entityTypes, mapped)
			} else {
				entityTypes = append(entityTypes, t.Normalized)
			}
		}
		ast.Subject = &SubjectClause{
			EntityTypes: entityTypes,
			CELExpr:     c.buildSubjectCEL(entityTypes),
		}
	}

	// Build threshold clauses
	thresholdTokens := filterTokens(ast.Tokens, TokenThreshold)
	for _, t := range thresholdTokens {
		threshold := c.parseThreshold(t)
		if threshold != nil {
			ast.Thresholds = append(ast.Thresholds, threshold)
		}
	}

	// Build timeframe clause
	timeTokens := filterTokens(ast.Tokens, TokenTimeframe)
	if len(timeTokens) > 0 {
		ast.Timeframe = &TimeframeClause{
			Duration: timeTokens[0].Value,
			CELExpr:  c.buildTimeframeCEL(timeTokens[0]),
		}
	}

	// Build action clause based on obligation type
	ast.Action = &ActionClause{
		Modality: c.getModality(ast.Type),
		CELExpr:  c.defaultActionExpr(ast.Type),
	}
}

// buildSubjectCEL generates CEL for subject matching.
func (c *Compiler) buildSubjectCEL(entityTypes []string) string {
	if len(entityTypes) == 0 {
		return "true"
	}

	conditions := make([]string, 0, len(entityTypes))
	for _, et := range entityTypes {
		conditions = append(conditions, fmt.Sprintf(`entity.type == "%s"`, et))
	}

	return strings.Join(conditions, " || ")
}

// parseThreshold extracts threshold data from token.
func (c *Compiler) parseThreshold(t *Token) *ThresholdClause {
	// Simple extraction - in production would use more sophisticated parsing
	value := extractNumber(t.Value)
	if value == 0 {
		return nil
	}

	threshold := &ThresholdClause{
		Name:     "amount",
		Value:    value,
		Operator: ">=",
		Unit:     "EUR",
	}

	if strings.Contains(strings.ToLower(t.Value), "under") ||
		strings.Contains(strings.ToLower(t.Value), "below") {
		threshold.Operator = "<"
	}

	threshold.CELExpr = fmt.Sprintf("transaction.amount %s %v", threshold.Operator, threshold.Value)
	return threshold
}

// buildTimeframeCEL generates CEL for timeframe constraints.
func (c *Compiler) buildTimeframeCEL(t *Token) string {
	lower := strings.ToLower(t.Value)

	if strings.Contains(lower, "immediate") {
		return "duration.hours(0)"
	}

	// Extract number and unit
	re := regexp.MustCompile(`(\d+)\s*(days?|hours?|months?)`)
	matches := re.FindStringSubmatch(lower)
	if len(matches) >= 3 {
		return fmt.Sprintf(`timestamp.now() - request.timestamp < duration.%s(%s)`, matches[2], matches[1])
	}

	return "true"
}

// getModality returns the modality string for obligation type.
func (c *Compiler) getModality(t jkg.ObligationType) string {
	switch t {
	case jkg.ObligationProhibition:
		return "must_not"
	case jkg.ObligationPermission:
		return "may"
	default:
		return "must"
	}
}

// defaultActionExpr returns default CEL for obligation type.
func (c *Compiler) defaultActionExpr(t jkg.ObligationType) string {
	switch t {
	case jkg.ObligationProhibition:
		return "!action.performed"
	case jkg.ObligationRequirement:
		return "action.performed"
	case jkg.ObligationReporting:
		return "action.reported"
	case jkg.ObligationRegistration:
		return "entity.registered"
	case jkg.ObligationPermission:
		return "true" // Permissive
	default:
		return "true"
	}
}

// combineExpressions creates the full CEL expression.
func (c *Compiler) combineExpressions(p *CompiledPolicy) string {
	parts := []string{
		fmt.Sprintf("(%s)", p.SubjectExpr),
		fmt.Sprintf("(%s)", p.TriggerExpr),
		fmt.Sprintf("(%s)", p.ExceptionExpr),
	}

	return fmt.Sprintf("(%s) ? %s : true",
		strings.Join(parts, " && "),
		p.ActionExpr,
	)
}

// assessRiskLevel determines risk from AST analysis.
func (c *Compiler) assessRiskLevel(ast *ObligationAST) jkg.RiskLevel {
	// High-risk frameworks
	highRisk := []string{"MiCA", "EU AI Act", "AMLD", "BSA"}
	for _, hr := range highRisk {
		if strings.Contains(ast.Framework, hr) {
			if ast.Type == jkg.ObligationProhibition {
				return jkg.RiskCritical
			}
			return jkg.RiskHigh
		}
	}

	// Check for high thresholds
	for _, t := range ast.Thresholds {
		if t.Value >= 1000000 {
			return jkg.RiskHigh
		}
	}

	if ast.Type == jkg.ObligationProhibition {
		return jkg.RiskHigh
	}

	return jkg.RiskMedium
}

// calculateConfidence calculates overall parsing confidence.
func (c *Compiler) calculateConfidence(ast *ObligationAST) float64 {
	if len(ast.Tokens) == 0 {
		return 0.5 // Base confidence
	}

	total := 0.0
	for _, t := range ast.Tokens {
		total += t.Confidence
	}

	tokenConf := total / float64(len(ast.Tokens))

	// Boost if we found key elements
	boost := 0.0
	if ast.Subject != nil {
		boost += 0.1
	}
	if len(ast.Thresholds) > 0 {
		boost += 0.05
	}
	if ast.Timeframe != nil {
		boost += 0.05
	}

	conf := tokenConf + boost
	if conf > 1.0 {
		conf = 1.0
	}
	return conf
}

// hashPolicy generates a deterministic hash.
func (c *Compiler) hashPolicy(p *CompiledPolicy) string {
	data := fmt.Sprintf("%s:%s:%s:%s:%s",
		p.ObligationID, p.SubjectExpr, p.TriggerExpr, p.ActionExpr, p.ExceptionExpr)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])[:16]
}

// updateMetrics updates compiler metrics.
func (c *Compiler) updateMetrics(ast *ObligationAST, success bool) {
	c.metrics.mu.Lock()
	defer c.metrics.mu.Unlock()

	c.metrics.TotalCompiled++
	if success {
		c.metrics.SuccessCount++
		if ast != nil {
			c.metrics.ByFramework[ast.Framework]++
			c.metrics.ByType[ast.Type]++

			// Update average confidence
			if c.metrics.AvgConfidence == 0 {
				c.metrics.AvgConfidence = ast.Confidence
			} else {
				c.metrics.AvgConfidence = (c.metrics.AvgConfidence + ast.Confidence) / 2
			}
		}
	} else {
		c.metrics.ErrorCount++
	}
}

// GetMetrics returns current metrics.
func (c *Compiler) GetMetrics() *CompilerMetrics {
	c.metrics.mu.RLock()
	defer c.metrics.mu.RUnlock()
	return c.metrics
}

// Helper functions

func defaultEntityMap() map[string]string {
	return map[string]string{
		"crypto-asset service provider":  "CASP",
		"crypto-asset service providers": "CASP",
		"crypto asset service provider":  "CASP",
		"crypto asset service providers": "CASP",
		"casp":                           "CASP",
		"credit institution":             "CREDIT_INSTITUTION",
		"credit institutions":            "CREDIT_INSTITUTION",
		"bank":                           "CREDIT_INSTITUTION",
		"banks":                          "CREDIT_INSTITUTION",
		"e-money institution":            "EMI",
		"e-money institutions":           "EMI",
		"emi":                            "EMI",
		"investment firm":                "INVESTMENT_FIRM",
		"investment firms":               "INVESTMENT_FIRM",
		"issuer":                         "ISSUER",
		"issuers":                        "ISSUER",
		"obliged entity":                 "OBLIGED_ENTITY",
		"obliged entities":               "OBLIGED_ENTITY",
		"financial institution":          "FINANCIAL_INSTITUTION",
		"financial institutions":         "FINANCIAL_INSTITUTION",
		"money service business":         "MSB",
		"money service businesses":       "MSB",
		"msb":                            "MSB",
		"ai provider":                    "AI_PROVIDER",
		"ai providers":                   "AI_PROVIDER",
		"ai system provider":             "AI_PROVIDER",
		"ai system providers":            "AI_PROVIDER",
	}
}

func defaultActionMap() map[string]string {
	return map[string]string{
		"shall":     "must",
		"must":      "must",
		"required":  "must",
		"shall not": "must_not",
		"must not":  "must_not",
		"may":       "may",
		"permitted": "may",
	}
}

func filterTokens(tokens []*Token, tokenType TokenType) []*Token {
	result := make([]*Token, 0)
	for _, t := range tokens {
		if t.Type == tokenType {
			result = append(result, t)
		}
	}
	return result
}

func extractNumber(s string) float64 {
	re := regexp.MustCompile(`(\d+(?:,\d{3})*(?:\.\d+)?)`)
	match := re.FindString(s)
	if match == "" {
		return 0
	}
	match = strings.ReplaceAll(match, ",", "")
	var value float64
	_, _ = fmt.Sscanf(match, "%f", &value) // Best effort parsing
	return value
}

func generateObligationID(framework, articleRef string) string {
	data := fmt.Sprintf("%s:%s", framework, articleRef)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])[:12]
}
