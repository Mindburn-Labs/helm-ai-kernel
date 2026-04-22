// Package conformance provides test fixtures for OWASP LLM Top 10 conformance tests.
//
// These fixtures create lightweight, self-contained simulations of HELM subsystems
// (threat scanner, firewall, egress checker, budget gate, delegation manager, etc.)
// without requiring full system initialization. This matches the pattern used by
// the L1/L2/L3 fixtures in fixtures.go and l3_fixtures.go.
//
// Each fixture wraps the minimum contract surface needed to verify the OWASP
// control, keeping tests fast and deterministic.
package conformance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ── Threat Scanner Fixtures (LLM01, LLM06) ─────────────────────────────

// owaspThreatScanResult is a simplified threat scan result for conformance testing.
type owaspThreatScanResult struct {
	FindingCount int
	MaxSeverity  string
	Findings     []owaspThreatFinding
}

// HasClass returns true if any finding matches the given threat class.
func (r *owaspThreatScanResult) HasClass(class string) bool {
	for _, f := range r.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

// Classes returns all unique finding classes.
func (r *owaspThreatScanResult) Classes() []string {
	seen := make(map[string]bool)
	var classes []string
	for _, f := range r.Findings {
		if !seen[f.Class] {
			seen[f.Class] = true
			classes = append(classes, f.Class)
		}
	}
	return classes
}

// owaspThreatFinding is a single finding in a scan result.
type owaspThreatFinding struct {
	Class    string
	Severity string
	RuleID   string
}

// owaspThreatScanner is a simplified threat scanner for conformance tests.
// It replicates the detection logic from core/pkg/threatscan/scanner.go
// at the contract level without requiring full scanner initialization.
type owaspThreatScanner struct {
	injectionPatterns []string
	jailbreakPatterns []string
	credentialKeys    []string
}

func newOWASPThreatScanner() *owaspThreatScanner {
	return &owaspThreatScanner{
		injectionPatterns: []string{
			"ignore previous instructions",
			"ignore all previous",
			"disregard previous",
			"disregard your instructions",
			"forget your instructions",
			"override system prompt",
			"reveal system prompt",
			"show me your system prompt",
			"print your instructions",
			"bypass safeguards",
			"bypass safety",
			"bypass restrictions",
			"you are now",
			"pretend you are",
			"act as if you have no restrictions",
			"from now on you will",
			"ignore content policy",
			"do anything now",
		},
		jailbreakPatterns: []string{
			"enter developer mode",
			"enable developer mode",
			"jailbreak",
			"ignore safety guidelines",
			"simulate a conversation",
		},
		credentialKeys: []string{
			"api key", "api_key", "apikey",
			"secret_key", "secret key",
			"access_key", "access key",
			"aws_secret", "AWS_SECRET",
			"sk-proj-", "sk-live-",
			"_authtoken", "_auth_token",
		},
	}
}

// Scan performs a threat scan on input with default channel/trust settings.
func (s *owaspThreatScanner) Scan(input string) *owaspThreatScanResult {
	return s.ScanWithChannel(input, "CHAT_USER", "EXTERNAL_UNTRUSTED")
}

// ScanWithChannel performs a threat scan with explicit channel and trust level.
func (s *owaspThreatScanner) ScanWithChannel(input, channel, trustLevel string) *owaspThreatScanResult {
	normalized := strings.ToLower(input)
	var findings []owaspThreatFinding

	// Check prompt injection patterns
	for _, pattern := range s.injectionPatterns {
		if strings.Contains(normalized, pattern) {
			sev := "HIGH"
			if trustLevel == "EXTERNAL_UNTRUSTED" || trustLevel == "TAINTED" {
				sev = "CRITICAL"
			}
			findings = append(findings, owaspThreatFinding{
				Class:    "PROMPT_INJECTION_PATTERN",
				Severity: sev,
				RuleID:   "PROMPT_INJECTION_01",
			})
			break // One match per category is sufficient
		}
	}

	// Check jailbreak patterns
	for _, pattern := range s.jailbreakPatterns {
		if strings.Contains(normalized, pattern) {
			findings = append(findings, owaspThreatFinding{
				Class:    "PROMPT_INJECTION_PATTERN",
				Severity: "HIGH",
				RuleID:   "JAILBREAK_01",
			})
			break
		}
	}

	// Check credential exposure
	for _, key := range s.credentialKeys {
		if strings.Contains(normalized, strings.ToLower(key)) {
			findings = append(findings, owaspThreatFinding{
				Class:    "CREDENTIAL_EXPOSURE_PATTERN",
				Severity: "HIGH",
				RuleID:   "CREDENTIAL_01",
			})
			break
		}
	}

	// Check unicode obfuscation (fullwidth characters, homoglyphs)
	hasFullwidth := false
	for _, r := range input {
		if r >= 0xFF01 && r <= 0xFF5E { // Fullwidth ASCII variants
			hasFullwidth = true
			break
		}
	}
	if hasFullwidth {
		findings = append(findings, owaspThreatFinding{
			Class:    "UNICODE_OBFUSCATION_PATTERN",
			Severity: "MEDIUM",
			RuleID:   "UNICODE_01",
		})
		// Also check if the normalized form contains injection after fullwidth decode
		decoded := decodeFullwidth(input)
		decodedLower := strings.ToLower(decoded)
		for _, pattern := range s.injectionPatterns {
			if strings.Contains(decodedLower, pattern) {
				findings = append(findings, owaspThreatFinding{
					Class:    "PROMPT_INJECTION_PATTERN",
					Severity: "HIGH",
					RuleID:   "UNICODE_INJECTION_01",
				})
				break
			}
		}
	}

	// Check indirect injection patterns (tool output channel)
	if channel == "TOOL_OUTPUT" {
		indirectPatterns := []string{
			"from now on", "you will", "execute all",
			"important:", "override", "disregard",
		}
		for _, pattern := range indirectPatterns {
			if strings.Contains(normalized, pattern) {
				sev := "MEDIUM"
				if trustLevel == "EXTERNAL_UNTRUSTED" || trustLevel == "TAINTED" {
					sev = "HIGH"
				}
				findings = append(findings, owaspThreatFinding{
					Class:    "INDIRECT_INJECTION_PATTERN",
					Severity: sev,
					RuleID:   "INDIRECT_01",
				})
				break
			}
		}
	}

	// Compute max severity
	maxSev := "INFO"
	sevOrder := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for _, f := range findings {
		if sevOrder[f.Severity] > sevOrder[maxSev] {
			maxSev = f.Severity
		}
	}

	return &owaspThreatScanResult{
		FindingCount: len(findings),
		MaxSeverity:  maxSev,
		Findings:     findings,
	}
}

// decodeFullwidth converts fullwidth ASCII characters to their standard equivalents.
func decodeFullwidth(s string) string {
	var buf strings.Builder
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			buf.WriteRune(r - 0xFF01 + 0x21) // Map to standard ASCII
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// ── Firewall Fixtures (LLM02, LLM07, LLM10) ────────────────────────────

// owaspFirewall is a simplified policy firewall for conformance testing.
type owaspFirewall struct {
	allowedTools map[string]bool
	schemas      map[string]string // tool -> JSON Schema
}

func newOWASPFirewall() *owaspFirewall {
	return &owaspFirewall{
		allowedTools: make(map[string]bool),
		schemas:      make(map[string]string),
	}
}

func (f *owaspFirewall) AllowTool(name, schema string) {
	f.allowedTools[name] = true
	if schema != "" {
		f.schemas[name] = schema
	}
}

func (f *owaspFirewall) AllowToolWithSchema(name, schema string) {
	f.allowedTools[name] = true
	f.schemas[name] = schema
}

func (f *owaspFirewall) CallTool(toolName string, params map[string]any) (any, error) {
	// 1. Allowlist check (fail-closed)
	if !f.allowedTools[toolName] {
		return nil, fmt.Errorf("firewall blocked tool %q: not in allowlist", toolName)
	}

	// 2. Schema validation (if configured)
	if schema, ok := f.schemas[toolName]; ok && schema != "" {
		if err := f.validateParams(toolName, schema, params); err != nil {
			return nil, fmt.Errorf("firewall blocked tool %q: schema validation failed: %w", toolName, err)
		}
	}

	return map[string]any{"status": "ok"}, nil
}

func (f *owaspFirewall) validateParams(tool, schema string, params map[string]any) error {
	// Simplified schema validation: check required fields from schema.
	// In production this uses jsonschema.Validate; here we check the basics.
	if strings.Contains(schema, `"required"`) {
		// Extract required fields (simplified parser for test fixtures)
		required := extractRequiredFields(schema)
		for _, field := range required {
			if _, ok := params[field]; !ok {
				return fmt.Errorf("missing required field %q for tool %s", field, tool)
			}
		}
	}
	return nil
}

// extractRequiredFields does a simplified extraction of required fields from JSON Schema.
func extractRequiredFields(schema string) []string {
	// Find "required": ["field1", "field2"] pattern
	idx := strings.Index(schema, `"required"`)
	if idx < 0 {
		return nil
	}
	rest := schema[idx:]
	start := strings.Index(rest, "[")
	end := strings.Index(rest, "]")
	if start < 0 || end < 0 || end <= start {
		return nil
	}
	inner := rest[start+1 : end]
	parts := strings.Split(inner, ",")
	var fields []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			fields = append(fields, p)
		}
	}
	return fields
}

// ── Egress Checker Fixtures (LLM04, LLM06, LLM07, LLM10) ──────────────

// owaspEgressDecision captures the result of an egress check.
type owaspEgressDecision struct {
	Allowed    bool
	ReasonCode string
}

// owaspEgressChecker is a simplified egress checker for conformance testing.
type owaspEgressChecker struct {
	allowedDomains map[string]bool
	allowedProtos  map[string]bool
	maxPayload     int64
}

func newOWASPEgressChecker(domains []string, maxPayload int64) *owaspEgressChecker {
	ec := &owaspEgressChecker{
		allowedDomains: make(map[string]bool),
		allowedProtos:  map[string]bool{"https": true, "grpc": true},
		maxPayload:     maxPayload,
	}
	for _, d := range domains {
		ec.allowedDomains[d] = true
	}
	return ec
}

func newOWASPEgressCheckerWithProtocols(domains, protocols []string, maxPayload int64) *owaspEgressChecker {
	ec := &owaspEgressChecker{
		allowedDomains: make(map[string]bool),
		allowedProtos:  make(map[string]bool),
		maxPayload:     maxPayload,
	}
	for _, d := range domains {
		ec.allowedDomains[d] = true
	}
	for _, p := range protocols {
		ec.allowedProtos[p] = true
	}
	return ec
}

func (ec *owaspEgressChecker) CheckEgress(domain, protocol string, payloadBytes int64) owaspEgressDecision {
	// Fail-closed: empty allowlist = deny all
	if len(ec.allowedDomains) == 0 {
		return owaspEgressDecision{Allowed: false, ReasonCode: "DATA_EGRESS_BLOCKED"}
	}
	if !ec.allowedDomains[domain] {
		return owaspEgressDecision{Allowed: false, ReasonCode: "DATA_EGRESS_BLOCKED"}
	}
	if len(ec.allowedProtos) > 0 && !ec.allowedProtos[protocol] {
		return owaspEgressDecision{Allowed: false, ReasonCode: "DATA_EGRESS_BLOCKED"}
	}
	if ec.maxPayload > 0 && payloadBytes > ec.maxPayload {
		return owaspEgressDecision{Allowed: false, ReasonCode: "DATA_EGRESS_BLOCKED"}
	}
	return owaspEgressDecision{Allowed: true}
}

// ── Budget Gate Fixtures (LLM04) ────────────────────────────────────────

// owaspBudgetCost is a simplified budget cost.
type owaspBudgetCost struct {
	Requests int64
}

// owaspBudgetGate is a simplified budget enforcement gate for conformance testing.
type owaspBudgetGate struct {
	mu       sync.Mutex
	limit    int64
	consumed map[string]int64
}

func newOWASPBudgetGate(limit int64) *owaspBudgetGate {
	return &owaspBudgetGate{
		limit:    limit,
		consumed: make(map[string]int64),
	}
}

func (bg *owaspBudgetGate) Check(budgetID string, cost owaspBudgetCost) (bool, error) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	return bg.consumed[budgetID]+cost.Requests <= bg.limit, nil
}

func (bg *owaspBudgetGate) Consume(budgetID string, cost owaspBudgetCost) error {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.consumed[budgetID] += cost.Requests
	return nil
}

// ── Effect Catalog Fixtures (LLM02, LLM08) ─────────────────────────────

// owaspEffectEntry represents a cataloged effect type.
type owaspEffectEntry struct {
	TypeID        string
	RiskClass     string
	ApprovalLevel string
	Reversibility string
	BlastRadius   string
}

// owaspEffectCatalog provides governance metadata for effect types.
type owaspEffectCatalog struct {
	entries map[string]*owaspEffectEntry
}

func newOWASPEffectCatalog() *owaspEffectCatalog {
	return &owaspEffectCatalog{
		entries: map[string]*owaspEffectEntry{
			"INFRA_DESTROY": {
				TypeID: "INFRA_DESTROY", RiskClass: "E4",
				ApprovalLevel: "dual_control", Reversibility: "irreversible",
				BlastRadius: "system_wide",
			},
			"SOFTWARE_PUBLISH": {
				TypeID: "SOFTWARE_PUBLISH", RiskClass: "E4",
				ApprovalLevel: "dual_control", Reversibility: "irreversible",
				BlastRadius: "system_wide",
			},
			"DATA_EGRESS": {
				TypeID: "DATA_EGRESS", RiskClass: "E4",
				ApprovalLevel: "dual_control", Reversibility: "irreversible",
				BlastRadius: "system_wide",
			},
			"CI_CREDENTIAL_ACCESS": {
				TypeID: "CI_CREDENTIAL_ACCESS", RiskClass: "E4",
				ApprovalLevel: "dual_control", Reversibility: "irreversible",
				BlastRadius: "session",
			},
			"SEND_EMAIL": {
				TypeID: "SEND_EMAIL", RiskClass: "E2",
				ApprovalLevel: "single_human", Reversibility: "irreversible",
				BlastRadius: "targeted",
			},
			"READ_FILE": {
				TypeID: "READ_FILE", RiskClass: "E0",
				ApprovalLevel: "none", Reversibility: "read_only",
				BlastRadius: "none",
			},
		},
	}
}

func (c *owaspEffectCatalog) Lookup(typeID string) *owaspEffectEntry {
	return c.entries[typeID]
}

// ── Effect Permit Fixtures (LLM08) ──────────────────────────────────────

// owaspEffectPermit is a simplified effect permit for conformance testing.
type owaspEffectPermit struct {
	PermitID    string
	ConnectorID string
	EffectClass string
	Scope       owaspEffectScope
	SingleUse   bool
	ExpiresAt   time.Time
	Nonce       string
}

type owaspEffectScope struct {
	AllowedAction string
}

func newOWASPEffectPermit(connectorID, action, effectClass string) *owaspEffectPermit {
	nonce := fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))[:16]
	return &owaspEffectPermit{
		PermitID:    "permit-" + nonce,
		ConnectorID: connectorID,
		EffectClass: effectClass,
		Scope:       owaspEffectScope{AllowedAction: action},
		SingleUse:   true,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Nonce:       nonce,
	}
}

// ── Delegation Manager Fixtures (LLM08) ─────────────────────────────────

// owaspDelegationRequest is a simplified delegation request.
type owaspDelegationRequest struct {
	DelegatorID   string
	DelegateeID   string
	Capabilities  []string
	MaxChainDepth int
	TTL           time.Duration
}

// owaspDelegationGrant is a simplified delegation grant.
type owaspDelegationGrant struct {
	GrantID       string
	DelegatorID   string
	DelegateeID   string
	Capabilities  []string
	MaxChainDepth int
	ChainDepth    int
	ExpiresAt     time.Time
	Revoked       bool
}

// owaspDelegationManager simulates the delegation manager for conformance tests.
type owaspDelegationManager struct {
	mu      sync.Mutex
	grants  map[string]*owaspDelegationGrant
	counter int
}

func newOWASPDelegationManager() *owaspDelegationManager {
	return &owaspDelegationManager{
		grants: make(map[string]*owaspDelegationGrant),
	}
}

func (dm *owaspDelegationManager) CreateDelegation(_ context.Context, req owaspDelegationRequest, delegatorCaps []string) (*owaspDelegationGrant, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Capability attenuation: requested must be subset of delegator's
	capSet := make(map[string]bool)
	for _, c := range delegatorCaps {
		capSet[c] = true
	}
	for _, rc := range req.Capabilities {
		if !capSet[rc] {
			return nil, fmt.Errorf("delegation: capability %q exceeds delegator's capabilities", rc)
		}
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	dm.counter++
	grant := &owaspDelegationGrant{
		GrantID:       fmt.Sprintf("grant-%d", dm.counter),
		DelegatorID:   req.DelegatorID,
		DelegateeID:   req.DelegateeID,
		Capabilities:  req.Capabilities,
		MaxChainDepth: req.MaxChainDepth,
		ChainDepth:    0,
		ExpiresAt:     time.Now().Add(ttl),
	}
	dm.grants[grant.GrantID] = grant
	return grant, nil
}

func (dm *owaspDelegationManager) ReDelegate(_ context.Context, parentGrantID string, req owaspDelegationRequest) (*owaspDelegationGrant, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	parent, ok := dm.grants[parentGrantID]
	if !ok {
		return nil, fmt.Errorf("delegation: parent grant %s not found", parentGrantID)
	}
	if parent.Revoked {
		return nil, fmt.Errorf("delegation: parent grant %s is revoked", parentGrantID)
	}
	if time.Now().After(parent.ExpiresAt) {
		return nil, fmt.Errorf("delegation: parent grant %s has expired", parentGrantID)
	}
	if parent.ChainDepth >= parent.MaxChainDepth {
		return nil, fmt.Errorf("delegation: max chain depth %d reached", parent.MaxChainDepth)
	}

	// Attenuation check
	parentCapSet := make(map[string]bool)
	for _, c := range parent.Capabilities {
		parentCapSet[c] = true
	}
	for _, rc := range req.Capabilities {
		if !parentCapSet[rc] {
			return nil, fmt.Errorf("delegation: capability %q exceeds parent grant's capabilities", rc)
		}
	}

	remaining := time.Until(parent.ExpiresAt)
	ttl := req.TTL
	if ttl <= 0 || ttl > remaining {
		ttl = remaining
	}

	dm.counter++
	grant := &owaspDelegationGrant{
		GrantID:       fmt.Sprintf("grant-%d", dm.counter),
		DelegatorID:   req.DelegatorID,
		DelegateeID:   req.DelegateeID,
		Capabilities:  req.Capabilities,
		MaxChainDepth: parent.MaxChainDepth,
		ChainDepth:    parent.ChainDepth + 1,
		ExpiresAt:     time.Now().Add(ttl),
	}
	dm.grants[grant.GrantID] = grant
	return grant, nil
}

// ── Plan Commit Controller Fixtures (LLM08, LLM09) ─────────────────────

// owaspExecutionPlan represents a plan awaiting approval.
type owaspExecutionPlan struct {
	PlanID      string
	EffectType  string
	EffectClass string
	Principal   string
	Description string
}

// owaspPlanDecision is the outcome of waiting for approval.
type owaspPlanDecision struct {
	Status   string // "APPROVED", "DENIED", "TIMEOUT"
	Approver string
}

// owaspPlanRef is a reference to a submitted plan.
type owaspPlanRef struct {
	PlanID string
}

// owaspPlanCommitController simulates plan-commit governance for conformance tests.
type owaspPlanCommitController struct {
	mu       sync.Mutex
	plans    map[string]*owaspExecutionPlan
	approved map[string]string // planID -> approverID
}

func newOWASPPlanCommitController() *owaspPlanCommitController {
	return &owaspPlanCommitController{
		plans:    make(map[string]*owaspExecutionPlan),
		approved: make(map[string]string),
	}
}

func (pc *owaspPlanCommitController) SubmitPlan(plan *owaspExecutionPlan) (owaspPlanRef, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.plans[plan.PlanID] = plan
	return owaspPlanRef{PlanID: plan.PlanID}, nil
}

func (pc *owaspPlanCommitController) Approve(planID, approverID string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.approved[planID] = approverID
}

func (pc *owaspPlanCommitController) WaitForApproval(ref owaspPlanRef, timeout time.Duration) (*owaspPlanDecision, error) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return &owaspPlanDecision{Status: "TIMEOUT"}, nil
		case <-ticker.C:
			pc.mu.Lock()
			approver, ok := pc.approved[ref.PlanID]
			pc.mu.Unlock()
			if ok {
				return &owaspPlanDecision{Status: "APPROVED", Approver: approver}, nil
			}
		}
	}
}

// ── Escalation Intent Fixtures (LLM09) ──────────────────────────────────

// owaspEscalationIntent simulates an escalation intent for conformance testing.
type owaspEscalationIntent struct {
	IntentID   string
	HeldEffect owaspHeldEffect
	Context    owaspEscalationContext
	ExpiresAt  time.Time
}

type owaspHeldEffect struct {
	EffectType  string
	EffectClass string
	BlastRadius string
	Description string
}

type owaspEscalationContext struct {
	Plan         *owaspEscalationPlan
	Risks        []owaspIdentifiedRisk
	RollbackPlan *owaspRollbackPlan
}

type owaspEscalationPlan struct {
	Summary string
	Steps   []string
}

type owaspIdentifiedRisk struct {
	Description string
	Severity    string
}

type owaspRollbackPlan struct {
	Summary string
	Steps   []string
}

func newOWASPEscalationIntent() *owaspEscalationIntent {
	return &owaspEscalationIntent{
		IntentID: "esc-001",
		HeldEffect: owaspHeldEffect{
			EffectType:  "SOFTWARE_PUBLISH",
			EffectClass: "E4",
			BlastRadius: "system_wide",
			Description: "Publish Docker image to production registry",
		},
		Context: owaspEscalationContext{
			Plan: &owaspEscalationPlan{
				Summary: "Deploy v2.1.0 to production container registry",
				Steps:   []string{"Build image", "Push to registry", "Update deployment"},
			},
			Risks: []owaspIdentifiedRisk{
				{Description: "Breaking change in API v2", Severity: "HIGH"},
				{Description: "No staging verification completed", Severity: "MEDIUM"},
			},
			RollbackPlan: &owaspRollbackPlan{
				Summary: "Revert to v2.0.9 tag",
				Steps:   []string{"Pull previous image", "Redeploy v2.0.9", "Verify health"},
			},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
}

// ── Verdict Fixtures (LLM09) ────────────────────────────────────────────

func owaspCanonicalVerdicts() []string {
	return []string{"ALLOW", "DENY", "ESCALATE"}
}

func isTerminalVerdict(v string) bool {
	return v == "ALLOW" || v == "DENY"
}

// ── Redaction Spec Fixtures (LLM06) ─────────────────────────────────────

type owaspRedactionRule struct {
	Field    string
	Strategy string
}

type owaspRedactionSpec struct {
	SpecID     string
	TargetType string
	Redactions []owaspRedactionRule
}

func newOWASPRedactionSpec() *owaspRedactionSpec {
	return &owaspRedactionSpec{
		SpecID:     "owasp-sensitive-fields",
		TargetType: "RECEIPT",
		Redactions: []owaspRedactionRule{
			{Field: "principal_id", Strategy: "HASH"},
			{Field: "api_key", Strategy: "REMOVE"},
			{Field: "ip_address", Strategy: "MASK"},
			{Field: "session_token", Strategy: "REMOVE"},
			{Field: "email", Strategy: "HASH"},
		},
	}
}

// ── Model Access Receipt Fixtures (LLM10) ───────────────────────────────

// owaspModelAccessReceipt represents an audit receipt for model access.
type owaspModelAccessReceipt struct {
	Hash     string
	PrevHash string
	Lamport  uint64
	ModelID  string
	Action   string
}

// sampleModelAccessReceiptChain returns a 5-entry receipt chain for model access auditing.
func sampleModelAccessReceiptChain() []owaspModelAccessReceipt {
	models := []string{
		"anthropic:claude-opus-4-6",
		"openai:gpt-5.4",
		"anthropic:claude-sonnet-4-6",
		"openai:gpt-4o",
		"anthropic:claude-haiku-4-5",
	}
	chain := make([]owaspModelAccessReceipt, 5)
	prevHash := ""
	for i := 0; i < 5; i++ {
		data := fmt.Sprintf("model-access-%d-%s-%s", i, models[i], prevHash)
		h := sha256.Sum256([]byte(data))
		hash := "sha256:" + hex.EncodeToString(h[:])
		chain[i] = owaspModelAccessReceipt{
			Hash:     hash,
			PrevHash: prevHash,
			Lamport:  uint64(i + 1),
			ModelID:  models[i],
			Action:   "INFERENCE",
		}
		prevHash = hash
	}
	return chain
}

// ── Model Catalog Fixtures (LLM10) ──────────────────────────────────────

type owaspModelEntry struct {
	ProviderID   string
	Name         string
	Capabilities []string
	Regions      []string
	RiskTier     string
}

func newOWASPModelCatalog() []owaspModelEntry {
	return []owaspModelEntry{
		{
			ProviderID: "anthropic:claude-opus-4-6", Name: "Claude Opus 4.6",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING"},
			Regions: []string{"US", "EU"}, RiskTier: "LOW",
		},
		{
			ProviderID: "openai:gpt-5.4", Name: "GPT-5.4",
			Capabilities: []string{"TEXT", "CODE", "VISION", "REASONING", "TOOL_USE"},
			Regions: []string{"US", "EU", "APAC"}, RiskTier: "LOW",
		},
		{
			ProviderID: "google:gemini-3-pro", Name: "Gemini 3 Pro",
			Capabilities: []string{"TEXT", "CODE", "VISION"},
			Regions: []string{"US", "EU"}, RiskTier: "LOW",
		},
	}
}
