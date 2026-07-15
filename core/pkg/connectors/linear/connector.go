package linear

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// Ensure Connector implements effects.Connector at compile time.
var _ effects.Connector = (*Connector)(nil)

// Connector is the HELM connector for the Linear project management API.
//
// It composes:
//   - Client:     HTTP bridge to Linear GraphQL API
//   - ZeroTrust:  connector trust gate (rate limits, data classes)
//   - ProofGraph: in-memory hash chain for permitted dispatch attempts
//
// Every permitted dispatch attempt produces an INTENT -> EFFECT chain.
type Connector struct {
	client       *Client
	gate         *connector.ZeroTrustGate
	graph        *proofgraph.Graph
	connectorID  string
	nonceMu      sync.Mutex
	permitNonces map[string]permitNonceState
	now          func() time.Time
	seq          atomic.Uint64
}

const (
	linearPermitMaxTTL          = time.Hour
	linearPermitNonceMaxEntries = 4096
)

type permitNonceState struct {
	expiresAt time.Time
	reserved  bool
}

var toolEffectTypeMap = map[string]effects.EffectType{
	"linear.create_issue": effects.EffectTypeWrite,
	"linear.update_issue": effects.EffectTypeWrite,
	"linear.get_issue":    effects.EffectTypeRead,
	"linear.list_issues":  effects.EffectTypeRead,
	"linear.add_comment":  effects.EffectTypeWrite,
}

// Config configures a new Linear connector.
//
// Token is optional. When empty, the underlying GraphQL client returns
// "not connected" errors — useful for unit tests. Set Token (Linear personal
// API key `lin_api_...` or OAuth bearer) to enable real API access.
type Config struct {
	BaseURL     string
	ConnectorID string
	Token       string
}

// NewConnector creates a new Linear connector.
//
// If cfg.Token is non-empty, the connector makes real authenticated GraphQL
// calls to Linear's API. If empty, every tool call returns a "not connected"
// error (preserving backward compat with token-less unit tests).
func NewConnector(cfg Config) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = ConnectorID
	}

	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        cfg.ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: 60,
		RequireProvenance:  true,
	})

	var client *Client
	if cfg.Token != "" {
		client = NewClientWithToken(cfg.BaseURL, cfg.Token)
	} else {
		client = NewClient(cfg.BaseURL)
	}

	return &Connector{
		client:       client,
		gate:         gate,
		graph:        proofgraph.NewGraph(),
		connectorID:  cfg.ConnectorID,
		permitNonces: make(map[string]permitNonceState),
		now:          time.Now,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// Execute dispatches a tool call through the zero-trust gate and records it in
// the ProofGraph. Implements effects.Connector.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	if params == nil {
		params = map[string]any{}
	}

	// 1. Resolve governed classifications before any side effect.
	dataClass, ok := toolDataClassMap[toolName]
	if !ok {
		return nil, fmt.Errorf("linear: unknown tool %q", toolName)
	}
	effectType, ok := toolEffectTypeMap[toolName]
	if !ok {
		return nil, fmt.Errorf("linear: missing effect classification for tool %q", toolName)
	}

	// 2. Validate the EffectPermit scope. Connectors are the last guard before
	// Linear GraphQL sinks, so they must not rely only on the gateway.
	if err := c.validatePermit(permit, toolName, effectType, params); err != nil {
		return nil, err
	}

	// 3. Reserve the nonce before the gate records a call. A replay must not
	// consume rate-limit capacity, while a gate denial must leave the permit
	// retryable until it expires.
	if err := c.reservePermitNonce(permit.Nonce, permit.ExpiresAt); err != nil {
		return nil, err
	}

	// 4. Gate check.
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		c.releasePermitNonce(permit.Nonce)
		return nil, fmt.Errorf("linear: gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 5. Compute input hash via canonicalize.CanonicalHash.
	inputHash, err := canonicalize.CanonicalHash(params)
	if err != nil {
		c.releasePermitNonce(permit.Nonce)
		return nil, fmt.Errorf("linear: canonical hash of params: %w", err)
	}

	// 6. Consume the single-use permit only after all pre-execution validation
	// and a successful gate, but before any ProofGraph intent or Linear GraphQL
	// call is made.
	if err := c.consumePermitNonce(permit.Nonce); err != nil {
		return nil, err
	}

	// 7. Append INTENT node to ProofGraph
	intentPayload, err := json.Marshal(map[string]any{
		"type":       "linear.intent",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
	})
	if err != nil {
		return nil, fmt.Errorf("linear: marshal intent payload: %w", err)
	}
	seq := c.seq.Add(1)
	if _, err := c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("linear: append intent: %w", err)
	}

	// 8. Dispatch to appropriate client method
	result, execErr := c.dispatch(ctx, toolName, params)

	// 9. Append EFFECT node to ProofGraph
	effectEntry := map[string]any{
		"type":       "linear.effect",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
		"success":    execErr == nil,
	}
	if execErr != nil {
		effectEntry["error"] = execErr.Error()
	} else {
		outputHash, hashErr := canonicalize.CanonicalHash(result)
		if hashErr == nil {
			effectEntry["output_hash"] = outputHash
		}
	}
	effectPayload, _ := json.Marshal(effectEntry)
	seq = c.seq.Add(1)
	if _, err := c.graph.Append(proofgraph.NodeTypeEffect, effectPayload, c.connectorID, seq); err != nil {
		return nil, fmt.Errorf("linear: append effect: %w", err)
	}

	if execErr != nil {
		return nil, execErr
	}
	return result, nil
}

func (c *Connector) validatePermit(permit *effects.EffectPermit, toolName string, effectType effects.EffectType, params map[string]any) error {
	if permit == nil {
		return fmt.Errorf("linear: missing effect permit")
	}
	if permit.ConnectorID != c.connectorID {
		return fmt.Errorf("linear: permit connector_id %q does not match %q", permit.ConnectorID, c.connectorID)
	}
	if permit.Scope.AllowedAction == "" {
		return fmt.Errorf("linear: permit missing allowed_action")
	}
	if permit.Scope.AllowedAction != toolName {
		return fmt.Errorf("linear: permit action %q does not authorize %q", permit.Scope.AllowedAction, toolName)
	}
	if permit.EffectType != effectType {
		return fmt.Errorf("linear: permit effect_type %q does not authorize %q", permit.EffectType, toolName)
	}
	now := c.now().UTC()
	if permit.IssuedAt.IsZero() {
		return fmt.Errorf("linear: permit missing issued_at")
	}
	if permit.IssuedAt.UTC().After(now.Add(time.Minute)) {
		return fmt.Errorf("linear: permit issued_at is in the future")
	}
	if permit.ExpiresAt.IsZero() {
		return fmt.Errorf("linear: permit missing expires_at")
	}
	if !now.Before(permit.ExpiresAt.UTC()) {
		return fmt.Errorf("linear: permit expired at %s", permit.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if permit.ExpiresAt.UTC().Sub(permit.IssuedAt.UTC()) > linearPermitMaxTTL {
		return fmt.Errorf("linear: permit ttl exceeds %s", linearPermitMaxTTL)
	}
	if !permit.SingleUse {
		return fmt.Errorf("linear: permit must be single-use")
	}
	if strings.TrimSpace(permit.Nonce) == "" {
		return fmt.Errorf("linear: permit missing nonce")
	}
	if err := validateParamScope(permit, toolName, effectType, params); err != nil {
		return err
	}
	return validateResourceScope(permit, toolName, params)
}

func validateParamScope(permit *effects.EffectPermit, toolName string, effectType effects.EffectType, params map[string]any) error {
	allowedKeys := make(map[string]struct{}, len(permit.Scope.AllowedParams))
	exactValues := map[string]string{}
	for _, raw := range permit.Scope.AllowedParams {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return fmt.Errorf("linear: permit contains blank allowed_param")
		}
		key, value, hasValue := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("linear: permit contains blank allowed_param key")
		}
		allowedKeys[key] = struct{}{}
		if hasValue {
			exactValues[key] = value
		}
	}
	if effectType == effects.EffectTypeWrite && len(allowedKeys) == 0 {
		return fmt.Errorf("linear: write action %q requires allowed_params scope", toolName)
	}
	if len(allowedKeys) > 0 {
		for key := range params {
			if _, ok := allowedKeys[key]; !ok {
				return fmt.Errorf("linear: param %q not authorized by permit scope", key)
			}
		}
	}
	for key, expected := range exactValues {
		actual, ok := params[key]
		if !ok {
			return fmt.Errorf("linear: permit scope requires param %q", key)
		}
		if got := scopeParamValue(actual); got != expected {
			return fmt.Errorf("linear: param %q value %q does not match permit scope", key, got)
		}
	}
	for key, value := range params {
		actual := scopeParamValue(value)
		for _, pattern := range permit.Scope.DenyPatterns {
			if matchesDenyPattern(pattern, key, actual) {
				return fmt.Errorf("linear: param %q matches deny pattern %q", key, pattern)
			}
		}
	}
	return nil
}

func validateResourceScope(permit *effects.EffectPermit, toolName string, params map[string]any) error {
	teamID := strings.TrimSpace(stringParam(params, "team_id"))
	issueID := strings.TrimSpace(stringParam(params, "issue_id"))
	resourceRef := strings.TrimSpace(permit.ResourceRef)
	if resourceRef == "" {
		return fmt.Errorf("linear: action %q requires permit resource_ref", toolName)
	}
	requiredKind := "issue"
	if toolName == "linear.create_issue" || toolName == "linear.list_issues" {
		requiredKind = "team"
	}
	if kind := linearResourceRefKind(resourceRef); kind != "" && kind != requiredKind {
		return fmt.Errorf("linear: permit resource_ref %q has kind %q; action %q requires %q", resourceRef, kind, toolName, requiredKind)
	}
	switch requiredKind {
	case "team":
		if teamID == "" {
			return fmt.Errorf("linear: permit resource_ref %q requires team_id", resourceRef)
		}
		issueID = ""
	case "issue":
		if issueID == "" {
			return fmt.Errorf("linear: permit resource_ref %q requires issue_id", resourceRef)
		}
		teamID = ""
	}
	if resourceRefMatchesLinear(resourceRef, teamID, issueID) {
		return nil
	}
	return fmt.Errorf("linear: permit resource_ref %q does not authorize team_id %q or issue_id %q", resourceRef, teamID, issueID)
}

func linearResourceRefKind(resourceRef string) string {
	switch {
	case strings.HasPrefix(resourceRef, "team:"), strings.HasPrefix(resourceRef, "linear:team:"):
		return "team"
	case strings.HasPrefix(resourceRef, "issue:"), strings.HasPrefix(resourceRef, "linear:issue:"):
		return "issue"
	default:
		return ""
	}
}

func resourceRefMatchesLinear(resourceRef, teamID, issueID string) bool {
	if teamID != "" {
		for _, candidate := range []string{teamID, "team:" + teamID, "linear:" + teamID, "linear:team:" + teamID} {
			if resourceRef == candidate {
				return true
			}
		}
	}
	if issueID != "" {
		for _, candidate := range []string{issueID, "issue:" + issueID, "linear:" + issueID, "linear:issue:" + issueID} {
			if resourceRef == candidate {
				return true
			}
		}
	}
	return false
}

func scopeParamValue(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case bool:
		return fmt.Sprint(typed)
	default:
		b, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(b)
	}
}

func matchesDenyPattern(pattern, key, value string) bool {
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return strings.HasSuffix(key, suffix) || strings.HasSuffix(value, suffix)
	}
	return key == pattern || value == pattern
}

// ponytail: this bounded, process-local tracker protects one connector process.
// Use a durable shared nonce store before deploying this connector across replicas.
func (c *Connector) reservePermitNonce(nonce string, expiresAt time.Time) error {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	c.pruneExpiredPermitNoncesLocked(c.now().UTC())
	if _, ok := c.permitNonces[nonce]; ok {
		return fmt.Errorf("linear: permit nonce %q already used", nonce)
	}
	if len(c.permitNonces) >= linearPermitNonceMaxEntries {
		return fmt.Errorf("linear: permit replay tracker is full")
	}
	c.permitNonces[nonce] = permitNonceState{expiresAt: expiresAt.UTC(), reserved: true}
	return nil
}

func (c *Connector) releasePermitNonce(nonce string) {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	if state, ok := c.permitNonces[nonce]; ok && state.reserved {
		delete(c.permitNonces, nonce)
	}
}

func (c *Connector) consumePermitNonce(nonce string) error {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	now := c.now().UTC()
	state, ok := c.permitNonces[nonce]
	c.pruneExpiredPermitNoncesLocked(now)
	if !ok {
		return fmt.Errorf("linear: permit nonce %q was not reserved", nonce)
	}
	if !now.Before(state.expiresAt) {
		return fmt.Errorf("linear: permit nonce %q expired", nonce)
	}
	if !state.reserved {
		return fmt.Errorf("linear: permit nonce %q already used", nonce)
	}
	state.reserved = false
	c.permitNonces[nonce] = state
	return nil
}

func (c *Connector) pruneExpiredPermitNoncesLocked(now time.Time) {
	for nonce, state := range c.permitNonces {
		if !now.Before(state.expiresAt) {
			delete(c.permitNonces, nonce)
		}
	}
}

// dispatch routes to the appropriate client method based on toolName.
func (c *Connector) dispatch(ctx context.Context, toolName string, params map[string]any) (any, error) {
	switch toolName {
	case "linear.create_issue":
		req := &CreateIssueRequest{
			TeamID:      stringParam(params, "team_id"),
			Title:       stringParam(params, "title"),
			Description: stringParam(params, "description"),
			Priority:    stringParam(params, "priority"),
			AssigneeID:  stringParam(params, "assignee_id"),
			LabelIDs:    stringSliceParam(params, "label_ids"),
		}
		if req.TeamID == "" {
			return nil, fmt.Errorf("linear: create_issue: missing required param team_id")
		}
		if req.Title == "" {
			return nil, fmt.Errorf("linear: create_issue: missing required param title")
		}
		return c.client.CreateIssue(ctx, req)

	case "linear.update_issue":
		req := &UpdateIssueRequest{
			IssueID: stringParam(params, "issue_id"),
		}
		if req.IssueID == "" {
			return nil, fmt.Errorf("linear: update_issue: missing required param issue_id")
		}
		if v, ok := params["title"]; ok {
			s, _ := v.(string)
			req.Title = &s
		}
		if v, ok := params["description"]; ok {
			s, _ := v.(string)
			req.Description = &s
		}
		if v, ok := params["state"]; ok {
			s, _ := v.(string)
			req.State = &s
		}
		if v, ok := params["priority"]; ok {
			s, _ := v.(string)
			req.Priority = &s
		}
		if v, ok := params["assignee_id"]; ok {
			s, _ := v.(string)
			req.AssigneeID = &s
		}
		if err := c.client.UpdateIssue(ctx, req); err != nil {
			return nil, err
		}
		return map[string]string{"status": "updated", "issue_id": req.IssueID}, nil

	case "linear.get_issue":
		issueID := stringParam(params, "issue_id")
		if issueID == "" {
			return nil, fmt.Errorf("linear: get_issue: missing required param issue_id")
		}
		return c.client.GetIssue(ctx, issueID)

	case "linear.list_issues":
		teamID := stringParam(params, "team_id")
		state := stringParam(params, "state")
		return c.client.ListIssues(ctx, teamID, state)

	case "linear.add_comment":
		req := &AddCommentRequest{
			IssueID: stringParam(params, "issue_id"),
			Body:    stringParam(params, "body"),
		}
		if req.IssueID == "" {
			return nil, fmt.Errorf("linear: add_comment: missing required param issue_id")
		}
		if req.Body == "" {
			return nil, fmt.Errorf("linear: add_comment: missing required param body")
		}
		return c.client.AddComment(ctx, req)

	default:
		return nil, fmt.Errorf("linear: unknown tool %q", toolName)
	}
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// stringParam extracts a string parameter from the params map.
func stringParam(params map[string]any, key string) string {
	v, _ := params[key].(string)
	return v
}

// stringSliceParam extracts a string slice parameter from the params map.
func stringSliceParam(params map[string]any, key string) []string {
	v, ok := params[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}
