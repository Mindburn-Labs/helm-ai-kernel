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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// Compile-time contracts for the governed execution path.
var (
	_ effects.Connector           = (*Connector)(nil)
	_ effects.PermitScopeProvider = (*Connector)(nil)
)

// Connector is the HELM connector for the Linear project management API.
//
// It composes:
//   - Client:     HTTP bridge to Linear GraphQL API
//   - ZeroTrust:  connector trust gate (rate limits, data classes)
//   - ProofGraph: cryptographic receipt chain
//
// Every tool call produces an INTENT -> EFFECT chain in the ProofGraph.
type Connector struct {
	client       *Client
	gate         *connector.ZeroTrustGate
	graph        *proofgraph.Graph
	connectorID  string
	permitPubKey string
	nonceMu      sync.Mutex
	permitNonces map[string]permitNonceState
	now          func() time.Time
	seq          atomic.Uint64
}

const linearPermitMaxTTL = time.Hour

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

var toolAllowedParamsMap = map[string][]string{
	"linear.create_issue": {"team_id", "title", "description", "priority", "assignee_id", "label_ids"},
	"linear.update_issue": {"issue_id", "title", "description", "state", "priority", "assignee_id"},
	"linear.get_issue":    {"issue_id"},
	"linear.list_issues":  {"team_id", "state"},
	"linear.add_comment":  {"issue_id", "body"},
}

// Config configures a new Linear connector.
// Config configures a new Linear connector.
//
// Token is optional. When empty, the underlying GraphQL client returns
// "not connected" errors — useful for unit tests. Set Token (Linear personal
// API key `lin_api_...` or OAuth bearer) to enable real API access.
type Config struct {
	BaseURL     string
	ConnectorID string
	Token       string
	// PermitPublicKey is the hex Ed25519 public key that EffectPermits for this
	// connector must be signed under — GovernedBridge.PermitSigningPublicKey().
	//
	// It is opt-in, and that is a deliberate transitional state, not a design:
	// leaving it empty preserves today's behaviour, where the permit carries no
	// cryptographic binding at all and the connector trusts whoever handed it
	// the struct. Setting it makes this connector fail closed on an unsigned,
	// tampered, or foreign-signed permit. Every deployment that wants the
	// permit to mean anything must set it.
	PermitPublicKey string
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
		permitPubKey: strings.TrimSpace(cfg.PermitPublicKey),
		permitNonces: make(map[string]permitNonceState),
		now:          time.Now,
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// MaxPermitTTL declares the connector's maximum accepted permit lifetime.
// GovernedBridge recognizes this optional connector contract and never mints a
// longer-lived Linear permit.
func (*Connector) MaxPermitTTL() time.Duration {
	return linearPermitMaxTTL
}

// PermitScope declares the exact connector-owned permit contract for a call.
// Every accepted parameter is bound by its type and JSON value, and every
// Linear action is bound to its team or issue resource.
func (c *Connector) PermitScope(toolName string, params map[string]any) (effects.EffectType, effects.EffectScope, string, error) {
	effectType, ok := toolEffectTypeMap[toolName]
	if !ok {
		return "", effects.EffectScope{}, "", fmt.Errorf("linear: unknown tool %q", toolName)
	}
	if err := validateToolParams(toolName, params); err != nil {
		return "", effects.EffectScope{}, "", err
	}
	allowedKeys := toolAllowedParamsMap[toolName]
	allowedParams := make([]string, 0, len(params))
	for _, key := range allowedKeys {
		if value, present := params[key]; present {
			encoded, err := scopeParamValue(value)
			if err != nil {
				return "", effects.EffectScope{}, "", fmt.Errorf("linear: encode permit param %q: %w", key, err)
			}
			allowedParams = append(allowedParams, key+"="+encoded)
		}
	}
	resourceRef, err := linearResourceRef(toolName, params)
	if err != nil {
		return "", effects.EffectScope{}, "", err
	}
	return effectType, effects.EffectScope{AllowedAction: toolName, AllowedParams: allowedParams}, resourceRef, nil
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

	// 2. Validate the EffectPermit scope. The connector is the last guard
	// before Linear's GraphQL sinks, so it cannot rely on the bridge alone.
	if err := c.validatePermit(permit, toolName, effectType, params); err != nil {
		return nil, err
	}

	// 3. Reserve before the gate records a call. A replay cannot consume
	// rate-limit capacity, while a gate denial releases a fresh permit.
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
	// and the gate succeed, but before any ProofGraph intent or Linear request.
	if err := c.consumePermitNonce(permit.Nonce); err != nil {
		return nil, err
	}

	// 7. Append INTENT node to ProofGraph.
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

	// 8. Dispatch to the appropriate client method.
	result, execErr := c.dispatch(ctx, toolName, params)

	// 9. Append EFFECT node to ProofGraph.
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
	// The signature is checked before any other permit field, and validatePermit
	// itself runs before the nonce reservation, the gate, the ProofGraph intent
	// and the GraphQL client. A permit that does not verify never reaches any of
	// them, so a refusal here means no effect was attempted.
	if err := c.verifyPermitSignature(permit); err != nil {
		return err
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
	if permit.ExpiresAt.IsZero() {
		return fmt.Errorf("linear: permit missing expires_at")
	}
	if !permit.ExpiresAt.UTC().After(permit.IssuedAt.UTC()) {
		return fmt.Errorf("linear: permit expires_at must be after issued_at")
	}
	if permit.IssuedAt.UTC().After(now.Add(time.Minute)) {
		return fmt.Errorf("linear: permit issued_at is in the future")
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
	if err := validateToolParams(toolName, params); err != nil {
		return err
	}
	if err := validateParamScope(permit, toolName, params); err != nil {
		return err
	}
	return validateResourceScope(permit, toolName, params)
}

// verifyPermitSignature enforces the permit's cryptographic binding when this
// connector was configured with a verification key. Without a key it is a
// no-op, which is what keeps every existing caller and test working.
//
// With a key it is fail-closed in all three directions: an unsigned permit, a
// permit whose covered fields were edited after signing, and a permit signed by
// a key this connector does not trust are all refused with an error. There is
// no path that downgrades to "accept unverified".
func (c *Connector) verifyPermitSignature(permit *effects.EffectPermit) error {
	if c.permitPubKey == "" {
		return nil
	}
	ok, err := crypto.VerifyPermit(c.permitPubKey, permit)
	if err != nil {
		return fmt.Errorf("linear: permit signature verification failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("linear: permit signature does not verify under the configured key")
	}
	return nil
}

func validateToolParams(toolName string, params map[string]any) error {
	allowed, ok := toolAllowedParamsMap[toolName]
	if !ok {
		return fmt.Errorf("linear: missing permit scope for tool %q", toolName)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key, value := range params {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("linear: param %q is not supported by %q", key, toolName)
		}
		if key == "label_ids" {
			if !isStringSlice(value) {
				return fmt.Errorf("linear: param %q for %q must be a string slice", key, toolName)
			}
			continue
		}
		if _, ok := value.(string); !ok {
			return fmt.Errorf("linear: param %q for %q must be a string", key, toolName)
		}
	}

	resourceKey, _ := linearResourceKey(toolName)
	resourceID, ok := stringParamExact(params, resourceKey)
	if !ok || strings.TrimSpace(resourceID) == "" {
		return fmt.Errorf("linear: action %q requires %s", toolName, resourceKey)
	}
	if resourceID != strings.TrimSpace(resourceID) {
		return fmt.Errorf("linear: %s must not contain surrounding whitespace", resourceKey)
	}
	switch toolName {
	case "linear.create_issue":
		if title, ok := stringParamExact(params, "title"); !ok || title == "" {
			return fmt.Errorf("linear: create_issue: missing required param title")
		}
	case "linear.update_issue":
		for _, key := range []string{"title", "description", "state", "priority", "assignee_id"} {
			if _, present := params[key]; present {
				return nil
			}
		}
		return fmt.Errorf("linear: update_issue: no fields to update")
	case "linear.add_comment":
		if body, ok := stringParamExact(params, "body"); !ok || body == "" {
			return fmt.Errorf("linear: add_comment: missing required param body")
		}
	}
	return nil
}

func validateParamScope(permit *effects.EffectPermit, toolName string, params map[string]any) error {
	exactValues := make(map[string]string, len(permit.Scope.AllowedParams))
	for _, raw := range permit.Scope.AllowedParams {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("linear: permit contains blank allowed_param")
		}
		key, value, hasValue := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("linear: permit contains blank allowed_param key")
		}
		if !hasValue {
			return fmt.Errorf("linear: permit param %q must bind an exact value", key)
		}
		if _, known := params[key]; !known {
			return fmt.Errorf("linear: permit scope requires param %q", key)
		}
		if _, duplicate := exactValues[key]; duplicate {
			return fmt.Errorf("linear: permit repeats allowed_param %q", key)
		}
		if !validScopeParamValue(value) {
			return fmt.Errorf("linear: permit param %q has invalid exact value", key)
		}
		exactValues[key] = value
	}
	if len(exactValues) != len(params) {
		return fmt.Errorf("linear: permit scope does not bind every supplied param")
	}
	for key, actual := range params {
		expected, ok := exactValues[key]
		if !ok {
			return fmt.Errorf("linear: param %q not authorized by permit scope", key)
		}
		got, err := scopeParamValue(actual)
		if err != nil {
			return fmt.Errorf("linear: encode param %q for permit validation: %w", key, err)
		}
		if got != expected {
			return fmt.Errorf("linear: param %q does not match permit scope", key)
		}
	}
	return nil
}

type scopedParamValue struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func scopeParamValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(scopedParamValue{Type: fmt.Sprintf("%T", value), Value: raw})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func validScopeParamValue(value string) bool {
	var decoded scopedParamValue
	return json.Unmarshal([]byte(value), &decoded) == nil && decoded.Type != "" && json.Valid(decoded.Value)
}

func validateResourceScope(permit *effects.EffectPermit, toolName string, params map[string]any) error {
	want, err := linearResourceRef(toolName, params)
	if err != nil {
		return err
	}
	if permit.ResourceRef != want {
		return fmt.Errorf("linear: permit resource_ref %q does not authorize %q", permit.ResourceRef, want)
	}
	return nil
}

func linearResourceRef(toolName string, params map[string]any) (string, error) {
	resourceKey, prefix := linearResourceKey(toolName)
	resourceID, ok := stringParamExact(params, resourceKey)
	if !ok || strings.TrimSpace(resourceID) == "" {
		return "", fmt.Errorf("linear: action %q requires %s", toolName, resourceKey)
	}
	if resourceID != strings.TrimSpace(resourceID) {
		return "", fmt.Errorf("linear: %s must not contain surrounding whitespace", resourceKey)
	}
	return prefix + resourceID, nil
}

func linearResourceKey(toolName string) (string, string) {
	if toolName == "linear.create_issue" || toolName == "linear.list_issues" {
		return "team_id", "team:"
	}
	return "issue_id", "issue:"
}

func stringParamExact(params map[string]any, key string) (string, bool) {
	value, ok := params[key]
	if !ok {
		return "", false
	}
	stringValue, ok := value.(string)
	return stringValue, ok
}

func isStringSlice(value any) bool {
	switch typed := value.(type) {
	case []string:
		return true
	case []any:
		for _, item := range typed {
			if _, ok := item.(string); !ok {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// NOTE: This is an in-process replay tracker that retains nonces only until
// each permit expires. Cross-replica deployments need a shared/durable store
// or equivalent strategy.
func (c *Connector) reservePermitNonce(nonce string, expiresAt time.Time) error {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	c.pruneExpiredPermitNoncesLocked(c.now().UTC())
	if _, ok := c.permitNonces[nonce]; ok {
		return fmt.Errorf("linear: permit nonce %q already used", nonce)
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
	c.pruneExpiredPermitNoncesLocked(c.now().UTC())
	state, ok := c.permitNonces[nonce]
	if !ok || !state.reserved {
		return fmt.Errorf("linear: permit nonce %q was not reserved", nonce)
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
