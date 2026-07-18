package github

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// Compile-time contracts for the governed execution path.
var (
	_ effects.Connector           = (*Connector)(nil)
	_ effects.PermitScopeProvider = (*Connector)(nil)
	_ effects.LifecycleConnector  = (*Connector)(nil)
)

// Connector is the HELM connector for the GitHub API.
//
// It composes:
//   - Client:     HTTP bridge to GitHub REST API
//   - ZeroTrust:  connector trust gate (rate limits, data classes)
//   - ProofGraph: cryptographic receipt chain
//
// Every tool call produces an INTENT -> EFFECT chain in the ProofGraph.
type Connector struct {
	client      *Client
	gate        *connector.ZeroTrustGate
	graph       *proofgraph.Graph
	connectorID string
	nonceMu     sync.Mutex
	usedNonces  map[string]struct{}
	seq         atomic.Uint64
}

const githubPermitMaxTTL = time.Hour

var toolEffectTypeMap = map[string]effects.EffectType{
	"github.list_prs":     effects.EffectTypeRead,
	"github.read_pr":      effects.EffectTypeRead,
	"github.create_issue": effects.EffectTypeWrite,
	"github.add_comment":  effects.EffectTypeWrite,
}

var toolAllowedParamsMap = map[string][]string{
	"github.list_prs":     {"repo", "state"},
	"github.read_pr":      {"repo", "number"},
	"github.create_issue": {"repo", "title", "body", "labels", "assignees"},
	"github.add_comment":  {"repo", "issue_number", "body"},
}

// Config configures a new GitHub connector.
//
// Token is optional. When empty, the underlying Client returns "not connected"
// errors for every method — useful for unit tests and schema-validation paths
// that should not touch the network. Set Token (a GitHub personal access token,
// classic or fine-grained) to enable real API calls.
type Config struct {
	BaseURL     string
	ConnectorID string
	Token       string
}

// NewConnector creates a new GitHub connector.
//
// If cfg.Token is non-empty, the connector will make authenticated requests
// to the GitHub REST API with rate-limit awareness and retry-on-transient.
// If cfg.Token is empty, every tool call returns a "not connected" error
// (preserving backward compatibility with token-less unit tests).
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
		RateLimitPerMinute: 30,
		RequireProvenance:  true,
	})

	var client *Client
	if cfg.Token != "" {
		client = NewClientWithToken(cfg.BaseURL, cfg.Token)
	} else {
		client = NewClient(cfg.BaseURL)
	}

	return &Connector{
		client:      client,
		gate:        gate,
		graph:       proofgraph.NewGraph(),
		connectorID: cfg.ConnectorID,
		usedNonces:  make(map[string]struct{}),
	}
}

// ID returns the connector identifier.
func (c *Connector) ID() string {
	return c.connectorID
}

// PermitScope returns the exact connector-owned permit contract for a call.
// Values are included as exact key=value constraints so the connector does not
// accept a permit that was minted for a different argument set.
func (c *Connector) PermitScope(toolName string, params map[string]any) (effects.EffectType, effects.EffectScope, string, error) {
	effectType, ok := toolEffectTypeMap[toolName]
	if !ok {
		return "", effects.EffectScope{}, "", fmt.Errorf("github: unknown tool %q", toolName)
	}
	allowedKeys, ok := toolAllowedParamsMap[toolName]
	if !ok {
		return "", effects.EffectScope{}, "", fmt.Errorf("github: missing permit scope for tool %q", toolName)
	}
	allowed := make([]string, 0, len(params))
	for _, key := range allowedKeys {
		if value, present := params[key]; present {
			allowed = append(allowed, key+"="+scopeParamValue(value))
		}
	}
	for key := range params {
		known := false
		for _, allowedKey := range allowedKeys {
			if key == allowedKey {
				known = true
				break
			}
		}
		if !known {
			return "", effects.EffectScope{}, "", fmt.Errorf("github: param %q is not supported by %q", key, toolName)
		}
	}
	resourceRef := strings.TrimSpace(stringParam(params, "repo"))
	if effectType == effects.EffectTypeWrite && resourceRef == "" {
		return "", effects.EffectScope{}, "", fmt.Errorf("github: write action %q requires repo", toolName)
	}
	return effectType, effects.EffectScope{AllowedAction: toolName, AllowedParams: allowed}, resourceRef, nil
}

// Execute dispatches a tool call through the zero-trust gate and records it in
// the ProofGraph. Implements effects.Connector.
func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	return c.execute(ctx, permit, toolName, params, nil)
}

// ExecuteWithLifecycle exposes GitHub's last pre-network seam to the durable
// effect reservation boundary. Production governed writes use this path;
// Execute remains for legacy/read-only callers that do not carry a reservation.
func (c *Connector) ExecuteWithLifecycle(
	ctx context.Context,
	permit *effects.EffectPermit,
	toolName string,
	params map[string]any,
	lifecycle effects.ExecutionLifecycle,
) (any, error) {
	if lifecycle == nil {
		return nil, fmt.Errorf("github: durable execution lifecycle is required")
	}
	return c.execute(ctx, permit, toolName, params, lifecycle)
}

func (c *Connector) execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any, lifecycle effects.ExecutionLifecycle) (any, error) {
	if params == nil {
		params = map[string]any{}
	}
	failNotStarted := func(reasonCode string, cause error) (any, error) {
		if lifecycle != nil {
			if transitionErr := lifecycle.MarkNotStarted(ctx, effects.ExecutionLifecycleMeta{ReasonCode: reasonCode}); transitionErr != nil {
				return nil, fmt.Errorf("%v; github: persist NOT_STARTED: %w", cause, transitionErr)
			}
		}
		return nil, cause
	}

	// 1. Resolve the tool's governed classifications before any side effect.
	dataClass, ok := toolDataClassMap[toolName]
	if !ok {
		return failNotStarted("GITHUB_TOOL_UNKNOWN", fmt.Errorf("github: unknown tool %q", toolName))
	}
	effectType, ok := toolEffectTypeMap[toolName]
	if !ok {
		return failNotStarted("GITHUB_EFFECT_CLASS_MISSING", fmt.Errorf("github: missing effect classification for tool %q", toolName))
	}

	// 2. Validate the EffectPermit scope. Connectors are the last guard before
	// GitHub network sinks, so they must not rely only on the gateway.
	if err := c.validatePermit(permit, toolName, effectType, params); err != nil {
		return failNotStarted("GITHUB_PERMIT_REJECTED", err)
	}

	// 3. Gate check
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return failNotStarted("GITHUB_GATE_DENIED", fmt.Errorf("github: gate denied: %s (%s)", decision.Reason, decision.Violation))
	}

	// 4. Compute input hash via canonicalize.CanonicalHash
	inputHash, err := canonicalize.CanonicalHash(params)
	if err != nil {
		return failNotStarted("GITHUB_INPUT_HASH_FAILED", fmt.Errorf("github: canonical hash of params: %w", err))
	}

	// Resolve and validate every deterministic client input before STARTED. The
	// returned closure captures immutable typed values, so crossing STARTED is
	// the last local seam before the HTTP client is invoked.
	dispatch, preflightErr := c.prepareDispatch(toolName, params)
	if preflightErr != nil {
		dispatch = func(context.Context) (any, error) { return nil, preflightErr }
	}

	// 5. Consume the single-use permit only after all pre-execution validation
	// succeeds, but before any ProofGraph intent or GitHub REST call is made.
	if preflightErr == nil {
		if err := c.consumePermitNonce(permit.Nonce); err != nil {
			return failNotStarted("GITHUB_PERMIT_REPLAY", err)
		}
	}

	// 6. Append INTENT node to ProofGraph
	intentPayload, err := json.Marshal(map[string]any{
		"type":       "github.intent",
		"tool":       toolName,
		"input_hash": inputHash,
		"permit_id":  permit.PermitID,
	})
	if err != nil {
		return failNotStarted("GITHUB_INTENT_MARSHAL_FAILED", fmt.Errorf("github: marshal intent payload: %w", err))
	}
	seq := c.seq.Add(1)
	intentNode, err := c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, seq)
	if err != nil {
		return failNotStarted("GITHUB_INTENT_APPEND_FAILED", fmt.Errorf("github: append intent: %w", err))
	}

	executionMeta := effects.ExecutionLifecycleMeta{
		ConnectorExecutionRef: "github-" + permit.PermitID,
		IntentRef:             intentNode.NodeHash,
	}
	started := false
	if lifecycle != nil && preflightErr != nil {
		if err := lifecycle.MarkNotStarted(ctx, effects.ExecutionLifecycleMeta{ReasonCode: "GITHUB_DISPATCH_PREFLIGHT_FAILED", IntentRef: executionMeta.IntentRef}); err != nil {
			return nil, fmt.Errorf("%v; github: persist NOT_STARTED: %w", preflightErr, err)
		}
	} else if lifecycle != nil {
		if err := lifecycle.MarkStarted(ctx, executionMeta); err != nil {
			_ = lifecycle.MarkUncertain(ctx, effects.ExecutionLifecycleMeta{
				ReasonCode: "GITHUB_START_TRANSITION_AMBIGUOUS", ConnectorExecutionRef: executionMeta.ConnectorExecutionRef,
				IntentRef: executionMeta.IntentRef,
			})
			return nil, fmt.Errorf("github: persist STARTED before dispatch: %w", err)
		}
		started = true
	}

	// 7. Dispatch to appropriate client method
	result, execErr := dispatch(ctx)

	// 8. Append EFFECT node to ProofGraph
	effectEntry := map[string]any{
		"type":       "github.effect",
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
	effectNode, graphErr := c.graph.Append(proofgraph.NodeTypeEffect, effectPayload, c.connectorID, seq)
	if graphErr != nil {
		if lifecycle != nil && started {
			_ = lifecycle.MarkUncertain(ctx, effects.ExecutionLifecycleMeta{
				ReasonCode: "GITHUB_EFFECT_EVIDENCE_MISSING", ConnectorExecutionRef: executionMeta.ConnectorExecutionRef,
				IntentRef: executionMeta.IntentRef,
			})
		}
		return nil, fmt.Errorf("github: append effect: %w", graphErr)
	}

	if execErr != nil {
		if lifecycle != nil && started {
			if transitionErr := lifecycle.MarkUncertain(ctx, effects.ExecutionLifecycleMeta{
				ReasonCode: "GITHUB_DISPATCH_OUTCOME_UNCERTAIN", ConnectorExecutionRef: executionMeta.ConnectorExecutionRef,
				IntentRef: executionMeta.IntentRef, EffectRef: effectNode.NodeHash,
			}); transitionErr != nil {
				return nil, fmt.Errorf("%v; github: persist UNCERTAIN: %w", execErr, transitionErr)
			}
		}
		return nil, execErr
	}
	return result, nil
}

func (c *Connector) validatePermit(permit *effects.EffectPermit, toolName string, effectType effects.EffectType, params map[string]any) error {
	if permit == nil {
		return fmt.Errorf("github: missing effect permit")
	}
	if permit.ConnectorID != c.connectorID {
		return fmt.Errorf("github: permit connector_id %q does not match %q", permit.ConnectorID, c.connectorID)
	}
	if permit.Scope.AllowedAction == "" {
		return fmt.Errorf("github: permit missing allowed_action")
	}
	if permit.Scope.AllowedAction != toolName {
		return fmt.Errorf("github: permit action %q does not authorize %q", permit.Scope.AllowedAction, toolName)
	}
	if permit.EffectType != effectType {
		return fmt.Errorf("github: permit effect_type %q does not authorize %q", permit.EffectType, toolName)
	}
	now := time.Now().UTC()
	if permit.IssuedAt.IsZero() {
		return fmt.Errorf("github: permit missing issued_at")
	}
	if permit.IssuedAt.UTC().After(now.Add(time.Minute)) {
		return fmt.Errorf("github: permit issued_at is in the future")
	}
	if permit.ExpiresAt.IsZero() {
		return fmt.Errorf("github: permit missing expires_at")
	}
	if !now.Before(permit.ExpiresAt.UTC()) {
		return fmt.Errorf("github: permit expired at %s", permit.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if permit.ExpiresAt.UTC().Sub(permit.IssuedAt.UTC()) > githubPermitMaxTTL {
		return fmt.Errorf("github: permit ttl exceeds %s", githubPermitMaxTTL)
	}
	if !permit.SingleUse {
		return fmt.Errorf("github: permit must be single-use")
	}
	if strings.TrimSpace(permit.Nonce) == "" {
		return fmt.Errorf("github: permit missing nonce")
	}
	if err := validateParamScope(permit, toolName, effectType, params); err != nil {
		return err
	}
	return validateResourceScope(permit, effectType, params)
}

func validateParamScope(permit *effects.EffectPermit, toolName string, effectType effects.EffectType, params map[string]any) error {
	allowedKeys := make(map[string]struct{}, len(permit.Scope.AllowedParams))
	exactValues := map[string]string{}
	for _, raw := range permit.Scope.AllowedParams {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return fmt.Errorf("github: permit contains blank allowed_param")
		}
		key, value, hasValue := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("github: permit contains blank allowed_param key")
		}
		allowedKeys[key] = struct{}{}
		if hasValue {
			exactValues[key] = value
		}
	}
	if effectType == effects.EffectTypeWrite && len(allowedKeys) == 0 {
		return fmt.Errorf("github: write action %q requires allowed_params scope", toolName)
	}
	if len(allowedKeys) > 0 {
		for key := range params {
			if _, ok := allowedKeys[key]; !ok {
				return fmt.Errorf("github: param %q not authorized by permit scope", key)
			}
		}
	}
	for key, expected := range exactValues {
		actual, ok := params[key]
		if !ok {
			return fmt.Errorf("github: permit scope requires param %q", key)
		}
		if got := scopeParamValue(actual); got != expected {
			return fmt.Errorf("github: param %q value %q does not match permit scope", key, got)
		}
	}
	return nil
}

func validateResourceScope(permit *effects.EffectPermit, effectType effects.EffectType, params map[string]any) error {
	repo := strings.TrimSpace(stringParam(params, "repo"))
	if repo == "" {
		return nil
	}
	resourceRef := strings.TrimSpace(permit.ResourceRef)
	if resourceRef == "" {
		if effectType == effects.EffectTypeWrite {
			return fmt.Errorf("github: write action requires permit resource_ref for repo %q", repo)
		}
		return nil
	}
	if resourceRefMatchesRepo(resourceRef, repo, params) {
		return nil
	}
	return fmt.Errorf("github: permit resource_ref %q does not authorize repo %q", resourceRef, repo)
}

func resourceRefMatchesRepo(resourceRef, repo string, params map[string]any) bool {
	if resourceRef == repo || resourceRef == "repo:"+repo || resourceRef == "github:"+repo || resourceRef == "github:repo:"+repo {
		return true
	}
	if issueNumber, ok := intParam(params, "issue_number"); ok {
		issueRef := repo + "#" + strconv.Itoa(issueNumber)
		if resourceRef == issueRef || resourceRef == repo+"/issues/"+strconv.Itoa(issueNumber) ||
			resourceRef == "github:"+issueRef || resourceRef == "github:repo:"+issueRef {
			return true
		}
	}
	return false
}

func scopeParamValue(v any) string {
	switch typed := v.(type) {
	case string:
		return typed
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		b, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(b)
	}
}

func (c *Connector) consumePermitNonce(nonce string) error {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	if _, ok := c.usedNonces[nonce]; ok {
		return fmt.Errorf("github: permit nonce %q already used", nonce)
	}
	c.usedNonces[nonce] = struct{}{}
	return nil
}

type preparedDispatch func(context.Context) (any, error)

// prepareDispatch validates deterministic connector/client inputs and captures
// an immutable typed request before the lifecycle crosses STARTED.
func (c *Connector) prepareDispatch(toolName string, params map[string]any) (preparedDispatch, error) {
	if err := validateGitHubBaseURL(c.client.baseURL); err != nil {
		return nil, err
	}
	switch toolName {
	case "github.list_prs":
		repo, repoOK := stringParamExact(params, "repo")
		if !repoOK || repo == "" {
			return nil, fmt.Errorf("github: list_prs: missing required param repo")
		}
		state, stateOK := stringParamExact(params, "state")
		if !stateOK {
			return nil, fmt.Errorf("github: list_prs: param state must be a string")
		}
		if state == "" {
			state = "open"
		}
		if c.client.token == "" {
			return nil, fmt.Errorf("github: ListPRs(%q, state=%q): not connected: requires personal access token", repo, state)
		}
		if _, _, err := splitRepo(repo); err != nil {
			return nil, fmt.Errorf("github: ListPRs: %w", err)
		}
		return func(ctx context.Context) (any, error) { return c.client.ListPRs(ctx, repo, state) }, nil

	case "github.read_pr":
		repo, repoOK := stringParamExact(params, "repo")
		if !repoOK || repo == "" {
			return nil, fmt.Errorf("github: read_pr: missing required param repo")
		}
		number, ok := intParam(params, "number")
		if !ok {
			return nil, fmt.Errorf("github: read_pr: missing required param number")
		}
		if c.client.token == "" {
			return nil, fmt.Errorf("github: ReadPR(%q, #%d): not connected: requires personal access token", repo, number)
		}
		if _, _, err := splitRepo(repo); err != nil {
			return nil, fmt.Errorf("github: ReadPR: %w", err)
		}
		if number <= 0 {
			return nil, fmt.Errorf("github: ReadPR: invalid PR number %d", number)
		}
		return func(ctx context.Context) (any, error) { return c.client.ReadPR(ctx, repo, number) }, nil

	case "github.create_issue":
		labels, ok := stringSliceParam(params, "labels")
		if !ok {
			return nil, fmt.Errorf("github: create_issue: param labels must be an array of strings")
		}
		assignees, ok := stringSliceParam(params, "assignees")
		if !ok {
			return nil, fmt.Errorf("github: create_issue: param assignees must be an array of strings")
		}
		repo, repoOK := stringParamExact(params, "repo")
		title, titleOK := stringParamExact(params, "title")
		body, bodyOK := stringParamExact(params, "body")
		if !repoOK || !titleOK || !bodyOK {
			return nil, fmt.Errorf("github: create_issue: repo, title, and body must be strings when present")
		}
		req := &CreateIssueRequest{
			Repo:      repo,
			Title:     title,
			Body:      body,
			Labels:    labels,
			Assignees: assignees,
		}
		if req.Repo == "" {
			return nil, fmt.Errorf("github: create_issue: missing required param repo")
		}
		if req.Title == "" {
			return nil, fmt.Errorf("github: create_issue: missing required param title")
		}
		if c.client.token == "" {
			return nil, fmt.Errorf("github: CreateIssue(%q, %q): not connected: requires personal access token", req.Repo, req.Title)
		}
		if _, _, err := splitRepo(req.Repo); err != nil {
			return nil, fmt.Errorf("github: CreateIssue: %w", err)
		}
		return func(ctx context.Context) (any, error) { return c.client.CreateIssue(ctx, req) }, nil

	case "github.add_comment":
		issueNumber, ok := intParam(params, "issue_number")
		if !ok {
			return nil, fmt.Errorf("github: add_comment: missing required param issue_number")
		}
		repo, repoOK := stringParamExact(params, "repo")
		body, bodyOK := stringParamExact(params, "body")
		if !repoOK || !bodyOK {
			return nil, fmt.Errorf("github: add_comment: repo and body must be strings")
		}
		req := &AddCommentRequest{
			Repo:        repo,
			IssueNumber: issueNumber,
			Body:        body,
		}
		if req.Repo == "" {
			return nil, fmt.Errorf("github: add_comment: missing required param repo")
		}
		if req.Body == "" {
			return nil, fmt.Errorf("github: add_comment: missing required param body")
		}
		if c.client.token == "" {
			return nil, fmt.Errorf("github: AddComment(%q, #%d): not connected: requires personal access token", req.Repo, req.IssueNumber)
		}
		if _, _, err := splitRepo(req.Repo); err != nil {
			return nil, fmt.Errorf("github: AddComment: %w", err)
		}
		if req.IssueNumber <= 0 {
			return nil, fmt.Errorf("github: AddComment: invalid issue_number %d", req.IssueNumber)
		}
		return func(ctx context.Context) (any, error) { return c.client.AddComment(ctx, req) }, nil

	default:
		return nil, fmt.Errorf("github: unknown tool %q", toolName)
	}
}

func validateGitHubBaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("github: invalid base URL %q", raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("github: invalid base URL scheme %q", parsed.Scheme)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("github: base URL must not contain userinfo, query, or fragment")
	}
	return nil
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

// stringParamExact distinguishes an absent optional string from a present
// value of the wrong type. Callers decide whether the empty/absent value is
// permitted, but never silently coerce or drop an approved value.
func stringParamExact(params map[string]any, key string) (string, bool) {
	value, present := params[key]
	if !present {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

// intParam extracts an integer parameter from the params map.
// Handles both int and float64 (JSON numbers decode to float64).
func intParam(params map[string]any, key string) (int, bool) {
	switch v := params[key].(type) {
	case int:
		return v, true
	case float64:
		limit := math.Ldexp(1, strconv.IntSize-1)
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v || v < -limit || v >= limit {
			return 0, false
		}
		return int(v), true
	case int64:
		if strconv.IntSize == 32 && (v < math.MinInt32 || v > math.MaxInt32) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		parsed, err := strconv.ParseInt(string(v), 10, strconv.IntSize)
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	default:
		return 0, false
	}
}

// stringSliceParam extracts a string slice parameter from the params map.
func stringSliceParam(params map[string]any, key string) ([]string, bool) {
	v, ok := params[key]
	if !ok {
		return nil, true
	}
	switch s := v.(type) {
	case []string:
		return append([]string(nil), s...), true
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			str, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, str)
		}
		return result, true
	default:
		return nil, false
	}
}
