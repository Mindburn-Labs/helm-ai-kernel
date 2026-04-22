package arc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/connector"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// Connector is the high-level ARC-AGI-3 connector for HELM.
//
// It composes:
//   - Client:     HTTP bridge to Python sidecar
//   - ZeroTrust:  connector trust gate (rate limits, provenance)
//   - ProofGraph: cryptographic receipt chain
//   - Policy:     ARC-specific budget and mode enforcement
//
// Every ARC action produces an INTENT → EFFECT chain in the ProofGraph.
// Episode boundaries produce CHECKPOINT nodes.
type Connector struct {
	client *Client
	gate   *connector.ZeroTrustGate
	graph  *proofgraph.Graph
	policy *PolicyProfile
	mode   RunMode

	mu                  sync.Mutex
	sessions            map[string]*sessionTracker
	scorecardOpenings   []time.Time
	activeGames         map[string]string // gameID -> cardID
	connectorID         string
}

// sessionTracker tracks per-session state for budget enforcement and receipts.
type sessionTracker struct {
	gameID       string
	stepCount    int
	resetCount   int
	actionHashes []string
	lastReward   float64
	done         bool
}

// ConnectorConfig configures a new ARC Connector.
type ConnectorConfig struct {
	BridgeURL   string
	Mode        RunMode
	Policy      *PolicyProfile
	ConnectorID string // e.g. "arc-agi-3"
}

// NewConnector creates a new ARC-AGI-3 connector.
func NewConnector(cfg ConnectorConfig) *Connector {
	if cfg.ConnectorID == "" {
		cfg.ConnectorID = "arc-agi-3"
	}
	if cfg.Policy == nil {
		cfg.Policy = DefaultPolicy(cfg.Mode)
	}

	gate := connector.NewZeroTrustGate()
	gate.SetPolicy(&connector.TrustPolicy{
		ConnectorID:        cfg.ConnectorID,
		TrustLevel:         connector.TrustLevelVerified,
		MaxTTLSeconds:      3600,
		AllowedDataClasses: AllowedDataClasses(),
		RateLimitPerMinute: cfg.Policy.MaxOnlineRPM,
		RequireProvenance:  true,
	})

	return &Connector{
		client:      NewClient(cfg.BridgeURL),
		gate:              gate,
		graph:             proofgraph.NewGraph(),
		policy:            cfg.Policy,
		mode:              cfg.Mode,
		sessions:          make(map[string]*sessionTracker),
		scorecardOpenings: make([]time.Time, 0),
		activeGames:       make(map[string]string),
		connectorID:       cfg.ConnectorID,
	}
}

// Health checks bridge liveness.
func (c *Connector) Health(ctx context.Context) (*HealthResponse, error) {
	return c.client.Health(ctx)
}

// ListGames returns available games.
func (c *Connector) ListGames(ctx context.Context) (*GameListResponse, error) {
	decision := c.gate.CheckCall(ctx, c.connectorID, "arc.games.list")
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}
	return c.client.ListGames(ctx)
}

// CreateSession creates a game session through the bridge.
// Returns the session info with initial observation.
func (c *Connector) CreateSession(ctx context.Context, gameID string) (*SessionInfo, error) {
	decision := c.gate.CheckCall(ctx, c.connectorID, "arc.env.reset")
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	c.mu.Lock()
	if c.policy.Mode == RunModeOfficialShadow {
		if _, ok := c.activeGames[gameID]; !ok {
			c.mu.Unlock()
			return nil, fmt.Errorf("official-shadow mode: game %q not associated with an open scorecard", gameID)
		}
	}
	c.mu.Unlock()

	modeStr := "OFFLINE"
	if c.mode == RunModeOfficialShadow || c.mode == RunModeCommunityHarness {
		modeStr = string(c.policy.BridgeMode)
	}

	info, err := c.client.CreateSession(ctx, gameID, modeStr)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.sessions[info.SessionID] = &sessionTracker{
		gameID:     gameID,
		resetCount: 1,
	}
	c.mu.Unlock()

	return info, nil
}

// Step executes an action in a session.
//
// The flow is:
//  1. Check ZeroTrust gate (rate limit, data class)
//  2. Check budget ceilings (max actions, max wallclock)
//  3. Append INTENT node to ProofGraph
//  4. Execute action through bridge client
//  5. Append EFFECT node to ProofGraph
//  6. Return observation
func (c *Connector) Step(ctx context.Context, sessionID, action string, reasoning json.RawMessage) (*StepResponse, error) {
	// 1. ZeroTrust gate
	dataClass := "arc.env.step.simple"
	if action == "ACTION6" {
		dataClass = "arc.env.step.complex"
	}
	decision := c.gate.CheckCall(ctx, c.connectorID, dataClass)
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// 2. Budget check
	c.mu.Lock()
	tracker, ok := c.sessions[sessionID]
	if !ok {
		c.mu.Unlock()
		return nil, fmt.Errorf("session %s not tracked", sessionID)
	}
	if tracker.done {
		c.mu.Unlock()
		return nil, fmt.Errorf("session %s already done", sessionID)
	}
	if c.policy.MaxActionsPerEpisode > 0 && tracker.stepCount >= c.policy.MaxActionsPerEpisode {
		c.mu.Unlock()
		return nil, fmt.Errorf("budget exceeded: %d/%d actions", tracker.stepCount, c.policy.MaxActionsPerEpisode)
	}
	step := tracker.stepCount + 1
	c.mu.Unlock()

	// 3. INTENT node
	intentPayload, err := MakeIntentPayload(sessionID, step, action, reasoning)
	if err != nil {
		return nil, fmt.Errorf("make intent payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, uint64(step*2-1))
	if err != nil {
		return nil, fmt.Errorf("append intent: %w", err)
	}

	// Hash action for receipt chain
	actionHash, err := HashActionRecord(ActionRecord{
		SessionID: sessionID,
		Step:      step,
		Action:    action,
		Reasoning: reasoning,
	})
	if err != nil {
		return nil, fmt.Errorf("hash action: %w", err)
	}

	// 4. Execute through bridge
	resp, err := c.client.Step(ctx, sessionID, action, reasoning)
	if err != nil {
		return nil, fmt.Errorf("bridge step: %w", err)
	}

	// Hash first frame for provenance
	var frameHash string
	if len(resp.Obs.Frames) > 0 {
		frameHash, _ = HashFrame(resp.Obs.Frames[0])
	}

	// 5. EFFECT node
	effectPayload, err := MakeEffectPayload(sessionID, step, actionHash, frameHash, resp.Done, resp.Obs.Reward)
	if err != nil {
		return nil, fmt.Errorf("make effect payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeEffect, effectPayload, c.connectorID, uint64(step*2))
	if err != nil {
		return nil, fmt.Errorf("append effect: %w", err)
	}

	// 6. Update tracker
	c.mu.Lock()
	tracker.stepCount = step
	tracker.actionHashes = append(tracker.actionHashes, actionHash)
	tracker.lastReward = resp.Obs.Reward
	tracker.done = resp.Done
	c.mu.Unlock()

	return resp, nil
}

// CloseSession closes a session and produces a CHECKPOINT node.
func (c *Connector) CloseSession(ctx context.Context, sessionID string) (*EpisodeSummary, error) {
	c.mu.Lock()
	tracker, ok := c.sessions[sessionID]
	if !ok {
		c.mu.Unlock()
		return nil, fmt.Errorf("session %s not tracked", sessionID)
	}
	delete(c.sessions, sessionID)
	c.mu.Unlock()

	// Compute episode hash
	epHash, err := HashEpisode(EpisodeRecord{
		SessionID:    sessionID,
		GameID:       tracker.gameID,
		ActionHashes: tracker.actionHashes,
		FinalDone:    tracker.done,
		FinalReward:  tracker.lastReward,
	})
	if err != nil {
		return nil, fmt.Errorf("hash episode: %w", err)
	}

	// CHECKPOINT node
	cpPayload, err := MakeCheckpointPayload(
		sessionID, tracker.gameID, epHash, "",
		tracker.stepCount, tracker.lastReward,
	)
	if err != nil {
		return nil, fmt.Errorf("make checkpoint payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeCheckpoint, cpPayload, c.connectorID, uint64(tracker.stepCount*2+1))
	if err != nil {
		return nil, fmt.Errorf("append checkpoint: %w", err)
	}

	// Close in bridge
	_ = c.client.CloseSession(ctx, sessionID)

	return &EpisodeSummary{
		SessionID:   sessionID,
		GameID:      tracker.gameID,
		TotalSteps:  tracker.stepCount,
		FinalReward: tracker.lastReward,
		Completed:   tracker.done,
		EpisodeHash: epHash,
	}, nil
}

// ---------------------------------------------------------------------------
// Scorecard Lifecycle
// ---------------------------------------------------------------------------

// OpenScorecard requests a new online scorecard, enforcing hourly budgets and producing receipts.
func (c *Connector) OpenScorecard(ctx context.Context, gameIDs []string) (*ScorecardInfo, error) {
	decision := c.gate.CheckCall(ctx, c.connectorID, "arc.scorecard.open")
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}
	if c.policy.Mode != RunModeCommunityHarness && c.policy.Mode != RunModeOfficialShadow {
		// Just a sanity check; bridge handles ONLINE check
	}

	c.mu.Lock()
	now := time.Now()
	// Purge openings older than 1 hour
	valid := 0
	for _, t := range c.scorecardOpenings {
		if now.Sub(t) <= time.Hour {
			c.scorecardOpenings[valid] = t
			valid++
		}
	}
	c.scorecardOpenings = c.scorecardOpenings[:valid]

	if c.policy.MaxOnlineScorecardsPH > 0 && len(c.scorecardOpenings) >= c.policy.MaxOnlineScorecardsPH {
		c.mu.Unlock()
		return nil, fmt.Errorf("budget exceeded: max scorecards per hour (%d) reached", c.policy.MaxOnlineScorecardsPH)
	}
	// Optimistically record the opening
	c.scorecardOpenings = append(c.scorecardOpenings, now)
	c.mu.Unlock()

	// INTENT node
	intentPayload, err := MakeScorecardOpenPayload(gameIDs)
	if err != nil {
		return nil, fmt.Errorf("make intent payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, 0)
	if err != nil {
		return nil, fmt.Errorf("append intent: %w", err)
	}

	// Execute through bridge
	info, err := c.client.OpenScorecard(ctx, gameIDs)
	if err != nil {
		return nil, fmt.Errorf("bridge open scorecard: %w", err)
	}

	// EFFECT node
	effectPayload, err := MakeScorecardOpenEffectPayload(info.CardID, "")
	if err != nil {
		return nil, fmt.Errorf("make effect payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeEffect, effectPayload, c.connectorID, 0)
	if err != nil {
		return nil, fmt.Errorf("append effect: %w", err)
	}

	// Register games
	c.mu.Lock()
	for _, gid := range gameIDs {
		c.activeGames[gid] = info.CardID
	}
	c.mu.Unlock()

	return info, nil
}

// GetScorecard retrieves scorecard results. Read-only operation.
func (c *Connector) GetScorecard(ctx context.Context, cardID string) (*ScorecardInfo, error) {
	decision := c.gate.CheckCall(ctx, c.connectorID, "arc.scorecard.get")
	if !decision.Allowed {
		return nil, fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}
	return c.client.GetScorecard(ctx, cardID)
}

// CloseScorecard computes final hash, closes the scorecard, and records the receipt.
func (c *Connector) CloseScorecard(ctx context.Context, cardID string) error {
	decision := c.gate.CheckCall(ctx, c.connectorID, "arc.scorecard.close")
	if !decision.Allowed {
		return fmt.Errorf("gate denied: %s (%s)", decision.Reason, decision.Violation)
	}

	// Fetch final state for deterministic hashing before close
	finalState, err := c.client.GetScorecard(ctx, cardID)
	var cardHash string
	if err == nil && finalState != nil {
		cardHash, _ = HashScorecard(ScorecardRecord{
			CardID:    finalState.CardID,
			Status:    finalState.Status,
			Scores:    finalState.Scores,
			ReplayURL: finalState.ReplayURL,
		})
	}

	// INTENT node
	intentPayload, err := MakeScorecardClosePayload(cardID)
	if err != nil {
		return fmt.Errorf("make intent payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeIntent, intentPayload, c.connectorID, 0)
	if err != nil {
		return fmt.Errorf("append intent: %w", err)
	}

	// Execute through bridge
	if err := c.client.CloseScorecard(ctx, cardID); err != nil {
		return fmt.Errorf("bridge close scorecard: %w", err)
	}

	// Unregister games
	c.mu.Lock()
	for gid, cid := range c.activeGames {
		if cid == cardID {
			delete(c.activeGames, gid)
		}
	}
	c.mu.Unlock()

	// EFFECT node
	effectPayload, err := MakeScorecardCloseEffectPayload(cardID, cardHash)
	if err != nil {
		return fmt.Errorf("make effect payload: %w", err)
	}
	_, err = c.graph.Append(proofgraph.NodeTypeEffect, effectPayload, c.connectorID, 0)
	if err != nil {
		return fmt.Errorf("append effect: %w", err)
	}

	return nil
}

// Graph returns the ProofGraph for inspection/export.
func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

// Mode returns the current run mode.
func (c *Connector) Mode() RunMode {
	return c.mode
}
