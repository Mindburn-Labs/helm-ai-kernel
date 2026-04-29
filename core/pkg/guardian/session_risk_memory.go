package guardian

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultSessionRiskAlpha     = 0.5
	defaultSessionRiskBaseline  = 0.08
	defaultSessionRiskThreshold = 0.38
	defaultSessionRiskWindow    = 8
)

// SessionRiskMemory adds deterministic trajectory authorization to the Guardian.
type SessionRiskMemory struct {
	mu        sync.Mutex
	sessions  map[string]sessionRiskState
	alpha     float64
	baseline  float64
	threshold float64
	window    int
	clock     Clock
}

// SessionRiskSnapshot is the signed/audited view of current session trajectory risk.
type SessionRiskSnapshot struct {
	SessionID              string    `json:"session_id"`
	TrajectoryRiskScore    float64   `json:"trajectory_risk_score"`
	SessionCentroidHash    string    `json:"session_centroid_hash"`
	RiskAccumulationWindow int       `json:"risk_accumulation_window"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type sessionRiskState struct {
	centroid [3]float64
	score    float64
	count    int
	updated  time.Time
}

type sessionRiskSignal struct {
	exfiltration float64
	privilege    float64
	compliance   float64
	risk         float64
}

// SessionRiskMemoryOption configures a SessionRiskMemory instance.
type SessionRiskMemoryOption func(*SessionRiskMemory)

func NewSessionRiskMemory(opts ...SessionRiskMemoryOption) *SessionRiskMemory {
	srm := &SessionRiskMemory{
		sessions:  make(map[string]sessionRiskState),
		alpha:     defaultSessionRiskAlpha,
		baseline:  defaultSessionRiskBaseline,
		threshold: defaultSessionRiskThreshold,
		window:    defaultSessionRiskWindow,
		clock:     wallClock{},
	}
	for _, opt := range opts {
		opt(srm)
	}
	if srm.clock == nil {
		srm.clock = wallClock{}
	}
	if srm.window < 1 {
		srm.window = defaultSessionRiskWindow
	}
	srm.alpha = clampRisk(srm.alpha)
	srm.baseline = clampRisk(srm.baseline)
	srm.threshold = clampRisk(srm.threshold)
	return srm
}

func WithSessionRiskClock(c Clock) SessionRiskMemoryOption {
	return func(srm *SessionRiskMemory) { srm.clock = c }
}

func WithSessionRiskThreshold(threshold float64) SessionRiskMemoryOption {
	return func(srm *SessionRiskMemory) { srm.threshold = threshold }
}

func WithSessionRiskAlpha(alpha float64) SessionRiskMemoryOption {
	return func(srm *SessionRiskMemory) { srm.alpha = alpha }
}

func WithSessionRiskWindow(window int) SessionRiskMemoryOption {
	return func(srm *SessionRiskMemory) { srm.window = window }
}

func (srm *SessionRiskMemory) Evaluate(sessionID string, history []SessionAction, current DecisionRequest) SessionRiskSnapshot {
	if srm == nil {
		return SessionRiskSnapshot{}
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		sessionID = "anonymous"
	}

	srm.mu.Lock()
	defer srm.mu.Unlock()

	state := srm.sessions[sessionID]
	if len(history) > 0 || state.count == 0 {
		state = sessionRiskState{}
		for _, action := range trimSessionRiskHistory(history, srm.window-1) {
			state = srm.observe(state, signalFromSessionAction(action, nil))
		}
	}

	state = srm.observe(state, signalFromSessionAction(SessionAction{
		Action:    current.Action,
		Resource:  current.Resource,
		Verdict:   VerdictPending,
		Timestamp: srm.clock.Now().UnixMilli(),
	}, current.Context))
	srm.sessions[sessionID] = state

	return state.snapshot(sessionID, srm.window)
}

func (srm *SessionRiskMemory) ShouldDeny(snapshot SessionRiskSnapshot) bool {
	if srm == nil {
		return false
	}
	return snapshot.RiskAccumulationWindow >= 2 && snapshot.TrajectoryRiskScore >= srm.threshold
}

func (srm *SessionRiskMemory) observe(state sessionRiskState, signal sessionRiskSignal) sessionRiskState {
	adjustedRisk := clampRisk(signal.risk - srm.baseline)
	vector := [3]float64{signal.exfiltration, signal.privilege, signal.compliance}
	if state.count == 0 {
		state.centroid = vector
		state.score = adjustedRisk
	} else {
		for i := range state.centroid {
			state.centroid[i] = srm.alpha*vector[i] + (1-srm.alpha)*state.centroid[i]
		}
		state.score = srm.alpha*adjustedRisk + (1-srm.alpha)*state.score
	}
	state.count++
	if state.count > srm.window {
		state.count = srm.window
	}
	state.score = roundRisk(state.score)
	state.updated = srm.clock.Now()
	return state
}

func (state sessionRiskState) snapshot(sessionID string, window int) SessionRiskSnapshot {
	return SessionRiskSnapshot{
		SessionID:              sessionID,
		TrajectoryRiskScore:    roundRisk(state.score),
		SessionCentroidHash:    hashSessionCentroid(sessionID, state.centroid, minInt(state.count, window)),
		RiskAccumulationWindow: minInt(state.count, window),
		UpdatedAt:              state.updated,
	}
}

func trimSessionRiskHistory(history []SessionAction, max int) []SessionAction {
	if max <= 0 || len(history) <= max {
		return history
	}
	return history[len(history)-max:]
}

func signalFromSessionAction(action SessionAction, context map[string]interface{}) sessionRiskSignal {
	text := strings.ToLower(action.Action + " " + action.Resource + " " + stableRiskContextText(context))
	exfiltration := keywordScore(text, []string{
		"secret", "credential", "token", "api_key", "apikey", "pii", "customer",
		"export", "upload", "external", "webhook", "exfil", "/etc/passwd", "/etc/shadow",
		"database", "dump", "archive",
	})
	privilege := keywordScore(text, []string{
		"sudo", "admin", "root", "privilege", "permission", "merge", "deploy", "publish",
		"delete", "write", "iam", "role", "policy", "shell", "exec",
	})
	compliance := keywordScore(text, []string{
		"hipaa", "gdpr", "sox", "compliance", "audit", "regulated", "customer_data",
		"phi", "pci", "retention",
	})

	risk := 0.08 + 0.60*exfiltration + 0.38*privilege + 0.26*compliance
	switch strings.ToUpper(action.Verdict) {
	case "DENY":
		risk += 0.18
	case "ESCALATE":
		risk += 0.12
	}
	switch strings.ToUpper(action.Action) {
	case "EXECUTE_TOOL", "WRITE", "DELETE", "PUBLISH", "DEPLOY":
		risk += 0.05
	}

	return sessionRiskSignal{
		exfiltration: exfiltration,
		privilege:    privilege,
		compliance:   compliance,
		risk:         clampRisk(risk),
	}
}

func stableRiskContextText(context map[string]interface{}) string {
	if len(context) == 0 {
		return ""
	}
	keys := make([]string, 0, len(context))
	for key := range context {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		ordered[key] = context[key]
	}
	data, err := json.Marshal(ordered)
	if err != nil {
		return ""
	}
	return string(data)
}

func keywordScore(text string, keywords []string) float64 {
	score := 0.0
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			score += 0.22
		}
	}
	return clampRisk(score)
}

func hashSessionCentroid(sessionID string, centroid [3]float64, window int) string {
	payload := struct {
		SessionID string    `json:"session_id"`
		Centroid  []float64 `json:"centroid"`
		Window    int       `json:"window"`
	}{
		SessionID: sessionID,
		Centroid:  []float64{roundRisk(centroid[0]), roundRisk(centroid[1]), roundRisk(centroid[2])},
		Window:    window,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func clampRisk(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func roundRisk(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
