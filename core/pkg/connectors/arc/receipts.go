package arc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// HashFrame computes a deterministic JCS hash of a single frame.
func HashFrame(f Frame) (string, error) {
	data, err := canonicalize.JCS(f)
	if err != nil {
		return "", fmt.Errorf("jcs frame: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// HashAction computes a deterministic hash for an action step.
type ActionRecord struct {
	SessionID string          `json:"session_id"`
	Step      int             `json:"step"`
	Action    string          `json:"action"`
	Reasoning json.RawMessage `json:"reasoning,omitempty"`
}

// HashActionRecord computes the JCS hash of an action record.
func HashActionRecord(rec ActionRecord) (string, error) {
	data, err := canonicalize.JCS(rec)
	if err != nil {
		return "", fmt.Errorf("jcs action: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// EpisodeRecord captures all action hashes for episode-level hashing.
type EpisodeRecord struct {
	SessionID    string   `json:"session_id"`
	GameID       string   `json:"game_id"`
	ActionHashes []string `json:"action_hashes"`
	FinalDone    bool     `json:"final_done"`
	FinalReward  float64  `json:"final_reward"`
}

// HashEpisode computes a deterministic hash over the full episode.
func HashEpisode(rec EpisodeRecord) (string, error) {
	data, err := canonicalize.JCS(rec)
	if err != nil {
		return "", fmt.Errorf("jcs episode: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// IntentPayload is the ProofGraph INTENT node payload for an ARC action.
type IntentPayload struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id"`
	Step      int             `json:"step"`
	Action    string          `json:"action"`
	Reasoning json.RawMessage `json:"reasoning,omitempty"`
}

// MakeIntentPayload creates a JSON payload for a ProofGraph INTENT node.
func MakeIntentPayload(sessionID string, step int, action string, reasoning json.RawMessage) ([]byte, error) {
	p := IntentPayload{
		Type:      "arc.env.step",
		SessionID: sessionID,
		Step:      step,
		Action:    action,
		Reasoning: reasoning,
	}
	return json.Marshal(p)
}

// EffectPayload is the ProofGraph EFFECT node payload after an ARC action.
type EffectPayload struct {
	Type       string `json:"type"`
	SessionID  string `json:"session_id"`
	Step       int    `json:"step"`
	ActionHash string `json:"action_hash"`
	FrameHash  string `json:"frame_hash,omitempty"`
	Done       bool   `json:"done"`
	Reward     float64 `json:"reward"`
}

// MakeEffectPayload creates a JSON payload for a ProofGraph EFFECT node.
func MakeEffectPayload(sessionID string, step int, actionHash, frameHash string, done bool, reward float64) ([]byte, error) {
	p := EffectPayload{
		Type:       "arc.env.effect",
		SessionID:  sessionID,
		Step:       step,
		ActionHash: actionHash,
		FrameHash:  frameHash,
		Done:       done,
		Reward:     reward,
	}
	return json.Marshal(p)
}

// CheckpointPayload is the ProofGraph CHECKPOINT node payload at episode boundary.
type CheckpointPayload struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	GameID      string `json:"game_id"`
	EpisodeHash string `json:"episode_hash"`
	ScorecardID string `json:"scorecard_id,omitempty"`
	TotalSteps  int    `json:"total_steps"`
	FinalReward float64 `json:"final_reward"`
}

// MakeCheckpointPayload creates a JSON payload for a ProofGraph CHECKPOINT node.
func MakeCheckpointPayload(sessionID, gameID, episodeHash, scorecardID string, totalSteps int, finalReward float64) ([]byte, error) {
	p := CheckpointPayload{
		Type:        "arc.episode.checkpoint",
		SessionID:   sessionID,
		GameID:      gameID,
		EpisodeHash: episodeHash,
		ScorecardID: scorecardID,
		TotalSteps:  totalSteps,
		FinalReward: finalReward,
	}
	return json.Marshal(p)
}

// ScorecardRecord is used to compute deterministic JCS hash of a scorecard.
type ScorecardRecord struct {
	CardID    string            `json:"card_id"`
	GameIDs   []string          `json:"game_ids"`
	Status    string            `json:"status"`
	Scores    map[string]string `json:"scores,omitempty"`
	ReplayURL string            `json:"replay_url,omitempty"`
}

// HashScorecard computes a deterministic JCS hash over a scorecard record.
func HashScorecard(rec ScorecardRecord) (string, error) {
	data, err := canonicalize.JCS(rec)
	if err != nil {
		return "", fmt.Errorf("jcs scorecard: %w", err)
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// ScorecardEventPayload is the ProofGraph INTENT/EFFECT payload for scorecard ops.
type ScorecardEventPayload struct {
	Type     string   `json:"type"`
	CardID   string   `json:"card_id,omitempty"`
	GameIDs  []string `json:"game_ids,omitempty"`
	CardHash string   `json:"card_hash,omitempty"`
}

// MakeScorecardOpenPayload creates an INTENT payload for opening a scorecard.
func MakeScorecardOpenPayload(gameIDs []string) ([]byte, error) {
	p := ScorecardEventPayload{
		Type:    "arc.scorecard.open.intent",
		GameIDs: gameIDs,
	}
	return json.Marshal(p)
}

// MakeScorecardOpenEffectPayload creates an EFFECT payload after opening a scorecard.
func MakeScorecardOpenEffectPayload(cardID, cardHash string) ([]byte, error) {
	p := ScorecardEventPayload{
		Type:     "arc.scorecard.open.effect",
		CardID:   cardID,
		CardHash: cardHash,
	}
	return json.Marshal(p)
}

// MakeScorecardClosePayload creates an INTENT payload for closing a scorecard.
func MakeScorecardClosePayload(cardID string) ([]byte, error) {
	p := ScorecardEventPayload{
		Type:   "arc.scorecard.close.intent",
		CardID: cardID,
	}
	return json.Marshal(p)
}

// MakeScorecardCloseEffectPayload creates an EFFECT payload after closing a scorecard.
func MakeScorecardCloseEffectPayload(cardID, cardHash string) ([]byte, error) {
	p := ScorecardEventPayload{
		Type:     "arc.scorecard.close.effect",
		CardID:   cardID,
		CardHash: cardHash,
	}
	return json.Marshal(p)
}
