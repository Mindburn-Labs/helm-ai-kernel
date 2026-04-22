package arc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the Python ARC Bridge sidecar.
// It implements the narrow, stable API contract between Go and Python.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new bridge client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// WithTimeout overrides the default HTTP timeout.
func (c *Client) WithTimeout(d time.Duration) *Client {
	c.httpClient.Timeout = d
	return c
}

// Health checks the bridge liveness.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.get(ctx, "/health")
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var h HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, fmt.Errorf("decode health response: %w", err)
	}
	return &h, nil
}

// ListGames returns available ARC-AGI-3 game IDs.
func (c *Client) ListGames(ctx context.Context) (*GameListResponse, error) {
	resp, err := c.get(ctx, "/games")
	if err != nil {
		return nil, fmt.Errorf("list games failed: %w", err)
	}
	defer resp.Body.Close()

	var g GameListResponse
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		return nil, fmt.Errorf("decode games response: %w", err)
	}
	return &g, nil
}

// CreateSession creates a new game session (RESET).
func (c *Client) CreateSession(ctx context.Context, gameID, mode string) (*SessionInfo, error) {
	req := CreateSessionRequest{GameID: gameID, Mode: mode}
	resp, err := c.post(ctx, "/session", req)
	if err != nil {
		return nil, fmt.Errorf("create session failed: %w", err)
	}
	defer resp.Body.Close()

	var s SessionInfo
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode session response: %w", err)
	}
	return &s, nil
}

// Step executes an action in a session.
func (c *Client) Step(ctx context.Context, sessionID string, action string, reasoning json.RawMessage) (*StepResponse, error) {
	req := StepRequest{Action: action, Reasoning: reasoning}
	resp, err := c.post(ctx, fmt.Sprintf("/session/%s/step", sessionID), req)
	if err != nil {
		return nil, fmt.Errorf("step failed: %w", err)
	}
	defer resp.Body.Close()

	var sr StepResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode step response: %w", err)
	}
	return &sr, nil
}

// CloseSession closes a game session.
func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/session/"+sessionID, nil)
	if err != nil {
		return fmt.Errorf("create close request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("close session failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("close session: status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// OpenScorecard opens an online scorecard (ONLINE mode only).
func (c *Client) OpenScorecard(ctx context.Context, gameIDs []string) (*ScorecardInfo, error) {
	req := ScorecardOpenRequest{GameIDs: gameIDs}
	resp, err := c.post(ctx, "/scorecard", req)
	if err != nil {
		return nil, fmt.Errorf("open scorecard failed: %w", err)
	}
	defer resp.Body.Close()

	var sc ScorecardInfo
	if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
		return nil, fmt.Errorf("decode scorecard response: %w", err)
	}
	return &sc, nil
}

// GetScorecard retrieves scorecard results.
func (c *Client) GetScorecard(ctx context.Context, cardID string) (*ScorecardInfo, error) {
	resp, err := c.get(ctx, "/scorecard/"+cardID)
	if err != nil {
		return nil, fmt.Errorf("get scorecard failed: %w", err)
	}
	defer resp.Body.Close()

	var sc ScorecardInfo
	if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
		return nil, fmt.Errorf("decode scorecard response: %w", err)
	}
	return &sc, nil
}

// CloseScorecard closes a scorecard.
func (c *Client) CloseScorecard(ctx context.Context, cardID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/scorecard/"+cardID, nil)
	if err != nil {
		return fmt.Errorf("create close scorecard request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("close scorecard failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("close scorecard: status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// --- internal helpers ---

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, body)
	}
	return resp, nil
}

func (c *Client) post(ctx context.Context, path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, respBody)
	}
	return resp, nil
}
