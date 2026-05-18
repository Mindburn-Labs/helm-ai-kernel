package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (p DigitalOceanProvisioner) Plan(launchID, planHash string) Plan {
	return Plan{
		Provider:       "digitalocean",
		LaunchID:       launchID,
		DryRun:         true,
		IdempotencyKey: IdempotencyKey("digitalocean", launchID, planHash),
		Resources:      map[string]string{"droplet": "planned", "firewall": "planned"},
	}
}

type DigitalOceanProvisioner struct {
	DryRun     bool
	Endpoint   string
	Token      string
	HTTPClient *http.Client
}

type DigitalOceanProvisionRequest struct {
	LaunchID     string   `json:"launch_id"`
	PlanHash     string   `json:"plan_hash"`
	Name         string   `json:"name"`
	Region       string   `json:"region"`
	Size         string   `json:"size"`
	Image        string   `json:"image"`
	Tags         []string `json:"tags,omitempty"`
	SSHKeys      []string `json:"ssh_keys,omitempty"`
	FirewallName string   `json:"firewall_name,omitempty"`
}

type DigitalOceanProvisionResult struct {
	Provider         string            `json:"provider"`
	IdempotencyKey   string            `json:"idempotency_key"`
	DropletID        int64             `json:"droplet_id,omitempty"`
	FirewallID       string            `json:"firewall_id,omitempty"`
	ResourceRefs     map[string]string `json:"resource_refs,omitempty"`
	ReceiptRefs      []string          `json:"receipt_refs,omitempty"`
	ReconcileOutcome Outcome           `json:"reconcile_outcome"`
}

type DigitalOceanDeleteRequest struct {
	LaunchID   string `json:"launch_id"`
	PlanHash   string `json:"plan_hash"`
	DropletID  int64  `json:"droplet_id,omitempty"`
	FirewallID string `json:"firewall_id,omitempty"`
}

type DigitalOceanReconcileResult struct {
	LaunchID     string            `json:"launch_id"`
	ResourceRefs map[string]string `json:"resource_refs,omitempty"`
	Outcome      Outcome           `json:"outcome"`
}

type DigitalOceanError struct {
	Op        string
	Status    int
	Ambiguous bool
	Outcome   Outcome
}

func (e *DigitalOceanError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("digitalocean %s failed with status %d", e.Op, e.Status)
	}
	return fmt.Sprintf("digitalocean %s failed", e.Op)
}

func (p DigitalOceanProvisioner) Create(ctx context.Context, req DigitalOceanProvisionRequest) (*DigitalOceanProvisionResult, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	client, endpoint, err := p.client()
	if err != nil {
		return nil, err
	}
	idempotencyKey := IdempotencyKey("digitalocean", req.LaunchID, req.PlanHash)
	tags := digitalOceanTags(req)
	dropletPayload := map[string]any{
		"name":   req.Name,
		"region": req.Region,
		"size":   req.Size,
		"image":  req.Image,
		"tags":   tags,
	}
	if len(req.SSHKeys) > 0 {
		dropletPayload["ssh_keys"] = req.SSHKeys
	}
	dropletRaw, err := p.doJSON(ctx, client, endpoint, http.MethodPost, "/v2/droplets", idempotencyKey, dropletPayload, http.StatusAccepted, http.StatusCreated, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var dropletResp struct {
		Droplet struct {
			ID int64 `json:"id"`
		} `json:"droplet"`
	}
	if err := json.Unmarshal(dropletRaw, &dropletResp); err != nil || dropletResp.Droplet.ID == 0 {
		return nil, &DigitalOceanError{Op: "decode droplet", Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}

	firewallPayload := map[string]any{
		"name":        firstNonEmpty(req.FirewallName, req.Name+"-firewall"),
		"droplet_ids": []int64{dropletResp.Droplet.ID},
		"tags":        tags,
		"inbound_rules": []map[string]any{{
			"protocol": "tcp",
			"ports":    "22",
			"sources":  map[string]any{"addresses": []string{"0.0.0.0/0", "::/0"}},
		}},
		"outbound_rules": []map[string]any{{
			"protocol":     "tcp",
			"ports":        "all",
			"destinations": map[string]any{"addresses": []string{"0.0.0.0/0", "::/0"}},
		}},
	}
	firewallRaw, err := p.doJSON(ctx, client, endpoint, http.MethodPost, "/v2/firewalls", idempotencyKey, firewallPayload, http.StatusAccepted, http.StatusCreated, http.StatusOK)
	if err != nil {
		_ = p.deleteDroplet(ctx, client, endpoint, idempotencyKey, dropletResp.Droplet.ID)
		return nil, &DigitalOceanError{Op: "create firewall", Status: statusFromError(err), Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	var firewallResp struct {
		Firewall struct {
			ID string `json:"id"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(firewallRaw, &firewallResp); err != nil || firewallResp.Firewall.ID == "" {
		_ = p.deleteDroplet(ctx, client, endpoint, idempotencyKey, dropletResp.Droplet.ID)
		return nil, &DigitalOceanError{Op: "decode firewall", Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}

	return &DigitalOceanProvisionResult{
		Provider:       "digitalocean",
		IdempotencyKey: idempotencyKey,
		DropletID:      dropletResp.Droplet.ID,
		FirewallID:     firewallResp.Firewall.ID,
		ResourceRefs: map[string]string{
			"droplet":  strconv.FormatInt(dropletResp.Droplet.ID, 10),
			"firewall": firewallResp.Firewall.ID,
		},
		ReceiptRefs:      []string{"receipt:digitalocean:" + req.LaunchID + ":provision"},
		ReconcileOutcome: ReconcileBeforeRetry(false),
	}, nil
}

func (p DigitalOceanProvisioner) Delete(ctx context.Context, req DigitalOceanDeleteRequest) (*TeardownResult, error) {
	client, endpoint, err := p.client()
	if err != nil {
		return nil, err
	}
	key := IdempotencyKey("digitalocean", req.LaunchID, req.PlanHash)
	if req.FirewallID != "" {
		if err := p.deletePath(ctx, client, endpoint, key, "/v2/firewalls/"+url.PathEscape(req.FirewallID)); err != nil {
			return nil, err
		}
	}
	if req.DropletID != 0 {
		if err := p.deleteDroplet(ctx, client, endpoint, key, req.DropletID); err != nil {
			return nil, err
		}
	}
	return &TeardownResult{ReceiptID: "receipt:digitalocean:" + req.LaunchID + ":teardown", Status: "deleted"}, nil
}

func (p DigitalOceanProvisioner) Reconcile(ctx context.Context, launchID string) (*DigitalOceanReconcileResult, error) {
	client, endpoint, err := p.client()
	if err != nil {
		return nil, err
	}
	tag := "helm-launchpad-" + launchID
	raw, err := p.doJSON(ctx, client, endpoint, http.MethodGet, "/v2/droplets?tag_name="+url.QueryEscape(tag), "", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Droplets []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"droplets"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, &DigitalOceanError{Op: "decode reconcile", Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	refs := map[string]string{}
	for _, droplet := range resp.Droplets {
		refs["droplet:"+droplet.Name] = strconv.FormatInt(droplet.ID, 10)
	}
	outcome := ReconcileBeforeRetry(len(refs) > 0)
	if len(refs) == 0 {
		outcome = Outcome{Status: ReconcileClean, Ambiguous: false, RequiresRetry: true, ReconciledFirst: true}
	}
	return &DigitalOceanReconcileResult{LaunchID: launchID, ResourceRefs: refs, Outcome: outcome}, nil
}

func (p DigitalOceanProvisioner) client() (*http.Client, string, error) {
	if p.Token == "" {
		return nil, "", fmt.Errorf("digitalocean token required")
	}
	endpoint := strings.TrimRight(firstNonEmpty(p.Endpoint, "https://api.digitalocean.com"), "/")
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return client, endpoint, nil
}

func (p DigitalOceanProvisioner) doJSON(ctx context.Context, client *http.Client, endpoint, method, path, idempotencyKey string, payload any, allowed ...int) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &DigitalOceanError{Op: strings.ToLower(method) + " " + path, Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	defer resp.Body.Close()
	if statusAllowed(resp.StatusCode, allowed...) {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return raw, nil
	}
	return nil, &DigitalOceanError{Op: strings.ToLower(method) + " " + path, Status: resp.StatusCode, Ambiguous: resp.StatusCode >= 500, Outcome: ReconcileBeforeRetry(resp.StatusCode >= 500)}
}

func (p DigitalOceanProvisioner) deleteDroplet(ctx context.Context, client *http.Client, endpoint, key string, dropletID int64) error {
	return p.deletePath(ctx, client, endpoint, key, "/v2/droplets/"+strconv.FormatInt(dropletID, 10))
}

func (p DigitalOceanProvisioner) deletePath(ctx context.Context, client *http.Client, endpoint, key, path string) error {
	_, err := p.doJSON(ctx, client, endpoint, http.MethodDelete, path, key, nil, http.StatusNoContent, http.StatusAccepted, http.StatusOK, http.StatusNotFound)
	return err
}

func (req DigitalOceanProvisionRequest) validate() error {
	if req.LaunchID == "" {
		return fmt.Errorf("digitalocean launch_id required")
	}
	if req.PlanHash == "" {
		return fmt.Errorf("digitalocean plan_hash required")
	}
	if req.Name == "" || req.Region == "" || req.Size == "" || req.Image == "" {
		return fmt.Errorf("digitalocean name, region, size, and image required")
	}
	return nil
}

func digitalOceanTags(req DigitalOceanProvisionRequest) []string {
	tags := []string{"helm-launchpad", "helm-launchpad-" + req.LaunchID}
	tags = append(tags, req.Tags...)
	return uniqueStrings(tags)
}

func statusAllowed(status int, allowed ...int) bool {
	for _, value := range allowed {
		if status == value {
			return true
		}
	}
	return false
}

func statusFromError(err error) int {
	if doErr, ok := err.(*DigitalOceanError); ok {
		return doErr.Status
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
