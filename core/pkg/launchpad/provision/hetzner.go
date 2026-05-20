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

func (p HetznerProvisioner) Plan(launchID, planHash string) Plan {
	return Plan{
		Provider:       "hetzner",
		LaunchID:       launchID,
		DryRun:         true,
		IdempotencyKey: IdempotencyKey("hetzner", launchID, planHash),
		Resources:      map[string]string{"server": "planned", "firewall": "planned"},
	}
}

type HetznerProvisioner struct {
	DryRun          bool
	AllowLiveWrites bool
	Endpoint        string
	Token           string
	HTTPClient      *http.Client
}

type HetznerProvisionRequest struct {
	LaunchID     string   `json:"launch_id"`
	PlanHash     string   `json:"plan_hash"`
	Name         string   `json:"name"`
	Location     string   `json:"location"`
	ServerType   string   `json:"server_type"`
	Image        string   `json:"image"`
	Labels       []string `json:"labels,omitempty"`
	SSHKeys      []string `json:"ssh_keys,omitempty"`
	FirewallName string   `json:"firewall_name,omitempty"`
}

type HetznerProvisionResult struct {
	Provider         string            `json:"provider"`
	DryRun           bool              `json:"dry_run"`
	IdempotencyKey   string            `json:"idempotency_key"`
	ServerID         int64             `json:"server_id,omitempty"`
	FirewallID       int64             `json:"firewall_id,omitempty"`
	ResourceRefs     map[string]string `json:"resource_refs,omitempty"`
	ReceiptRefs      []string          `json:"receipt_refs,omitempty"`
	ReconcileOutcome Outcome           `json:"reconcile_outcome"`
}

type HetznerDeleteRequest struct {
	LaunchID   string `json:"launch_id"`
	PlanHash   string `json:"plan_hash"`
	ServerID   int64  `json:"server_id,omitempty"`
	FirewallID int64  `json:"firewall_id,omitempty"`
}

type HetznerReconcileResult struct {
	LaunchID     string            `json:"launch_id"`
	ResourceRefs map[string]string `json:"resource_refs,omitempty"`
	Outcome      Outcome           `json:"outcome"`
}

type HetznerError struct {
	Op        string
	Status    int
	Ambiguous bool
	Outcome   Outcome
}

func (e *HetznerError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("hetzner %s failed with status %d", e.Op, e.Status)
	}
	return fmt.Sprintf("hetzner %s failed", e.Op)
}

func (p HetznerProvisioner) Create(ctx context.Context, req HetznerProvisionRequest) (*HetznerProvisionResult, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	key := IdempotencyKey("hetzner", req.LaunchID, req.PlanHash)
	if p.DryRun || !p.AllowLiveWrites {
		return &HetznerProvisionResult{
			Provider:         "hetzner",
			DryRun:           true,
			IdempotencyKey:   key,
			ResourceRefs:     map[string]string{"server": "planned", "firewall": "planned"},
			ReceiptRefs:      []string{"receipt:hetzner:" + req.LaunchID + ":dry-run"},
			ReconcileOutcome: ReconcileBeforeRetry(false),
		}, nil
	}
	client, endpoint, err := p.client()
	if err != nil {
		return nil, err
	}
	labels := hetznerLabels(req)
	firewallPayload := map[string]any{
		"name":   firstNonEmpty(req.FirewallName, req.Name+"-firewall"),
		"labels": labels,
		"rules":  []any{},
	}
	firewallRaw, err := p.doJSON(ctx, client, endpoint, http.MethodPost, "/firewalls", key, firewallPayload, http.StatusCreated, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var firewallResp struct {
		Firewall struct {
			ID int64 `json:"id"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(firewallRaw, &firewallResp); err != nil || firewallResp.Firewall.ID == 0 {
		return nil, &HetznerError{Op: "decode firewall", Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	serverPayload := map[string]any{
		"name":               req.Name,
		"location":           req.Location,
		"server_type":        req.ServerType,
		"image":              req.Image,
		"labels":             labels,
		"start_after_create": true,
		"firewalls":          []map[string]any{{"firewall": firewallResp.Firewall.ID}},
	}
	if len(req.SSHKeys) > 0 {
		serverPayload["ssh_keys"] = uniqueStrings(req.SSHKeys)
	}
	serverRaw, err := p.doJSON(ctx, client, endpoint, http.MethodPost, "/servers", key, serverPayload, http.StatusCreated, http.StatusAccepted, http.StatusOK)
	if err != nil {
		_ = p.deletePath(ctx, client, endpoint, key, "/firewalls/"+strconv.FormatInt(firewallResp.Firewall.ID, 10))
		return nil, &HetznerError{Op: "create server", Status: statusFromHetznerError(err), Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	var serverResp struct {
		Server struct {
			ID int64 `json:"id"`
		} `json:"server"`
	}
	if err := json.Unmarshal(serverRaw, &serverResp); err != nil || serverResp.Server.ID == 0 {
		_ = p.deletePath(ctx, client, endpoint, key, "/firewalls/"+strconv.FormatInt(firewallResp.Firewall.ID, 10))
		return nil, &HetznerError{Op: "decode server", Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	return &HetznerProvisionResult{
		Provider:       "hetzner",
		IdempotencyKey: key,
		ServerID:       serverResp.Server.ID,
		FirewallID:     firewallResp.Firewall.ID,
		ResourceRefs: map[string]string{
			"server":   strconv.FormatInt(serverResp.Server.ID, 10),
			"firewall": strconv.FormatInt(firewallResp.Firewall.ID, 10),
		},
		ReceiptRefs:      []string{"receipt:hetzner:" + req.LaunchID + ":provision"},
		ReconcileOutcome: ReconcileBeforeRetry(false),
	}, nil
}

func (p HetznerProvisioner) Delete(ctx context.Context, req HetznerDeleteRequest) (*TeardownResult, error) {
	if p.DryRun || !p.AllowLiveWrites {
		return &TeardownResult{ReceiptID: "receipt:hetzner:" + req.LaunchID + ":teardown-dry-run", Status: "dry-run"}, nil
	}
	client, endpoint, err := p.client()
	if err != nil {
		return nil, err
	}
	key := IdempotencyKey("hetzner", req.LaunchID, req.PlanHash)
	if req.ServerID != 0 {
		if err := p.deletePath(ctx, client, endpoint, key, "/servers/"+strconv.FormatInt(req.ServerID, 10)); err != nil {
			return nil, err
		}
	}
	if req.FirewallID != 0 {
		if err := p.deletePath(ctx, client, endpoint, key, "/firewalls/"+strconv.FormatInt(req.FirewallID, 10)); err != nil {
			return nil, err
		}
	}
	return &TeardownResult{ReceiptID: "receipt:hetzner:" + req.LaunchID + ":teardown", Status: "deleted"}, nil
}

func (p HetznerProvisioner) Reconcile(ctx context.Context, launchID string) (*HetznerReconcileResult, error) {
	client, endpoint, err := p.client()
	if err != nil {
		return nil, err
	}
	selector := url.QueryEscape("helm-launchpad-launch-id=" + launchID)
	raw, err := p.doJSON(ctx, client, endpoint, http.MethodGet, "/servers?label_selector="+selector, "", nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Servers []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, &HetznerError{Op: "decode reconcile", Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	refs := map[string]string{}
	for _, server := range resp.Servers {
		refs["server:"+server.Name] = strconv.FormatInt(server.ID, 10)
	}
	outcome := ReconcileBeforeRetry(len(refs) > 0)
	if len(refs) == 0 {
		outcome = Outcome{Status: ReconcileClean, Ambiguous: false, RequiresRetry: true, ReconciledFirst: true}
	}
	return &HetznerReconcileResult{LaunchID: launchID, ResourceRefs: refs, Outcome: outcome}, nil
}

func (p HetznerProvisioner) client() (*http.Client, string, error) {
	if p.Token == "" {
		return nil, "", fmt.Errorf("hetzner token required")
	}
	endpoint := strings.TrimRight(firstNonEmpty(p.Endpoint, "https://api.hetzner.cloud/v1"), "/")
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return client, endpoint, nil
}

func (p HetznerProvisioner) doJSON(ctx context.Context, client *http.Client, endpoint, method, path, key string, payload any, allowed ...int) ([]byte, error) {
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
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &HetznerError{Op: strings.ToLower(method) + " " + path, Ambiguous: true, Outcome: ReconcileBeforeRetry(true)}
	}
	defer resp.Body.Close()
	if statusAllowed(resp.StatusCode, allowed...) {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return raw, nil
	}
	return nil, &HetznerError{Op: strings.ToLower(method) + " " + path, Status: resp.StatusCode, Ambiguous: resp.StatusCode >= 500, Outcome: ReconcileBeforeRetry(resp.StatusCode >= 500)}
}

func (p HetznerProvisioner) deletePath(ctx context.Context, client *http.Client, endpoint, key, path string) error {
	_, err := p.doJSON(ctx, client, endpoint, http.MethodDelete, path, key, nil, http.StatusNoContent, http.StatusAccepted, http.StatusOK, http.StatusNotFound)
	return err
}

func (req HetznerProvisionRequest) validate() error {
	if req.LaunchID == "" {
		return fmt.Errorf("hetzner launch_id required")
	}
	if req.PlanHash == "" {
		return fmt.Errorf("hetzner plan_hash required")
	}
	if req.Name == "" || req.Location == "" || req.ServerType == "" || req.Image == "" {
		return fmt.Errorf("hetzner name, location, server_type, and image required")
	}
	return nil
}

func hetznerLabels(req HetznerProvisionRequest) map[string]string {
	labels := map[string]string{
		"helm-launchpad":           "true",
		"helm-launchpad-launch-id": req.LaunchID,
	}
	for _, label := range req.Labels {
		key, value, ok := strings.Cut(label, "=")
		if ok && key != "" && value != "" {
			labels[key] = value
		}
	}
	return labels
}

func statusFromHetznerError(err error) int {
	if hcloudErr, ok := err.(*HetznerError); ok {
		return hcloudErr.Status
	}
	return 0
}
