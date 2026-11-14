package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// surfaceInspectOptions uses the same private credential file, bearer auth,
// URL validation and redirect policy as watch. Scope headers are assertions
// that the server must authenticate; they do not grant authority in the CLI.
type surfaceInspectOptions struct {
	server, apiKeyFile           string
	tenant, principal, workspace string
}

func registerSurfaceInspectFlags(cmd *flag.FlagSet, tenantScoped bool) *surfaceInspectOptions {
	options := &surfaceInspectOptions{}
	cmd.StringVar(&options.server, "server", defaultReceiptsServer(), "HELM server URL (HELM_URL)")
	cmd.StringVar(&options.apiKeyFile, "api-key-file", "", "Private admin API key file (defaults to HELM_ADMIN_API_KEY)")
	if tenantScoped {
		cmd.StringVar(&options.tenant, "tenant", os.Getenv(runtimeTenantIDEnv), "Tenant binding (HELM_RUNTIME_TENANT_ID)")
		cmd.StringVar(&options.principal, "principal", os.Getenv(runtimePrincipalIDEnv), "Principal binding (HELM_RUNTIME_PRINCIPAL_ID)")
		cmd.StringVar(&options.workspace, "workspace", os.Getenv(runtimeWorkspaceIDEnv), "Workspace binding (HELM_RUNTIME_WORKSPACE_ID)")
	}
	return options
}

// displayServer never copies URL credentials, query values or fragments to an
// inspect report, including when the URL is invalid and no request is made.
func (o *surfaceInspectOptions) displayServer() string {
	client, err := newApprovalHTTPClient(o.server, "")
	if err != nil {
		return "[invalid server URL]"
	}
	return client.baseURL.Scheme + "://" + client.baseURL.Host
}

func (o *surfaceInspectOptions) request(method, path string, query url.Values, body any, tenantScoped bool, out any) error {
	key, err := resolveWatchAPIKey(o.apiKeyFile)
	if err != nil {
		// File errors can include a sensitive path; never echo it or the key.
		return errors.New("admin credential unavailable; set HELM_ADMIN_API_KEY or use a private --api-key-file")
	}
	client, err := newApprovalHTTPClient(o.server, key)
	if err != nil {
		return errors.New("invalid server URL; use https or loopback http without credentials, query or fragment")
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return errors.New("cannot encode API request")
		}
		reader = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	endpoint := client.baseURL.JoinPath(path)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return errors.New("cannot construct API request")
	}
	if tenantScoped {
		if strings.TrimSpace(o.tenant) == "" || strings.TrimSpace(o.principal) == "" {
			return errors.New("receipt inspection requires --tenant and --principal or HELM_RUNTIME_TENANT_ID and HELM_RUNTIME_PRINCIPAL_ID")
		}
		req.Header.Set(tenantHeader, o.tenant)
		req.Header.Set(principalHeader, o.principal)
		if o.workspace != "" {
			req.Header.Set(workspaceHeader, o.workspace)
		}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return errors.New("API request unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A server may reflect credentials in its error body. Only report the
		// status code; redirects are rejected by the shared watch transport.
		return fmt.Errorf("API request returned HTTP %d", resp.StatusCode)
	}
	const maxResponseBytes = 1 << 20
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil || len(payload) > maxResponseBytes {
		return errors.New("API response incomplete or too large")
	}
	var document any
	if json.Unmarshal(payload, &document) != nil {
		return errors.New("API response is not a JSON document")
	}
	if surfaceResponseContainsCredential(document, key) {
		return errors.New("API response contains credential material")
	}
	if json.Unmarshal(payload, out) != nil {
		return errors.New("API response does not match the expected schema")
	}
	return nil
}

func surfaceResponseContainsCredential(value any, key string) bool {
	switch v := value.(type) {
	case string:
		return strings.Contains(v, key)
	case []any:
		for _, item := range v {
			if surfaceResponseContainsCredential(item, key) {
				return true
			}
		}
	case map[string]any:
		for name, item := range v {
			if strings.Contains(name, key) || surfaceResponseContainsCredential(item, key) {
				return true
			}
		}
	}
	return false
}

// These endpoints perform a fresh check for each request. Permit a minute of
// clock skew between the client and server, but never reuse an old observation
// or accept a timestamp substantially in the future as current readiness.
func surfaceCheckIsCurrent(checkedAt, started time.Time) bool {
	return !checkedAt.IsZero() && !checkedAt.Before(started.Add(-time.Minute)) && !checkedAt.After(time.Now().Add(time.Minute))
}
