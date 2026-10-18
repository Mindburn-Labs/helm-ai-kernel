package runtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/activitytrail"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/custody"
)

const (
	envActivitySourcesFile       = "HELM_GATEWAY_ACTIVITY_SOURCES_FILE"
	envActivityPollInterval      = "HELM_GATEWAY_ACTIVITY_POLL_INTERVAL"
	envActivityWebhookSecretFile = "HELM_GATEWAY_ACTIVITY_WEBHOOK_SECRET_FILE"
	maxActivityConfigBytes       = 1 << 20
	maxActivityWebhookBytes      = 8 << 20
)

// The file is mounted by the operator. Its tenant/workspace mapping is never
// taken from provider content. Removing an entry does not erase its ledger;
// set enabled=false to make a deliberate source transition.
type activitySourceConfig struct {
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Repository  string `json:"repository"`
	Enabled     *bool  `json:"enabled"`
}

type activityConfig struct {
	Sources []activitySourceConfig `json:"sources"`
}

type activityRuntime struct {
	trail       *activitytrail.Service
	sources     []activitySourceConfig
	credentials admission.Credentials
	interval    time.Duration
	webhook     http.Handler
}

func newActivityRuntime(db *sql.DB, getenv func(string) string, credentials admission.Credentials) (*activityRuntime, error) {
	apiURL, err := custody.GitHubAPIURL(getenv)
	if err != nil {
		return nil, err
	}
	trail, err := activitytrail.New(db, apiURL, nil)
	if err != nil {
		return nil, err
	}
	a := &activityRuntime{trail: trail, credentials: credentials, interval: time.Minute}
	if raw := strings.TrimSpace(getenv(envActivityPollInterval)); raw != "" {
		a.interval, err = time.ParseDuration(raw)
		if err != nil || a.interval < 15*time.Second || a.interval > time.Hour {
			return nil, fmt.Errorf("%s must be between 15s and 1h", envActivityPollInterval)
		}
	}
	path := strings.TrimSpace(getenv(envActivitySourcesFile))
	secretPath := strings.TrimSpace(getenv(envActivityWebhookSecretFile))
	if path == "" {
		if secretPath != "" {
			return nil, fmt.Errorf("%s requires %s", envActivityWebhookSecretFile, envActivitySourcesFile)
		}
		return a, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-selected mounted configuration
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envActivitySourcesFile, err)
	}
	if len(raw) > maxActivityConfigBytes {
		return nil, fmt.Errorf("%s exceeds 1 MiB", envActivitySourcesFile)
	}
	var config activityConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return nil, fmt.Errorf("%s: %w", envActivitySourcesFile, err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s contains trailing data", envActivitySourcesFile)
	}
	if len(config.Sources) == 0 || len(config.Sources) > 100 {
		return nil, fmt.Errorf("%s needs 1 to 100 sources", envActivitySourcesFile)
	}
	type scopeKey struct{ tenant, workspace, repository string }
	seen := map[scopeKey]bool{}
	for _, entry := range config.Sources {
		scope := entry.scope()
		if err := scope.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", envActivitySourcesFile, err)
		}
		if entry.Enabled == nil {
			return nil, fmt.Errorf("%s: every source needs enabled", envActivitySourcesFile)
		}
		key := scopeKey{scope.TenantID, scope.WorkspaceID, strings.ToLower(scope.Repository)}
		if seen[key] {
			return nil, fmt.Errorf("%s repeats a source scope", envActivitySourcesFile)
		}
		seen[key] = true
		if *entry.Enabled && credentials == nil {
			return nil, fmt.Errorf("%s requires GitHub App credentials for enabled sources", envActivitySourcesFile)
		}
	}
	a.sources = config.Sources
	if secretPath != "" {
		secret, err := os.ReadFile(secretPath) // #nosec G304 -- operator-selected secret mount
		if err != nil {
			return nil, fmt.Errorf("%s: %w", envActivityWebhookSecretFile, err)
		}
		if len(secret) < 16 {
			return nil, fmt.Errorf("%s must contain at least 16 bytes", envActivityWebhookSecretFile)
		}
		a.webhook = a.webhookHandler(secret)
	}
	return a, nil
}

func (s activitySourceConfig) scope() activitytrail.Scope {
	return activitytrail.Scope{TenantID: s.TenantID, WorkspaceID: s.WorkspaceID, Repository: s.Repository}
}

type activityReadToken struct {
	credentials admission.Credentials
	scope       activitytrail.Scope
}

func (t activityReadToken) Token(ctx context.Context) (string, error) {
	return t.credentials.Token(ctx, t.scope.TenantID, adapters.Effect{EffectType: "github.repository.get", Target: t.scope.Repository})
}

func (a *activityRuntime) poll(ctx context.Context) {
	a.pollOnce(ctx)
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollOnce(ctx)
		}
	}
}

func (a *activityRuntime) pollOnce(ctx context.Context) {
	for _, source := range a.sources {
		if ctx.Err() != nil {
			return
		}
		scope := source.scope()
		callCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		coverage, err := a.trail.CoverageMap(callCtx, scope)
		if err == nil && !*source.Enabled && coverage.Enabled {
			err = a.trail.Disable(callCtx, scope)
		}
		if err == nil && *source.Enabled {
			token := activityReadToken{credentials: a.credentials, scope: scope}
			if !coverage.Enabled {
				_, err = a.trail.Enable(callCtx, scope, token)
			}
			if err == nil {
				_, err = a.trail.PollDefaultBranch(callCtx, scope, token)
			}
			if err == nil {
				_, err = a.trail.PollRepositoryEvents(callCtx, scope, token)
			}
		}
		if err != nil {
			slog.Error("activity trail poll failed", "repository", scope.Repository, "workspace", scope.WorkspaceID, "error", err)
		}
		cancel()
	}
}

// The webhook authenticates the raw body before reading provider identity.
// One signed delivery fans out only to operator-configured matching scopes.
func (a *activityRuntime) webhookHandler(secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-GitHub-Event") != "push" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxActivityWebhookBytes+1))
		if err != nil || len(body) == 0 || len(body) > maxActivityWebhookBytes {
			http.Error(w, "invalid delivery", http.StatusBadRequest)
			return
		}
		signature := r.Header.Get("X-Hub-Signature-256")
		provided, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(body)
		if err != nil || !strings.HasPrefix(signature, "sha256=") || !hmac.Equal(provided, mac.Sum(nil)) {
			http.Error(w, "invalid delivery", http.StatusUnauthorized)
			return
		}
		var push struct {
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &push); err != nil {
			http.Error(w, "invalid delivery", http.StatusBadRequest)
			return
		}
		deliveryID := r.Header.Get("X-GitHub-Delivery")
		matched := false
		for _, source := range a.sources {
			if !*source.Enabled || !strings.EqualFold(strings.TrimPrefix(source.Repository, "github.com/"), push.Repository.FullName) {
				continue
			}
			matched = true
			if _, _, err := a.trail.IngestSignedPush(r.Context(), source.scope(), "push", deliveryID, signature, body, secret); err != nil {
				slog.Error("activity trail delivery failed", "repository", source.Repository, "workspace", source.WorkspaceID, "error", err)
				http.Error(w, "delivery could not be stored", http.StatusServiceUnavailable)
				return
			}
		}
		if !matched {
			http.Error(w, "unconfigured repository", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
