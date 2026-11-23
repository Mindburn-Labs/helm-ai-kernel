package main

// quantum_posture: policy trust configuration checks Ed25519 public keys and delegates verification to the policy reconciler.

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

func resolveServerLogFormat(mode string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(os.Getenv("HELM_LOG_FORMAT")))
	if format == "" {
		if mode == "quickstart" {
			return "text", nil
		}
		return "json", nil
	}
	if format != "json" && format != "text" {
		return "", fmt.Errorf("invalid HELM_LOG_FORMAT %q: expected json or text", format)
	}
	return format, nil
}

func newServerLogHandler(w io.Writer, format string) slog.Handler {
	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) == 0 && attr.Key == slog.TimeKey && attr.Value.Kind() == slog.KindTime {
				return slog.String("timestamp", attr.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
			}
			return attr
		}})
	case "text":
		handler = slog.NewTextHandler(w, nil)
	}
	return tracing.NewSlogHandler(handler)
}

func configureServerLogger(w io.Writer, mode string) (*slog.Logger, string, error) {
	format, err := resolveServerLogFormat(mode)
	if err != nil {
		return nil, "", err
	}
	logger := slog.New(newServerLogHandler(w, format))
	slog.SetDefault(logger)
	return logger, format, nil
}

func writeServerNarration(logger *slog.Logger, format string, human io.Writer, humanText, message string, attrs ...any) {
	if format == "json" {
		logger.Info(message, attrs...)
		return
	}
	_, _ = fmt.Fprintln(human, humanText)
}

func servicesInitFailureIsFatal() bool {
	return envBool("HELM_PRODUCTION") || emergencyStopFenceEnabled() || envBool(approvalConsumptionEnabledEnv) || envBool(generatedSpecApprovalEnabledEnv)
}

func envBool(key string) bool {
	value := os.Getenv(key)
	return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES"
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func semanticThreatEscalationBPFromEnv() (int, error) {
	value := strings.TrimSpace(os.Getenv("HELM_SEMANTIC_THREAT_ESCALATION_BP"))
	if value == "" {
		return 0, nil
	}
	threshold, err := strconv.Atoi(value)
	if err != nil || threshold < 0 || threshold > 10000 {
		return 0, fmt.Errorf("HELM_SEMANTIC_THREAT_ESCALATION_BP must be an integer from 0 to 10000")
	}
	return threshold, nil
}

func configurePostgresPool(db *sql.DB) {
	maxOpen := envInt("HELM_DB_MAX_OPEN_CONNS", 25)
	maxIdle := envInt("HELM_DB_MAX_IDLE_CONNS", 10)
	if maxIdle > maxOpen && maxOpen > 0 {
		maxIdle = maxOpen
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(durationFromEnv("HELM_DB_CONN_MAX_LIFETIME", 30*time.Minute))
}

func policyPollIntervalFromEnv() time.Duration {
	return durationFromEnv("HELM_POLICY_POLL_INTERVAL", 10*time.Second)
}

func policyInitialReconcileTimeoutFromEnv() time.Duration {
	return durationFromEnv("HELM_POLICY_INITIAL_RECONCILE_TIMEOUT", 30*time.Second)
}

func policyLastKnownGoodConfigFromEnv() (bool, time.Duration, error) {
	action := strings.TrimSpace(os.Getenv("HELM_POLICY_ON_INVALID_UPDATE"))
	switch {
	case action == "" || strings.EqualFold(action, "keepLastKnownGood"):
		maxAge := policyreconcile.DefaultLKGMaxAge
		if raw := strings.TrimSpace(os.Getenv("HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE")); raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed <= 0 {
				return false, 0, fmt.Errorf("HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE must be a positive duration")
			}
			maxAge = parsed
		}
		return true, maxAge, nil
	case strings.EqualFold(action, "deny"):
		return false, 0, nil
	default:
		return false, 0, fmt.Errorf("HELM_POLICY_ON_INVALID_UPDATE must be deny or keepLastKnownGood")
	}
}

func policySourceFromEnv(policyPath string, scope policyreconcile.PolicyScope) (policyreconcile.PolicySource, string, error) {
	kind := strings.TrimSpace(os.Getenv("HELM_POLICY_SOURCE_KIND"))
	if kind == "" {
		kind = "mountedFile"
	}
	switch strings.ToLower(kind) {
	case "mountedfile", "mounted-file", "mounted_file":
		if envBool("HELM_PRODUCTION") {
			return nil, "mountedFile", fmt.Errorf("HELM_PRODUCTION=1 rejects mountedFile policy sources because filesystem timestamps are not source-owned monotonic publication epochs; use controlplane")
		}
		return policyreconcile.NewMountedFileSource(policyPath, scope), "mountedFile", nil
	case "controlplane", "control-plane", "control_plane":
		baseURL := strings.TrimSpace(os.Getenv("HELM_POLICY_CONTROLPLANE_URL"))
		if baseURL == "" {
			return nil, "controlplane", fmt.Errorf("HELM_POLICY_CONTROLPLANE_URL is required when HELM_POLICY_SOURCE_KIND=controlplane")
		}
		if err := policyreconcile.ValidateControlPlaneURL(baseURL); err != nil {
			return nil, "controlplane", err
		}
		bearerToken, bearerTokenFile, err := policyControlPlaneAuthFromEnv()
		if err != nil {
			return nil, "controlplane", err
		}
		source := policyreconcile.NewControlPlaneSource(baseURL, scope)
		caFile := strings.TrimSpace(os.Getenv("HELM_POLICY_CONTROLPLANE_CA_FILE"))
		if envBool("HELM_PRODUCTION") && caFile == "" && !policyreconcile.IsLoopbackControlPlaneURL(baseURL) {
			return nil, "controlplane", fmt.Errorf("HELM_POLICY_CONTROLPLANE_CA_FILE is required in production so managed policy TLS uses an exclusive trust root")
		}
		if caFile != "" {
			client, err := policyreconcile.NewControlPlaneHTTPClient(baseURL, caFile)
			if err != nil {
				return nil, "controlplane", err
			}
			source.HTTPClient = client
		}
		source.BearerToken = bearerToken
		source.BearerTokenFile = bearerTokenFile
		return source, "controlplane", nil
	case "crd":
		return nil, "crd", fmt.Errorf("HELM_POLICY_SOURCE_KIND=crd requires a CRD source implementation in the runtime build; this OSS binary only ships the chart CRD/RBAC contract")
	default:
		return nil, kind, fmt.Errorf("unsupported HELM_POLICY_SOURCE_KIND %q", kind)
	}
}

func policyControlPlaneAuthFromEnv() (string, string, error) {
	authMode := strings.TrimSpace(os.Getenv("HELM_POLICY_CONTROLPLANE_AUTH_MODE"))
	if authMode == "" && strings.TrimSpace(os.Getenv("HELM_POLICY_BEARER_TOKEN")) != "" {
		authMode = "bearerToken"
	}

	var token string
	var tokenFile string
	switch strings.ToLower(authMode) {
	case "bearertoken", "bearer-token", "bearer_token":
		token = os.Getenv("HELM_POLICY_BEARER_TOKEN")
	case "serviceaccountjwt", "service-account-jwt", "service_account_jwt":
		tokenFile = strings.TrimSpace(os.Getenv("HELM_POLICY_SERVICE_ACCOUNT_TOKEN_FILE"))
		if tokenFile == "" {
			tokenFile = "/var/run/secrets/helm-policy/token"
		}
		if !filepath.IsAbs(tokenFile) {
			return "", "", fmt.Errorf("HELM_POLICY_SERVICE_ACCOUNT_TOKEN_FILE must be an absolute path")
		}
		data, err := os.ReadFile(filepath.Clean(tokenFile))
		if err != nil {
			return "", "", fmt.Errorf("read projected policy service account token: %w", err)
		}
		token = string(data)
	case "":
		return "", "", fmt.Errorf("HELM_POLICY_CONTROLPLANE_AUTH_MODE is required when HELM_POLICY_SOURCE_KIND=controlplane")
	default:
		return "", "", fmt.Errorf("HELM_POLICY_CONTROLPLANE_AUTH_MODE must be serviceAccountJWT or bearerToken")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", fmt.Errorf("controlplane policy authentication token is empty")
	}
	if len(token) > 64*1024 || strings.ContainsAny(token, "\r\n") {
		return "", "", fmt.Errorf("controlplane policy authentication token is invalid")
	}
	if tokenFile != "" {
		return "", tokenFile, nil
	}
	return token, "", nil
}

func policySignatureVerifierFromEnv(sourceKind string) (policyreconcile.SignatureVerifier, bool, error) {
	requireSignature := envBool("HELM_POLICY_SIGNATURE_REQUIRED")
	publicKey := strings.TrimSpace(os.Getenv("HELM_POLICY_TRUST_PUBLIC_KEY"))
	if strings.EqualFold(sourceKind, "controlplane") && !requireSignature {
		return nil, false, fmt.Errorf("HELM_POLICY_SIGNATURE_REQUIRED=true is required when HELM_POLICY_SOURCE_KIND=controlplane")
	}
	if publicKey == "" {
		if requireSignature {
			return nil, true, fmt.Errorf("HELM_POLICY_TRUST_PUBLIC_KEY is required when HELM_POLICY_SIGNATURE_REQUIRED=true")
		}
		return nil, false, nil
	}
	keyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, requireSignature, fmt.Errorf("HELM_POLICY_TRUST_PUBLIC_KEY must be hex encoded: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, requireSignature, fmt.Errorf("HELM_POLICY_TRUST_PUBLIC_KEY must be a %d-byte Ed25519 public key encoded as hex", ed25519.PublicKeySize)
	}
	return policyreconcile.NewEd25519PolicyVerifier(publicKey), requireSignature, nil
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return fallback
	}
	return duration
}
