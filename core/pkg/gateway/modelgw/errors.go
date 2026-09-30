package modelgw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

// errorKind is the family of an error, mapped to each API's own error types so
// that an unmodified SDK raises the exception it would for the provider itself.
type errorKind int

const (
	kindInvalidRequest errorKind = iota + 1
	kindAuthentication
	kindPermission
	kindNotFound
	kindConflict
	kindTooLarge
	kindRateLimit
	kindAPI
)

// apiError is a refusal the gateway makes itself: nothing was sent to a
// provider. A provider's own error is relayed as the provider wrote it.
type apiError struct {
	Status  int
	Kind    errorKind
	Code    string
	Message string
	// Reason is the registry code when the authority gateway decided.
	Reason contracts.ReasonCode
	// AttemptID names the attempt the refusal belongs to, when there is one.
	AttemptID string
}

func (e *apiError) Error() string { return e.Message }

func refuse(status int, kind errorKind, code, message string) *apiError {
	return &apiError{Status: status, Kind: kind, Code: code, Message: message}
}

// The headers a caller can correlate a refusal with.
const (
	headerReasonCode = "X-Helm-Reason-Code"
	headerAttemptID  = "X-Helm-Attempt-Id"
	headerReplayed   = "X-Helm-Replayed"
)

// writeAPIError writes e in api's own error format: {"error": {...}} for the
// OpenAI APIs, {"type": "error", "error": {...}} for Anthropic's.
func writeAPIError(w http.ResponseWriter, api string, e *apiError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if e.Reason != "" {
		w.Header().Set(headerReasonCode, string(e.Reason))
	}
	if e.AttemptID != "" {
		w.Header().Set(headerAttemptID, e.AttemptID)
	}
	var body any
	if api == effectargs.APIAnthropicMessages {
		id := make([]byte, 12)
		_, _ = rand.Read(id)
		body = map[string]any{
			"type":       "error",
			"error":      map[string]any{"type": anthropicErrorType(e), "message": e.Message},
			"request_id": "req_helm_" + hex.EncodeToString(id),
		}
	} else {
		body = map[string]any{"error": map[string]any{
			"message": e.Message, "type": openAIErrorType(e), "param": nil, "code": openAICode(e),
		}}
	}
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(body)
}

func anthropicErrorType(e *apiError) string {
	switch e.Kind {
	case kindInvalidRequest, kindConflict:
		return "invalid_request_error"
	case kindAuthentication:
		return "authentication_error"
	case kindPermission:
		return "permission_error"
	case kindNotFound:
		return "not_found_error"
	case kindTooLarge:
		return "request_too_large"
	case kindRateLimit:
		return "rate_limit_error"
	}
	return "api_error"
}

func openAIErrorType(e *apiError) string {
	switch e.Kind {
	case kindAPI:
		return "server_error"
	case kindRateLimit:
		return "rate_limit_error"
	case kindPermission:
		return "permission_error"
	case kindAuthentication:
		return "authentication_error"
	}
	return "invalid_request_error"
}

// openAICode is the code field: the helm reason when the authority gateway
// decided, else the refusal's own code.
func openAICode(e *apiError) any {
	switch {
	case e.Reason != "":
		return string(e.Reason)
	case e.Code != "":
		return e.Code
	}
	return nil
}
