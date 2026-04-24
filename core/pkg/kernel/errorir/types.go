package errorir

import "strings"

// ErrorIR represents the canonical error format per Addendum 8.5.X.
type ErrorIR struct {
	Type     string      `json:"type"`
	Title    string      `json:"title"`
	Status   int         `json:"status"`
	Detail   string      `json:"detail"`
	Instance string      `json:"instance"`
	HELM     HELMDetails `json:"helm"`
}

type HELMDetails struct {
	ErrorCode           string           `json:"error_code"`
	Namespace           string           `json:"namespace"`
	Classification      string           `json:"classification"`
	CanonicalCauseChain []CanonicalCause `json:"canonical_cause_chain,omitempty"`
}

type CanonicalCause struct {
	ErrorCode string `json:"error_code"`
	At        string `json:"at"`
}

// Classification constants
const (
	ClassificationRetryable            = "RETRYABLE"
	ClassificationNonRetryable         = "NON_RETRYABLE"
	ClassificationIdempotentSafe       = "IDEMPOTENT_SAFE"
	ClassificationCompensationRequired = "COMPENSATION_REQUIRED"
)

// Standard Error Codes
const (
	CodeValidationSchemaMismatch  = "HELM/CORE/VALIDATION/SCHEMA_MISMATCH"
	CodeValidationCSNFViolation   = "HELM/CORE/VALIDATION/CSNF_VIOLATION"
	CodeAuthUnauthorized          = "HELM/CORE/AUTH/UNAUTHORIZED"
	CodeAuthForbidden             = "HELM/CORE/AUTH/FORBIDDEN"
	CodeEffectTimeout             = "HELM/CORE/EFFECT/TIMEOUT"
	CodeEffectUpstreamError       = "HELM/CORE/EFFECT/UPSTREAM_ERROR"
	CodeEffectIdempotencyConflict = "HELM/CORE/EFFECT/IDEMPOTENCY_CONFLICT"
	CodePolicyDenied              = "HELM/CORE/POLICY/DENIED"
	CodeResourceNotFound          = "HELM/CORE/RESOURCE/NOT_FOUND"
	CodeResourceConflict          = "HELM/CORE/RESOURCE/CONFLICT"
	CodeCELDPError                = "HELM/CORE/CEL_DP/EVALUATION_ERROR"
)

// NewErrorIR creates a canonical error value.
func NewErrorIR(code, title, detail string, status int, classification string) ErrorIR {
	return ErrorIR{
		Type:   "https://helm.org/errors/" + code,
		Title:  title,
		Status: status,
		Detail: detail,
		HELM: HELMDetails{
			ErrorCode:      code,
			Namespace:      namespaceFromErrorCode(code),
			Classification: classification,
		},
	}
}

func namespaceFromErrorCode(code string) string {
	parts := strings.Split(code, "/")
	if len(parts) < 2 || parts[0] != "HELM" || parts[1] == "" {
		return "UNKNOWN"
	}
	if parts[1] == "ADAPTER" && len(parts) >= 3 && parts[2] != "" {
		return parts[1] + "/" + parts[2]
	}
	return parts[1]
}
