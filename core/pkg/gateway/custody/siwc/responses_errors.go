package siwc

import (
	"errors"
	"strings"
)

var (
	ErrResponseRequest     = errors.New("ChatGPT inference request is unsupported or invalid")
	ErrResponseProtocol    = errors.New("ChatGPT inference stream is invalid")
	ErrResponseIncomplete  = errors.New("ChatGPT inference did not complete")
	ErrResponseInterrupted = errors.New("ChatGPT inference was interrupted")
	ErrUsageLimited        = errors.New("ChatGPT plan usage is limited for this application")
)

type ResponseRecovery string

const (
	RecoveryInspect       ResponseRecovery = "inspect_failure"
	RecoveryPauseUsage    ResponseRecovery = "pause_plan_requests"
	RecoveryRetryLater    ResponseRecovery = "retry_later"
	RecoveryFixRequest    ResponseRecovery = "fix_request"
	RecoveryEligibility   ResponseRecovery = "explain_eligibility"
	RecoveryCheckRoute    ResponseRecovery = "check_route"
	RecoveryCheckGrant    ResponseRecovery = "check_grant"
	RecoveryAuthorization ResponseRecovery = "diagnose_authorization"
)

// ResponseFailure contains bounded machine fields, never provider error text,
// credentials or partial model output. MayHaveDispatched does not prove a
// Kernel dispatch or settlement; it prohibits assuming that nothing was sent.
// Recovery is guidance for the caller. This package never retries, switches
// accounts, starts OAuth, resets a limit or falls back to a paid API key.
type ResponseFailure struct {
	Code              string           `json:"code"`
	Param             string           `json:"param,omitempty"`
	Recovery          ResponseRecovery `json:"recovery"`
	HTTPStatus        int              `json:"http_status,omitempty"`
	RequestID         string           `json:"request_id,omitempty"`
	MayHaveDispatched bool             `json:"may_have_dispatched"`
	cause             error
}

func (e *ResponseFailure) Error() string { return "ChatGPT inference: " + e.Code }
func (e *ResponseFailure) Unwrap() error { return e.cause }

func responseFailure(code, param string, status int, requestID string) *ResponseFailure {
	if !responseIdentifier(code, false) {
		code = "provider_failure"
	}
	if !responseIdentifier(param, true) {
		param = ""
	}
	if !responseIdentifier(requestID, true) {
		requestID = ""
	}
	e := &ResponseFailure{Code: code, Param: param, Recovery: RecoveryInspect,
		HTTPStatus: status, RequestID: requestID, MayHaveDispatched: true, cause: ErrUnavailable}
	switch code {
	case "subscription_sharing_usage_limit_exceeded":
		e.Recovery, e.cause = RecoveryPauseUsage, ErrUsageLimited
	case "subscription_sharing_usage_unavailable", "subscription_sharing_user_unavailable":
		e.Recovery = RecoveryRetryLater
	case "subscription_sharing_user_not_eligible":
		e.Recovery, e.cause = RecoveryEligibility, ErrPermission
	case "subscription_sharing_unsupported_capability":
		e.Recovery, e.cause = RecoveryFixRequest, ErrResponseRequest
	case "subscription_sharing_route_not_supported":
		e.Recovery, e.cause = RecoveryCheckRoute, ErrPermission
	case "chatpass_v2_scope_not_authorized", "chatpass_v2_invalid_authorization_context":
		e.Recovery, e.cause = RecoveryCheckGrant, ErrPermission
	case "subscription_sharing_invalid_user":
		e.Recovery = RecoveryAuthorization
	default:
		if status == 401 {
			e.Recovery = RecoveryAuthorization
		}
	}
	return e
}

func responseIdentifier(value string, path bool) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' ||
			path && (c == '.' || c == '[' || c == ']' || c == '-' || c == ':') {
			continue
		}
		return false
	}
	return true
}
