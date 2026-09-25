package httperr

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// decodeErrorDetail parses helm.errors.v1.ErrorDetail wire bytes with the
// protobuf library, so the hand encoder in httperr is checked against a real
// decoder rather than against itself.
func decodeErrorDetail(t *testing.T, value string) (reasonCode string, retryable bool) {
	t.Helper()
	raw, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("detail value is not unpadded base64: %v", err)
	}
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			t.Fatalf("bad tag: %v", protowire.ParseError(n))
		}
		raw = raw[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(raw)
			if m < 0 {
				t.Fatalf("bad reason_code: %v", protowire.ParseError(m))
			}
			reasonCode, raw = v, raw[m:]
		case num == 2 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				t.Fatalf("bad retryable: %v", protowire.ParseError(m))
			}
			retryable, raw = protowire.DecodeBool(v), raw[m:]
		default:
			t.Fatalf("unexpected field %d type %d in ErrorDetail", num, typ)
		}
	}
	return reasonCode, retryable
}

type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Debug struct {
			ReasonCode string `json:"reason_code"`
			Retryable  bool   `json:"retryable"`
		} `json:"debug"`
	} `json:"details"`
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Legacy struct {
		Message    string `json:"message"`
		Type       string `json:"type"`
		Code       string `json:"code"`
		ReasonCode string `json:"reason_code"`
	} `json:"error"`
}

func readWireError(t *testing.T, rec *httptest.ResponseRecorder) wireError {
	t.Helper()
	var body wireError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v\n%s", err, rec.Body.String())
	}
	if len(body.Details) != 1 || body.Details[0].Type != "helm.errors.v1.ErrorDetail" {
		t.Fatalf("want exactly one helm.errors.v1.ErrorDetail, got %+v", body.Details)
	}
	return body
}

func TestWriteError_OneErrorModel(t *testing.T) {
	cases := []struct {
		status        int
		code          string
		legacyType    string
		wantRetryable bool
	}{
		{http.StatusBadRequest, "invalid_argument", "invalid_request", false},
		{http.StatusUnauthorized, "unauthenticated", "authentication_error", false},
		{http.StatusForbidden, "permission_denied", "permission_denied", false},
		{http.StatusNotFound, "not_found", "not_found", false},
		{http.StatusConflict, "aborted", "invalid_request", false},
		{http.StatusTooManyRequests, "resource_exhausted", "invalid_request", true},
		{http.StatusInternalServerError, "internal", "internal_error", false},
		{http.StatusServiceUnavailable, "unavailable", "internal_error", true},
		{http.StatusGatewayTimeout, "deadline_exceeded", "internal_error", true},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		WriteError(rec, tc.status, http.StatusText(tc.status), "what went wrong")

		if rec.Code != tc.status {
			t.Fatalf("%d: HTTP status changed to %d", tc.status, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Fatalf("%d: Content-Type = %q", tc.status, got)
		}
		body := readWireError(t, rec)
		if body.Code != tc.code || body.Message != "what went wrong" {
			t.Errorf("%d: Connect members = %q/%q, want %q/%q", tc.status, body.Code, body.Message, tc.code, "what went wrong")
		}
		if body.Status != tc.status || body.Title != http.StatusText(tc.status) || body.Detail != "what went wrong" || body.Type == "" {
			t.Errorf("%d: RFC 7807 members changed: %+v", tc.status, body)
		}
		if body.Legacy.Message != "what went wrong" || body.Legacy.Type != tc.legacyType || body.Legacy.Code != tc.code || body.Legacy.ReasonCode != "" {
			t.Errorf("%d: legacy error object = %+v", tc.status, body.Legacy)
		}
		detail := body.Details[0]
		reason, retryable := decodeErrorDetail(t, detail.Value)
		if reason != "" || retryable != tc.wantRetryable || detail.Debug.ReasonCode != "" || detail.Debug.Retryable != tc.wantRetryable {
			t.Errorf("%d: detail = (%q, %v) debug %+v, want retryable=%v", tc.status, reason, retryable, detail.Debug, tc.wantRetryable)
		}
	}
}

func TestNewProblem_CarriesReasonCodeInDetailAndLegacy(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, NewProblem(http.StatusServiceUnavailable, "Service Unavailable", "fence active", "EMERGENCY_STOP_FENCED"))

	body := readWireError(t, rec)
	reason, retryable := decodeErrorDetail(t, body.Details[0].Value)
	if reason != "EMERGENCY_STOP_FENCED" || !retryable {
		t.Fatalf("wire detail = (%q, %v)", reason, retryable)
	}
	if body.Details[0].Debug.ReasonCode != "EMERGENCY_STOP_FENCED" || body.Legacy.ReasonCode != "EMERGENCY_STOP_FENCED" {
		t.Fatalf("debug/legacy reason_code = %q/%q", body.Details[0].Debug.ReasonCode, body.Legacy.ReasonCode)
	}
}

func TestWriteErrorR_KeepsRequestContext(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "req-1")
	WriteErrorR(rec, httptest.NewRequest(http.MethodGet, "/api/v1/receipts", nil), http.StatusNotFound, "Not Found", "no receipt")

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["instance"] != "/api/v1/receipts" || body["trace_id"] != "req-1" || body["code"] != "not_found" {
		t.Fatalf("body = %v", body)
	}
}

// TestErrorModelVector pins the body the SDKs parse in their own tests
// (protocols/specs/errors/error-model-503.json), so the writer and the five
// parsers cannot drift apart.
func TestErrorModelVector(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "protocols", "specs", "errors", "error-model-503.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	WriteProblem(rec, NewProblem(http.StatusServiceUnavailable, "Service Unavailable", "emergency-stop fence active", "EMERGENCY_STOP_FENCED"))
	var got, wantJSON any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, wantJSON) {
		t.Fatalf("error body drifted from the SDK vector:\n got %s\nwant %s", rec.Body.String(), want)
	}
}
