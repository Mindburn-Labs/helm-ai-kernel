package siwc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

const responseRequestFixture = `{"model":"available","input":[{"role":"user","content":"Non-sensitive fixture"}],"store":false,"stream":true}`
const responseCompletedFixture = `{"type":"response.completed","response":{"id":"resp_fixture","model":"available","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"fixture result"}]}],"usage":{"input_tokens":4,"output_tokens":2},"error":null,"incomplete_details":null}}`

func responseSSE(value string) string { return "data: " + value + "\n\n" }

func responseFixture(t *testing.T, handle func(http.ResponseWriter, *http.Request)) (*oidcFixture, *Store, Account, *atomic.Int32) {
	t.Helper()
	f, store := newOIDC(t), newStore(t)
	account, err := f.login(store, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := store.AccessToken(context.Background(), f.client, account.Reference())
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expected || r.URL.RawQuery != "" {
			t.Error("selected registration or fixed endpoint binding was lost")
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/models" {
			_, _ = fmt.Fprint(w, `{"models":[{"slug":"available","display_name":"Available","visibility":"list"}]}`)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" || r.Header.Get("Accept") != "text/event-stream" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("inference endpoint, method or media types changed")
		}
		calls.Add(1)
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil || string(body["store"]) != "false" || string(body["stream"]) != "true" || body["previous_response_id"] != nil || body["max_output_tokens"] != nil {
			t.Error("inference lost required stateless streaming contract")
		}
		handle(w, r)
	}))
	t.Cleanup(api.Close)
	f.client.modelsURL = api.URL + "/v1/models"
	f.client.responsesURL = api.URL + "/v1/responses"
	return f, store, account, &calls
}

func TestResponsesPublishesOnlyCompletedFullOutputForCurrentAccount(t *testing.T) {
	f, s, a, calls := responseFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("X-Request-Id", "req_fixture")
		_, _ = fmt.Fprint(w, responseSSE(`{"type":"response.created","response":{"id":"resp_fixture","status":"in_progress"}}`)+
			responseSSE(`{"type":"response.output_text.delta","delta":"partial output is not a result"}`)+responseSSE(responseCompletedFixture))
	})
	out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(responseRequestFixture))
	if err != nil || calls.Load() != 1 || out.ID != "resp_fixture" || out.Model != "available" || out.RequestedModel != "available" || out.RequestID != "req_fixture" {
		t.Fatalf("completed inference binding missing: %+v, %v, calls=%d", out, err, calls.Load())
	}
	if !strings.Contains(string(out.Body), "fixture result") || strings.Contains(string(out.Body), "partial output is not a result") {
		t.Fatal("completion did not retain the terminal output as history")
	}
	if NewClient().responsesURL != "https://api.openai.com/v1/responses" {
		t.Fatal("production inference endpoint drifted")
	}
}

func TestResponsesConsumesActualQuotaFailureEvenWithoutMediaType(t *testing.T) {
	f, s, a, calls := responseFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = fmt.Fprint(w, responseSSE(`{"type":"response.created","response":{"id":"resp_fixture","status":"in_progress"}}`)+
			responseSSE(`{"type":"response.output_text.delta","delta":"must-not-publish-partial"}`)+
			responseSSE(`{"type":"error","code":"subscription_sharing_usage_limit_exceeded","message":"must-not-leak-provider-message"}`))
	})
	out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(responseRequestFixture))
	var failure *ResponseFailure
	if !errors.Is(err, ErrUsageLimited) || !errors.As(err, &failure) || failure.Recovery != RecoveryPauseUsage || !failure.MayHaveDispatched || failure.HTTPStatus != 200 || calls.Load() != 1 || out.ID != "" || out.Body != nil {
		t.Fatalf("HTTP200 quota failure was hidden: %+v, %v, calls=%d", out, err, calls.Load())
	}
	encoded, _ := json.Marshal(failure)
	if strings.Contains(string(encoded), "must-not-") || strings.Contains(err.Error(), "must-not-") {
		t.Fatal("failure exposed provider text or partial model output")
	}
	accounts, err := s.Accounts(context.Background())
	if err != nil || len(accounts) != 1 || !accounts[0].SignedIn || accounts[0].Reference() != a.Reference() {
		t.Fatal("quota error erased or changed valid credentials")
	}
}

func TestResponsesHandlesStructuredHTTPFailuresWithoutRetryOrOAuth(t *testing.T) {
	for _, tc := range []struct {
		code     string
		status   int
		want     error
		recovery ResponseRecovery
	}{
		{"subscription_sharing_unsupported_capability", 400, ErrResponseRequest, RecoveryFixRequest},
		{"subscription_sharing_usage_unavailable", 503, ErrUnavailable, RecoveryRetryLater},
		{"subscription_sharing_invalid_user", 401, ErrUnavailable, RecoveryAuthorization},
		{"chatpass_v2_scope_not_authorized", 403, ErrPermission, RecoveryCheckGrant},
	} {
		t.Run(tc.code, func(t *testing.T) {
			f, s, a, calls := responseFixture(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"param":"tools[0].type","message":"must-not-leak-fixture-secret"}}`, tc.code)
			})
			out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(responseRequestFixture))
			var failure *ResponseFailure
			if !errors.Is(err, tc.want) || !errors.As(err, &failure) || failure.Code != tc.code || failure.Param != "tools[0].type" || failure.Recovery != tc.recovery || calls.Load() != 1 || out.Body != nil {
				t.Fatalf("wrong structured failure: %+v, %v, calls=%d", out, err, calls.Load())
			}
			accounts, readErr := s.Accounts(context.Background())
			if readErr != nil || !accounts[0].SignedIn || accounts[0].Reference() != a.Reference() || f.tokens.Load() != 1 {
				t.Fatal("HTTP rejection reset credentials or repeated OAuth")
			}
		})
	}
}

func TestResponsesRejectsInvalidRequestsBeforeProviderEgress(t *testing.T) {
	f, s, a, calls := responseFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid request reached inference") })
	for _, body := range []string{
		`{"model":"available","input":[],"store":false,"stream":true}`,
		`{"model":"available","input":"not full history","store":false,"stream":true}`,
		`{"model":"available","input":[{"role":"system","content":"unsupported"}],"store":false,"stream":true}`,
		strings.Replace(responseRequestFixture, `"store":false`, `"store":true`, 1),
		strings.Replace(responseRequestFixture, `"stream":true`, `"stream":false`, 1),
		strings.Replace(responseRequestFixture, `"store":false`, `"store":false,"store":true`, 1),
		strings.TrimSuffix(responseRequestFixture, "}") + `,"max_output_tokens":10}`,
		strings.TrimSuffix(responseRequestFixture, "}") + `,"previous_response_id":"resp_old"}`,
	} {
		out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(body))
		if !errors.Is(err, ErrResponseRequest) || out.Body != nil || calls.Load() != 0 {
			t.Fatalf("invalid request was accepted: %v, calls=%d", err, calls.Load())
		}
	}
	if _, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(strings.Replace(responseRequestFixture, "available", "unavailable", 1))); !errors.Is(err, ErrPermission) || calls.Load() != 0 {
		t.Fatal("a model absent from the selected account catalog was sent", err)
	}
	ref := a.Reference()
	ref.Generation = "stale-selection"
	if _, err := s.Responses(context.Background(), f.client, ref, json.RawMessage(responseRequestFixture)); !errors.Is(err, ErrChanged) || calls.Load() != 0 {
		t.Fatal("stale generation reached inference", err)
	}
}

func TestResponseStreamRefusesFalseCompletion(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
	}{
		{"only deltas", responseSSE(`{"type":"response.output_text.delta","delta":"partial"}`), ErrResponseIncomplete},
		{"incomplete", responseSSE(`{"type":"response.incomplete","response":{"status":"incomplete"}}`), ErrResponseIncomplete},
		{"failed response", responseSSE(`{"type":"response.failed","response":{"id":"resp_fixture","status":"failed","error":{"code":"subscription_sharing_usage_limit_exceeded","message":"must-not-leak"}}}`), ErrUsageLimited},
		{"no event delimiter", strings.TrimSuffix(responseSSE(responseCompletedFixture), "\n"), ErrResponseIncomplete},
		{"event mismatch", "event: response.failed\n" + responseSSE(responseCompletedFixture), ErrResponseProtocol},
		{"wrong status", responseSSE(strings.Replace(responseCompletedFixture, `"status":"completed"`, `"status":"incomplete"`, 1)), ErrResponseProtocol},
		{"missing output", responseSSE(strings.Replace(responseCompletedFixture, `"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"fixture result"}]}]`, `"output":null`, 1)), ErrResponseProtocol},
		{"changed response", responseSSE(`{"type":"response.created","response":{"id":"resp_other"}}`) + responseSSE(responseCompletedFixture), ErrResponseProtocol},
		{"duplicate status", responseSSE(strings.Replace(responseCompletedFixture, `"status":"completed"`, `"status":"failed","status":"completed"`, 1)), ErrResponseProtocol},
		{"SSE limit", "data: " + strings.Repeat("x", maxResponseEventBytes+1) + "\n\n", ErrResponseProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := readResponseStream(context.Background(), strings.NewReader(tc.body), 200, "")
			if !errors.Is(err, tc.want) || out.Body != nil {
				t.Fatalf("false completion survived: %+v, %v", out, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := readResponseStream(ctx, strings.NewReader(responseSSE(responseCompletedFixture)), 200, ""); !errors.Is(err, context.Canceled) || out.Body != nil {
		t.Fatal("cancelled stream published completion", err)
	}
}

func TestResponseStreamRejectsContradictorySuffix(t *testing.T) {
	complete := responseSSE(responseCompletedFixture)
	for _, tc := range []struct {
		name, suffix string
		want         error
	}{
		{"failed after completion", responseSSE(`{"type":"response.failed","response":{"id":"resp_fixture","status":"failed","error":{"code":"subscription_sharing_usage_limit_exceeded","message":"must-not-leak"}}}`), ErrUsageLimited},
		{"error after completion", responseSSE(`{"type":"error","code":"subscription_sharing_usage_limit_exceeded","message":"must-not-leak"}`), ErrUsageLimited},
		{"conflicting completion", responseSSE(strings.Replace(responseCompletedFixture, "fixture result", "different result", 1)), ErrResponseProtocol},
		{"duplicate completion", complete, ErrResponseProtocol},
		{"incomplete after completion", responseSSE(`{"type":"response.incomplete"}`), ErrResponseIncomplete},
		{"progress after completion", responseSSE(`{"type":"response.in_progress","response":{"id":"resp_fixture","status":"in_progress"}}`), ErrResponseProtocol},
		{"unfinished suffix", "data: {\"type\":\"response.failed\"}\n", ErrResponseIncomplete},
		{"oversize suffix", "data: " + strings.Repeat("x", maxResponseEventBytes+1) + "\n\n", ErrResponseProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := readResponseStream(context.Background(), strings.NewReader(complete+tc.suffix), 200, "req_suffix")
			var failure *ResponseFailure
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(out, Response{}) || !errors.As(err, &failure) || !failure.MayHaveDispatched {
				t.Fatal("contradictory suffix published completed output or lost dispatch uncertainty", err)
			}
			if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("provider error message escaped custody")
			}
		})
	}
	t.Run("interruption after completion", func(t *testing.T) {
		out, err := readResponseStream(context.Background(), io.MultiReader(strings.NewReader(complete), responseInterruptedReader{}), 200, "req_suffix")
		var failure *ResponseFailure
		if !errors.Is(err, ErrResponseInterrupted) || !reflect.DeepEqual(out, Response{}) || !errors.As(err, &failure) || !failure.MayHaveDispatched {
			t.Fatal("read interruption published staged completion", err)
		}
	})
}

type responseInterruptedReader struct{}

func (responseInterruptedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestResponsesAllowsMissingMediaTypeOnlyWithRealCompletion(t *testing.T) {
	f, s, a, calls := responseFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = fmt.Fprint(w, responseSSE(responseCompletedFixture))
	})
	out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(responseRequestFixture))
	if err != nil || out.ID != "resp_fixture" || calls.Load() != 1 {
		t.Fatal("valid terminal SSE with omitted media type was rejected", err)
	}
}

func TestResponsesRejectsCompletionAfterLogoutDuringInference(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	f, s, a, calls := responseFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, responseSSE(`{"type":"response.created","response":{"id":"resp_fixture","status":"in_progress"}}`))
		w.(http.Flusher).Flush()
		close(started)
		<-release
		_, _ = fmt.Fprint(w, responseSSE(responseCompletedFixture))
	})
	result := make(chan error, 1)
	go func() {
		out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(responseRequestFixture))
		if out.Body != nil {
			t.Error("old account completion was published")
		}
		result <- err
	}()
	<-started
	_, logoutErr := s.Logout(context.Background(), f.client, a.Reference())
	close(release)
	if logoutErr != nil {
		t.Fatal(logoutErr)
	}
	err := <-result
	var failure *ResponseFailure
	if !errors.Is(err, ErrChanged) || !errors.As(err, &failure) || !failure.MayHaveDispatched || calls.Load() != 1 {
		t.Fatal("logout did not invalidate in-flight completion", err)
	}
}

func TestResponsesNeverRedirectsSelectedAccountCredentials(t *testing.T) {
	var escaped atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer other.Close()
	f, s, a, calls := responseFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	out, err := s.Responses(context.Background(), f.client, a.Reference(), json.RawMessage(responseRequestFixture))
	if err == nil || out.Body != nil || escaped.Load() != 0 || calls.Load() != 1 {
		t.Fatal("inference followed redirect or retried", err, escaped.Load(), calls.Load())
	}
}
