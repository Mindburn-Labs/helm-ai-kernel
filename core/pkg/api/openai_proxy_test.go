package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// decodeJSONObject decodes a request body keeping numbers exact, so a
// comparison sees 2048 and 0 as sent rather than as float64 values.
func decodeJSONObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return object
}

// proxyUpstreamBody sends body through HandleOpenAIProxy and returns the
// request body the upstream provider received.
func proxyUpstreamBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var received []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-gpt6","choices":[]}`))
	}))
	defer upstream.Close()
	t.Setenv("HELM_UPSTREAM_URL", upstream.URL)

	rec := httptest.NewRecorder()
	HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	return decodeJSONObject(t, received)
}

func TestOpenAIProxyForwardsGPT6RequestFieldsUnchanged(t *testing.T) {
	for name, body := range map[string]string{
		"astra with tools": `{
			"model": "gpt-6-astra",
			"messages": [{"role": "user", "content": "look it up"}],
			"max_completion_tokens": 2048,
			"reasoning_effort": "high",
			"verbosity": "low",
			"tools": [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}}}],
			"tool_choice": "auto",
			"parallel_tool_calls": false
		}`,
		"sol at effort none samples at temperature 0": `{
			"model": "gpt-6-sol",
			"messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}],
			"max_completion_tokens": 512,
			"reasoning_effort": "none",
			"temperature": 0,
			"top_p": 1,
			"response_format": {"type": "json_object"}
		}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := proxyUpstreamBody(t, body)
			if want := decodeJSONObject(t, []byte(body)); !reflect.DeepEqual(got, want) {
				t.Fatalf("upstream body changed\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestOpenAIProxyDefaultsModelAndKeepsGPT6Fields(t *testing.T) {
	got := proxyUpstreamBody(t, `{"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":256,"reasoning_effort":"low"}`)
	want := decodeJSONObject(t, []byte(`{"model":"gpt-6-sol","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":256,"reasoning_effort":"low"}`))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("upstream body = %#v, want %#v", got, want)
	}
}

func TestOpenAIProxyRejectsNonObjectBody(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `"text"`} {
		rec := httptest.NewRecorder()
		HandleOpenAIProxy(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}
