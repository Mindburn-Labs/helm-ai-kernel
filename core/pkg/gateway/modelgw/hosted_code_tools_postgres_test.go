package modelgw

import (
	"strings"
	"testing"
)

// A model request cannot delegate code execution to a provider-hosted tool,
// regardless of the provider request shape.
func TestPostgresHostedCodeExecutionIsRefusedBeforeAdmission(t *testing.T) {
	e := newEnv(t, 1_000_000)
	e.openai.on(sseHandler(responsesStream))
	e.anthropic.on(sseHandler(anthropicStream))
	for name, tc := range map[string]struct {
		path, body string
		headers    map[string]string
		errorText  string
	}{
		"responses code interpreter": {
			"/v1/responses",
			`{"model":"gpt-6-sol","input":"x","tools":[{"type":"code_interpreter","container":{"type":"auto"}}]}`,
			bearerHeader(tokenAgent),
			"unsupported_tool",
		},
		"messages code execution": {
			"/v1/messages",
			`{"model":"claude-sonnet-5-5","max_tokens":9,"messages":[],"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}`,
			workerHeaders(tokenAgent),
			"outside this gateway's authority",
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := post(t, e.worker.URL, tc.path, tc.headers, tc.body)
			if response.Status != 400 || !strings.Contains(string(response.Body), tc.errorText) {
				t.Fatalf("hosted code tool was not refused: %s", response)
			}
			if len(e.attempts()) != 0 || e.openai.calls.Load()+e.anthropic.calls.Load() != 0 {
				t.Fatal("hosted code tool created an attempt or reached a provider")
			}
			if used, reserved := e.counters(); used != 0 || reserved != 0 {
				t.Fatalf("hosted code tool changed budget: used=%d reserved=%d", used, reserved)
			}
		})
	}
	control := post(t, e.worker.URL, "/v1/responses", bearerHeader(tokenAgent),
		`{"model":"gpt-6-sol","stream":true,"input":"x","tools":[{"type":"function","name":"f"}]}`)
	if control.Status != 200 || e.openai.calls.Load() != 1 {
		t.Fatalf("client-executed function control was not served: %s calls=%d", control, e.openai.calls.Load())
	}
}
