package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
)

type ossAGUIRunRequest struct {
	ThreadID       string           `json:"threadId,omitempty"`
	RunID          string           `json:"runId,omitempty"`
	Messages       []ossAGUIMessage `json:"messages,omitempty"`
	State          map[string]any   `json:"state,omitempty"`
	WorkspaceID    string           `json:"workspaceId,omitempty"`
	CurrentSurface string           `json:"currentSurface,omitempty"`
}

type ossAGUIMessage struct {
	ID      string `json:"id,omitempty"`
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// RegisterConsoleAGUIRoutes exposes the optional OSS read-only AG-UI runtime.
// It is intentionally thin: no commercial graph/spec concepts and no kernel
// package mutation. Tool results are derived from existing console/demo routes.
func RegisterConsoleAGUIRoutes(mux *http.ServeMux, svc *Services, opts serverOptions) {
	infoHandler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			api.WriteMethodNotAllowed(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"runtime":   "helm-oss-ag-ui",
			"protocol":  "ag-ui",
			"transport": "sse",
			"version":   "0.0.53",
			"policy": map[string]any{
				"hosting":            "self-hosted",
				"scope":              "oss-read-only",
				"copilot_cloud":      "disabled",
				"commercial_objects": "disabled",
			},
			"tools": []map[string]any{
				ossAGUITool("evaluate_intent", "Explain intent evaluation against current OSS policy/demo state."),
				ossAGUITool("verify_demo_receipt", "Verify the public proof demo receipt."),
				ossAGUITool("tamper_demo_receipt", "Run the tamper proof demo."),
				ossAGUITool("run_replay_probe", "Run replay probe over current evidence."),
			},
		})
	})

	runHandler := protectRuntimeHandler(RouteAuthTenant, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		var req ossAGUIRunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.WriteBadRequest(w, "Invalid AG-UI run body")
			return
		}
		prompt := strings.TrimSpace(lastOSSAGUIUserMessage(req.Messages))
		if prompt == "" {
			api.WriteBadRequest(w, "message is required")
			return
		}

		threadID := firstOSSNonEmpty(req.ThreadID, "oss-thread")
		runID := firstOSSNonEmpty(req.RunID, fmt.Sprintf("oss-run-%d", time.Now().UTC().UnixNano()))
		messageID := fmt.Sprintf("oss-msg-%d", time.Now().UTC().UnixNano())

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		emit := func(eventType string, payload map[string]any) bool {
			payload["type"] = eventType
			payload["timestamp"] = time.Now().UTC().UnixMilli()
			return writeOSSAGUIEvent(w, eventType, payload)
		}

		receipts := listConsoleReceipts(r.Context(), svc, 25)
		state := jsonSafeOSSState(req.State)
		state["receipt_count"] = len(receipts)
		state["current_surface"] = firstOSSNonEmpty(req.CurrentSurface, "command")
		state["conformance"] = envOrDefault("HELM_CONFORMANCE_STATUS", "unreported")

		if !emit("RUN_STARTED", map[string]any{"threadId": threadID, "runId": runID}) {
			return
		}
		if !emit("STATE_SNAPSHOT", map[string]any{"snapshot": state}) {
			return
		}
		if !emit("TEXT_MESSAGE_START", map[string]any{"messageId": messageID, "role": "assistant"}) {
			return
		}
		if !emit("TEXT_MESSAGE_CONTENT", map[string]any{
			"messageId": messageID,
			"delta":     ossAGUIExplanation(prompt, receipts, opts),
		}) {
			return
		}
		if !emit("TEXT_MESSAGE_END", map[string]any{"messageId": messageID}) {
			return
		}

		toolName := detectOSSAGUITool(prompt)
		toolCallID := fmt.Sprintf("oss-tool-%d", time.Now().UTC().UnixNano())
		if !emit("TOOL_CALL_START", map[string]any{
			"toolCallId":      toolCallID,
			"toolCallName":    toolName,
			"parentMessageId": messageID,
		}) {
			return
		}
		argsJSON, _ := json.Marshal(map[string]any{"prompt": prompt, "surface": state["current_surface"]})
		if !emit("TOOL_CALL_ARGS", map[string]any{"toolCallId": toolCallID, "delta": string(argsJSON)}) {
			return
		}
		if !emit("TOOL_CALL_END", map[string]any{"toolCallId": toolCallID}) {
			return
		}
		resultJSON, _ := json.Marshal(map[string]any{
			"status":  "complete",
			"summary": ossAGUIToolSummary(toolName, len(receipts)),
			"data": map[string]any{
				"tool":          toolName,
				"receipt_count": len(receipts),
				"policy_status": policyStatus(opts),
			},
			"receipt_refs": []string{"receipt:selected"},
			"proof_refs":   []string{"oss-proof-demo"},
			"next_actions": []string{"Use the public proof demo controls for verify, tamper, and replay."},
		})
		if !emit("TOOL_CALL_RESULT", map[string]any{
			"messageId":  fmt.Sprintf("oss-tool-msg-%d", time.Now().UTC().UnixNano()),
			"toolCallId": toolCallID,
			"role":       "tool",
			"content":    string(resultJSON),
		}) {
			return
		}
		emit("RUN_FINISHED", map[string]any{
			"threadId": threadID,
			"runId":    runID,
			"result":   map[string]any{"status": "complete"},
		})
	})

	mux.HandleFunc("/api/v1/agent-ui/info", infoHandler)
	mux.HandleFunc("/api/v1/agent-ui/run", runHandler)
	mux.HandleFunc("/api/ag-ui/info", infoHandler)
	mux.HandleFunc("/api/ag-ui/run", runHandler)
}

func ossAGUITool(name, description string) map[string]any {
	return map[string]any{
		"name":                  name,
		"description":           description,
		"risk_class":            "read",
		"authority_requirement": "console.admin",
		"result_renderer_id":    "helm_oss_proof_result",
		"parameters": map[string]any{
			"type":                 "object",
			"additionalProperties": true,
		},
	}
}

func writeOSSAGUIEvent(w http.ResponseWriter, eventType string, payload map[string]any) bool {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, encoded); err != nil {
		return false
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return true
}

func lastOSSAGUIUserMessage(messages []ossAGUIMessage) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.EqualFold(messages[i].Role, "user") && strings.TrimSpace(messages[i].Content) != "" {
			return messages[i].Content
		}
	}
	if len(messages) > 0 {
		return messages[len(messages)-1].Content
	}
	return ""
}

func detectOSSAGUITool(prompt string) string {
	normalized := strings.ToLower(prompt)
	switch {
	case strings.Contains(normalized, "tamper"):
		return "tamper_demo_receipt"
	case strings.Contains(normalized, "verify"):
		return "verify_demo_receipt"
	case strings.Contains(normalized, "replay"):
		return "run_replay_probe"
	default:
		return "evaluate_intent"
	}
}

func ossAGUIExplanation(prompt string, _ any, opts serverOptions) string {
	return fmt.Sprintf(
		"OSS agent runtime is read-only. It can explain %q using current receipts, policy status %s, and proof demo endpoints; governed writes are not exposed in OSS Console.",
		prompt,
		policyStatus(opts),
	)
}

func ossAGUIToolSummary(toolName string, receiptCount int) string {
	switch toolName {
	case "verify_demo_receipt":
		return fmt.Sprintf("Prepared demo receipt verification with %d receipt(s) available.", receiptCount)
	case "tamper_demo_receipt":
		return "Prepared tamper demonstration; the original receipt remains unchanged."
	case "run_replay_probe":
		return "Prepared replay probe against current evidence state."
	default:
		return "Evaluated prompt against current OSS Console state."
	}
}

func jsonSafeOSSState(state map[string]any) map[string]any {
	if state == nil {
		return map[string]any{}
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return map[string]any{}
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return map[string]any{}
	}
	return decoded
}

func firstOSSNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
