package claudemanaged

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/actuators"
)

type ToolClass string

const (
	ToolBash           ToolClass = "bash"
	ToolCode           ToolClass = "code"
	ToolFileRead       ToolClass = "file_read"
	ToolFileWrite      ToolClass = "file_write"
	ToolFileList       ToolClass = "file_list"
	ToolValidation     ToolClass = "validation"
	ToolOutputArtifact ToolClass = "output_artifact"
	ToolMCP            ToolClass = "mcp_tool"
	ToolMemoryWrite    ToolClass = "memory_write"
)

type ToolRequest struct {
	RequestID string            `json:"request_id"`
	SandboxID string            `json:"sandbox_id"`
	ToolName  string            `json:"tool_name"`
	Class     ToolClass         `json:"class"`
	Command   []string          `json:"command,omitempty"`
	Path      string            `json:"path,omitempty"`
	Data      []byte            `json:"data,omitempty"`
	Target    string            `json:"target,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type ToolResponse struct {
	Allowed           bool           `json:"allowed"`
	IsError           bool           `json:"is_error"`
	Content           string         `json:"content,omitempty"`
	StructuredContent map[string]any `json:"structured_content,omitempty"`
	ReceiptID         string         `json:"receipt_id,omitempty"`
	ReasonCode        string         `json:"reason_code,omitempty"`
}

type ToolDispatcher interface {
	Dispatch(ctx context.Context, req ToolRequest) (ToolResponse, error)
}

type WorkerShim struct {
	Actuator   *Adapter
	Dispatcher ToolDispatcher
	Clock      func() time.Time
}

func (s WorkerShim) HandleTool(ctx context.Context, req ToolRequest) (ToolResponse, error) {
	if req.RequestID == "" {
		req.RequestID = fmt.Sprintf("tool-%d", s.now().UnixNano())
	}
	if s.Actuator == nil {
		return ToolResponse{}, fmt.Errorf("claude managed agents shim requires actuator")
	}
	switch req.Class {
	case ToolBash, ToolCode, ToolValidation:
		result, err := s.Actuator.Exec(ctx, req.SandboxID, &actuators.ExecRequest{Command: req.Command})
		if err != nil {
			return ToolResponse{}, err
		}
		managedReceipt, err := s.Actuator.managedReceiptForTool(req, contracts.VerdictAllow, "", "", map[string]string{
			"stdout": result.Receipt.StdoutHash,
			"stderr": result.Receipt.StderrHash,
		}, result.Receipt.RequestHash, s.now())
		if err != nil {
			return ToolResponse{}, err
		}
		return ToolResponse{
			Allowed:   true,
			IsError:   !result.Success(),
			Content:   string(result.Stdout),
			ReceiptID: managedReceipt.ReceiptID,
			StructuredContent: map[string]any{
				"exit_code":                    result.ExitCode,
				"stderr_hash":                  result.Receipt.StderrHash,
				"stdout_hash":                  result.Receipt.StdoutHash,
				"receipt_provider":             result.Receipt.Provider,
				"receipt_fragment_ref":         result.Receipt.RequestHash,
				"managed_agent_receipt_hash":   managedReceipt.ReceiptHash,
				"managed_agent_receipt_schema": ReceiptVersionManagedAgentExecution,
			},
		}, nil
	case ToolFileRead:
		data, err := s.Actuator.ReadFile(ctx, req.SandboxID, req.Path)
		if err != nil {
			return ToolResponse{}, err
		}
		managedReceipt, err := s.Actuator.managedReceiptForTool(req, contracts.VerdictAllow, "", "", map[string]string{"content": hashBytes(data)}, "", s.now())
		if err != nil {
			return ToolResponse{}, err
		}
		return allowedToolResponse(string(data), managedReceipt), nil
	case ToolFileWrite:
		if err := s.Actuator.WriteFile(ctx, req.SandboxID, req.Path, req.Data); err != nil {
			return ToolResponse{}, err
		}
		managedReceipt, err := s.Actuator.managedReceiptForTool(req, contracts.VerdictAllow, "", "", map[string]string{"content": hashBytes(req.Data)}, "", s.now())
		if err != nil {
			return ToolResponse{}, err
		}
		return allowedToolResponse("ok", managedReceipt), nil
	case ToolFileList:
		entries, err := s.Actuator.ListFiles(ctx, req.SandboxID, req.Path)
		if err != nil {
			return ToolResponse{}, err
		}
		payload, _ := json.Marshal(entries)
		managedReceipt, err := s.Actuator.managedReceiptForTool(req, contracts.VerdictAllow, "", "", map[string]string{"listing": hashBytes(payload)}, "", s.now())
		if err != nil {
			return ToolResponse{}, err
		}
		return allowedToolResponse(string(payload), managedReceipt), nil
	case ToolOutputArtifact:
		path := req.Path
		if path == "" {
			path = "/mnt/session/outputs/" + req.RequestID
		}
		req.Path = path
		if err := s.Actuator.WriteFile(ctx, req.SandboxID, path, req.Data); err != nil {
			return ToolResponse{}, err
		}
		managedReceipt, err := s.Actuator.managedReceiptForTool(req, contracts.VerdictAllow, "", "", map[string]string{"artifact": hashBytes(req.Data)}, "", s.now())
		if err != nil {
			return ToolResponse{}, err
		}
		return allowedToolResponse("ok", managedReceipt), nil
	case ToolMemoryWrite:
		return s.denyTool(req, contracts.ReasonSessionRiskDeny, "Managed Agents memory is unsupported for self-hosted sandboxes"), nil
	case ToolMCP:
		if req.Metadata["route"] != "helm-mcp-gateway" {
			return s.denyTool(req, contracts.ReasonSandboxViolation, "MCP tunnel target bypasses HELM MCP Gateway"), nil
		}
		if s.Dispatcher == nil {
			return s.denyTool(req, contracts.ReasonPDPError, "MCP dispatcher is not configured"), nil
		}
		resp, err := s.Dispatcher.Dispatch(ctx, req)
		if err != nil {
			return ToolResponse{}, err
		}
		verdict := contracts.VerdictAllow
		var reason contracts.ReasonCode
		if !resp.Allowed || resp.IsError {
			verdict = contracts.VerdictDeny
			reason = contracts.ReasonCode(resp.ReasonCode)
			if reason == "" {
				reason = contracts.ReasonPDPError
			}
		}
		gatewayReceiptRef := resp.ReceiptID
		managedReceipt, err := s.Actuator.managedReceiptForTool(req, verdict, reason, resp.Content, nil, gatewayReceiptRef, s.now())
		if err != nil {
			return ToolResponse{}, err
		}
		if resp.StructuredContent == nil {
			resp.StructuredContent = map[string]any{}
		}
		resp.StructuredContent["managed_agent_receipt_hash"] = managedReceipt.ReceiptHash
		resp.StructuredContent["managed_agent_receipt_schema"] = managedReceipt.ReceiptVersion
		if gatewayReceiptRef != "" {
			resp.StructuredContent["mcp_gateway_receipt_ref"] = gatewayReceiptRef
		}
		resp.ReceiptID = managedReceipt.ReceiptID
		return resp, nil
	default:
		return s.denyTool(req, contracts.ReasonSchemaViolation, "unknown Claude Managed Agents tool class"), nil
	}
}

func allowedToolResponse(content string, receipt *ManagedAgentExecutionReceipt) ToolResponse {
	return ToolResponse{
		Allowed:   true,
		Content:   content,
		ReceiptID: receipt.ReceiptID,
		StructuredContent: map[string]any{
			"managed_agent_receipt_hash":   receipt.ReceiptHash,
			"managed_agent_receipt_schema": receipt.ReceiptVersion,
		},
	}
}

func (s WorkerShim) denyTool(req ToolRequest, reason contracts.ReasonCode, message string) ToolResponse {
	receiptID := denialReceiptID(req, reason)
	structured := map[string]any{
		"verdict":     string(contracts.VerdictDeny),
		"reason_code": string(reason),
		"request_id":  req.RequestID,
	}
	if s.Actuator != nil && req.SandboxID != "" {
		if receipt, err := s.Actuator.managedReceiptForTool(req, contracts.VerdictDeny, reason, message, nil, receiptID, s.now()); err == nil {
			receiptID = receipt.ReceiptID
			structured["managed_agent_receipt_hash"] = receipt.ReceiptHash
			structured["managed_agent_receipt_schema"] = receipt.ReceiptVersion
		}
	}
	return ToolResponse{
		Allowed:           false,
		IsError:           true,
		Content:           message,
		ReceiptID:         receiptID,
		ReasonCode:        string(reason),
		StructuredContent: structured,
	}
}

func denialReceiptID(req ToolRequest, reason contracts.ReasonCode) string {
	payload, _ := json.Marshal(struct {
		RequestID string               `json:"request_id"`
		Class     ToolClass            `json:"class"`
		Path      string               `json:"path,omitempty"`
		Target    string               `json:"target,omitempty"`
		Reason    contracts.ReasonCode `json:"reason,omitempty"`
	}{
		RequestID: req.RequestID,
		Class:     req.Class,
		Path:      req.Path,
		Target:    req.Target,
		Reason:    reason,
	})
	return hashBytes(payload)
}

func (s WorkerShim) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock()
}
