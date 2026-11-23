package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// proxyReceipt is the governance receipt attached to every proxied request.
//
// Fields in the gen_ai.* family follow the OTel GenAI semantic conventions
// (see core/pkg/observability/genai_attrs.go). gen_ai.tool.call.id mirrors
// the helm correlation_id so OTel traces and helm-ai-kernel receipts cross-reference 1:1.
type proxyReceipt struct {
	ReceiptID        string   `json:"receipt_id"`
	Timestamp        string   `json:"timestamp"`
	Upstream         string   `json:"upstream"`
	Model            string   `json:"model,omitempty"`
	InputHash        string   `json:"input_hash"`
	OutputHash       string   `json:"output_hash,omitempty"`
	ToolCalls        int      `json:"tool_calls_intercepted"`
	ToolNames        []string `json:"tool_names,omitempty"`
	ArgsHashes       []string `json:"args_hashes,omitempty"`
	ArgsValid        []bool   `json:"args_valid,omitempty"`
	Status           string   `json:"status"`
	ReasonCode       string   `json:"reason_code,omitempty"`
	DecisionID       string   `json:"decision_id,omitempty"`
	ProofGraphNodeID string   `json:"proofgraph_node,omitempty"`
	LamportClock     uint64   `json:"lamport_clock"`
	PrevHash         string   `json:"prev_hash"`
	Signature        string   `json:"signature,omitempty"`

	// helm-specific governance correlation. Equals gen_ai.tool.call.id below.
	CorrelationID string `json:"correlation_id,omitempty"`
	// SessionID keys the per-session iteration and wallclock limits.
	SessionID string `json:"session_id,omitempty"`

	// OTel GenAI semconv mirrors. Persisted alongside the receipt so the
	// receipt is self-contained for replay/audit even without the OTel trace.
	GenAISystem        string `json:"gen_ai_system,omitempty"`
	GenAIRequestModel  string `json:"gen_ai_request_model,omitempty"`
	GenAIOperationName string `json:"gen_ai_operation_name,omitempty"`
	GenAIToolCallID    string `json:"gen_ai_tool_call_id,omitempty"`
	GenAIInputTokens   int64  `json:"gen_ai_input_tokens,omitempty"`
	GenAIOutputTokens  int64  `json:"gen_ai_output_tokens,omitempty"`
	GenAIFinishReason  string `json:"gen_ai_finish_reason,omitempty"`

	// W3C traceparent header recorded with the receipt for trace ↔ receipt joins.
	Traceparent string `json:"traceparent,omitempty"`
}

// receiptStore persists receipts to a JSONL file for auditability.
type receiptStore struct {
	mu          sync.Mutex
	file        *os.File
	prevHash    string
	lastLamport uint64
}

func newReceiptStore(path string) (*receiptStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	prevHash, lastLamport, err := recoverReceiptStoreState(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &receiptStore{file: f, prevHash: prevHash, lastLamport: lastLamport}, nil
}

func recoverReceiptStoreState(path string) (string, uint64, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return "GENESIS", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	expectedPrevHash := "GENESIS"
	var lastLamport uint64
	reader := bufio.NewReader(f)
	for lineNo := 1; ; lineNo++ {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimRight(line, "\r\n")
			if len(bytes.TrimSpace(line)) == 0 {
				return "", 0, fmt.Errorf("receipt chain line %d is empty", lineNo)
			}
			var rcpt proxyReceipt
			if err := json.Unmarshal(line, &rcpt); err != nil {
				return "", 0, fmt.Errorf("receipt chain line %d is invalid JSON: %w", lineNo, err)
			}
			if rcpt.PrevHash != expectedPrevHash {
				return "", 0, fmt.Errorf("receipt chain line %d prev_hash %q does not match expected %q", lineNo, rcpt.PrevHash, expectedPrevHash)
			}
			if rcpt.LamportClock == 0 {
				return "", 0, fmt.Errorf("receipt chain line %d has zero lamport_clock", lineNo)
			}
			if lastLamport != 0 && rcpt.LamportClock != lastLamport+1 {
				return "", 0, fmt.Errorf("receipt chain line %d lamport_clock %d does not follow %d", lineNo, rcpt.LamportClock, lastLamport)
			}
			h := sha256.Sum256(line)
			expectedPrevHash = "sha256:" + hex.EncodeToString(h[:])
			lastLamport = rcpt.LamportClock
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, fmt.Errorf("read receipt chain line %d: %w", lineNo, readErr)
		}
	}
	return expectedPrevHash, lastLamport, nil
}

// Append assigns the receipt's Lamport clock and chain link under the store
// lock, lets seal finish it (receipt id, signature) with those values, and
// writes it. Taking the clock here rather than in the request goroutine keeps
// the clock order and the file order identical under concurrent requests; a
// caller-assigned clock wedged the chain after one out-of-order completion
// (audit 03-01). A seal or write error leaves the chain where it was.
func (s *receiptStore) Append(rcpt *proxyReceipt, seal func(*proxyReceipt) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rcpt.LamportClock = s.lastLamport + 1
	rcpt.PrevHash = s.prevHash
	if seal != nil {
		if err := seal(rcpt); err != nil {
			return err
		}
	}

	data, err := json.Marshal(rcpt)
	if err != nil {
		return err
	}

	// Update causal chain: prevHash = SHA-256 of this receipt's JSON
	h := sha256.Sum256(data)
	nextPrevHash := "sha256:" + hex.EncodeToString(h[:])
	data = append(data, '\n')
	if _, err := s.file.Write(data); err != nil {
		return err
	}
	s.prevHash = nextPrevHash
	s.lastLamport = rcpt.LamportClock
	return nil
}

func (s *receiptStore) LastLamport() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastLamport
}

func (s *receiptStore) Close() error {
	return s.file.Close()
}
