package capabilities

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// StdioMCPClient talks to an MCP server via stdio.
type StdioMCPClient struct {
	Command string
	Args    []string
}

func NewStdioMCPClient(cmd string, args ...string) *StdioMCPClient {
	return &StdioMCPClient{Command: cmd, Args: args}
}

type mcpRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      int            `json:"id"`
}

func (s *StdioMCPClient) Call(tool string, params map[string]any) error {
	req := mcpRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  map[string]any{"name": tool, "arguments": params},
		ID:      1,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal MCP request: %w", err)
	}

	var stdin bytes.Buffer
	if _, err := fmt.Fprintf(&stdin, "Content-Length: %d\r\n\r\n", len(reqBytes)); err != nil {
		return fmt.Errorf("format MCP request header: %w", err)
	}
	if _, err := stdin.Write(reqBytes); err != nil {
		return fmt.Errorf("write MCP request body: %w", err)
	}

	//nolint:gosec // G204: Command args are controlled by internal caller
	cmd := exec.CommandContext(context.Background(), s.Command, s.Args...)
	cmd.Stdin = &stdin

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mcp error: %w, output: %s", err, out)
	}

	slog.Debug("mcp stdio output", "output", string(out))
	if _, parseErr := decodeStdioMCPResponse(out); parseErr != nil {
		return fmt.Errorf("mcp response parse error: %w", parseErr)
	}
	return nil
}

func decodeStdioMCPResponse(out []byte) (map[string]any, error) {
	reader := bufio.NewReader(strings.NewReader(string(out)))
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "{") {
		var payload map[string]any
		if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
			return nil, err
		}
		return payload, nil
	}

	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
		return nil, fmt.Errorf("unexpected MCP response header: %s", trimmed)
	}
	length, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}

	// Consume the blank line.
	if _, err := reader.ReadString('\n'); err != nil {
		return nil, err
	}

	payloadBytes := make([]byte, length)
	if _, err := io.ReadFull(reader, payloadBytes); err != nil {
		return nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}
