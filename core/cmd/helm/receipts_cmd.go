package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func runReceiptsCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm receipts tail --agent <id> [--server <url>] [--since <cursor>] [--json] [--limit <n>]")
		return 2
	}
	switch args[0] {
	case "tail":
		return runReceiptsTailCmd(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown receipts command: %s\n", args[0])
		_, _ = fmt.Fprintln(stderr, "Usage: helm receipts tail --agent <id> [--server <url>] [--since <cursor>] [--json] [--limit <n>]")
		return 2
	}
}

func runReceiptsTailCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("receipts tail", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		agentID string
		server  string
		since   string
		jsonOut bool
		limit   int
	)

	cmd.StringVar(&agentID, "agent", "", "Agent id to tail")
	cmd.StringVar(&server, "server", "", "HELM server URL")
	cmd.StringVar(&since, "since", "", "Receipt cursor")
	cmd.BoolVar(&jsonOut, "json", false, "Print receipt JSON")
	cmd.IntVar(&limit, "limit", 100, "Maximum receipts per poll")

	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if cmd.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected argument: %s\n", cmd.Arg(0))
		return 2
	}
	if strings.TrimSpace(agentID) == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --agent is required")
		return 2
	}
	if server == "" {
		server = os.Getenv("HELM_URL")
	}
	if server == "" {
		server = "http://127.0.0.1:7714"
	}

	tailURL, err := buildReceiptsTailURL(server, agentID, since, limit)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: invalid server URL: %v\n", err)
		return 2
	}

	client := &http.Client{Timeout: 0}
	req, err := http.NewRequest(http.MethodGet, tailURL, nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: cannot create request: %v\n", err)
		return 2
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: receipt stream unavailable: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_, _ = fmt.Fprintf(stderr, "Error: receipt stream returned %d: %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}

	return streamReceipts(resp.Body, stdout, stderr, jsonOut)
}

func buildReceiptsTailURL(server, agentID, since string, limit int) (string, error) {
	base, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/receipts/tail"
	query := base.Query()
	query.Set("agent", agentID)
	if since != "" {
		query.Set("since", since)
	}
	if limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", limit))
	}
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func streamReceipts(body io.Reader, stdout, stderr io.Writer, jsonOut bool) int {
	scanner := bufio.NewScanner(body)
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if data.Len() > 0 {
				printReceiptEvent(stdout, data.String(), jsonOut)
				data.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: receipt stream interrupted: %v\n", err)
		return 1
	}
	return 0
}

func printReceiptEvent(stdout io.Writer, raw string, jsonOut bool) {
	if jsonOut {
		_, _ = fmt.Fprintln(stdout, raw)
		return
	}
	var receipt struct {
		ReceiptID    string    `json:"receipt_id"`
		Status       string    `json:"status"`
		ExecutorID   string    `json:"executor_id"`
		Timestamp    time.Time `json:"timestamp"`
		LamportClock uint64    `json:"lamport_clock"`
	}
	if err := json.Unmarshal([]byte(raw), &receipt); err != nil {
		_, _ = fmt.Fprintln(stdout, raw)
		return
	}
	stamp := receipt.Timestamp.Format(time.RFC3339)
	if receipt.Timestamp.IsZero() {
		stamp = "unknown-time"
	}
	_, _ = fmt.Fprintf(stdout, "%s · %s · %s · lamport %d · %s\n", stamp, receipt.ExecutorID, receipt.Status, receipt.LamportClock, receipt.ReceiptID)
}

func init() {
	Register(Subcommand{Name: "receipts", Aliases: []string{}, Usage: "Tail durable receipts (tail --agent)", RunFn: runReceiptsCmd})
}
