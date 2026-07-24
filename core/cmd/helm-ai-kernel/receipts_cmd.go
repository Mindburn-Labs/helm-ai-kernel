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

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

func runReceiptsCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel receipts tail --agent <id> [--server <url>] [--since <cursor>] [--json] [--limit <n>]")
		return 2
	}
	switch args[0] {
	case "tail":
		return runReceiptsTailCmd(args[1:], stdout, stderr)
	default:
		_ = cliui.WriteError(stderr, cliui.UsageErrorf("receipts", "unknown command: %s", args[0]))
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel receipts tail --agent <id> [--server <url>] [--since <cursor>] [--json] [--limit <n>]")
		return 2
	}
}

func runReceiptsTailCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("receipts tail", flag.ContinueOnError)

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
	cmd.BoolVar(&jsonOut, "json", false, "Print receipt JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	cmd.IntVar(&limit, "limit", 100, "Maximum receipts per poll")

	if code, ok := cliui.ParseFlags(cmd, args, stderr, "receipts tail"); !ok {
		return code
	}
	jsonOut = jsonOut || formatFlag.IsJSON()
	// Errors follow the effective output mode (legacy --json included).
	errFormat := cliui.FormatText
	if jsonOut {
		errFormat = cliui.FormatJSON
	}
	if cmd.NArg() > 0 {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts tail", "unexpected argument: %s", cmd.Arg(0)), errFormat)
	}
	if strings.TrimSpace(agentID) == "" {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts tail", "--agent is required"), errFormat)
	}
	if server == "" {
		server = os.Getenv("HELM_URL")
	}
	if server == "" {
		server = "http://127.0.0.1:7714"
	}

	tailURL, err := buildReceiptsTailURL(server, agentID, since, limit)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitUsage, "receipts tail", "invalid server URL"), errFormat)
	}

	client := &http.Client{Timeout: 0}
	req, err := http.NewRequest(http.MethodGet, tailURL, nil)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitUsage, "receipts tail", "cannot create request"), errFormat)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "receipts tail", "receipt stream unavailable"), errFormat)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return cliui.WriteErrorFormat(stderr, cliui.Failf("receipts tail", "receipt stream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), errFormat)
	}

	return streamReceipts(resp.Body, stdout, stderr, jsonOut, errFormat)
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

func streamReceipts(body io.Reader, stdout, stderr io.Writer, jsonOut bool, format cliui.Format) int {
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
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "receipts tail", "receipt stream interrupted"), format)
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
