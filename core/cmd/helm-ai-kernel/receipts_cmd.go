package main

import (
	"bufio"
	"context"
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
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel receipts <status|list|show|tail|verify|export> [flags]")
		return 2
	}
	switch args[0] {
	case "status":
		return runReceiptsStatusCmd(args[1:], stdout, stderr)
	case "list":
		return runReceiptsListCmd(args[1:], stdout, stderr)
	case "show":
		return runReceiptsShowCmd(args[1:], stdout, stderr)
	case "tail":
		return runReceiptsTailCmd(args[1:], stdout, stderr)
	case "verify":
		return runVerifyReceiptCmd(args[1:], stdout, stderr)
	case "export":
		if receiptsExportWantsNDJSON(args[1:]) {
			return runReceiptsExportNDJSON(args[1:], stdout, stderr)
		}
		return runExportCmd(args[1:], stdout, stderr)
	default:
		_ = cliui.WriteError(stderr, cliui.UsageErrorf("receipts", "unknown command: %s", args[0]).
			WithHint("status|list|show|tail|verify|export"))
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel receipts <status|list|show|tail|verify|export> [flags]")
		return 2
	}
}

type receiptsEdgeReport struct {
	Server  string `json:"server"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

func defaultReceiptsServer() string {
	if server := strings.TrimSpace(os.Getenv("HELM_URL")); server != "" {
		return server
	}
	return "http://127.0.0.1:7714"
}

func probeReceiptsEdge() receiptsEdgeReport {
	server := defaultReceiptsServer()
	report := receiptsEdgeReport{Server: server, Status: "FAIL", Message: "receipt stream unavailable"}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server, nil)
	if err != nil {
		report.Message = "invalid receipts server URL"
		return report
	}
	resp, err := (&http.Client{Timeout: 800 * time.Millisecond}).Do(req)
	if err != nil {
		report.Message = "receipt stream unavailable"
		return report
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	report.Status = "PASS"
	report.Message = fmt.Sprintf("edge answered %d", resp.StatusCode)
	return report
}

func runReceiptsStatusCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("receipts status", flag.ContinueOnError)
	var jsonOut bool
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "receipts status", cliui.FormatText); !ok {
		return code
	}
	jsonOut = jsonOut || formatFlag.IsJSON()
	report := probeReceiptsEdge()
	if jsonOut {
		if err := cliui.WriteJSON(stdout, report); err != nil {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "[%s]  receipts edge  %s  %s\n", report.Status, report.Server, report.Message)
	if report.Status == "PASS" {
		return 0
	}
	return 1
}

type receiptsListReport struct {
	Server     string          `json:"server"`
	Status     string          `json:"status"`
	Message    string          `json:"message"`
	Count      int             `json:"count"`
	Receipts   json.RawMessage `json:"receipts,omitempty"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type receiptsShowReport struct {
	Server  string          `json:"server"`
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Receipt json.RawMessage `json:"receipt,omitempty"`
}

func runReceiptsListCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("receipts list", flag.ContinueOnError)
	var (
		server  string
		jsonOut bool
		limit   int
	)
	cmd.StringVar(&server, "server", "", "HELM server URL")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	cmd.IntVar(&limit, "limit", 20, "Maximum receipts to fetch")
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "receipts list", cliui.FormatText); !ok {
		return code
	}
	jsonOut = jsonOut || formatFlag.IsJSON()
	errFormat := cliui.FormatText
	if jsonOut {
		errFormat = cliui.FormatJSON
	}
	if cmd.NArg() > 0 {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts list", "unexpected argument: %s", cmd.Arg(0)), errFormat)
	}
	if server == "" {
		server = defaultReceiptsServer()
	}
	if limit <= 0 {
		limit = 20
	}
	listURL, err := buildReceiptsListURL(server, limit)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitUsage, "receipts list", "invalid server URL"), errFormat)
	}
	body, status, message := fetchReceiptsDocument(listURL)
	report := receiptsListReport{Server: server, Status: status, Message: message}
	if status == "PASS" {
		var payload struct {
			Receipts   json.RawMessage `json:"receipts"`
			Count      int             `json:"count"`
			NextCursor string          `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			report.Status = "FAIL"
			report.Message = "receipt list was not JSON"
		} else {
			report.Receipts = payload.Receipts
			report.Count = payload.Count
			report.NextCursor = payload.NextCursor
		}
	}
	return writeReceiptsInspect(stdout, jsonOut, report, report.Status)
}

func runReceiptsShowCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("receipts show", flag.ContinueOnError)
	var (
		id      string
		file    string
		server  string
		jsonOut bool
	)
	cmd.StringVar(&id, "id", "", "Receipt id")
	cmd.StringVar(&file, "file", "", "Local receipt JSON file")
	cmd.StringVar(&server, "server", "", "HELM server URL")
	cmd.BoolVar(&jsonOut, "json", false, "Print JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "receipts show", cliui.FormatText); !ok {
		return code
	}
	jsonOut = jsonOut || formatFlag.IsJSON()
	errFormat := cliui.FormatText
	if jsonOut {
		errFormat = cliui.FormatJSON
	}
	if id == "" && cmd.NArg() == 1 {
		id = cmd.Arg(0)
	} else if cmd.NArg() > 0 {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts show", "unexpected argument: %s", cmd.Arg(0)), errFormat)
	}
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "receipts show", "read %s", file), errFormat)
		}
		report := receiptsShowReport{Server: "file:" + file, Status: "PASS", Message: "local receipt file", Receipt: json.RawMessage(raw)}
		return writeReceiptsInspect(stdout, jsonOut, report, report.Status)
	}
	if strings.TrimSpace(id) == "" {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts show", "receipt id is required").
			WithHint("pass <id> or --id, or --file for a local receipt"), errFormat)
	}
	if server == "" {
		server = defaultReceiptsServer()
	}
	showURL, err := buildReceiptsShowURL(server, id)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitUsage, "receipts show", "invalid server URL"), errFormat)
	}
	body, status, message := fetchReceiptsDocument(showURL)
	report := receiptsShowReport{Server: server, Status: status, Message: message}
	if status == "PASS" {
		report.Receipt = json.RawMessage(body)
	}
	return writeReceiptsInspect(stdout, jsonOut, report, report.Status)
}

func buildReceiptsListURL(server string, limit int) (string, error) {
	base, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/receipts"
	query := base.Query()
	query.Set("limit", fmt.Sprintf("%d", limit))
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func buildReceiptsShowURL(server, id string) (string, error) {
	base, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/receipts/" + url.PathEscape(id)
	return base.String(), nil
}

func fetchReceiptsDocument(rawURL string) (body []byte, status, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "FAIL", "invalid receipts server URL"
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 800 * time.Millisecond}).Do(req)
	if err != nil {
		return nil, "FAIL", "receipt stream unavailable"
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, "FAIL", fmt.Sprintf("edge answered %d", resp.StatusCode)
	}
	return body, "PASS", fmt.Sprintf("edge answered %d", resp.StatusCode)
}

func writeReceiptsInspect(stdout io.Writer, jsonOut bool, payload any, status string) int {
	if jsonOut {
		if err := cliui.WriteJSON(stdout, payload); err != nil {
			return 1
		}
	} else {
		switch report := payload.(type) {
		case receiptsListReport:
			fmt.Fprintf(stdout, "[%s]  receipts list  %s  %s  count=%d\n", report.Status, report.Server, report.Message, report.Count)
		case receiptsShowReport:
			fmt.Fprintf(stdout, "[%s]  receipts show  %s  %s\n", report.Status, report.Server, report.Message)
			if len(report.Receipt) > 0 {
				_, _ = fmt.Fprintln(stdout, string(report.Receipt))
			}
		default:
			_ = cliui.WriteJSON(stdout, payload)
		}
	}
	if status == "PASS" {
		return 0
	}
	return 1
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

	if code, ok := cliui.ParseFlags(cmd, args, stderr, "receipts tail", cliui.FormatText); !ok {
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
	Register(Subcommand{
		Name:    "receipts",
		Aliases: []string{},
		Usage:   "Inspect durable receipts (status|list|show|tail|verify|export)",
		RunFn:   runReceiptsCmd,
		HelpFn:  printReceiptsUsage,
	})
}

func printReceiptsUsage(stdout io.Writer) {
	fmt.Fprintln(stdout, "Usage: helm-ai-kernel receipts status [--json|--format text|json]")
	fmt.Fprintln(stdout, "       helm-ai-kernel receipts list [--server URL] [--limit N] [--json|--format text|json]")
	fmt.Fprintln(stdout, "       helm-ai-kernel receipts show <id> [--server URL] [--file PATH] [--json|--format text|json]")
	fmt.Fprintln(stdout, "       helm-ai-kernel receipts tail --agent <id> [--server URL] [--since CURSOR] [--limit N] [--json|--format text|json]")
	fmt.Fprintln(stdout, "       helm-ai-kernel receipts verify --receipt FILE --trusted-public-key-file KEY")
	fmt.Fprintln(stdout, "       helm-ai-kernel receipts export --ndjson [--file PATH|--dir DIR|--server URL]")
	fmt.Fprintln(stdout, "       helm-ai-kernel receipts export --evidence DIR --out DIR")
	fmt.Fprintln(stdout, "status, list, and show are bounded HTTP inspect. tail streams SSE for one agent.")
	fmt.Fprintln(stdout, "verify aliases verify receipt. export --ndjson emits compact signed envelopes;")
	fmt.Fprintln(stdout, "verify them with receipts verify --receipt FILE --trusted-public-key-file KEY.")
	fmt.Fprintln(stdout, "export without --ndjson still aliases EvidencePack export.")
	fmt.Fprintln(stdout, "None of these verbs invent evidence.")
}
