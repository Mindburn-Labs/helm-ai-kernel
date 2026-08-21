package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
)

const receiptEnvelopeSchema = "helm-ai-kernel.receipt-envelope.v1"

// receiptNDJSONEnvelope is one SIEM-grade line. The receipt object is the
// signed envelope already produced by Kernel; this wrapper does not resign.
type receiptNDJSONEnvelope struct {
	Schema  string           `json:"schema"`
	Receipt json.RawMessage  `json:"receipt"`
	Verify  receiptVerifyRef `json:"verify"`
}

type receiptVerifyRef struct {
	Command string `json:"command"`
	Hint    string `json:"hint"`
}

func runReceiptsExportNDJSON(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("receipts export", flag.ContinueOnError)
	var (
		ndjson  bool
		file    string
		dir     string
		server  string
		limit   int
		jsonOut bool
	)
	cmd.BoolVar(&ndjson, "ndjson", false, "Emit newline-delimited signed receipt envelopes")
	cmd.StringVar(&file, "file", "", "Local receipt JSON file")
	cmd.StringVar(&dir, "dir", "", "Directory of local receipt JSON files")
	cmd.StringVar(&server, "server", "", "HELM server URL for a bounded list")
	cmd.IntVar(&limit, "limit", 100, "Maximum receipts to fetch from --server")
	cmd.BoolVar(&jsonOut, "json", false, "Ignored for --ndjson; envelopes stay compact")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "receipts export", cliui.FormatText); !ok {
		return code
	}
	jsonOut = jsonOut || formatFlag.IsJSON()
	errFormat := cliui.FormatText
	if jsonOut {
		errFormat = cliui.FormatJSON
	}
	if !ndjson {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts export", "--ndjson is required for the receipt stream").
			WithHint("EvidencePack export remains: receipts export --evidence DIR --out DIR"), errFormat)
	}
	if cmd.NArg() > 0 {
		return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("receipts export", "unexpected argument: %s", cmd.Arg(0)), errFormat)
	}

	envelopes, err := collectReceiptEnvelopes(file, dir, server, limit)
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "receipts export", "collect receipts"), errFormat)
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	for _, env := range envelopes {
		if err := enc.Encode(env); err != nil {
			return 1
		}
	}
	return 0
}

func collectReceiptEnvelopes(file, dir, server string, limit int) ([]receiptNDJSONEnvelope, error) {
	var raws []json.RawMessage
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		compact, err := compactReceiptJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		raws = append(raws, compact)
	}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(dir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			compact, err := compactReceiptJSON(raw)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			raws = append(raws, compact)
		}
	}
	if file == "" && dir == "" {
		if server == "" {
			server = defaultReceiptsServer()
		}
		if limit <= 0 {
			limit = 100
		}
		listURL, err := buildReceiptsListURL(server, limit)
		if err != nil {
			return nil, err
		}
		body, status, message := fetchReceiptsDocument(listURL)
		if status != "PASS" {
			return nil, fmt.Errorf("%s", message)
		}
		var payload struct {
			Receipts json.RawMessage `json:"receipts"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("receipt list was not JSON")
		}
		listed, err := splitReceiptArray(payload.Receipts)
		if err != nil {
			return nil, err
		}
		raws = append(raws, listed...)
	}
	out := make([]receiptNDJSONEnvelope, 0, len(raws))
	for _, raw := range raws {
		out = append(out, receiptNDJSONEnvelope{
			Schema:  receiptEnvelopeSchema,
			Receipt: raw,
			Verify: receiptVerifyRef{
				Command: "helm-ai-kernel receipts verify --receipt FILE --trusted-public-key-file KEY",
				Hint:    "existing receipts verify; this stream does not invent signatures",
			},
		})
	}
	return out, nil
}

func compactReceiptJSON(raw []byte) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty receipt")
	}
	var value any
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return nil, err
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(compact), nil
}

func splitReceiptArray(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("receipts array was not JSON")
	}
	out := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		compact, err := compactReceiptJSON(item)
		if err != nil {
			return nil, err
		}
		out = append(out, compact)
	}
	return out, nil
}

func receiptsExportWantsNDJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--ndjson" || strings.HasPrefix(arg, "--ndjson=") {
			return true
		}
	}
	return false
}
