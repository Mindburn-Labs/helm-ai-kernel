package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	lpcmd "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/cmd"
)

// bridgeExpirySkew refreshes the access token slightly before its recorded
// expiry so a token that would lapse mid-request is rotated first.
const bridgeExpirySkew = 30 * time.Second

// maxBridgeResponseBytes caps how much of a remote MCP response the bridge
// buffers before relaying it; a truncated body fails JSON compaction and is
// surfaced to the client as an error instead of a corrupt frame.
const maxBridgeResponseBytes = 32 << 20

// runMCPBridge implements `helm-ai-kernel mcp bridge` — a stdio↔cloud MCP
// forwarder. It speaks the same stdio framing as `mcp serve --transport stdio`
// on stdin/stdout and forwards each JSON-RPC message to the remote HELM MCP
// HTTP endpoint, attaching an Authorization bearer loaded from the persisted
// `connect` machine credential at request time. On 401 or local expiry it
// refreshes the credential once via the device refresh endpoint and retries
// once; if auth still fails it returns a JSON-RPC error to the client and
// exits non-zero — it never forwards unauthenticated traffic. Token material
// is never printed or logged.
func runMCPBridge(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp bridge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var remoteURL string
	fs.StringVar(&remoteURL, "url", "", "Remote HELM MCP endpoint (default: the persisted connect credential's MCP edge)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(remoteURL) == "" {
		mc, err := lpcmd.LoadMachineCredential()
		if err != nil {
			fmt.Fprintf(stderr, "mcp bridge: %v\n", err)
			return 2
		}
		remoteURL = deriveCloudMCPURL(mc.APIURL)
	}
	if err := lpcmd.RequireSecureBaseURL(remoteURL); err != nil {
		fmt.Fprintf(stderr, "mcp bridge: %v\n", err)
		return 2
	}
	client := &http.Client{Timeout: 60 * time.Second}
	if err := runMCPBridgeLoop(os.Stdin, stdout, remoteURL, client, time.Now); err != nil {
		fmt.Fprintf(stderr, "mcp bridge: %v\n", err)
		return 1
	}
	return 0
}

// runMCPBridgeLoop reads stdio-framed JSON-RPC messages (same framing as
// `mcp serve --transport stdio`) and forwards each to the remote endpoint. A
// returned error means the bridge must stop (fail-closed auth or broken pipe);
// per-message remote failures are reported to the client as JSON-RPC errors
// and the loop continues.
func runMCPBridgeLoop(stdin io.Reader, stdout io.Writer, remoteURL string, client *http.Client, now func() time.Time) error {
	reader := bufio.NewReader(stdin)
	for {
		req, err := readMCPRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := bridgeForwardMessage(stdout, remoteURL, client, now, req); err != nil {
			return err
		}
	}
}

func bridgeForwardMessage(stdout io.Writer, remoteURL string, client *http.Client, now func() time.Time, req *mcpRPCRequest) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return bridgeWriteError(stdout, req, -32700, fmt.Sprintf("re-encode request: %v", err))
	}

	cred, err := lpcmd.LoadMachineCredential()
	if err != nil {
		return bridgeFailClosed(stdout, req, fmt.Sprintf("no usable cloud credential: %v", err))
	}
	refreshed := false
	if bridgeAccessExpired(cred, now()) {
		cred, err = lpcmd.RefreshMachineCredential(client, cred)
		if err != nil {
			return bridgeFailClosed(stdout, req, fmt.Sprintf("machine credential refresh failed: %v", err))
		}
		refreshed = true
	}

	status, body, err := bridgePost(client, remoteURL, payload, cred.AccessToken)
	if err != nil {
		return bridgeWriteError(stdout, req, -32000, fmt.Sprintf("forward to remote MCP endpoint failed: %v", err))
	}
	if status == http.StatusUnauthorized && !refreshed {
		cred, err = lpcmd.RefreshMachineCredential(client, cred)
		if err != nil {
			return bridgeFailClosed(stdout, req, fmt.Sprintf("machine credential refresh failed: %v", err))
		}
		status, body, err = bridgePost(client, remoteURL, payload, cred.AccessToken)
		if err != nil {
			return bridgeWriteError(stdout, req, -32000, fmt.Sprintf("forward to remote MCP endpoint failed: %v", err))
		}
	}
	if status == http.StatusUnauthorized {
		return bridgeFailClosed(stdout, req, "remote MCP endpoint rejected the machine credential after refresh; run 'helm-ai-kernel connect' again")
	}
	if status < 200 || status > 299 {
		return bridgeWriteError(stdout, req, -32000, fmt.Sprintf("remote MCP endpoint returned HTTP %d", status))
	}
	// Notifications get no response frame, and an empty body has nothing to relay.
	if req.ID == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, body); err != nil {
		return bridgeWriteError(stdout, req, -32700, "remote MCP endpoint returned a non-JSON response")
	}
	if _, err := stdout.Write(compacted.Bytes()); err != nil {
		return err
	}
	_, err = fmt.Fprint(stdout, "\n")
	return err
}

// bridgeAccessExpired reports whether the stored access token is missing or at
// (or within bridgeExpirySkew of) its recorded expiry. An unparseable expiry
// is treated as not-yet-expired; the remote 401 path still fails closed.
func bridgeAccessExpired(cred lpcmd.MachineCredential, now time.Time) bool {
	if strings.TrimSpace(cred.AccessToken) == "" {
		return true
	}
	expiry, err := time.Parse(time.RFC3339, cred.AccessExpiresAt)
	if err != nil {
		return false
	}
	return !now.Add(bridgeExpirySkew).Before(expiry)
}

func bridgePost(client *http.Client, url string, payload []byte, accessToken string) (int, []byte, error) {
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("User-Agent", "helm-ai-kernel/mcp-bridge")
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBridgeResponseBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// bridgeWriteError reports a per-message failure to the client (requests only;
// notifications get no response frame) and lets the loop continue.
func bridgeWriteError(stdout io.Writer, req *mcpRPCRequest, code int, message string) error {
	if req.ID == nil {
		return nil
	}
	return writeMCPResponse(stdout, &mcpRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Error:   &mcpRPCError{Code: code, Message: message},
	})
}

// bridgeFailClosed reports an unrecoverable authentication failure to the
// client and returns an error so the bridge exits non-zero instead of ever
// forwarding unauthenticated traffic.
func bridgeFailClosed(stdout io.Writer, req *mcpRPCRequest, message string) error {
	_ = bridgeWriteError(stdout, req, -32000, message)
	return errors.New(message)
}
