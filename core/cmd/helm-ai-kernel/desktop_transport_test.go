package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type desktopTransportWriteCounter struct {
	buffer bytes.Buffer
	writes int
}

func (w *desktopTransportWriteCounter) Write(p []byte) (int, error) {
	w.writes++
	return w.buffer.Write(p)
}

func (w *desktopTransportWriteCounter) String() string {
	return w.buffer.String()
}

func TestDesktopTransportReadyRecordFollowsBoundListener(t *testing.T) {
	key := make([]byte, desktopTransportKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	nonceBytes := make([]byte, desktopTransportMinNonceSize)
	for i := range nonceBytes {
		nonceBytes[i] = byte(i + 1)
	}
	keyEncoded := base64.RawURLEncoding.EncodeToString(key)
	config := &desktopTransportConfig{
		key:   append([]byte(nil), key...),
		nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	stdout := &desktopTransportWriteCounter{}

	listener, port, err := startDesktopTransport(config, stdout)
	if err != nil {
		t.Fatalf("start desktop transport: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if stdout.writes != 1 {
		t.Fatalf("stdout writes = %d, want exactly one", stdout.writes)
	}
	line := stdout.String()
	if len(line) > desktopTransportMaxRecordSize {
		t.Fatalf("record length = %d, max = %d", len(line), desktopTransportMaxRecordSize)
	}
	if strings.Count(line, desktopTransportRecordPrefix) != 1 || strings.Count(line, "\n") != 1 {
		t.Fatalf("unexpected record framing: %q", line)
	}
	if strings.Contains(line, keyEncoded) {
		t.Fatal("readiness record exposes the transport key")
	}

	var record desktopTransportReadyRecord
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(line, desktopTransportRecordPrefix), "\n")), &record); err != nil {
		t.Fatalf("decode readiness record: %v", err)
	}
	if record.Version != desktopTransportVersion || record.Host != desktopTransportHost || record.Port != port || record.Nonce != config.nonce {
		t.Fatalf("unexpected readiness record: %#v", record)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.Port != record.Port {
		t.Fatalf("record port %d was not the already-bound listener %v", record.Port, listener.Addr())
	}
	payload, err := desktopTransportMACPayload(record.Host, record.Port, record.Nonce)
	if err != nil {
		t.Fatalf("build MAC payload: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	wantProof := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(record.Proof), []byte(wantProof)) {
		t.Fatalf("record proof = %q, want %q", record.Proof, wantProof)
	}
	if !bytes.Equal(config.key, make([]byte, desktopTransportKeySize)) {
		t.Fatal("transport key bytes were retained after readiness record")
	}
}

func TestDesktopTransportInvalidConfigFailsBeforeReadyRecord(t *testing.T) {
	validKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, desktopTransportKeySize))
	validNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, desktopTransportMinNonceSize))
	cases := []struct {
		name  string
		key   string
		nonce string
		args  []string
	}{
		{name: "missing key", nonce: validNonce, args: []string{"--" + desktopTransportFlag}},
		{name: "invalid key", key: "not-base64url", nonce: validNonce, args: []string{"--" + desktopTransportFlag}},
		{name: "padded nonce", key: validKey, nonce: validNonce + "=", args: []string{"--" + desktopTransportFlag}},
		{name: "fixed address rejected", key: validKey, nonce: validNonce, args: []string{"--" + desktopTransportFlag, "--addr", "127.0.0.1"}},
		{name: "fixed port rejected", key: validKey, nonce: validNonce, args: []string{"--" + desktopTransportFlag, "--port", "8420"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(desktopTransportKeyEnv, tc.key)
			t.Setenv(desktopTransportNonceEnv, tc.nonce)
			var stdout, stderr bytes.Buffer
			if code := runServerCommand("server", tc.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stderr=%q", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("invalid config emitted stdout: %q", stdout.String())
			}
			if tc.key != "" && strings.Contains(stderr.String(), tc.key) {
				t.Fatalf("stderr exposes transport key: %q", stderr.String())
			}
		})
	}
}

func TestDesktopTransportListenerErrorEmitsNoReadyRecord(t *testing.T) {
	originalListen := desktopTransportListen
	desktopTransportListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("listener occupied")
	}
	t.Cleanup(func() { desktopTransportListen = originalListen })

	stdout := &desktopTransportWriteCounter{}
	config := &desktopTransportConfig{
		key:   bytes.Repeat([]byte{1}, desktopTransportKeySize),
		nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, desktopTransportMinNonceSize)),
	}
	if _, _, err := startDesktopTransport(config, stdout); err == nil {
		t.Fatal("listener error was accepted")
	}
	if stdout.writes != 0 || stdout.String() != "" {
		t.Fatalf("listener failure emitted readiness record: %q", stdout.String())
	}
	if !bytes.Equal(config.key, make([]byte, desktopTransportKeySize)) {
		t.Fatal("listener failure retained transport key bytes")
	}
}

func TestDesktopTransportMACPayloadIsCanonical(t *testing.T) {
	nonce := "AQIDBAUGBwgJCgsMDQ4PEA"
	payload, err := desktopTransportMACPayload(desktopTransportHost, 3400, nonce)
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}
	wantPayload, err := hex.DecodeString("001968656c6d2d6465736b746f702d7472616e73706f72742d7631000100093132372e302e302e310d48001641514944424155474277674a4367734d445134504541")
	if err != nil {
		t.Fatalf("decode expected payload: %v", err)
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Fatalf("payload = %x, want %x", payload, wantPayload)
	}

	key := make([]byte, desktopTransportKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	config := &desktopTransportConfig{key: append([]byte(nil), key...), nonce: nonce}
	var stdout desktopTransportWriteCounter
	if err := writeDesktopTransportReadyRecord(&stdout, config, desktopTransportHost, 3400); err != nil {
		t.Fatalf("write readiness record: %v", err)
	}
	var record desktopTransportReadyRecord
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(stdout.String(), desktopTransportRecordPrefix), "\n")), &record); err != nil {
		t.Fatalf("decode readiness record: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(wantPayload)
	if wantProof := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); record.Proof != wantProof {
		t.Fatalf("proof = %q, want %q", record.Proof, wantProof)
	}
	if _, err := desktopTransportMACPayload(desktopTransportHost, 3400, nonce+"="); err == nil {
		t.Fatal("accepted non-canonical padded nonce")
	}
}

func TestResolveServerAddressKeepsNormalFixedPort(t *testing.T) {
	t.Setenv("HELM_BIND_ADDR", "0.0.0.0")
	t.Setenv("HELM_PORT", "9999")
	bindAddr, port := resolveServerAddress(serverOptions{BindAddr: "127.0.0.1", Port: 7714})
	if bindAddr != "127.0.0.1" || port != 7714 {
		t.Fatalf("normal fixed address = %s:%d, want 127.0.0.1:7714", bindAddr, port)
	}
}

func TestDesktopTransportChildProcess(t *testing.T) {
	if os.Getenv("HELM_DESKTOP_TRANSPORT_CHILD") != "1" {
		return
	}
	code := runServerCommand("server", []string{
		"--" + desktopTransportFlag,
		"--data-dir", os.Getenv("HELM_DESKTOP_TRANSPORT_CHILD_DATA_DIR"),
	}, os.Stdout, os.Stderr)
	os.Exit(code)
}

type desktopTransportChildResult struct {
	lines []string
	err   error
}

func TestDesktopTransportChildStdoutAndHealth(t *testing.T) {
	key := make([]byte, desktopTransportKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, desktopTransportMinNonceSize))
	dataDir := t.TempDir()

	cmd := exec.Command(os.Args[0], "-test.run=^TestDesktopTransportChildProcess$")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{
		"HELM_DESKTOP_TRANSPORT_CHILD=1",
		"HELM_DESKTOP_TRANSPORT_CHILD_DATA_DIR=" + dataDir,
		desktopTransportKeyEnv + "=" + base64.RawURLEncoding.EncodeToString(key),
		desktopTransportNonceEnv + "=" + nonce,
		"HELM_ADMIN_API_KEY=desktop-transport-test-key",
		"PATH=" + os.Getenv("PATH"),
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("open child stdout: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start desktop transport child: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	first, all := scanDesktopTransportChildOutput(stdout)
	var line string
	select {
	case result := <-first:
		if result.err != nil {
			waitErr := <-done
			stopped = true
			t.Fatalf("desktop transport child ended before readiness: %v (wait=%v, stderr=%s)", result.err, waitErr, stderr.String())
		}
		line = result.lines[0]
	case <-time.After(15 * time.Second):
		t.Fatal("desktop transport child did not emit a readiness record")
	}

	var record desktopTransportReadyRecord
	if !strings.HasPrefix(line, desktopTransportRecordPrefix) {
		t.Fatalf("child stdout is not a desktop transport record: %q", line)
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, desktopTransportRecordPrefix)), &record); err != nil {
		t.Fatalf("decode child readiness record: %v", err)
	}
	if record.Nonce != nonce {
		t.Fatalf("child nonce = %q, want %q", record.Nonce, nonce)
	}
	payload, err := desktopTransportMACPayload(record.Host, record.Port, record.Nonce)
	if err != nil {
		t.Fatalf("build child readiness payload: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if wantProof := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); !hmac.Equal([]byte(record.Proof), []byte(wantProof)) {
		t.Fatalf("child proof = %q, want %q", record.Proof, wantProof)
	}
	if err := waitForDesktopTransportHealth(record); err != nil {
		t.Fatal(err)
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("stop desktop transport child: %v", err)
	}
	if err := <-done; err != nil {
		stopped = true
		t.Fatalf("desktop transport child exit: %v; stderr=%s", err, stderr.String())
	}
	stopped = true
	result := <-all
	if result.err != nil {
		t.Fatalf("read desktop transport child stdout: %v", result.err)
	}
	if len(result.lines) != 1 || result.lines[0] != line {
		t.Fatalf("child stdout lines = %#v, want exactly the signed record", result.lines)
	}
}

func scanDesktopTransportChildOutput(stdout io.Reader) (<-chan desktopTransportChildResult, <-chan desktopTransportChildResult) {
	first := make(chan desktopTransportChildResult, 1)
	all := make(chan desktopTransportChildResult, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, desktopTransportMaxRecordSize), desktopTransportMaxRecordSize)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
			if len(lines) == 1 {
				first <- desktopTransportChildResult{lines: append([]string(nil), lines...)}
			}
		}
		result := desktopTransportChildResult{lines: lines, err: scanner.Err()}
		if len(lines) == 0 {
			first <- result
		}
		all <- result
	}()
	return first, all
}

func waitForDesktopTransportHealth(record desktopTransportReadyRecord) error {
	if record.Version != desktopTransportVersion || record.Host != desktopTransportHost || record.Port < 1 || record.Port > 65535 {
		return fmt.Errorf("invalid desktop transport readiness record: %#v", record)
	}
	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://%s:%d/healthz", record.Host, record.Port))
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("attested desktop transport listener did not become healthy")
}
