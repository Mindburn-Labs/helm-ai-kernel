package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestDesktopTransportV1DisabledPreservesNormalMode(t *testing.T) {
	t.Setenv(desktopTransportV1EnabledEnv, "")

	transport, err := desktopTransportV1FromEnv()
	if err != nil {
		t.Fatalf("read desktop transport config: %v", err)
	}
	if transport != nil {
		t.Fatal("disabled desktop transport must leave normal server mode available")
	}
}

func TestDesktopTransportV1RejectsMissingOrBadConfig(t *testing.T) {
	valid := strings.Repeat("a", desktopTransportV1SecretLength)
	for name, tc := range map[string]struct {
		key   string
		nonce string
	}{
		"missing key":   {nonce: valid},
		"missing nonce": {key: valid},
		"uppercase key": {key: strings.ToUpper(valid), nonce: valid},
		"short nonce":   {key: valid, nonce: valid[:desktopTransportV1SecretLength-1]},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(desktopTransportV1EnabledEnv, "1")
			t.Setenv(desktopTransportV1KeyEnv, tc.key)
			t.Setenv(desktopTransportV1NonceEnv, tc.nonce)
			if transport, err := desktopTransportV1FromEnv(); err == nil || transport != nil {
				t.Fatalf("bad desktop transport config must fail closed, transport=%#v err=%v", transport, err)
			}
		})
	}

	t.Setenv(desktopTransportV1EnabledEnv, "true")
	if transport, err := desktopTransportV1FromEnv(); err == nil || transport != nil {
		t.Fatalf("non-canonical transport gate must fail closed, transport=%#v err=%v", transport, err)
	}

	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, valid)
	t.Setenv(desktopTransportV1NonceEnv, strings.Repeat("b", desktopTransportV1SecretLength))
	if transport, err := desktopTransportV1FromEnv(); err != nil || transport == nil {
		t.Fatalf("valid desktop transport config was rejected, transport=%#v err=%v", transport, err)
	}
}

func TestRunServerCommandRejectsBadDesktopTransportBeforeStartup(t *testing.T) {
	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, "")
	t.Setenv(desktopTransportV1NonceEnv, "")

	var stdout, stderr bytes.Buffer
	code := runServerCommand("server", []string{"--desktop-transport-v1", "--port", "1"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("bad desktop transport config returned %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("server started despite bad desktop transport config: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "desktop transport v1 configuration") {
		t.Fatalf("missing configuration error: %q", stderr.String())
	}
}

func TestDesktopTransportV1ReadinessRecordBindsNonceOriginAndMAC(t *testing.T) {
	transport := &desktopTransportV1{
		key:   strings.Repeat("a", desktopTransportV1SecretLength),
		nonce: strings.Repeat("b", desktopTransportV1SecretLength),
	}
	listener, origin, err := transport.bind()
	if err != nil {
		t.Fatalf("bind desktop transport listener: %v", err)
	}
	defer listener.Close()
	if !strings.HasPrefix(origin, "http://127.0.0.1:") {
		t.Fatalf("origin %q is not canonical loopback", origin)
	}
	if replacement, err := net.Listen("tcp", listener.Addr().String()); err == nil {
		_ = replacement.Close()
		t.Fatal("dynamic desktop transport endpoint was not held by the Kernel listener")
	}

	var output bytes.Buffer
	if err := transport.writeReadinessRecord(&output, origin); err != nil {
		t.Fatalf("write readiness record: %v", err)
	}
	line := strings.TrimSuffix(output.String(), "\n")
	if len(output.Bytes()) > desktopTransportV1RecordLimit {
		t.Fatalf("readiness record is not bounded: %d bytes", len(output.Bytes()))
	}
	if strings.Contains(line, transport.key) {
		t.Fatal("readiness record must not expose the transport key")
	}
	encoded, ok := strings.CutPrefix(line, desktopTransportV1RecordPrefix)
	if !ok {
		t.Fatalf("record missing prefix: %q", line)
	}

	var record desktopTransportV1Record
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatalf("decode readiness record: %v", err)
	}
	if record.Schema != desktopTransportV1Schema || record.Nonce != transport.nonce || record.Origin != origin {
		t.Fatalf("unexpected readiness record: %#v", record)
	}

	expected := desktopTransportTestMAC(transport.key, transport.nonce, origin)
	if !hmac.Equal([]byte(record.MAC), []byte(expected)) {
		t.Fatalf("record MAC mismatch: got %q want %q", record.MAC, expected)
	}
	if record.MAC == desktopTransportTestMAC(transport.key, strings.Repeat("c", desktopTransportV1SecretLength), origin) {
		t.Fatal("record MAC must bind the launch nonce")
	}
	if record.MAC == desktopTransportTestMAC(transport.key, transport.nonce, "http://127.0.0.1:1") {
		t.Fatal("record MAC must bind the dynamic origin")
	}
}

func desktopTransportTestMAC(key, nonce, origin string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(desktopTransportV1Schema + "\n" + nonce + "\n" + origin))
	return hex.EncodeToString(mac.Sum(nil))
}
