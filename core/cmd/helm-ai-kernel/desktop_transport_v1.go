package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	desktopTransportV1EnabledEnv = "HELM_DESKTOP_TRANSPORT_V1"
	desktopTransportV1KeyEnv     = "HELM_DESKTOP_TRANSPORT_KEY"
	desktopTransportV1NonceEnv   = "HELM_DESKTOP_TRANSPORT_NONCE"

	desktopTransportV1Schema       = "helm-desktop-transport-v1"
	desktopTransportV1RecordPrefix = "HELM_DESKTOP_TRANSPORT_V1 "
	desktopTransportV1RecordLimit  = 1024
	desktopTransportV1SecretLength = 64
)

// desktopTransportV1 is an opt-in direct-child readiness contract for the
// packaged Desktop. The key and nonce remain process environment only.
type desktopTransportV1 struct {
	key   string
	nonce string
}

type desktopTransportV1Record struct {
	Schema string `json:"schema"`
	Nonce  string `json:"nonce"`
	Origin string `json:"origin"`
	MAC    string `json:"mac"`
}

func desktopTransportV1FromEnv() (*desktopTransportV1, error) {
	enabled, present := os.LookupEnv(desktopTransportV1EnabledEnv)
	if !present || enabled == "" {
		return nil, nil
	}
	if enabled != "1" {
		return nil, fmt.Errorf("%s must be exactly \"1\" when set", desktopTransportV1EnabledEnv)
	}

	key, err := desktopTransportV1SecretFromEnv(desktopTransportV1KeyEnv)
	if err != nil {
		return nil, err
	}
	nonce, err := desktopTransportV1SecretFromEnv(desktopTransportV1NonceEnv)
	if err != nil {
		return nil, err
	}
	return &desktopTransportV1{key: key, nonce: nonce}, nil
}

func desktopTransportV1SecretFromEnv(name string) (string, error) {
	value := os.Getenv(name)
	if len(value) != desktopTransportV1SecretLength {
		return "", fmt.Errorf("%s must be %d lowercase hexadecimal characters", name, desktopTransportV1SecretLength)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return "", fmt.Errorf("%s must be %d lowercase hexadecimal characters", name, desktopTransportV1SecretLength)
	}
	return value, nil
}

// bind reserves the dynamic loopback endpoint before it is disclosed. Do not
// replace this with an availability check followed by a later bind.
func (t *desktopTransportV1) bind() (net.Listener, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("bind desktop transport listener: %w", err)
	}

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || addr.Port <= 0 {
		_ = listener.Close()
		return nil, "", fmt.Errorf("desktop transport listener returned a non-loopback address")
	}
	return listener, fmt.Sprintf("http://127.0.0.1:%d", addr.Port), nil
}

func (t *desktopTransportV1) readinessRecord(origin string) (string, error) {
	message := desktopTransportV1Schema + "\n" + t.nonce + "\n" + origin
	// The Desktop treats the canonical hex text as the HMAC key bytes; keep the
	// cross-process contract literal instead of decoding it before signing.
	mac := hmac.New(sha256.New, []byte(t.key))
	_, _ = io.WriteString(mac, message)
	record, err := json.Marshal(desktopTransportV1Record{
		Schema: desktopTransportV1Schema,
		Nonce:  t.nonce,
		Origin: origin,
		MAC:    hex.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		return "", fmt.Errorf("encode desktop transport readiness record: %w", err)
	}
	line := desktopTransportV1RecordPrefix + string(record)
	if len(line)+1 > desktopTransportV1RecordLimit {
		return "", fmt.Errorf("desktop transport readiness record exceeds %d bytes", desktopTransportV1RecordLimit)
	}
	return line, nil
}

func (t *desktopTransportV1) writeReadinessRecord(out io.Writer, origin string) error {
	line, err := t.readinessRecord(origin)
	if err != nil {
		return err
	}
	written, err := io.WriteString(out, line+"\n")
	if err != nil {
		return fmt.Errorf("write desktop transport readiness record: %w", err)
	}
	if written != len(line)+1 {
		return io.ErrShortWrite
	}
	return nil
}
