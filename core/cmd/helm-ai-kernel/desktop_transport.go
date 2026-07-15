package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Desktop transport v1 is deliberately private process bootstrap protocol, not
// a public Kernel API. The Desktop starts `server --desktop-transport` with a
// one-launch 32-byte key and nonce in the environment. Kernel binds first, then
// writes exactly one bounded line on its direct child's stdout:
//
// HELM_DESKTOP_TRANSPORT_V1 {"version":1,"host":"127.0.0.1","port":...,"nonce":"...","proof":"..."}\n
//
// proof is HMAC-SHA256 over a binary, length-prefixed canonical payload. The
// JSON is transport framing only and is never itself signed.
const (
	desktopTransportFlag          = "desktop-transport"
	desktopTransportKeyEnv        = "HELM_DESKTOP_TRANSPORT_KEY_B64"
	desktopTransportNonceEnv      = "HELM_DESKTOP_TRANSPORT_NONCE_B64"
	desktopTransportProtocol      = "helm-desktop-transport-v1"
	desktopTransportRecordPrefix  = "HELM_DESKTOP_TRANSPORT_V1 "
	desktopTransportVersion       = 1
	desktopTransportHost          = "127.0.0.1"
	desktopTransportMaxRecordSize = 512
	desktopTransportKeySize       = 32
	desktopTransportMinNonceSize  = 16
	desktopTransportMaxNonceSize  = 64
)

type desktopTransportConfig struct {
	key   []byte
	nonce string
}

type desktopTransportReadyRecord struct {
	Version int    `json:"version"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Nonce   string `json:"nonce"`
	Proof   string `json:"proof"`
}

// desktopTransportListen is a small test seam for the listener-error case.
var desktopTransportListen = net.Listen

func loadDesktopTransportConfig() (*desktopTransportConfig, error) {
	key, err := decodeCanonicalRawURLBase64(desktopTransportKeyEnv, os.Getenv(desktopTransportKeyEnv), desktopTransportKeySize, desktopTransportKeySize)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeCanonicalRawURLBase64(desktopTransportNonceEnv, os.Getenv(desktopTransportNonceEnv), desktopTransportMinNonceSize, desktopTransportMaxNonceSize)
	if err != nil {
		clear(key)
		return nil, err
	}
	return &desktopTransportConfig{
		key:   key,
		nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}, nil
}

func decodeCanonicalRawURLBase64(name, value string, minSize, maxSize int) ([]byte, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url", name)
	}
	if len(decoded) < minSize || len(decoded) > maxSize {
		if minSize == maxSize {
			return nil, fmt.Errorf("%s must decode to exactly %d bytes", name, minSize)
		}
		return nil, fmt.Errorf("%s must decode to %d-%d bytes", name, minSize, maxSize)
	}
	return decoded, nil
}

// startDesktopTransport binds the only desktop listener before it emits the
// readiness frame. The caller owns the returned listener and must pass it to
// http.Server.Serve; no fixed API, health, or metrics port is used in v1.
func startDesktopTransport(config *desktopTransportConfig, stdout io.Writer) (net.Listener, int, error) {
	if config == nil {
		return nil, 0, errors.New("invalid desktop transport configuration")
	}
	defer clear(config.key)
	if err := validateDesktopTransportConfig(config); err != nil {
		return nil, 0, err
	}
	if stdout == nil {
		return nil, 0, errors.New("desktop transport stdout is unavailable")
	}

	listener, err := desktopTransportListen("tcp4", desktopTransportHost+":0")
	if err != nil {
		return nil, 0, fmt.Errorf("bind desktop transport listener: %w", err)
	}
	port, err := desktopTransportListenerPort(listener)
	if err != nil {
		_ = listener.Close()
		return nil, 0, err
	}
	if err := writeDesktopTransportReadyRecord(stdout, config, desktopTransportHost, port); err != nil {
		_ = listener.Close()
		return nil, 0, err
	}
	return listener, port, nil
}

func desktopTransportListenerPort(listener net.Listener) (int, error) {
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.Port < 1 || tcpAddr.Port > 65535 {
		return 0, errors.New("desktop transport listener did not expose a TCP port")
	}
	return tcpAddr.Port, nil
}

func writeDesktopTransportReadyRecord(stdout io.Writer, config *desktopTransportConfig, host string, port int) error {
	if config == nil {
		return errors.New("invalid desktop transport configuration")
	}
	defer clear(config.key)
	if err := validateDesktopTransportConfig(config); err != nil {
		return err
	}

	payload, err := desktopTransportMACPayload(host, port, config.nonce)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, config.key)
	_, _ = mac.Write(payload)
	recordBytes, err := json.Marshal(desktopTransportReadyRecord{
		Version: desktopTransportVersion,
		Host:    host,
		Port:    port,
		Nonce:   config.nonce,
		Proof:   base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		return fmt.Errorf("encode desktop transport readiness record: %w", err)
	}
	line := append([]byte(desktopTransportRecordPrefix), recordBytes...)
	line = append(line, '\n')
	if len(line) > desktopTransportMaxRecordSize {
		return errors.New("desktop transport readiness record exceeds size limit")
	}
	n, err := stdout.Write(line)
	if err != nil {
		return fmt.Errorf("write desktop transport readiness record: %w", err)
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return nil
}

func validateDesktopTransportConfig(config *desktopTransportConfig) error {
	if config == nil || len(config.key) != desktopTransportKeySize {
		return errors.New("invalid desktop transport configuration")
	}
	_, err := decodeCanonicalRawURLBase64("desktop transport nonce", config.nonce, desktopTransportMinNonceSize, desktopTransportMaxNonceSize)
	return err
}

// desktopTransportMACPayload is a binary, length-prefixed payload:
// u16(domain length) | domain | u16(version) | u16(host length) | host |
// u16(port) | u16(nonce length) | nonce. All integers are big-endian.
func desktopTransportMACPayload(host string, port int, nonce string) ([]byte, error) {
	if host != desktopTransportHost {
		return nil, errors.New("desktop transport host must be loopback")
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("desktop transport port is invalid")
	}
	canonicalNonce, err := decodeCanonicalRawURLBase64("desktop transport nonce", nonce, desktopTransportMinNonceSize, desktopTransportMaxNonceSize)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(canonicalNonce) != nonce {
		return nil, errors.New("desktop transport nonce is not canonical")
	}

	payload := make([]byte, 0, len(desktopTransportProtocol)+len(host)+len(nonce)+10)
	payload = appendDesktopTransportString(payload, desktopTransportProtocol)
	payload = binary.BigEndian.AppendUint16(payload, desktopTransportVersion)
	payload = appendDesktopTransportString(payload, host)
	payload = binary.BigEndian.AppendUint16(payload, uint16(port))
	payload = appendDesktopTransportString(payload, nonce)
	return payload, nil
}

func appendDesktopTransportString(payload []byte, value string) []byte {
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(value)))
	return append(payload, value...)
}
