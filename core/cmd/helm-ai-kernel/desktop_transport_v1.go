package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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

	desktopTransportV1ProofPath            = "/api/v1/desktop/transport/proof"
	desktopTransportV1ChallengeHeader      = "X-Helm-Desktop-Transport-Challenge"
	desktopTransportV1ProofHeader          = "X-Helm-Desktop-Transport-Proof"
	desktopTransportV1HandoffMessagePrefix = "helm-desktop-transport-v1-handoff"
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
	if !desktopTransportV1IsLowerHex(value) {
		return "", fmt.Errorf("%s must be %d lowercase hexadecimal characters", name, desktopTransportV1SecretLength)
	}
	return value, nil
}

func desktopTransportV1IsLowerHex(value string) bool {
	if len(value) != desktopTransportV1SecretLength {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
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
	record, err := json.Marshal(desktopTransportV1Record{
		Schema: desktopTransportV1Schema,
		Nonce:  t.nonce,
		Origin: origin,
		MAC:    t.hmac(message),
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

func (t *desktopTransportV1) hmac(message string) string {
	// The Desktop treats the canonical hex text as the HMAC key bytes; keep the
	// cross-process contract literal instead of decoding it before signing.
	mac := hmac.New(sha256.New, []byte(t.key))
	_, _ = io.WriteString(mac, message)
	return hex.EncodeToString(mac.Sum(nil))
}

func (t *desktopTransportV1) handoffProof(origin, challenge string) string {
	return t.hmac(desktopTransportV1HandoffMessagePrefix + "\n" + t.nonce + "\n" + origin + "\n" + challenge)
}

// registerProofRoute exposes a no-bearer, direct-child proof only while the
// Desktop transport owns the attested loopback listener. The fresh challenge
// prevents a released-port claimant from replaying the startup record.
func (t *desktopTransportV1) registerProofRoute(mux *http.ServeMux, origin string) {
	mux.HandleFunc(desktopTransportV1ProofPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		challenge := r.Header.Get(desktopTransportV1ChallengeHeader)
		if !desktopTransportV1IsLowerHex(challenge) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(desktopTransportV1ProofHeader, t.handoffProof(origin, challenge))
		w.WriteHeader(http.StatusNoContent)
	})
}

func registerDesktopTransportV1ProofRoute(mux *http.ServeMux, transport *desktopTransportV1, origin string) {
	if transport != nil {
		transport.registerProofRoute(mux, origin)
	}
}

func desktopTransportV1SuppressesAuxiliaryHealth(transport *desktopTransportV1, healthPort int, metricsEnabled bool) (bool, error) {
	if transport == nil || healthPort != 0 {
		return false, nil
	}
	if metricsEnabled {
		return false, fmt.Errorf("HELM_METRICS_ENABLED cannot be enabled when HELM_HEALTH_PORT=0")
	}
	return true, nil
}
