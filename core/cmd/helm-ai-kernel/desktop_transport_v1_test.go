package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestDesktopTransportV1RequiresTheExplicitServerOption(t *testing.T) {
	valid := strings.Repeat("a", desktopTransportV1SecretLength)
	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, valid)
	t.Setenv(desktopTransportV1NonceEnv, strings.Repeat("b", desktopTransportV1SecretLength))

	transport, err := desktopTransportV1ForOptions(serverOptions{})
	if err != nil || transport != nil {
		t.Fatalf("transport env without the explicit server option must preserve normal mode, transport=%#v err=%v", transport, err)
	}

	transport, err = desktopTransportV1ForOptions(serverOptions{DesktopTransportV1: true})
	if err != nil || transport == nil {
		t.Fatalf("explicit transport option must accept valid transport env, transport=%#v err=%v", transport, err)
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

func TestDesktopTransportV1ProofRouteIsModeLocalAndChallengeBound(t *testing.T) {
	transport := &desktopTransportV1{
		key:   strings.Repeat("a", desktopTransportV1SecretLength),
		nonce: strings.Repeat("b", desktopTransportV1SecretLength),
	}
	origin := "http://127.0.0.1:45321"
	challenge := strings.Repeat("c", desktopTransportV1SecretLength)

	normalMux := http.NewServeMux()
	registerDesktopTransportV1ProofRoute(normalMux, nil, origin)
	normalResponse := httptest.NewRecorder()
	normalMux.ServeHTTP(normalResponse, httptest.NewRequest(http.MethodGet, desktopTransportV1ProofPath, nil))
	if normalResponse.Code != http.StatusNotFound {
		t.Fatalf("normal mode registered Desktop proof route: status=%d", normalResponse.Code)
	}

	mux := http.NewServeMux()
	registerDesktopTransportV1ProofRoute(mux, transport, origin)
	request := httptest.NewRequest(http.MethodGet, desktopTransportV1ProofPath, nil)
	request.Header.Set(desktopTransportV1ChallengeHeader, challenge)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid no-bearer proof request status=%d, want %d", response.Code, http.StatusNoContent)
	}
	if response.Body.Len() != 0 {
		t.Fatalf("proof response body must be empty: %q", response.Body.String())
	}
	proof := response.Header().Get(desktopTransportV1ProofHeader)
	expected := desktopTransportTestHandoffMAC(transport.key, transport.nonce, origin, challenge)
	if !hmac.Equal([]byte(proof), []byte(expected)) {
		t.Fatalf("proof mismatch: got %q want %q", proof, expected)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("proof response cache control=%q, want no-store", response.Header().Get("Cache-Control"))
	}
	if strings.Contains(proof, transport.key) {
		t.Fatal("proof must not expose the transport key")
	}

	for _, challenge := range []string{"", strings.Repeat("a", desktopTransportV1SecretLength-1), strings.Repeat("A", desktopTransportV1SecretLength), strings.Repeat("g", desktopTransportV1SecretLength)} {
		request := httptest.NewRequest(http.MethodGet, desktopTransportV1ProofPath, nil)
		request.Header.Set(desktopTransportV1ChallengeHeader, challenge)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid challenge %q status=%d, want %d", challenge, response.Code, http.StatusBadRequest)
		}
		if response.Header().Get(desktopTransportV1ProofHeader) != "" {
			t.Fatalf("invalid challenge %q returned a proof", challenge)
		}
	}

	methodResponse := httptest.NewRecorder()
	mux.ServeHTTP(methodResponse, httptest.NewRequest(http.MethodPost, desktopTransportV1ProofPath, nil))
	if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("non-GET proof request status=%d allow=%q", methodResponse.Code, methodResponse.Header().Get("Allow"))
	}
}

func TestDesktopTransportV1SuppressesAuxiliaryHealthAndRejectsMetrics(t *testing.T) {
	transport := &desktopTransportV1{}
	if suppress, err := desktopTransportV1SuppressesAuxiliaryHealth(transport, 0, false); err != nil || !suppress {
		t.Fatalf("Desktop transport should suppress port-zero auxiliary health, suppress=%t err=%v", suppress, err)
	}
	if suppress, err := desktopTransportV1SuppressesAuxiliaryHealth(transport, 0, true); err == nil || suppress {
		t.Fatalf("Desktop transport must reject metrics with port-zero auxiliary health, suppress=%t err=%v", suppress, err)
	}
	if suppress, err := desktopTransportV1SuppressesAuxiliaryHealth(nil, 0, true); err != nil || suppress {
		t.Fatalf("normal mode must keep its existing health behavior, suppress=%t err=%v", suppress, err)
	}

	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, strings.Repeat("a", desktopTransportV1SecretLength))
	t.Setenv(desktopTransportV1NonceEnv, strings.Repeat("b", desktopTransportV1SecretLength))
	t.Setenv("HELM_HEALTH_PORT", "0")
	t.Setenv("HELM_METRICS_ENABLED", "1")
	t.Setenv("HELM_METRICS_PORT", "")
	var stdout, stderr bytes.Buffer
	err := runServerWithOptions(serverOptions{DesktopTransportV1: true, Stdout: &stdout, Stderr: &stderr})
	if err == nil || !strings.Contains(err.Error(), "HELM_METRICS_ENABLED") {
		t.Fatalf("expected fail-closed auxiliary metrics configuration error, err=%v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid auxiliary metrics configuration must fail before startup output: %q", stdout.String())
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

func TestDesktopTransportV1DoesNotDependOnLegacyFixedPortAvailability(t *testing.T) {
	legacy, err := net.Listen("tcp", "127.0.0.1:8420")
	if err != nil {
		t.Skipf("cannot pre-bind legacy fixed port in this environment: %v", err)
	}
	defer legacy.Close()

	transport := &desktopTransportV1{
		key:   strings.Repeat("a", desktopTransportV1SecretLength),
		nonce: strings.Repeat("b", desktopTransportV1SecretLength),
	}
	listener, origin, err := transport.bind()
	if err != nil {
		t.Fatalf("dynamic Desktop transport bind failed while legacy port was occupied: %v", err)
	}
	defer listener.Close()
	if origin == "http://127.0.0.1:8420" {
		t.Fatal("dynamic Desktop transport reused the pre-bound legacy port")
	}
}

func desktopTransportTestMAC(key, nonce, origin string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(desktopTransportV1Schema + "\n" + nonce + "\n" + origin))
	return hex.EncodeToString(mac.Sum(nil))
}

func desktopTransportTestHandoffMAC(key, nonce, origin, challenge string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte("helm-desktop-transport-v1-handoff\n" + nonce + "\n" + origin + "\n" + challenge))
	return hex.EncodeToString(mac.Sum(nil))
}
