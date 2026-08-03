package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

func testDesktopTransportV1() *desktopTransportV1 {
	return &desktopTransportV1{
		key:   strings.Repeat("a", desktopTransportV1SecretLength),
		nonce: strings.Repeat("b", desktopTransportV1SecretLength),
	}
}

func TestDesktopTransportV1RequiresExplicitModeAndConsumesSecrets(t *testing.T) {
	transport := testDesktopTransportV1()
	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, transport.key)
	t.Setenv(desktopTransportV1NonceEnv, transport.nonce)

	got, err := desktopTransportV1ForOptions(serverOptions{})
	if err != nil || got != nil {
		t.Fatalf("transport environment without the explicit option must preserve normal mode, transport=%#v err=%v", got, err)
	}
	if _, present := os.LookupEnv(desktopTransportV1KeyEnv); !present {
		t.Fatal("normal mode consumed a transport secret")
	}

	got, err = desktopTransportV1ForOptions(serverOptions{DesktopTransportV1: true})
	if err != nil || got == nil {
		t.Fatalf("explicit transport option rejected valid config, transport=%#v err=%v", got, err)
	}
	for _, name := range []string{desktopTransportV1EnabledEnv, desktopTransportV1KeyEnv, desktopTransportV1NonceEnv} {
		if _, present := os.LookupEnv(name); present {
			t.Fatalf("%s remains in the process environment", name)
		}
	}
}

func TestDesktopTransportV1RejectsInvalidConfigurationBeforeStartup(t *testing.T) {
	valid := strings.Repeat("a", desktopTransportV1SecretLength)
	for name, tc := range map[string]struct {
		enabled string
		key     string
		nonce   string
	}{
		"missing enablement": {key: valid, nonce: valid},
		"bad enablement":     {enabled: "true", key: valid, nonce: valid},
		"missing key":        {enabled: "1", nonce: valid},
		"uppercase key":      {enabled: "1", key: strings.ToUpper(valid), nonce: valid},
		"short nonce":        {enabled: "1", key: valid, nonce: valid[:desktopTransportV1SecretLength-1]},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(desktopTransportV1EnabledEnv, tc.enabled)
			t.Setenv(desktopTransportV1KeyEnv, tc.key)
			t.Setenv(desktopTransportV1NonceEnv, tc.nonce)
			if transport, err := desktopTransportV1ForOptions(serverOptions{DesktopTransportV1: true}); err == nil || transport != nil {
				t.Fatalf("invalid transport config must fail closed, transport=%#v err=%v", transport, err)
			}
		})
	}

	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, "")
	t.Setenv(desktopTransportV1NonceEnv, "")
	var stdout, stderr bytes.Buffer
	if code := runServerCommand("server", []string{"--desktop-transport-v1"}, &stdout, &stderr); code != 1 {
		t.Fatalf("invalid transport server exited %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid transport config emitted a readiness record: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "desktop transport v1 configuration") {
		t.Fatalf("configuration failure missing from stderr: %q", stderr.String())
	}
}

func TestDesktopTransportV1BindsAnOccupiedLegacyPortAtomicallyOnLoopback(t *testing.T) {
	legacy, err := net.Listen("tcp", "127.0.0.1:8420")
	if err != nil {
		t.Skipf("cannot pre-bind legacy fixed port: %v", err)
	}
	defer legacy.Close()

	listener, origin, err := testDesktopTransportV1().bind()
	if err != nil {
		t.Fatalf("bind desktop transport listener: %v", err)
	}
	defer listener.Close()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || addr.Port <= 0 {
		t.Fatalf("listener address = %v, want allocated IPv4 loopback", listener.Addr())
	}
	if origin != "http://127.0.0.1:"+strconv.Itoa(addr.Port) || addr.Port == 8420 {
		t.Fatalf("origin = %q, listener = %v", origin, listener.Addr())
	}
	if replacement, err := net.Listen("tcp", listener.Addr().String()); err == nil {
		_ = replacement.Close()
		t.Fatal("transport disclosed a released listener")
	}
}

func TestDesktopTransportV1RecordAndProofBindKeyNonceAndOrigin(t *testing.T) {
	transport := testDesktopTransportV1()
	origin := "http://127.0.0.1:45321"
	line, err := transport.readinessRecord(origin)
	if err != nil {
		t.Fatal(err)
	}
	if len(line)+1 > desktopTransportV1RecordLimit || strings.Contains(line, transport.key) {
		t.Fatalf("unsafe readiness record: %q", line)
	}
	encoded, ok := strings.CutPrefix(line, desktopTransportV1RecordPrefix)
	if !ok {
		t.Fatalf("record missing prefix: %q", line)
	}
	var record desktopTransportV1Record
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatal(err)
	}
	if record.Schema != desktopTransportV1Schema || record.Nonce != transport.nonce || record.Origin != origin {
		t.Fatalf("record = %#v", record)
	}
	if !hmac.Equal([]byte(record.MAC), []byte(transport.hmac(desktopTransportV1Schema+"\n"+transport.nonce+"\n"+origin))) {
		t.Fatalf("record MAC is not bound to its nonce and origin: %q", record.MAC)
	}

	normalMux := http.NewServeMux()
	registerDesktopTransportV1ProofRoute(normalMux, nil, origin)
	normal := httptest.NewRecorder()
	normalMux.ServeHTTP(normal, httptest.NewRequest(http.MethodGet, desktopTransportV1ProofPath, nil))
	if normal.Code != http.StatusNotFound {
		t.Fatalf("normal mode registered Desktop proof route: status=%d", normal.Code)
	}

	mux := http.NewServeMux()
	registerDesktopTransportV1ProofRoute(mux, transport, origin)
	challenge := strings.Repeat("c", desktopTransportV1SecretLength)
	request := httptest.NewRequest(http.MethodGet, desktopTransportV1ProofPath, nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set(desktopTransportV1ChallengeHeader, challenge)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("proof response = status %d body %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q", response.Header().Get("Cache-Control"))
	}
	if got, want := response.Header().Get(desktopTransportV1ProofHeader), transport.handoffProof(origin, challenge); !hmac.Equal([]byte(got), []byte(want)) {
		t.Fatalf("proof = %q, want %q", got, want)
	}

	for _, tc := range []struct {
		name          string
		remote        string
		challenge     string
		authorization string
		duplicate     bool
	}{
		{name: "non-loopback", remote: "192.0.2.10:12345", challenge: challenge},
		{name: "bearer", remote: "127.0.0.1:12345", challenge: challenge, authorization: "Bearer must-not-be-sent"},
		{name: "malformed challenge", remote: "127.0.0.1:12345", challenge: "not-hex"},
		{name: "duplicate challenge", remote: "127.0.0.1:12345", challenge: challenge, duplicate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, desktopTransportV1ProofPath, nil)
			req.RemoteAddr = tc.remote
			req.Header.Set(desktopTransportV1ChallengeHeader, tc.challenge)
			if tc.duplicate {
				req.Header.Add(desktopTransportV1ChallengeHeader, strings.Repeat("d", desktopTransportV1SecretLength))
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound || rec.Header().Get(desktopTransportV1ProofHeader) != "" || rec.Body.Len() != 0 {
				t.Fatalf("unsafe proof response: status=%d headers=%#v body=%q", rec.Code, rec.Header(), rec.Body.String())
			}
		})
	}

	method := httptest.NewRecorder()
	mux.ServeHTTP(method, httptest.NewRequest(http.MethodPost, desktopTransportV1ProofPath, nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("non-GET proof response = status %d allow %q", method.Code, method.Header().Get("Allow"))
	}
}

func TestDesktopTransportV1SuppressesAuxiliaryHealthAndMetrics(t *testing.T) {
	transport := testDesktopTransportV1()
	if suppress, err := desktopTransportV1SuppressesAuxiliaryHealth(transport, 0, false); err != nil || !suppress {
		t.Fatalf("desktop transport must suppress port-zero auxiliary health, suppress=%t err=%v", suppress, err)
	}
	if suppress, err := desktopTransportV1SuppressesAuxiliaryHealth(transport, 0, true); err == nil || suppress {
		t.Fatalf("desktop transport must reject metrics with port-zero health, suppress=%t err=%v", suppress, err)
	}
	if suppress, err := desktopTransportV1SuppressesAuxiliaryHealth(nil, 0, true); err != nil || suppress {
		t.Fatalf("normal mode health behavior changed, suppress=%t err=%v", suppress, err)
	}

	t.Setenv(desktopTransportV1EnabledEnv, "1")
	t.Setenv(desktopTransportV1KeyEnv, transport.key)
	t.Setenv(desktopTransportV1NonceEnv, transport.nonce)
	t.Setenv("HELM_HEALTH_PORT", "0")
	t.Setenv("HELM_METRICS_ENABLED", "1")
	var stdout, stderr bytes.Buffer
	err := runServerWithOptions(serverOptions{DesktopTransportV1: true, Stdout: &stdout, Stderr: &stderr})
	if err == nil || !strings.Contains(err.Error(), "HELM_METRICS_ENABLED") {
		t.Fatalf("metrics leakage configuration error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("metrics leakage configuration emitted a readiness record: %q", stdout.String())
	}
}
