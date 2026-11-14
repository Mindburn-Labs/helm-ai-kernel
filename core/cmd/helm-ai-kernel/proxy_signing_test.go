// quantum_posture: these tests pin when the proxy attaches its classical
// Ed25519 receipt signature; they add no cryptographic control and no
// post-quantum claim.

package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// proxySignSeedHex is a 32-byte Ed25519 seed in hex, the form --sign uses
// without deriving one from a passphrase.
const proxySignSeedHex = "4242424242424242424242424242424242424242424242424242424242424242"

// TestProxyReceiptsAreSignedOnlyWithSignSeed pins what the proxy guides state:
// a receipt carries a signature only when the proxy was started with --sign,
// and that signature covers receipt id, output hash, status and Lamport clock.
func TestProxyReceiptsAreSignedOnlyWithSignSeed(t *testing.T) {
	policy := allowPolicyGraph(t, "get_weather")

	t.Run("without --sign", func(t *testing.T) {
		upstream, _ := newFakeUpstream(t, chatToolCallReply("get_weather", `{"city":"Berlin"}`))
		proxySrv, rt := startTestProxy(t, upstream.URL, policy, nil)

		resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
		if resp.status != http.StatusOK || resp.header.Get("X-Helm-Status") != "APPROVED" {
			t.Fatalf("status=%d X-Helm-Status=%q body=%s", resp.status, resp.header.Get("X-Helm-Status"), resp.body)
		}
		if got := resp.header.Get("X-Helm-Signature"); got != "" {
			t.Fatalf("X-Helm-Signature = %q on a proxy started without --sign", got)
		}
		receipts := readProxyReceipts(t, rt)
		if len(receipts) != 1 {
			t.Fatalf("receipts = %+v", receipts)
		}
		if receipts[0].Signature != "" {
			t.Fatalf("receipt is signed without --sign: %q", receipts[0].Signature)
		}
		if receipts[0].PrevHash != "GENESIS" || receipts[0].LamportClock != 1 {
			t.Fatalf("unsigned receipt lost its chain link: prev_hash=%q lamport=%d", receipts[0].PrevHash, receipts[0].LamportClock)
		}
		if rt.signer != nil {
			t.Fatal("proxy runtime holds a receipt signer without --sign")
		}
	})

	t.Run("with --sign", func(t *testing.T) {
		upstream, _ := newFakeUpstream(t, chatToolCallReply("get_weather", `{"city":"Berlin"}`))
		proxySrv, rt := startTestProxy(t, upstream.URL, policy, func(cfg *proxyConfig) {
			cfg.signKey = proxySignSeedHex
		})

		resp := postToProxy(t, proxySrv.URL, toolRequest, nil)
		if resp.status != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.status, resp.body)
		}
		receipts := readProxyReceipts(t, rt)
		if len(receipts) != 1 || receipts[0].Signature == "" {
			t.Fatalf("receipt is not signed with --sign: %+v", receipts)
		}
		rcpt := receipts[0]
		if got := resp.header.Get("X-Helm-Signature"); got != rcpt.Signature {
			t.Fatalf("X-Helm-Signature = %q, receipt signature = %q", got, rcpt.Signature)
		}
		if rt.signer == nil {
			t.Fatal("proxy runtime has no receipt signer with --sign")
		}
		payload := fmt.Sprintf("%s:%s:%s:%d", rcpt.ReceiptID, rcpt.OutputHash, rcpt.Status, rcpt.LamportClock)
		ok, err := helmcrypto.Verify(rt.signer.PublicKey(), rcpt.Signature, []byte(payload))
		if err != nil || !ok {
			t.Fatalf("signature does not verify over id:output_hash:status:lamport_clock: ok=%v err=%v", ok, err)
		}
		tampered := fmt.Sprintf("%s:%s:%s:%d", rcpt.ReceiptID, rcpt.OutputHash, "DENIED", rcpt.LamportClock)
		if ok, _ := helmcrypto.Verify(rt.signer.PublicKey(), rcpt.Signature, []byte(tampered)); ok {
			t.Fatal("signature verifies over a changed status")
		}
	})
}

// TestProxyBannerStatesWhetherReceiptsAreSigned pins the startup banner line
// that tells the operator whether receipts are signed. The proxy runs up to its
// listen call, which fails here because the port is already taken, so the
// banner is complete and the command returns.
func TestProxyBannerStatesWhetherReceiptsAreSigned(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "without --sign",
			want: "  Signing:     none (receipts are hash-chained, not signed; pass --sign <seed>)\n",
		},
		{
			name: "with --sign",
			args: []string{"--sign", proxySignSeedHex},
			want: "  Signing:     Ed25519 (key: helm-proxy)\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HELM_DATA_DIR", t.TempDir())
			t.Setenv("HELM_PRODUCTION", "")
			t.Setenv(proxyBindAddrEnv, "")
			t.Setenv(proxyTokenEnv, "")

			taken, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("reserve port: %v", err)
			}
			defer taken.Close()
			port := taken.Addr().(*net.TCPAddr).Port

			args := append([]string{"--port", strconv.Itoa(port), "--receipts-dir", t.TempDir()}, tc.args...)
			var stdout, stderr bytes.Buffer
			if code := runProxyCmd(args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2 from the taken port; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("banner does not state the signing mode %q:\n%s", tc.want, stdout.String())
			}
			if got := strings.Count(stdout.String(), "Signing:"); got != 1 {
				t.Fatalf("banner has %d Signing lines, want 1:\n%s", got, stdout.String())
			}
		})
	}
}
