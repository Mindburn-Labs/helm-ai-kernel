package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
)

// This route is intentionally absent outside a Desktop-launched Kernel. The
// native shell uses the per-launch token to prove that the process listening on
// its loopback port is the Kernel it started before it gives the Console an
// admin credential for that endpoint.
const (
	desktopReadyTokenEnv     = "HELM_DESKTOP_KERNEL_READY_TOKEN"
	desktopReadyPath         = "/_helm/desktop-ready"
	desktopReadyNonceHeader  = "X-HELM-Desktop-Nonce"
	desktopReadyProofHeader  = "X-HELM-Desktop-Proof"
	desktopReadyMaxNonceSize = 256
)

func registerDesktopReadyRoute(mux *http.ServeMux) {
	token := strings.TrimSpace(os.Getenv(desktopReadyTokenEnv))
	if token == "" {
		return
	}

	mux.HandleFunc(desktopReadyPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		nonce := strings.TrimSpace(r.Header.Get(desktopReadyNonceHeader))
		if !validDesktopReadyNonce(nonce) {
			// Do not expose a signing oracle to malformed callers. The token is
			// still held only by the launched Kernel process.
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(desktopReadyProofHeader, desktopReadyProof(token, nonce))
		w.WriteHeader(http.StatusNoContent)
	})
}

func validDesktopReadyNonce(nonce string) bool {
	if nonce == "" || len(nonce) > desktopReadyMaxNonceSize {
		return false
	}
	for _, ch := range nonce {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func desktopReadyProof(token, nonce string) string {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}
