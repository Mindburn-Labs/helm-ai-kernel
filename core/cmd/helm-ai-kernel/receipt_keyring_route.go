package main

// quantum_posture: this route publishes the public half of whichever receipt
// signer the Kernel runs: classical Ed25519, hybrid Ed25519 + ML-DSA-65, or
// ML-DSA-65 alone. It signs nothing and claims no profile the signer lacks.

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptkeyring"
)

// receiptKeyringPath is where the keyring is served. The document is
// receiptkeyring's, the one shape helm-gateway publishes for its own signer
// at the same path: the Control Plane pins it as HELM_KERNEL_RECEIPT_KEYRING.
const receiptKeyringPath = receiptkeyring.Path

// registerReceiptKeyringRoute serves the receipt keyring. The body is built
// once from the running signer; without a publishable signer the route answers
// 503 and never an empty keyring, which the Control Plane reads as "not
// configured".
func registerReceiptKeyringRoute(mux routeMux, svc *Services) {
	var body []byte
	if svc != nil && svc.ReceiptSigner != nil {
		if encoded, err := receiptkeyring.Encode(svc.ReceiptSigner); err == nil {
			body = encoded
		}
	}
	mux.HandleFunc(http.MethodGet+" "+receiptKeyringPath, protectRuntimeHandler(RouteAuthPublic, func(w http.ResponseWriter, _ *http.Request) {
		if body == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Receipt keyring unavailable", "kernel receipt signer is not initialized")
			return
		}
		receiptkeyring.Write(w, body)
	}))
}
