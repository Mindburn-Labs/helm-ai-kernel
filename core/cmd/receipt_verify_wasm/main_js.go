//go:build js && wasm

// quantum_posture: this entrypoint exposes the classical receipt verifier only.
// Command receipt_verify_wasm is an offline JSON bridge, not an EvidencePack
// reader or an organization-runtime verifier. The host supplies trust out of
// band; no key or configuration is discovered from browser state.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

var verifyFunc js.Func
var encoder, documentBuffer, trustBuffer js.Value

// Encode into fixed host buffers before copying into linear memory. Converting
// an arbitrary JS string with Value.String first would allocate it before the
// Go adapter could enforce its byte limit.
func boundedJSON(value, buffer js.Value, limit int) ([]byte, bool) {
	units := js.Global().Get("Object").Invoke(value).Get("length").Float()
	if units > float64(limit) {
		return nil, false
	}
	encoded := encoder.Call("encodeInto", value, buffer)
	written := encoded.Get("written").Int()
	defer buffer.Call("fill", 0, 0, written)
	if written > limit || encoded.Get("read").Float() != units {
		return nil, false
	}
	bytes := make([]byte, written)
	js.CopyBytesToGo(bytes, buffer)
	return bytes, true
}

func failed(message string) receiptverify.DocumentResult {
	return receiptverify.DocumentResult{SchemaVersion: receiptverify.DocumentSchemaVersion,
		Verdict: receiptverify.VerdictFailed, Verification: receiptverify.Result{Errors: []string{message}}}
}

func main() {
	encoder = js.Global().Get("TextEncoder").New()
	documentBuffer = js.Global().Get("Uint8Array").New(receiptverify.MaxDocumentBytes + 1)
	trustBuffer = js.Global().Get("Uint8Array").New(receiptverify.MaxTrustRootBytes + 1)
	verifyFunc = js.FuncOf(func(_ js.Value, args []js.Value) any {
		var result receiptverify.DocumentResult
		if len(args) < 1 || len(args) > 2 || args[0].Type() != js.TypeString ||
			(len(args) == 2 && args[1].Type() != js.TypeString) {
			result = failed("verifyJSON requires artifact JSON text and optional separate trust-root JSON text")
		} else {
			document, ok := boundedJSON(args[0], documentBuffer, receiptverify.MaxDocumentBytes)
			if !ok {
				result = failed("receipt document exceeds the 8 MiB limit")
			} else {
				var trust []byte
				if len(args) == 2 {
					trust, ok = boundedJSON(args[1], trustBuffer, receiptverify.MaxTrustRootBytes)
				}
				if !ok {
					result = failed("trust root exceeds the 64 KiB limit")
				} else {
					result = receiptverify.VerifyJSON(document, trust)
				}
			}
		}
		encoded, _ := json.Marshal(result) // The result contains only JSON-safe fields.
		return string(encoded)
	})
	js.Global().Set("HELMReceiptVerifier", map[string]any{
		"schemaVersion": receiptverify.DocumentSchemaVersion,
		"verifyJSON":    verifyFunc,
	})
	select {}
}
