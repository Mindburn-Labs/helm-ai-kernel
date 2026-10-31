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

func main() {
	verifyFunc = js.FuncOf(func(_ js.Value, args []js.Value) any {
		var result receiptverify.DocumentResult
		if len(args) < 1 || len(args) > 2 || args[0].Type() != js.TypeString ||
			(len(args) == 2 && args[1].Type() != js.TypeString) {
			result = receiptverify.DocumentResult{
				SchemaVersion: receiptverify.DocumentSchemaVersion,
				Verdict:       receiptverify.VerdictFailed,
				Verification: receiptverify.Result{Errors: []string{
					"verifyJSON requires artifact JSON text and optional separate trust-root JSON text",
				}},
			}
		} else {
			var trust string
			if len(args) == 2 {
				trust = args[1].String()
			}
			result = receiptverify.VerifyJSON([]byte(args[0].String()), []byte(trust))
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
