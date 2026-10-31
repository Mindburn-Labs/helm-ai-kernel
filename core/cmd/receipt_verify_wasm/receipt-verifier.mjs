// The caller loads the matching wasm_exec.js and supplies its Go class plus
// the pinned WASM bytes. Loading assets and choosing trust remain host actions.
// Verification itself performs no fetch and never discovers a trust root.
export async function loadReceiptVerifier(wasmBytes, Go) {
  if (typeof Go !== "function") throw new TypeError("the matching Go runtime is required");
  if (globalThis.HELMReceiptVerifier !== undefined) {
    throw new Error("a receipt verifier is already installed in this realm; use a separate Worker");
  }
  const go = new Go();
  const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
  const terminated = go.run(instance);
  const api = globalThis.HELMReceiptVerifier;
  if (api?.schemaVersion !== "helm.receipt-verification.v1" || typeof api.verifyJSON !== "function") {
    await terminated;
    throw new Error("the WASM module did not expose the receipt verifier contract");
  }
  return Object.freeze({
    schemaVersion: api.schemaVersion,
    verifyJSON: (...args) => JSON.parse(api.verifyJSON(...args)),
    terminated,
  });
}
