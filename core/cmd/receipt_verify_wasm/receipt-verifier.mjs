// The caller loads the matching wasm_exec.js and supplies its Go class plus
// the pinned WASM bytes. Loading assets and choosing trust remain host actions.
// Verification itself performs no fetch and never discovers a trust root.
const initialization = Symbol.for("helm.receipt-verifier.initialization");

export async function loadReceiptVerifier(wasmBytes, Go) {
  if (typeof Go !== "function") throw new TypeError("the matching Go runtime is required");
  if (typeof globalThis.TextEncoder?.prototype?.encodeInto !== "function") {
    throw new TypeError("TextEncoder.encodeInto is required for bounded input conversion");
  }
  if (globalThis.HELMReceiptVerifier !== undefined || globalThis[initialization] !== undefined) {
    throw new Error("a receipt verifier is installed or initializing in this realm; use a separate Worker");
  }
  const lease = {};
  globalThis[initialization] = lease;
  let started = false;
  let ready = false;
  try {
    const go = new Go();
    const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
    started = true;
    const terminated = go.run(instance);
    void terminated.catch(() => {}); // The original promise remains observable by the caller.
    const api = globalThis.HELMReceiptVerifier;
    if (api?.schemaVersion !== "helm.receipt-verification.v1" || typeof api.verifyJSON !== "function") {
      throw new Error("the WASM runtime did not expose the verifier contract; discard this realm");
    }
    ready = true;
    return Object.freeze({
      schemaVersion: api.schemaVersion,
      verifyJSON: (...args) => JSON.parse(api.verifyJSON(...args)),
      terminated,
    });
  } finally {
    // A failed instantiation can be retried. After an unknown runtime starts,
    // retain the lease: another permanent instance must not be added to it.
    if ((!started || ready) && globalThis[initialization] === lease) delete globalThis[initialization];
  }
}
