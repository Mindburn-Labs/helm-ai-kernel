// The caller loads the matching wasm_exec.js and supplies its Go class plus
// the pinned WASM bytes. Loading assets and choosing trust remain host actions.
// Verification itself performs no fetch and never discovers a trust root.
//
// verifyJSON(receiptJSON, trustRootJSON) returns the report as an object. Two
// refusals concern how a host reads the receipt it passed in:
//
//   - Member names are matched exactly, as JSON.parse matches them. A document
//     in which a receipt, bundle or permit member is spelled in another letter
//     case is FAILED with an error naming "letter case". Read a member from a
//     document only after the verifier accepted that same text.
//   - In the bundle form ({"receipts":[...]}) only the entries of receipts are
//     checked. A receipt member beside them, such as a top-level "verdict", is
//     FAILED with an error naming the "receipt member": read a receipt's
//     members from the entries of receipts, never from the bundle object.
//   - A receipt with no signature_version is a legacy receipt. Its signature
//     does not cover verdict, tool_name or timestamp, and a receipt.v5
//     signature can be replayed as one. It is not checked: the verdict is
//     UNVERIFIABLE with no checks, and this bridge has no option to check it.
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
