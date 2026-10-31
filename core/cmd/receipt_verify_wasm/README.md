# Receipt verifier for JavaScript and WebAssembly

<!-- quantum_posture: This bridge exposes the existing classical Ed25519 verifier; it adds no cryptography or trust roots. -->

Build the classical Ed25519 receipt verifier and its matching Go runtime:

```sh
make receipt-verify-wasm
make verify-receipt-verifier-wasm
```

The build uses the exact Go version in `core/go.mod` and writes
`bin/receipt-verifier-wasm/`. `build.json` records the source revision, whether
the checkout was dirty, the compiler version and every shipped file's SHA-256.
It is build metadata, not a signature or release attestation. A local dirty
build is not an exact published source checkpoint.

Load the matching runtime and pinned WASM bytes in a browser or Worker:

```js
import { loadReceiptVerifier } from "./receipt-verifier.mjs";
await import("./wasm_exec.js");
const bytes = await (await fetch("./receipt_verify.wasm")).arrayBuffer();
const verifier = await loadReceiptVerifier(bytes, globalThis.Go);
const report = verifier.verifyJSON(receiptJSON, trustRootJSON);
```

The host needs `TextEncoder.encodeInto` for bounded UTF-8 conversion before data
is copied into WASM memory. Asset loading is a host action. Verification does not fetch keys, read browser
storage, inspect the environment or consult a clock. One verifier instance is
installed per realm; concurrent or repeated initialization is refused. A failed
instantiation can be retried. If a runtime starts without the required exports,
discard the realm. Use a separate Worker for another instance.

`receiptJSON` is JSON text containing one receipt, an array in causal order,
or a bundle with `receipts` and optional `permits`, `key_id` and
`public_key_hex`. The shared `receiptverify.ParseBundle` parser retains raw
receipt objects until signed-member validation finishes. Do not parse and
re-serialize untrusted JSON before handing it to the verifier: that can erase
duplicate members or invalid number spellings.

Supply `trustRootJSON` independently of the artifact, as
`{"keys":{"key-id":"32-byte-Ed25519-public-key-as-hex"}}`. No production key
is bundled. Omitting the argument, supplying `{}`, or relying only on the
artifact's key returns `UNVERIFIABLE`. An explicitly supplied wrong key fails;
the verifier never falls back to an embedded key. There is no browser
self-attestation option and no ambient trust configuration.

The result has schema `helm.receipt-verification.v1`, a `verdict` and the full
`verification` result with the original checks, errors and coverage details:

- `VERIFIED`: the existing verifier accepted the signatures and applicable
  consistency checks under caller-supplied trust.
- `FAILED`: input validation or a verifier check failed.
- `UNVERIFIABLE`: the existing verifier refused because no trusted key was
  supplied. No successful identity check is invented.

Inputs are limited to 8 MiB of receipt JSON, 64 KiB of trust-root JSON and 128
trusted keys. Iterative preflight also limits input to 64 nested containers,
100000 JSON tokens, 256 bytes per object member name and 64 KiB per decoded
string or number token before recursive parsing. The native
`receiptverify.VerifyJSON` API has the same contract.
The existing native CLI retains its flags and explicit inspection behavior.

The shared corpus reuses frozen public receipt/permit fixtures without private
keys. It tests native/WASM result parity, artifact-only trust refusal, wrong
roots, signed-field and permit tampering, strict wire parsing and argument/size
refusals. It also covers initialization races and parsing-work refusals followed
by successful reuse. The JavaScript harness runs the actual WASM module in Node
with WASM linear memory capped at 128 MiB and records its exact binary hash and named
results in `conformance.json`.

The shipped `js/wasm` entrypoint is declared in `scripts/ci/deadcode-wasm-roots.txt`.
The reachability gate measures both targets and combines findings only where
they compile the same source declaration. Its frozen allowlist remains unchanged.
The native control registry continues to read its separate native roots list.

After a successful main `CI` run, `Receipt verifier WASM` rebuilds and tests the
exact source revision and uploads the bundle as a commit-bound Actions artifact.
Consumers must retain that run/artifact identity and verify the file hashes.
This publication is a CI artifact, not a stable release or deployment.

These checks do not verify an entire EvidencePack or DSSE-v6 export, establish
who a key belongs to, re-execute an effect, or evaluate permit expiry. They do
not establish Console integration, browser UI acceptance or a living
organization runtime. Those remain separate B7 and product acceptance work.
