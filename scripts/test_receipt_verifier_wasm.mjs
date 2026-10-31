// quantum_posture: frozen classical receipt/permit fixtures; no signing keys.
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [bundle, corpusPath, nativePath] = process.argv.slice(2);
assert(bundle && corpusPath && nativePath, "bundle, corpus and native results are required");
const readJSON = async (p) => JSON.parse(await readFile(p, "utf8"));
const manifest = await readJSON(path.join(bundle, "build.json"));
assert.equal(manifest.target, "js/wasm");
assert.equal(manifest.verification_schema, "helm.receipt-verification.v1");
for (const [file, expected] of Object.entries(manifest.sha256)) {
  assert.equal(createHash("sha256").update(await readFile(path.join(bundle, file))).digest("hex"), expected);
}
const corpus = await readJSON(corpusPath);
const native = await readJSON(nativePath);
assert(corpus.cases.length >= 30, "the security corpus must not be empty or shortened");
assert.equal(new Set(corpus.cases.map((c) => c.name)).size, corpus.cases.length, "duplicate fixture names");
for (const [file, expected] of Object.entries(corpus.source_sha256)) {
  assert.equal(createHash("sha256").update(await readFile(path.join(path.dirname(corpusPath), file))).digest("hex"), expected);
}
assert.deepEqual(JSON.parse(corpus.documents.chain), await readJSON(path.join(path.dirname(corpusPath), "frozen-chain-2026.json")), "frozen receipt lineage");
if (!globalThis.crypto) globalThis.crypto = webcrypto;
await import(pathToFileURL(path.join(bundle, "wasm_exec.js")).href);
const { loadReceiptVerifier } = await import(pathToFileURL(path.join(bundle, "receipt-verifier.mjs")).href);
class AmbientTrustGo extends globalThis.Go {
  constructor() {
    super();
    this.env = {
      HELM_ALLOW_SELF_ATTESTED_EVIDENCE: "1",
      HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX: "00".repeat(32),
      HELM_EVIDENCE_TRUST_CONFIG: "/not-a-trust-root",
    };
  }
}
const verifier = await loadReceiptVerifier(await readFile(path.join(bundle, "receipt_verify.wasm")), AmbientTrustGo);
// Assets are already loaded. Any attempt to fetch a key during verification fails.
globalThis.fetch = () => { throw new Error("verification attempted network access"); };
let passed = 0;
const results = [];
for (const c of corpus.cases) {
  const document = corpus.documents[c.document];
  const trust = corpus.trust_roots[c.trust_root];
  assert.equal(typeof document, "string", `missing artifact for ${c.name}`);
  assert.equal(typeof trust, "string", `missing explicit trust input for ${c.name}`);
  const got = verifier.verifyJSON(document, trust);
  assert.equal(got.verdict, c.expected, c.name);
  assert.equal(got.verification.valid, c.expected === "VERIFIED", c.name);
  assert.deepEqual(got, native[c.name], `native/WASM drift: ${c.name}`);
  results.push({ case: c.name, verdict: got.verdict, result: "PASS" });
  passed++;
}
for (const [index, args] of [[], [{}], ["{}", {}], ["{}", "{}", "unexpected"]].entries()) {
  assert.equal(verifier.verifyJSON(...args).verdict, "FAILED", "invalid JS argument shape");
  results.push({ case: `invalid-js-arguments-${index + 1}`, verdict: "FAILED", result: "PASS" });
  passed++;
}
assert.equal(verifier.verifyJSON(corpus.documents.chain).verdict, "UNVERIFIABLE");
const largeDocument = corpus.documents.chain + " ".repeat(8 * 1024 * 1024 + 1);
const largeTrust = corpus.trust_roots.receipt + " ".repeat(64 * 1024 + 1);
assert.equal(verifier.verifyJSON(largeDocument, corpus.trust_roots.receipt).verdict, "FAILED");
assert.equal(verifier.verifyJSON(corpus.documents.chain, largeTrust).verdict, "FAILED");
results.push({ case: "default-trust-refusal", verdict: "UNVERIFIABLE", result: "PASS" },
  { case: "document-size-limit", verdict: "FAILED", result: "PASS" },
  { case: "trust-size-limit", verdict: "FAILED", result: "PASS" });
passed += 3;
const report = { schema_version: "helm.receipt-verifier-wasm-conformance.v1",
  result: "PASS", cases: passed, native_wasm_parity_cases: corpus.cases.length,
  source_revision: manifest.source_revision, source_dirty: manifest.source_dirty,
  node_version: process.version, named_corpus_results: results,
  wasm_sha256: manifest.sha256["receipt_verify.wasm"],
  scope: "native and Node JavaScript/WebAssembly conformance; no Console/browser UI/runtime acceptance" };
await writeFile(path.join(bundle, "conformance.json"), JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report));
process.exit(0); // The task-owned Go instance intentionally keeps its callback live.
