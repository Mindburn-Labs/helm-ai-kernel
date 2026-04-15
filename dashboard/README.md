# HELM EvidencePack Viewer (OSS-lite dashboard)

A static, zero-backend, zero-telemetry viewer for HELM EvidencePack `.tar` archives.

**Roadmap reference**: P3-09 (OSS-lite dashboard) — companion to the commercial helm/ Studio forensic timeline.

## What it does

- Parses a dropped EvidencePack TAR in the browser (pure JS, no WASM bundle).
- Verifies every blob's SHA-256 against the pack's `manifest.json` using the Web Crypto API.
- Renders decisions as a table (seq / actor / tool / verdict / reason).
- Renders ProofGraph nodes as an indented causal tree, ordered by Lamport sequence.
- Does **not** verify the Ed25519 manifest signature — that's what the `helm verify` CLI is for. This viewer is a *diagnostic* tool, not the authoritative verifier.

## What it does NOT do

- No file upload to any server. Nothing leaves your browser.
- No trust-root or Ed25519 verification (would require key distribution + trust management; out of scope for OSS-lite).
- No attempt to re-execute the session or compare replays. Use `helm replay` for that.

## Running locally

Open `index.html` directly in a modern browser. No build step. No dependencies.

```bash
cd dashboard
python3 -m http.server 8000
# open http://localhost:8000/
```

Or host from GitHub Pages by pointing Pages at this directory.

## Deploying

Recommended URL: `https://try.mindburn.org/` (apex of the `try` subdomain). Deploy via GitHub Pages from this `dashboard/` path — DNS managed by DigitalOcean (`doctl compute domain records`), CNAME `try` → `mindburn-labs.github.io`.

## File layout

| File | Role |
|------|------|
| `index.html` | Single-page shell. Drop zone + section skeleton. |
| `styles.css` | Dark/light theme via `prefers-color-scheme`; minimal utility CSS. |
| `main.js` | Pipeline: file → parseTar → loadManifest → verifyBlobs → render. |
| `tar-reader.js` | Minimal USTAR parser. No PAX extended headers; safe for HELM's TAR output. |
| `evidencepack.js` | Manifest parsing + blob SHA-256 verification via Web Crypto. |
| `proofgraph.js` | Renders the causal DAG as nested `<details>` elements. |

## Compatibility notes

**TAR format**: the parser expects USTAR (POSIX.1-1988). EvidencePacks produced by HELM OSS 0.3.0+ stay within USTAR's 100-char name limit and do not use PAX extended headers. If that changes, the parser will report unsupported entries and skip them without crashing.

**Manifest shape**: we accept three shapes for maximum forward-compat:
1. `{files: [{path, sha256}, ...]}` — primary shape.
2. `{entries: [{path, sha256}, ...]}` — alternate name.
3. `{"<path>": "<hash>", ...}` — bare map (legacy).

**Decisions / ProofGraph**: looked up at these paths (first hit wins):
- `decisions.json` · `decisions.jsonl` · `decisions/decisions.json`
- `proofgraph.json` · `proofgraph.jsonl` · `proofgraph/nodes.json` · `proofgraph/nodes.jsonl`

If the pack uses different paths, add them to the candidate list in `evidencepack.js`.

## Browser requirements

- Modern browser with Web Crypto API (`crypto.subtle.digest`) — all evergreen browsers.
- ES modules (`<script type="module">`) — same coverage.
- No Service Worker required.

## License

Apache-2.0, same as the parent repo.
