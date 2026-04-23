# HELM Evidence Viewer

This directory contains a static viewer for HELM evidence bundles.

## Scope

The viewer:

- parses a local bundle in the browser
- renders bundle metadata, decisions, and proof-graph data
- performs client-side hash checks for files listed in the manifest

The viewer does not replace `helm verify`. Use the CLI for authoritative cryptographic verification.

## Run Locally

```bash
cd dashboard
python3 -m http.server 8000
```

Open `http://localhost:8000/` and drop a bundle into the page.

## Optional Static Deployment

GitHub Pages should stay disabled unless this directory is deliberately published as the Pages source and smoke-tested after each change. A valid Pages deployment serves the contents of `dashboard/` directly and must not replace CLI verification in review workflows.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | static entry page |
| `main.js` | UI orchestration |
| `tar-reader.js` | bundle parsing |
| `evidencepack.js` | manifest and hash handling |
| `proofgraph.js` | proof-graph rendering |
| `styles.css` | viewer styling |
