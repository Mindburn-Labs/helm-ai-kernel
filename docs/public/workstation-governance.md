# Govern Local Coding Agents Without Competing With Them

Codex, Claude Code, Cursor, Devin, Replit Agent, and similar tools compete on developer productivity. HELM governs the evidence and selected side effects around those workflows.

HELM answers:

- What did the agent try?
- What was allowed?
- What was denied?
- What files changed?
- Which validations ran?
- What memory would become durable?
- Which recurring loops were registered?
- What proof survives after the run?

## What ships here

- Manifest-first local adapter for Codex or Claude Code-style artifact directories.
- Signed Agent Run Receipt.
- Deterministic ProofGraph mapping.
- Selected-effect policy decision receipts for shell, network, MCP, file, memory, and recurring-loop classes.
- CLI/hook enforcement bridge for denied selected effects.
- Operator views for run list, denied timeline, memory review queue, and recurring loop registry.
- Conformance pack and sample EvidencePack.

## What remains outside scope

HELM does not claim full control over proprietary hosted agents, private browser sessions, IDE internals, or arbitrary desktop processes unless those effects pass through a HELM adapter or wrapper. The first release is a governance and selected-effect enforcement surface, not a complete operating-system sandbox.

## Walkthrough

1. Run a local coding agent with a wrapper that produces `run.manifest.json`, `git.diff-summary.json`, `validation.json`, and optional `tool-events.ndjson`.
2. Import artifacts with `helm-ai-kernel workstation import`.
3. Review the signed Agent Run Receipt with `helm-ai-kernel workstation view`.
4. Use `helm-ai-kernel workstation enforce` around selected network, MCP, memory, loop, shell, or file effects.
5. Export a sample EvidencePack with `helm-ai-kernel workstation evidence`.
6. Certify adapter behavior with `helm-ai-kernel workstation certify`.

This lets a buyer evaluate workstation governance without understanding kernel internals.
