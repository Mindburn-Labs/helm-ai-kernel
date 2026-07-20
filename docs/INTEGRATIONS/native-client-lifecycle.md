---
title: Native Client Lifecycle Review Protocol
last_reviewed: 2026-07-14
visibility: maintainer
---

# Native Client Lifecycle Review Protocol

This maintainer protocol separates local configuration proof from proof that a
real native client loaded and obeyed that configuration. It is the source of
truth for Codex project lifecycle state. It does not expand HELM's execution
boundary beyond configured hook classes and MCP calls.

## What Codex Project Setup Owns

`helm-ai-kernel setup codex --scope project --yes` writes only the HELM-owned
entries that its preflight can prove safe to manage. Project-specific state is
separated by a SHA-256 workspace-path identity:

```text
<data-dir>/native-client/codex-projects/v1/<workspace-path-sha256>/
  codex-project-binding.json
  .helm-setup-recovery/
  autoconfigure/
```

The local signing authority, receipt database, and lifecycle evidence remain
shared beneath `<data-dir>`. A project binding, recovery journal, or generated
artifact is never a fallback for another project that happens to use the same
data directory.

The authority root and every existing HELM-owned descendant must be real,
owner-controlled directories; symlinks, group/world-writable modes, and special
modes are rejected. On POSIX the existing directory owner must be the current
user. The code rechecks that state before it treats a binding, recovery journal,
or evidence file as authority.

## Lifecycle Receipts And Recovery

Codex project install and removal use a durable transaction. The transaction
records exact config snapshots and stages HELM-owned changes before it mutates
the live client configuration. A signed lifecycle receipt and canonical
lifecycle evidence bind the operation, selected Kernel binary, workspace
identity, data-directory identity, and observed local configuration.

The durable receipt database stores the full canonical receipt envelope, not
only an index projection. Recovery reads an existing receipt database
read-only, re-canonicalizes the envelope, and checks that its receipt ID agrees
with the database row. A missing, malformed, non-canonical, or legacy row that
lacks the envelope fails closed for automatic provenance recovery.

If setup is interrupted, do not rerun install or removal until you inspect the
transaction:

```bash
helm-ai-kernel setup status codex --scope project --json
helm-ai-kernel setup recover codex --scope project --dry-run --json
helm-ai-kernel setup recover codex --scope project --yes
```

`recover` either removes incomplete HELM residue, resumes the exact recorded
transaction, or cleans a transaction already committed but not yet tidied. It
does not overwrite a changed client configuration. Removal uses the same
transaction and only deletes exact HELM-owned entries:

```bash
helm-ai-kernel setup remove codex --scope project --dry-run --json
helm-ai-kernel setup remove codex --scope project --yes
```

Older unscoped Codex state needs the explicit migration command; normal runtime
admission never silently adopts it:

```bash
helm-ai-kernel setup migrate codex --scope project --dry-run --json
helm-ai-kernel setup migrate codex --scope project --yes
```

Migration validates the full current legacy source-and-destination snapshot:
the selected binding and artifacts or structured recovery state, current
workspace, and project namespace. Normal runtime admission never adopts
unscoped state. `--dry-run` performs that validation without writing or
reserving the snapshot. With `--yes`, HELM takes the project lifecycle lock and
revalidates before moving validated state into the v1 project namespace. For a
new binding destination, it stages and validates the complete namespaced
binding/artifact set before publication; recovery migration rolls its validated
recovery directory back if later sync or validation fails. A legacy binding
pinned to a different currently-running Kernel binary is refused. If source
retirement cannot finish or fully roll back after v1 publication, the command
reports a sealed retired-source cleanup warning: v1 remains the active project
authority and the retained source copy is not. Inspect `setup status` after
migration, and use `setup recover` when a project recovery journal is present.

## What Local Setup Proves — And Does Not

The setup result intentionally reports `client_load_observed=false`. A matching
local config and the Kernel-only synthetic denial prove that HELM generated and
checked local artifacts; they do **not** prove that Codex opened them, launched
the configured stdio server, or blocked an action in a real session.

Likewise, a configured hook is limited to the exact hook classes in the client
configuration, and a configured MCP server governs only calls routed through
that server. Neither result proves every Codex action, every terminal command,
browser use, desktop action, or a bypassing upstream server. Do not turn a
configuration receipt or synthetic denial into a native-client session claim.

Claude Code is intentionally not treated as equivalent to the Codex project
lifecycle. Its setup resolves a direct `claude` executable, invokes its MCP CLI,
and writes the selected PreToolUse hook configuration. HELM does not read back
the CLI-owned MCP serialization, create a Codex-style project binding, or
establish client-session proof. If `claude` resolves through a mise shim, setup
refuses it. Set `CLAUDE_CODE_BIN` to the direct executable path instead:

```bash
CLAUDE_CODE_BIN=/absolute/path/to/claude helm-ai-kernel setup claude-code --yes
```

## Evidence Ladder

Keep these evidence levels separate:

1. **Source and focused-test proof** — the lifecycle, recovery, receipt, and
   admission tests pass from the reviewed commit.
2. **Local setup proof** — preflight, exact config ownership, signed lifecycle
   receipt, and the Kernel-only synthetic denial pass. `client_load_observed`
   remains false at this level.
3. **Sterile native-client review** — a disposable client home and workspace
   load the generated configuration in a real, user-authorized client session;
   the reviewer observes the configured server, invokes only configured hook
   classes and a routed MCP call, and verifies the resulting signed receipts.
4. **Release proof** — the reviewed binary, source commit, hashes, signatures,
   and test output are attached to a signed release artifact.
5. **Approved environment proof** — an operator repeats the limited real-client
   checks in an approved environment with the resulting evidence retained.

Levels 1 and 2 do not substitute for levels 3 through 5.

## Sterile Native-Client Review

Use this protocol before claiming a real native-client integration:

1. Record the Kernel binary path and content hash, source commit, client
   version, policy inputs, and the disposable workspace path.
2. Create a new client home such as `CODEX_HOME=<empty-directory>`; never copy
   an existing browser session, client credential, or cached config into it.
3. Run project setup with an explicit private data directory, retain the JSON
   summary, and verify the lifecycle receipt/evidence before launching the
   client.
4. Have the authorized operator complete the client login in that sterile home.
   Observe that the configured HELM stdio server is actually loaded.
5. Run one harmless controlled case for each hook class present in the generated
   configuration and one routed MCP call. Capture client-visible results and
   verify the corresponding HELM receipts. A denied case must show no target
   side effect.
6. Tamper with an owned config or lifecycle proof only in the disposable
   fixture, then confirm that admission fails closed. Remove the fixture with
   the normal project-scope removal path.

The review record must name the exact classes and MCP server/tool exercised.
It must state `not exercised` for every other client action; absence of a test
is not coverage.

## Source Truth And Checks

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/setup_codex_project_paths.go`
- `core/cmd/helm-ai-kernel/setup_codex_lifecycle.go`
- `core/cmd/helm-ai-kernel/setup_lifecycle_readonly.go`
- `core/cmd/helm-ai-kernel/setup_recovery_*.go`
- `core/cmd/helm-ai-kernel/setup_claude_code_binary.go`
- `core/cmd/helm-ai-kernel/setup_recovery_security_test.go`
- `core/cmd/helm-ai-kernel/setup_cmd_test.go`

Run the focused lifecycle suite for code changes, then `make docs-coverage
docs-truth` for documentation changes.
