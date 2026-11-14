---
title: HELM AI Kernel Changelog
last_reviewed: 2026-09-28
---

# Changelog

## Audience

This changelog is for developers, operators, security reviewers, and evaluators tracking public HELM AI Kernel interface changes across releases.

## Outcome

After this page you should know what this surface is for, which source files own the behavior, which public route or adjacent page to use next, and which validation command to run before changing the claim.

## Source Truth

- Public route: `helm-ai-kernel/changelog`
- Source document: `helm-ai-kernel/CHANGELOG.md`
- Public manifest: `helm-ai-kernel/docs/public-docs.manifest.json`
- Source inventory: `helm-ai-kernel/docs/source-inventory.manifest.json`
- Validation: `make docs-coverage`, `make docs-truth`, and `npm run coverage:inventory` from `docs-platform`

Do not expand this page with unsupported product, SDK, deployment, compliance, or integration claims unless the inventory manifest points to code, schemas, tests, examples, or an owner doc that proves the claim.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| A link or route is missing from the docs website | Check `docs/public-docs.manifest.json`, `llms.txt`, search, and the per-page Markdown export before changing navigation. |
| A claim is not backed by code or tests | Remove the claim or add the missing code, example, schema, or validation command before publishing. |

## Diagram

This scheme maps the main sections of HELM AI Kernel Changelog in reading order.

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        Page["HELM AI Kernel Changelog"]
        A["[Unreleased]"]
        R5["[0.8.5] - 2026-08-23"]
        R4["[0.8.4] - 2026-08-12"]
        A00["[0.7.2] - 2026-07-13"]
        A0["[0.7.1] - 2026-07-07"]
        A1["[0.7.0] - 2026-07-05"]
        A2["[0.6.0] - 2026-07-02"]
        B["[0.5.20] - 2026-07-01"]
        B0["[0.5.19] - 2026-07-01"]
        B1["[0.5.16] - 2026-06-18"]
        B2["[0.5.10] - 2026-06-04"]
        C["[0.5.9] - 2026-06-03"]
        D["[0.5.4] - 2026-05-20"]
        E["[0.5.3] - 2026-05-19"]
        F["[0.5.2] - 2026-05-19"]
        G["[0.5.1] - 2026-05-18"]
        H["[0.5.0] - 2026-05-13"]
        I["[0.4.0] - 2026-04-25"]
        J["Validation"]
    end

    %% Operational Flow Edges
    Page --> A
    A --> R5
    R5 --> R4
    R4 --> A00
    A00 --> A0
    A0 --> A1
    A1 --> A2
    A2 --> B
    B --> B0
    B0 --> B1
    B1 --> B2
    B2 --> C
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H
    H --> I
    I --> J

    %% Premium Styling Rules
```


All notable changes to the retained HELM AI Kernel surface are documented here. Public entries focus on developer-visible interfaces, compatibility, verification, SDKs, and security-relevant documentation.

## [Unreleased]

### Upgrade notes

- Run `helm-ai-kernel setup <client> --yes` again after upgrading. The hook
  matcher for Claude Code, Hermes and the DeepSeek harness now also routes the
  read and fetch tools (`Read`, `Grep`, `Glob`, `WebFetch` and their
  equivalents), Claude Code's `ReadMcpResourceTool` and
  `ListMcpResourcesTool`, and Hermes `execute_code`, `browser_navigate` and
  `vision_analyze`; an existing install keeps its narrower matcher until then.
  `setup status` now reports such a matcher: `hook_matcher` (the first
  entry's), `hook_matchers` (every entry that holds the HELM hook),
  `hook_matcher_expected`, `hook_matcher_outdated`,
  `hook_matcher_missing_tools` (the tools no such entry routes) and
  `hook_matcher_upgrade_command` (the `setup` command, with the install's
  `--scope`, `--workspace`, `--data-dir` and `--policy-profile`, that
  upgrades it) in `--json`, client state `degraded` and a non-zero exit. A
  Claude Code matcher is read as Claude Code reads it: one made only of
  letters, digits, `_` and `|` is a list of exact tool names, so `Edit` does
  not route `MultiEdit`. Two entries that hold the same HELM hook command no
  longer make `setup status` fail as ambiguous. When the HELM hook shares a
  hook entry with another hook, `setup` leaves that entry's matcher alone and
  prints a warning naming the file and the matcher (`warnings` in `--json`).
  `setup status` gives that warning, not an upgrade command, when every entry
  that holds the HELM hook is shared, since setup would not change it; it
  then has no `hook_matcher_upgrade_command`.
- Under the built-in profile, which has no egress allowlist, once setup has
  been run again: a routed `WebFetch` and Hermes `browser_navigate` are
  denied like `curl` already was, Hermes `vision_analyze` given a URL is
  denied as network egress, `execute_code` is denied like any shell
  operation, and Claude Code `ReadMcpResourceTool` and `ListMcpResourcesTool`
  are denied as MCP calls (`mcp.mutate`), except for the HELM server setup
  installs.
- A tool the hook has no class for is no longer passed: it is decided as a
  tool call and needs the `mcp.mutate` permission. The installed matchers do
  not route such tools; a matcher you widened yourself now does get denials
  for them under the built-in profile.
- Hook network receipts bind the destination, not the URL: `request.target` is
  the SHA-256 of `scheme://host[:port]`, one receipt per destination, and
  `target_binding` is `sha256:utf-8:network-destination`. Receipts written by
  earlier releases carry `sha256:utf-8` over the whole URL and still verify;
  other hook receipts keep `sha256:utf-8`.
- Every hook receipt carries, in its signed bytes, `call_id`,
  `call_receipts`, `call_verdict`, `tool_input_binding: jcs-sha256` and
  `tool_input_sha256`. The hook decides every effect of a call before writing
  any receipt; a denied call leaves only its denials on disk, where an
  earlier release could leave an `ALLOW` receipt for an effect decided before
  the denial. When a later receipt of a call cannot be written, the call is
  denied and the `ALLOW` receipts already written for it are removed; a
  denial already written stays.
- An MCP resource receipt carries `mcp_server`, the server the call names.
- A hook call that names more than 64 destinations is one
  `EGRESS_DESTINATION_UNDETERMINED` decision, and one that names more than 64
  credential paths is one secret read with `secret.target_count`. A hook
  payload over 4 MiB is not classified: it is denied with the new reason code
  `TOOL_INPUT_TOO_LARGE` and a receipt of effect type
  `WORKSTATION_MCP_TOOL_CALL` (a call into a tool the hook cannot see into),
  action `oversized_tool_call`, `tool_input_limit_bytes`, and in place of the
  input digest `tool_input_binding: payload-prefix-sha256`,
  `tool_input_sha256` (the SHA-256 of the bytes the hook read) and
  `tool_input_bytes_read`. Its `tool_id` and `tool` name the tool when the
  payload names it before the limit, and are `unknown` and empty otherwise.
- The hook decides on the first JSON value on standard input and no longer
  reads to the end of it: a client that leaves standard input open after the
  payload gets its answer at once, and anything after the first value is
  ignored. A payload over 4 MiB whose JSON is malformed well before the
  limit is now a decode error (exit 2), as a shorter malformed payload always
  was, rather than a `TOOL_INPUT_TOO_LARGE` denial.
- A shell tool call whose `command` is missing or is not a string is decided
  as a shell operation (`shell.operate`) instead of passed.
- The shell path guard preserves directory spelling when resolving symlinks
  before matching globs. On case-sensitive filesystems, a mixed-case alias
  to protected signing material is now refused; aliases to unrelated
  directories still pass this guard.
- Setup's preview exception uses the effective `--dry-run` value, including
  repeated flags, and refuses ambiguous argument lists. SSH destination
  parsing keeps the first `HostName`; conflicting port options or a URL
  combined with host/port overrides are undetermined under an allowlist.
- Curl calls combining multiple protocols with `--connect-to` or `--resolve`
  are undetermined under an allowlist. Split those transfers into separate
  commands. A `--connect-to` destination that omits its host or port inherits
  the corresponding explicit source field; inheritance from a wildcard
  source is undetermined. This prevents receipts from naming the wrong
  protocol or port.
- A caller-supplied workstation trust key remains authoritative without a
  descriptive source label. Reports identify the unlabeled key by its key
  ID and keep other signers' receipts out of trusted audit totals.
- Under the built-in profile, `ls ~/.helm-ai-kernel` and any other command
  that names the data directory itself is denied with
  `TRUST_MATERIAL_ACCESS_DENIED`, and `Read` or `Grep` of a credential path
  (`.env`, `~/.ssh/id_ed25519`, `~/.aws/credentials`) is a denied secret read
  where it was passed. A search glob is decided too: one aimed at the hook's
  key files (`**/*.seed`, `file_glob: workstation-ed25519.*`) is denied with
  `TRUST_MATERIAL_ACCESS_DENIED` under every profile, and one that selects
  credential files (`glob: .env`, `**/*.pem`) is a secret read. Upgrade note:
  a glob selects a credential file inside a directory (`.docker/config.json`,
  `.ssh/config`, `.kube/config`, `.aws/credentials`, `.config/gcloud/`) when
  it names that directory or its `**` can stand for it, so `Grep` or `Glob`
  with `**/*.json`, `**/config`, `*/credentials` or `.docker/*.json` is a
  denied secret read under the built-in profile; `*.json`, `*.db`, `*config`
  and `credentials` are not. A glob whose last segment matches ordinary file
  names (`*`, `*.*`) selects files in general and is a secret read only when
  its text names a credential path, so `.ssh/*` is one and `.docker/*`,
  `.kube/*` and `.aws/*` are not, although ripgrep selects the credential
  file in that directory with each of them. A public key
  and an example env file (`.env.example`, `.env.sample`, `.env.template`)
  are not credentials: reading one passes, through `Read` and through a shell
  alike. A search glob for every public key (`Grep` `glob: *.pub`, `Glob`
  `**/*.pub`) is denied with `TRUST_MATERIAL_ACCESS_DENIED` under every
  profile wherever it runs, because it names the hook's trusted public key
  `workstation-ed25519.pub`; search for a key by its name (`id_ed25519.pub`).
- Search and shell globs are read in a small grammar, not by imitating each
  tool's dialect: `/`-separated segments of letters, digits, `.`, `_`, `-`,
  `+`, `@`, `=`, `%`, `:`, `*` and `?`, a whole-segment `**`, and in a search
  glob brace groups of two or more alternatives, nested at most 4 deep.
  Inside the grammar a glob is matched against what the key directory holds
  as a search tool may anchor it. A search reaches the hook's key files only
  when it starts at the data directory, inside it or above it (`/` is above
  everything, a missing `path` means the working directory, and a start that
  cannot be resolved, or a `path` that does not exist, is taken as `/`, since
  Hermes searches every comma- or white-space-separated part of such a
  `path`), and then only through a glob that can name what the key
  directory holds; `src/**/*.go` and `docs/*.md` from the home directory pass.
  An absolute `Glob` pattern starts at the directory its literal leading
  segments name, and at `/` when its first segment has a wildcard, a brace
  group or a bracket (`/*/*/.h*/k*/*` is denied whatever `path`
  the call gives). Claude Code `Grep`'s `glob` is split on white space, and on
  commas when a part has no brace group, as Claude Code splits it, so
  `*.ts,*.tsx` is two globs in the grammar and is not refused in a large
  repository, and `*.go *.seed` is denied.
  A glob outside the grammar is not read: a bracket class, a backslash, a
  leading `/`, `!`, white space, a character outside ASCII, a brace group that
  is unbalanced, has one alternative or nests deeper than 4, a `.` or `..`
  segment, or `**` inside a segment. Upgrade note: such a glob is now denied
  with `TRUST_MATERIAL_ACCESS_DENIED` under every profile, and a reason that
  names the construct, when the search starts at, inside or above the data
  directory (`Grep` from the home directory with `glob: *.[ch]` or
  `glob: !**/node_modules/**`), or when a walk of the search root (65,536
  entries, four roots per call) finds a file named like a key file or cannot
  finish; under the built-in profile it is a secret read when that walk finds
  a credential file (`glob: .en[v]` in a project holding `.env`). Rewrite such
  a glob in the grammar (`*.c` and `*.h` for `*.[ch]`) or start the search
  below the home directory. A shell word with a bracket class
  (`cat ~/.helm-ai-kernel/k[]e]ys/*`) or a segment longer than 1024 bytes is
  denied when the directory it starts in is at, inside or above the data
  directory. A shell word with a brace group is matched on its text before
  the first group: it is denied with `TRUST_MATERIAL_ACCESS_DENIED` under
  every profile when that text is at the data directory, at or inside the key
  directory, or has begun to spell the name of one of them
  (`cat ~/.helm-ai-kernel/{keys,x}/*`, `cat ~/.helm-{ai-kernel,x}/keys/*`).
  The groups are not expanded, so a group that spells the data directory's
  name from above it (`cat ~/{.helm-ai-kernel,zz}/keys/*`) or climbs to it
  with `..` (`cat ~/proj/{..,x}/.helm-ai-kernel/k*/*`) is not a
  trust-material denial: the built-in profile denies it as an opaque shell
  operation (`OPERATE_PERMISSIONS_EMPTY`) and a profile that grants
  `shell.operate` runs it. CTL-035 states this as a bypass assumption; the
  structural fix is to keep the signing seed out of the agent's reach
  (helm-tracker#333). In a repository of more than 65,536 entries a filter
  outside the grammar (`!node_modules/**`, `*.[jt]s`) is denied because the
  walk cannot finish. So a search from `/`, an
  escaped spelling of a key file name (`*.see\d`, `*.see[d\]`) and a filter
  that starts with `/`, which ripgrep anchors at its working directory, are
  denied.
- Upgrade note: the globs of one call share one expansion budget, 256
  alternatives and 64 KiB of expansion together, a glob outside the grammar
  counting as one alternative of its own length. A call past it is denied with
  `TRUST_MATERIAL_ACCESS_DENIED` under every profile, with a reason that says
  its globs are too large to expand; a call of many globs, each under what one
  glob was allowed, used to be expanded glob by glob, and close to 4 MiB of
  them held the hook past the client's timeout. The hook also stops
  classifying a call after 10 seconds, denies it the same way and stops the
  classification. A call whose classifier panics is denied the same way, with
  a signed receipt, instead of ending the hook without a decision.
- Hermes `search_files` `pattern` is read as a glob only when `target` is
  `files`; for a content search it is a regular expression and is not
  decided as a glob, so a regular expression with many `{m,n}` quantifiers is
  no longer refused as a glob too large to expand.
- Upgrade note: an MCP tool's `pattern` is decided as a path pattern when it
  is in the glob grammar, so `mcp__fs__search` with `pattern: **/*.seed` is
  denied with `TRUST_MATERIAL_ACCESS_DENIED` under every profile wherever it
  runs. Outside the grammar it is taken as a regular expression: it is denied
  with `TRUST_MATERIAL_ACCESS_DENIED` under every profile when the search
  starts at, inside or above the data directory (`pattern: foo|bar` with
  `path` set to the home directory), and is otherwise not decided as a glob.
- Through a shell, a credential path is read with a backslash taken as
  quoting the next character, so `rg -g '.en\v'` and
  `grep --include='.en\v'` are secret reads. A shell word whose wildcard or
  bracket would expand to a credential file (`cat .en?`, `cat .e*`,
  `cat .en[v]`) is still decided on its text, not on what it expands to, and
  is not a secret read under the built-in profile.
- `BASH_ENV` and `ENV` set on a command line, like a connection variable, make
  its network destinations undetermined.
- Under a profile with an egress allowlist, a command whose destinations
  cannot all be read from its arguments is denied with
  `EGRESS_DESTINATION_UNDETERMINED`. This includes `curl --location`, `wget`
  without `--max-redirect=0` and `git` over HTTP without
  `-c http.followRedirects=false`, because the client follows redirects to
  hosts the hook cannot see.
- Under an allowlist profile, an option the hook's table for a client does
  not know is denied with `EGRESS_DESTINATION_UNDETERMINED` instead of being
  skipped: an `ssh -o` key outside the common ones, an `openssl s_client`
  option that loads code or fetches from an address, a `git` global option
  the table does not list. `scp` and `sftp` options written after an operand
  are denied the same way.
- `git clone`, `fetch`, `pull`, `push` and `ls-remote` with an address on the
  command line, `git remote add` and `set-url`, and `git submodule update` are
  now network egress. `git` with a remote named in git configuration is
  unchanged.
- A credential path given to any command, not only to `cat`, `grep` and the
  other readers, is a secret read. `ls`, `test`, `chmod`, `rm` and similar
  commands that do not show content are the exception.
- `workstation enforce -- command` decides on the command's argv. `--class
  network --target URL` with a command that does not connect to that host is
  refused, as is a shell `--target` that is not the command line. It also
  decides on its own environment: a proxy variable set there is a destination
  the allowlist must hold, and a connection variable, `LD_PRELOAD`,
  `DYLD_INSERT_LIBRARIES`, `BASH_ENV` or `ENV` makes the destinations
  undetermined. It exits with the command's own exit code (it was 1 for any
  failure), 128 plus the signal number when a signal ends it, 127 when the
  command cannot be started, and 126, not 1, when a receipt cannot be written;
  the command does not run then. Exit 2 means the flags could not be parsed
  or no decision could be made (the policy profile or the signing seed is
  unavailable); the command does not run then either.
- `workstation enforce` writes only the denials of a command it refuses, as
  the hook does, so `--receipt-dir` no longer holds an `ALLOW` receipt for an
  effect of a command that never ran, and `audit scope` over it no longer
  counts that effect as allowed. A command whose decisions are all `ALLOW`
  but not all in operate mode (`--class shell` decides in observe mode) is
  refused before any receipt is written, and leaves none; it left an observe
  `ALLOW` before. Upgrade note: every `enforce` receipt now has a random
  `request_id`, so its `decision_id` and its file name in `--receipt-dir`
  differ on every run, and each such file is created new, never replacing
  one already there; two runs of the same command used to leave one receipt.
  A script that predicted the file name must list the directory instead.
  `--out` still replaces the file it names. Every `enforce` receipt now carries, in its
  signed bytes, `call_id` (shared by the receipts of one run),
  `call_receipts` and `call_verdict`, beside `argv_binding` and
  `argv_sha256`. When a receipt cannot be written, the `ALLOW` receipts
  already written for the run are removed.
- `workstation list`, `denied`, `memory`, `loops`, `operator` and
  `audit scope` leave out a receipt that is unsigned or does not match its
  signature, and `audit scope` fails when no input is left. The Go functions
  `workstation.BuildOperatorView` and `workstation.BuildScopeAudit` take a
  `workstation.TrustAnchor` as their first argument.
- `workstation list`, `denied`, `memory` and `loops` with `--json` print an
  object instead of a bare array: the section's items under the key
  `operator --json` uses (`runs`, `denied_timeline`, `memory_review_queue`,
  `recurring_loops`) and `verification` beside them. Every denied, memory and
  loop item carries the `signature_status` of its receipt. Read `.runs` where
  you read the array before.
- The text output of `workstation denied`, `memory`, `loops`, `list` and
  `operator` ends each run, denied, memory and loop row with the
  `signature_status` of its receipt, and starts with a `Signatures:` line, a
  line per input not counted or counted once, and a `Signer trust:` line. The
  text output of `audit scope` gains `signatures:`, `not counted:`,
  `duplicate, counted once:`, `signer trust:` and, when there are any,
  `other signers:` lines, and `scope-audit.md` a `Receipts of another signer,
  counted apart` line and the signature statements under Limitations. A
  script that splits these lines on spaces or counts them needs updating.
- An input file that repeats a receipt already read is counted once by the
  operator commands and `audit scope`, and named in
  `verification.duplicate_inputs`.
- With a trusted key available, `audit scope` counts a receipt signed by any
  other key, the retired built-in key included, in
  `summary.untrusted_signer_receipts` and `summary.untrusted_signer_actions`
  only; it was in every total. The scope audit report schema gains these two
  properties.
- `workstation evidence` refuses an output directory that is not empty; export
  into a new or empty one. So does `audit scope --out`, with or without
  `--evidence-pack`, and the Go function `workstation.WriteScopeAuditArtifacts`:
  running an audit into the
  directory of an earlier one now fails, so write each into a directory of
  its own. Every file is created new through the opened directory, so a file
  or directory linked to one elsewhere is not written through.
- The unused Go export wrapper `workstation.ExportScopeAuditEvidencePack` is
  removed. Use `workstation.WriteScopeAuditArtifacts(report, outDir, true)`;
  the pack is written under `scope-audit-evidencepack` and its path is returned
  in `EvidencePackDir`. The CLI export path is unchanged.
- New workstation decision-receipt directories are owner-only (`0700`), as
  the receipt files already are (`0600`). Existing directories keep their mode.
- `shellscan` network facts carry the canonical destination in `Target`, and
  a command with several destinations yields several facts.

- Live model spending uses `helm-gateway serve` and the existing transactional
  Postgres authority ledger. `helm-ai-kernel spend-proxy`, including `up`,
  live flags and `reconcile`, now exits 2 with migration guidance. Local logs,
  opening balances and envelope configs cannot create or restore live authority.
  Follow [the migration instructions](examples/spend-proxy/README.md). The old
  embeddings endpoint has no replacement on this listener.
- The retired `inferencegateway` package, `api.GovernedGateway`, spend-proxy
  server/dispatch/reconciliation APIs and their live-only economic constructors
  are removed. Historical receipt schemas and offline export/verification stay
  available. Go callers of the removed runtime must migrate to helm-gateway.
- `spend-proxy export`, `savings-export` and `savings-verify` remain offline.
  Receipt signatures require independently pinned issuer keys. Record types and
  tenant/intent identities must match their signed payloads; a settlement must
  reference a matching signed usage receipt within its intent. A release record
  must bind the versioned action and reason in its signed quote metadata.
  Exporting pending or failed records never settles, releases or retries them.
- Model gateway requests are read against a closed list of supported members,
  nested content and provider options. Unsupported stored state, remote or
  uploaded media, PDFs, audio, hidden provider tools, predicted outputs, routing
  overrides, unpriced service tiers and betas are refused before admission.
  Clients must use the supported forms in
  [the model gateway contract](docs/architecture/model-gateway.md).
- Quotes count input bytes and conservative image/tool floors, fit the output
  limit within the durable budget, and include prompt-cache write prices.
  Missing cache-write prices on Anthropic and compatible routes default to
  1.25 times input for five-minute writes (rounded up) and twice input for
  one-hour writes. Set explicit route prices when different rates apply.
- Responses are forwarded with `store: false`. OpenAI and Anthropic routes
  normalize an absent or `auto` service tier to `default` or `standard_only`;
  compatible routes refuse `auto`. The request digest binds the forwarded body.
  Anthropic headers are forwarded only on the Messages API.

### Security

- helm-gateway holds an authority plan to its stage (helm-tracker#334). A
  `helm.authority.provision.v1` or `narrow.v1` plan whose mandates grant more
  than its stage allows is refused at Propose and again when it is applied
  (`STAGE_CEILING_EXCEEDED`): `draft` grants no write but an internal one,
  `approval-required` puts every write behind `approval_required` with no
  `approval_threshold`, and the live stages grant by mandate terms. A write is
  an effect type whose declaration's `Reversible` is not "not applicable"; an
  undeclared effect type counts as a write. A narrowing plan never raises the
  stage (`STAGE_RAISE_REQUIRES_PROVISION`). New `adapters.Declaration.Internal`
  marks a write of the composing Control Plane's own rows. Control CTL-067.
- helm-gateway verifies the owner's own passkey (helm-tracker#334). The
  owner's WebAuthn credential is enrolled at the tenant's genesis by
  `EnsurePrincipals` with a self-signed `genesis_assertion`; afterwards
  `EnsurePrincipals` adds no human and no passkey to a tenant (provision plans
  enrol them, through an optional `credentials` member of a human principal).
  `ApproveRequest.owner_assertion` is verified by the gateway against the
  approver's passkey over `pending_approval.owner_challenge`, and the approval
  row keeps it. `HELM_GATEWAY_OWNER_ASSERTION_REQUIRED` (default off; chart
  value `gateway.ownerAssertionRequired`) makes it the only proof of any required
  step-up, including authority widening, high-risk and irreversible effects, requires a passkey owner at genesis and refuses
  humans on existing tenants. Gateway schema version 17 adds
  `authority_principal_credentials`. Control CTL-068; `OWNER_ASSERTION_REQUIRED`
  joins the reason-code registry with the two stage codes. The receipt
  binding is unchanged.

  Control Plane migration, in order:

  1. Compose the effect-type declarations every plan grants, in the gateway
     and in kernel test fixtures: an `admission.Config` holding only the
     provision adapter now judges `github.repository.get` and `helm.work.get`
     undeclared, so a draft or approval-required plan granting them is refused
     (on Control Plane `aafbe18e`:
     `internal/organization/activation/authority_readback_kernel_observed_test.go:176`
     and `internal/console/company_ai_os_attention_native_action_source_test.go:248`).
  2. Set `Internal: true` on the `helm.work.*` and
     `helm.org.request_capability` writes `gatewayadapter` declares
     (`declarations.go`). `model.semantic.evaluate` (`ReversibleNo`) counts as a
     write: keep it out of draft plans, or declare it `ReversibleNotApplicable`
     as the kernel's `model.inference` is.
  3. Classify a stage-rank increase as widening in
     `internal/organization/provision/compare.go`, so it goes as a provision
     plan.
  4. Stop adding humans to an existing tenant through `EnsurePrincipals`
     (`company_ai_os_attention_native_action_source_test.go:783` does): add
     them through a provision plan, with their passkeys in `credentials`. The
     stand's repeated bootstrap keeps working, since a registered human
     presented as it is is answered unchanged.
  5. Bump the kernel pin; `admission.Tables` now includes
     `authority_principal_credentials`, which test fixtures grant to the
     runtime role.
  6. Signup: call `EnsurePrincipals` once per tenant with the owner's passkey
     (SPKI converted from the go-webauthn COSE key, `rp_id` of the relying
     party) and the genesis assertion over the genesis challenge. For tenants
     registered before this change, enrol the owner's passkey through a
     provision plan approved with the step-up proof while the flag is off.
  7. Approval UI: use `pending_approval.owner_challenge`, read with the
     approver's own token, as the WebAuthn challenge, and forward the
     assertion as `owner_assertion`.
  8. Set `HELM_GATEWAY_OWNER_ORIGINS` to the exact served Console origins.
     Flip `HELM_GATEWAY_OWNER_ASSERTION_REQUIRED` once 6 and 7 are live.
- Pack directory listings and directory `Open` calls acquire a directory-only
  handle and verify its identity. Replacing a checked child directory with a
  named pipe can no longer block either call; replacing it with a different
  directory is refused. The regular-file and pack-root rules are unchanged.
- Pack filesystem names use slash separators. Windows rejects backslash
  names before native lookup; Unix retains literal backslashes in names.

- The Go toolchain is 1.26.11 in `mise.toml`, `go.work`, every `go.mod`, the
  build images and the workflows. Go 1.26.10 carries GO-2026-6859 (an HTTP/1
  server crash in `net/http`), which `govulncheck` reports as reachable. Every
  module now declares `go 1.26.11`, so consumers need Go 1.26.11 or newer.

- Guardian selects the policy rule, and names an execution intent's allowed
  tool, from the evaluated request. Only `EXECUTE_TOOL` has a tool Guardian
  binds: its `tool_name` is the request resource. For every other action the
  top-level `tool_name` in request context is removed before any gate or
  policy reads it, so the top-level `tool_name` the PDP sees is never the
  caller's, and a `CALL_TOOL` request, which has no typed tool field, is
  evaluated as `CALL_TOOL`. `POST /api/v1/evaluate` and the governed OpenAI
  proxy previously evaluated the rule named by a caller's `tool_name` and
  signed an ALLOW for a different tool. A managed-policy pattern is still
  matched against the whole request, caller args included: a pattern that
  names `tool_name`, `effect_class`, `effect_class_source` or
  `effect_class_declared` also matches a member of that name the caller
  nested in `args` or in another context member. The `effect_class`,
  `action` and `resource` selectors read the bound values, and for deny and
  escalate rules also the kept declaration.
- On `POST /api/v1/evaluate`, the organization-runtime evaluate route and
  ext-authz, the request's effect class is recorded as a declaration and can
  no longer talk a catalogued effect under a policy ceiling. When the kernel's
  effect type catalog knows the evaluated action, the bound `effect_class` is
  never below the catalog's class: `INFRA_DESTROY` declared as `E0`, or named
  as the tool of an `EXECUTE_TOOL` request, is evaluated as `E4`, and the
  activation ceiling is checked against that class. The resource of any other
  action does not change its class, so `effect_level` remains a policy
  resource even when it is spelled like a catalogued effect id, and a caller
  cannot pick the class of an action the catalog does not know by naming an
  effect beside it.
- The signed effect carries `effect_class_source`: `effect_catalog` when the
  bound class is the catalog's class for the evaluated action, `tool_catalog`
  on MCP, `kernel_route` on the governed proxy, and `caller_declared` when the
  bound class is the one the caller declared. When the kernel bound a
  class other than the declared one, the caller's own value is kept as
  `effect_class_declared`. Managed policy matches every rule against the
  request as bound without `effect_class_source` and `effect_class_declared`,
  and deny and escalate rules also against the request as declared, where
  `effect_class` holds the declaration. It never matches an allow rule
  against the request as declared, and no pattern against the top-level
  provenance members, so neither an allow rule's `effect_class` selector nor
  its pattern reads the declaration.
- A receipt with no `signature_version` (a legacy receipt, signed before
  `receipt.v5`) is no longer checked by default. `receipt_verify` exits 2 for a
  file that holds one; pass `--allow-legacy-v4` to check it. Go callers of
  `core/pkg/receiptverify` set `Options.AllowLegacyV4`. The JavaScript and
  WebAssembly verifier has no opt-in and returns `UNVERIFIABLE`.
- Under the opt-in, a legacy receipt whose `receipt_id` begins with `{` fails:
  it is the signature of a versioned payload read back as a legacy receipt.
  `core/pkg/crypto` returns `ErrLegacyReceiptReplay` for it.
- `POST /api/v1/evidence/verify` reports a receipt with no `signature_version`
  as not checked: its `receipt_signatures` check is `UNVERIFIABLE`, where it
  used to be `VERIFIED` when the legacy signature matched. This holds when the
  runtime trust anchor is a `KeyRing` too.
- `POST /api/v1/evidence/verify` reads every receipt file with the parser
  `receipt_verify` uses. A bundle that holds a receipt file with a member
  written twice, or with a receipt member spelled in another letter case, is
  refused: `bundle_format` is `FAILED` and no receipt check runs. So is a
  receipt file that breaks the `receipt.v5` member contract, such as a
  `lamport_clock` that is not an unsigned integer: it used to fail
  `receipt_signatures` and now fails `bundle_format`.
- In `core/pkg/crypto`, `ReceiptVerifyPayload`, `VerifyReceiptProfile`,
  `VerifyReceiptRequiredProfile` and `VerifyReceiptSignature` return
  `ErrLegacyReceiptRefused` for a receipt with no `signature_version` unless
  given `AllowLegacyReceiptPreimages`; no other option value checks one. Every
  `VerifyReceipt` method, `KeyRing.VerifyReceipt` included, takes no option and
  returns `ErrLegacyReceiptRefused` for such a receipt when it carries a
  signature.
- `receipt_verify`, the JavaScript verifier and `helm-ai-kernel verify receipt`
  refuse a file in which a receipt, bundle, permit or binding member is
  spelled in another letter case. Write member names exactly as the schema
  spells them. Keys of `metadata`, `public_key_set`, `subject` and other
  free-form values are compared exactly, so `a` and `A` there are two keys.
- `receipt_verify` and the JavaScript verifier refuse a bundle (an object with
  a `receipts` array) that carries a receipt member such as `verdict`,
  `status` or `tool_name` at its top level. `key_id`, `public_key_hex`,
  `permits` and `gateway_bindings` are the bundle's own members and stay; so
  does any name that is not a receipt member. The `--format json` report of
  `helm-ai-kernel receipts list` is refused for its top-level `status`: pass
  its `receipts` array instead.
- A document nested deeper than 64 levels is refused by `receipt_verify`, as
  the JavaScript verifier already did, and by every other path that reads
  receipts with `core/pkg/receiptverify`: `helm-ai-kernel verify receipt`
  exits 1 (`parse receipt: JSON exceeds the 64-level nesting limit`) where it
  exited 0; `POST /api/v1/evidence/verify` fails `bundle_format`;
  `POST /api/demo/verify` and `POST /api/demo/tamper` answer 400 for a request
  body nested that deep; and `helm-ai-kernel verify` fails
  `embedded_signature_trust` for such a file in `receipts/` or
  `07_ATTESTATIONS/`, with the reason `N file(s) refused unread: JSON exceeds
  the 64-level nesting limit`, which does not count the file as a signature,
  and fails `chain_integrity` and `lamport_monotonicity` for such a receipt
  file in a pack whose receipts are chained.
- The `integrity` check of `receipt_verify` is now `not_applicable` where it
  was `pass`. It never compared anything; `closure` is the check that compares
  the hashes of a chain. Exit codes and the `valid` member are unchanged.
- `receipt_verify --json`: the new `legacy_receipts` counts the receipts
  checked under the legacy preimage. It appears only when that count is above
  zero, so only under `--allow-legacy-v4`. It is a member of
  `receiptverify.Result`, which the JavaScript verifier returns as
  `verification`; that verifier has no opt-in and never emits it.
  `preimage_version` is `mixed` for a chain checked under more than one
  preimage, and the new `preimage_versions` lists each with its receipt count.
  The new `key_id_note` says that `key_id` is the receipt's unsigned claim. No
  member was renamed or removed.
- `helm-ai-kernel verify receipt --json` adds `signed_members`,
  `unsigned_members` and `integrity_scope`. `integrity_valid` and
  `signer_trusted` keep their names and meaning: both are about the 13 signed
  members only.
- `helm-ai-kernel verify` no longer checks a dev-local MCP proof receipt that
  has no `signature_version`; `embedded_signature_trust` fails for a pack that
  holds one, and its reason says the receipt was `not checked: no
  signature_version` and names the flag. Pass `--allow-legacy-v4-receipts` for
  a pack known to predate `receipt.v5`
  (`verifier.VerifyOptions.AllowLegacyV4Receipts`).
- `helm-ai-kernel verify` refuses a chained receipt file that spells a member
  of a receipt, or of a struct a receipt holds, in another letter case
  (`"PREV_HASH"` for `prev_hash`, `"LOG_ID"` inside `transparency`), or that
  writes any member twice at any depth: inside `metadata` or a
  `witness_signatures` entry too, and two names that decode to one string,
  such as two lone surrogates, which Go decodes to U+FFFD. `chain_integrity`
  and `lamport_monotonicity` fail with `receipt <file> is refused: ...`; such
  a file passed them before, read as the last value written. A receipt file
  that is not valid JSON, or that has a trailing value, failed them before and
  still does, but the reason now reads `receipt <file> is refused: ...` (for
  example `invalid receipt JSON at $: ...` or `receipt has a trailing JSON
  value ...`) where it read `receipt <file> is not valid JSON: ...`. Nesting
  deeper than 64 levels is the bullet above. Go callers that decode a receipt
  document into `contracts.Receipt` themselves can apply the same rules with
  `receiptverify.ValidateReceiptMemberNames`. The nesting-limit refusal is now
  the exported `receiptverify.ErrJSONTooDeep`.
- In the chain checks of `helm-ai-kernel verify`, a `receipt.v5` receipt links
  only to a predecessor whose `contracts.ReceiptChainHash`, or the SHA-256 of
  whose file, is its `prev_hash`. A `hash` member a receipt declares about
  itself links only a successor whose `signature_version` is not `receipt.v5`.
  A pack in which a `receipt.v5` receipt names its predecessor only by that predecessor's
  declared `hash` now fails `chain_integrity` and `lamport_monotonicity`: the
  receipt is unreachable from genesis.
- `helm-ai-kernel evidence correlate-host` applies the same member-name rules
  to each receipt file of the pack before it decodes it, and exits 2 with
  `receipt <file> is refused: ...` for a file they refuse, one nested deeper
  than 64 levels included. A receipt file that is not valid JSON, which it
  skipped, now stops it the same way.
- `POST /api/demo/verify` and `POST /api/demo/tamper` answer 400 for a receipt
  with a member written twice or spelled in another letter case, and for a
  body with no `receipt` or with `"receipt": null`, where both answered 200
  (`/api/demo/verify` with `valid: false`). They read the request body by
  exact member name: a member other than `receipt`, `expected_receipt_hash`
  and, for `/api/demo/tamper`, `mutation` is refused with 400, a letter-case
  variant such as `"Receipt"` included, and so are a member written twice and
  a trailing value after the body (`request body has a trailing JSON value
  ...`). The OpenAPI request schemas of both routes declare
  `unevaluatedProperties: false`; `oasdiff breaking` reports no breaking
  change, and the generated SDK models are unchanged. `verified_fields` now
  lists the 13 members a `receipt.v5` signature covers, and is empty when the
  signature was not verified.

### Added

- `shellscan.ClassifyArgvAt` classifies a command given as argv, and
  `shellscan.PathGuard` with `shellscan.WithPathGuard` reports any reference
  to paths the caller protects. The new `netdest` package parses a URL or host
  into the endpoint a client connects to.
- `workstation list`, the other operator commands and `audit scope` take
  `--data-dir` and `--trusted-public-key-file`, print which signature checks
  the input receipts went through, and give each run a `signature_status`.
- `shellscan.WithEnvironment` classifies a command as run with an inherited
  environment. `shellscan.NewSearchCall` collects the globs of one search
  call (`AddFilter`, `AddPathPattern`) under one budget,
  `shellscan.MaxSearchGlobAlternatives` and `shellscan.MaxSearchGlobBytes`;
  `PathGuard.MatchSearch` decides whether it reaches protected material and
  `SearchCall.SecretRead` whether it selects credential files, and a call
  past the budget is reported as `shellscan.UnexpandableSearchGlob`. A path
  guard pattern reads `**` as any number of directories.

- `helm-ai-kernel shadow scan --require-complete` exits 2, with no report,
  unless every in-scope path was read in full.

- Package `core/pkg/verifier/packfs` reads one EvidencePack directory through
  an `os.Root`: it refuses names and symbolic links that leave the pack,
  absolute symbolic links and files that are not regular, reads whole files
  up to 64 MiB (`MaxFileBytes`), and checks the letter case of a name a pack
  states (`CheckCase`).
- `core/pkg/tape`: `LoadTape` reads a tape from a file system (`LstatFS`)
  into a `Tape`, and `Tape.Replay` replays it; `verify` and `replay` both use
  them. `ParseManifest` decodes `tape_manifest.json` and `EntryFileNames`
  lists entry files in number order.
- `helm-ai-kernel verify --require-check <names>` fails the pack when a named
  check did not run, for example `--require-check chain_integrity` for a pack
  that must carry a receipt chain. Repeat the flag or separate names with
  commas; every named check is required.
- `verify --json` reports `outcome` (`VERIFIED`, `FAILED` or `UNVERIFIABLE`),
  `check_counts` and a `status` on every check. `evidence inspect --json`
  carries `outcome` and `check_counts` too.

### Changed

- CLI and served text now state what the code does. `helm-ai-kernel proxy`
  prints `Signing: none` when started without `--sign`; `bundle` help describes
  `bundle build` as compiling Rego or Cedar and printing the bundle identity,
  with no signature and no CEL; the `helm.evaluate` skill on the A2A agent card
  no longer offers envelope signature verification; and the packed MCP bundle
  manifest and `mcp-bundle.json` list only the governance features a shipped
  command performs.

### Upgrade notes

- The request context gained members that managed policy patterns never
  read at the top level. `effect_class_source`, and `effect_class_declared`
  when the kernel bound a class other than the declared one, sort after
  `effect_class` in the canonical request, with nothing between them but a
  member whose name begins with `effect_class`. Every pattern is matched
  against the request without those two members, the text it was written
  for, so a pattern such as `"effect_class":"E1","principal_id":"..."` matches
  as it did. In that reading `effect_class` is the class the kernel bound,
  which for a catalogued effect is the catalog's class and not the declared
  one; deny and escalate rules are also matched against it with
  `effect_class` holding the kept declaration. A pattern that names
  `effect_class_source` or `effect_class_declared` matches only a member of
  that name the caller nested, so it neither admits nor refuses on the source
  or the declaration the kernel bound. Where the PDP's ALLOW is not
  authoritative (no PDP, or the CEL/PRG runtime policy), a PRG expression can
  refuse caller-declared classes by reading `effect_class_source` from the
  effect's params; under ManagedPolicyPDP an ALLOW replaces local PRG
  evaluation, so no rule can refuse a caller-declared class until a typed
  `effect_class_source` selector lands (helm-tracker#322). A pattern is matched against the whole request, so it also
  matches a member named `effect_class` or `tool_name` that the caller nested
  in `args` or in another context member. The `effect_class`, `action` and
  `resource` selectors read the bound values, and for deny and escalate rules
  also the kept declaration.
- A class-keyed allow rule now admits a catalogued action sent with a label in
  place of its class: on ext-authz or the evaluate route, `SEND_EMAIL` with
  the effect class `ticket.read` is evaluated as the catalog's `E2`, so a rule
  that allows `E2` admits it, where before the label selected no class rule.
- A CEL or PRG expression that restricted on a caller's label for a catalogued
  effect must read `effect_class_declared`: `effect_class` now holds the
  catalog's class there.
- A policy that matched a top-level `tool_name` in request context for an
  action other than `EXECUTE_TOOL` no longer sees it. Guardian removes that
  member, because only `EXECUTE_TOOL` has a tool the kernel binds. A
  `tool_name` nested in `args` or in another context member is left as the
  caller sent it.
- MCP refuses a tool call with a top-level argument named `effect_class_source`
  or `effect_class_declared`, as it already did for `effect_class`: tool
  arguments become top-level members of the policy input, where those names
  carry authority. A tool that needs such a parameter must nest it inside
  another argument or rename it. The evaluate routes and the governed proxy
  strip the same top-level context members and leave nested ones alone.
- Effect digests of decisions on the evaluate routes, ext-authz, the governed
  proxy and MCP change. The effect's params gain `effect_class_source`, and
  `effect_class_declared` where the kernel bound a class other than the
  declared one. On the evaluate routes and ext-authz `effect_class` holds the
  bound class, which for a catalogued action can differ from the declared
  value. A top-level `tool_name` the caller put in context is no longer in the
  params of any action but `EXECUTE_TOOL`, whose `tool_name` is the request
  resource as before.
- The signed ext-authz response still echoes the request's `effect_class` and
  `risk_class` as submitted. It does not carry the class the kernel bound or
  its source, so when the kernel evaluated a higher class the response alone
  does not say so. The evaluated class is in the decision's effect.
- The format of the organization-runtime decision attestation is unchanged,
  and its `effect_class` is still the submitted value, which the control plane
  verifies against what it sent, also when the kernel checked the activation
  ceiling against a higher class and refused. Its other values can change,
  because the activation record's binding check now reads the class the kernel
  bound. A catalogued action declared below its catalog class is refused with
  `ACTIVATION_CEILING_EXCEEDED` where its record's ceiling is below the
  catalog's class. A catalogued action sent with a label in place of its class
  (`SEND_CHAT_MESSAGE` with `ops.label`) used to fail the binding check
  (`ACTIVATION_BINDING_MISMATCH`, a presented identity); it is now checked
  against the catalog's class, so over an E0 record it is refused with
  `ACTIVATION_CEILING_EXCEEDED`, and the attestation reports a verified
  identity with the record's ref and hash. The decision record's input context
  carries the class the ceiling was checked against with its source and
  declaration, on a refusal as on a pass. The record signed for a refusal of
  the activation gate carries no effect digest, so its signature does not
  cover that context.

- `helm-ai-kernel verify` no longer counts a check as passed when the pack
  gave it nothing to read. The summary is now, for example,
  `VERIFIED: 5 passed, 0 failed, 8 not run; this result covers only the 5
  checks that ran`, where it used to be `PASS: 12/12 checks passed`; a failed
  result starts with `FAILED:` instead of `FAIL:`. In `--json`, such a check
  has `"pass": false` and `"status": "NOT_RUN"`. Clients that count
  `pass: false` entries as failures must read `status`, `outcome` or
  `check_counts` instead. `verified` and the exit code are unchanged for packs
  that verified before, except a pack whose `manifest.json` does not parse
  (see Fixed) and the packs named in the notes below. `verifier_version` is
  `0.3.0`.
- `helm-ai-kernel replay` now exits 1 for a tape with a missing entry, a
  changed value, entry files out of sequence order, a manifest that disagrees
  with the tape on any field it carries, or no entries. It used to exit 0 for
  all of these unless `--verify` was passed. The hash and sequence checks
  always run; `--verify` now only adds the `data_class` requirement. A
  symbolic link in place of `08_TAPES`, the manifest or an entry file exits 2.
  `--json` gains `entries_replayed` and `seal_checked` (always `false`), and
  `replay_status` can be `NOT_RUN`.
- `helm-ai-kernel verify` validates evidence a pack carries even when nothing
  requires it, so these packs no longer verify: a
  `02_PROOFGRAPH/determinism_manifest.json` with diverging or missing hashes
  in a pack that does not declare gate `G2`; a `gates` value that is not a
  list of gate names; an invalid `eu_ai_act_profile` in a JSON file over
  2 MiB, in a later document of a line-delimited file or under a repeated
  key; a file under `host_evidence/` or `11_HOST_EVIDENCE/` named like a
  correlation or verification report that does not hold one JSON object or
  array, or that holds a failing receipt chain; and an `00_INDEX.json` or
  `manifest.json` path that is absolute, contains `..` or resolves outside
  the pack through a symbolic link.
- `helm-ai-kernel evidence inspect` exits 1 when the outcome is `FAILED` or
  `UNVERIFIABLE`, in `--json` mode too; `--json` used to exit 0 whatever the
  outcome. It now applies the pack layout check `verify` applies, so a pack
  with an unexpected top-level entry or a missing mandatory directory is
  `FAILED` there as well.
- `verify --require-check` with an empty value, or with a name that is not a
  check, exits 2.
- `protocols/json-schemas/cli/helm_cli_schema.json` requires `outcome`,
  `check_counts` and `checks[].status`. A report from a verifier older than
  `0.3.0` does not validate against it.
- Text output changed in three places that scripts may match. Read `--json`
  instead, which keeps the structure:
  - `verify` prints a `checks: N passed, N failed, N not run` line after the
    headline in every outcome (with `N unverifiable, ` before the not-run
    count when a check is unverifiable, and `; this result covers only the
    checks that ran` after it on a `VERIFIED` result with checks not run),
    followed by up to 20 `  not run: <check>: <reason>` lines and
    `  ... and N more not run (use --json for all of them)`.
  - `evidence inspect` prints `  Outcome:` as the second line, so
    `  Verified:` and `  Summary:` move down one line, and it ends with the
    failed and unverifiable checks (`  - <check>: <reason>`) and the same
    counts block.
  - `replay` prints `Replay DIVERGED: X of Y tape entries replayed, N issues:`
    where it printed `Replay DIVERGED (N issues):`, and every result ends with
    `Run ID:` and `Status:` lines.
- Text output of `verify`, `evidence inspect` and `replay` writes a backslash
  from the pack as `\\`, so a Windows path prints as `C:\\path\\file`.
  Characters that print as blank space (space separators other than the ASCII
  space, the Hangul fillers, the blank Braille pattern), runs of three or
  more spaces (each space as `\x20`) and combining marks past the second on
  one letter (as `\uXXXX`, or `\UXXXXXXXX` above U+FFFF) are escaped too.
  `--json` is unchanged.
- `helm-ai-kernel verify` and `evidence inspect` read the pack through an
  `os.Root` opened on its directory in every check except `roots` and
  `evidence_pack_seal`, including the conformance signature check and the
  `--require-eidas` and `--require-tee` checks, and read only regular files.
  These packs no longer verify: one where a file a check reads is a symbolic
  link whose target is outside the pack, or an absolute symbolic link (also
  one that points back into the pack); one where it is a named pipe, a device
  or a socket; one whose `11_HOST_EVIDENCE` or `host_evidence` directory is a
  symbolic link out of the pack (the new `external_host:evidence_dir` check
  fails it); one that holds a `.json` file over 64 MiB, or `.json` files past
  256 MiB in all, which the EU AI Act scan names instead of reading; one
  whose `00_INDEX.json` or `manifest.json` names a file in another letter
  case than the pack directory lists it; one with a host receipt chain file
  (`.json`, `.jsonl` or `.ndjson` under `host_evidence/` or
  `11_HOST_EVIDENCE/`) over 64 MiB, which fails `external_host:chain_file`
  instead of being read whole; and one whose seal file
  `07_ATTESTATIONS/evidence_pack.sig`, index or an indexed file is a symbolic
  link or not a regular file (the seal check refuses them before opening).
  `--require-eidas` also fails, as `eidas:read_anchor`, when
  `02_PROOFGRAPH/anchors` or `00_INDEX.json` is refused, and `--require-tee`,
  as `tee:read_receipt`, when `receipts` is. `verify` used to
  hang on a named pipe in the pack. `evidence inspect` leaves out the launch
  id and evidence graph it prints when their files are refused.
- `helm-ai-kernel verify` replays a tape that carries entries with the code
  `helm-ai-kernel replay` runs, under gate `G2` or not, so a pack whose tape
  `replay` reports `DIVERGED` (without `--verify`, whose `data_class`
  requirement `verify` does not apply) no longer verifies; that includes
  `tape_manifest.json` rows that name entries the tape does not hold. Entry
  files without a `tape_manifest.json` fail. Under `G2`, an empty file whose
  name starts with `.` in `05_DIFFS`, such as the launchpad writer's `.keep`,
  no longer fails the pack.
- `helm-ai-kernel replay` reports `DIVERGED` for a manifest row that lacks
  `seq`, `type`, `key`, `sha256` or `size_bytes`, and for an entry whose type
  is empty or not one the recorder writes. Entry files are read in the order
  of the number in their name (`entry_2.json` before `entry_12.json`). With
  `--json`, a tape that cannot be read still prints a result
  with `replay_status` `NOT_RUN`, `entries_replayed` `0` and the new `error`
  member, and exits 2 as before.
- The EU AI Act scan reads past a UTF-8 byte order mark and fails a `.json`
  file that names `eu_ai_act_profile` and does not parse, wherever the damage
  is, so a pack with such a file no longer verifies. A file nested deeper than
  10000 levels, the limit `encoding/json` keeps, is one that does not parse;
  the scan keeps its own bounded stack and never recurses.
- The EU AI Act scan matches the member name in any letter case, the way
  `encoding/json` matches it to the `eu_ai_act_profile` field of the Go
  types that read a pack, so a pack with an invalid profile under
  `EU_AI_ACT_PROFILE` no longer verifies. It validates at most 1024 profiles
  per pack: a pack with more fails `eu_ai_act_profile`, naming the file that
  holds the 1025th. A failed reason lists the first 10 validation issues and
  ends `; and N more`.
- `verify` and `replay` read at most 256 MiB of tape entry files per tape,
  sized before any is read. A larger tape fails `replay_determinism`, and
  exits `replay` with 2 (`NOT_RUN` under `--json`), naming the entry file
  that passes the bound.
- Under gate `G2`, a tape with no entries fails `replay_determinism`: it
  replays nothing, which `replay` reports as `NOT_RUN` with exit 1. Without
  `G2` the check names it as not replayed, as before.
- The layout check that `verify` and `evidence inspect` add tests the
  mandatory names, lists the pack directory and `99_EXT`, and reads
  `00_INDEX.json` through the `os.Root` on the pack. A mandatory name or
  `99_EXT` that is a symbolic link out of the pack fails as
  `conform:<name> is not read: ...`; `99_EXT` linked out of the pack is no
  longer listed, so the names of the files outside are not printed.

### Removed

- `tape.ReadManifest(dir)` in `core/pkg/tape`. Read the file and call
  `tape.ParseManifest`, or load the whole tape with `tape.LoadTape`.

### Upgrade notes

- `helm-ai-kernel skills verify` and `skills scan` exit 1 for every verdict
  other than `ALLOW`. Text output used to exit 0 for `ESCALATE`.
- `skills search --json` returns each skill as
  `{"manifest": ..., "publisher_verification": ...}`; the manifest fields used
  to be at the top level of each entry. The text output shows the computed
  publisher state where it showed the status the manifest declares.
- Go callers of `core/pkg/skillpacks`: `VerifyPublisherSignature`,
  `TrustedPublisherKeyring`, `DefaultTrustedPublisherKeyring` and
  `ValidatePolicyFile` are removed. `CheckPublisher` reports the computed
  publisher state, `ListCatalog` returns `[]CatalogEntry`, and
  `MarketplacePlugin.ScannedAt` is `RecordedAt` (`recorded_at`).
  `ProjectionLifecycle` rejects a manifest that declares `status: verified`
  unless its two files are a pack the binary pins.
  The shipped pack explicitly records its `SKILL.md` content hash so those
  exact pinned files also satisfy the lifecycle's artifact identity checks.

### Fixed

- The hook's egress allowlist was decided on the first URL of a command only.
  A second URL, a host hidden behind `user@`, and an option or variable that
  moves the connection (`--connect-to`, `--resolve`, a proxy, `ssh -J`) now
  each count as a destination, in the hook and in `workstation` policy
  evaluation, which share one parser. The parser reads each client's command
  line the way the client does: `ssh` options written after the host,
  `-o=Key=Value`, an `openssl s_client` peer given as an operand or with
  `-host` and `-port`, the last value of a repeated `git -c
  http.followRedirects`, an address stored with `git config --file`, and a
  proxy variable exported as one quoted word.
- A fetch tool that takes a list (`urls`) is decided on every URL in it. It
  was denied as undetermined under an allowlist profile even when every URL
  was allowed.
- A shell path pattern with a bracket class (`[!x]*`) is no longer matched
  as if `!` were a member: it is outside the glob grammar and is denied when
  it starts at, inside or above the data directory.
- The hook did not protect its own signing material. A call that reaches the
  key directory, a seed passed by flag, the policy profile, or the kernel
  command that signs or installs the hook is now denied with
  `TRUST_MATERIAL_ACCESS_DENIED` under every profile, through any tool.
- `Read`, `WebFetch` and other tools that are not a shell were passed without
  a decision when routed to the hook.
- `workstation evidence` wrote outside its output directory when a receipt
  carried a `receipt_id` with path separators. The identifier is now checked
  and every pack file is written through the opened directory.
- `workstation enforce` ran a command after deciding on the declared class and
  target instead of the command, and passed its own environment to the command
  undecided, so an inherited `HTTPS_PROXY` moved the connection after an
  `ALLOW` for the named host.
- `audit scope` and `workstation list` reported on receipts whose signature
  was missing or did not match.
- The operator commands and `audit scope` counted a duplicated input file
  twice.
- `workstation evidence` opened pack files with truncation, so a file
  hard-linked into a reused output directory was written through, and a
  re-export left stale receipt files the index did not list. `audit scope
  --out` with `--evidence-pack` did the same with its report and pack files,
  and wrote through a pack subdirectory linked to a directory elsewhere.
- The hook waited for standard input to close before deciding, so a client
  that kept it open after the payload got no answer until its timeout.
- When a later receipt of a call could not be written, the hook removed the
  denials it had already written with the `ALLOW` receipts.
- Retired live `helm-ai-kernel spend-proxy`, local-file reconciliation and
  the legacy `core/pkg/inferencegateway` / `api.GovernedGateway` execution
  surfaces. Model calls use `helm-gateway` and its transactional Postgres
  admission, budget, idempotency and recovery state. Legacy config flags and
  embeddings require migration; historical receipt files do not create grants.
- Preserved offline spend exports and savings-pack verification. Export checks
  that record identities match signed payloads and binds a settlement to its
  signed usage receipt before reporting an intent's signatures verified.
- Skill Pack verification no longer trusts what a pack says about itself. The
  check compared the manifest's publisher, a `signature_ref` that follows from
  the pack name and version, and the `SKILL.md` hash, so any pack that copied
  those strings scanned as `ALLOW` and installed, and the policy that judged a
  pack was read from the pack's own repository. Now a pack is first party only
  when every one of its files hashes to a digest compiled into the binary for
  the packs under `registry/skills/helm/`. No signature is checked: that
  comparison shows the pack is the one the binary was built with, and Skill
  Packs from other publishers cannot be verified. `skills verify` reports the
  computed `publisher_verification` state (`first_party`,
  `first_party_mismatch` or `unsigned`), denies a pack that declares
  `status: verified` without matching a pinned digest, escalates any other
  unsigned pack, and `skills install` writes nothing for either.
- The scan judges every pack under rules built into the binary and records the
  SHA-256 of `policies/skills/first-party.safe.toml` as `policy_hash`. Receipts
  used to carry the pack's own `policy_ref` string in that field, and a policy
  file beside the pack could change the verdict.
- The pack digest covers every file in the pack, read once without following a
  link out of it. A file over 1 MiB, more than 1024 files or more than 16 MiB in
  one pack is denied; files over 1 MiB used to skip the binary check.
  The initial `SKILL.md` and manifest reads also enforce the file limit and
  containment before scanning. Loading and scanning reuse the verifier's
  nonblocking file and directory reader, so named pipes cannot stall them.
- `skills verify` flags instructions that run commands or fetch from outside
  the pack, such as a download piped into a shell, using the kernel's threat
  scanner. Such a pack needs review even when it is first party.
- `skills search`, `skills inspect` and the install record shown by
  `skills list` carry the computed publisher state. They used to show only the
  `verified` status a manifest declares. Pack-controlled values in formatted
  text output are escaped so a version, description or publisher reason cannot
  insert a forged verdict or terminal control sequence; JSON preserves the values.
- A `skills export` receipt carries the scan's verdict instead of a constant
  `ALLOW`, and `plugin.json` records the scan verdict and publisher state.
  `skills marketplace add` records an entry as `recorded`; it runs no scan and
  used to say `scanned`.
- The model gateway's hold bounds what a request can make the provider bill,
  under the assumptions `docs/architecture/model-gateway.md` lists ("The bound
  and what it rests on": one token per byte, the image and tool floors, an
  honoured output maximum, the route's price at its tier) (helm-tracker#313,
  audit H6). The quote counted request bytes and the output maximum, while a
  request could make the provider bill a stored conversation, a stored
  prompt, stored reasoning named by its id, remote media, a routing fallback,
  a compaction pass or an account's priority tier. Requests are now read
  against a closed list per API, nested configuration included
  (`core/pkg/gateway/modelbound`); refusals carry the new error codes
  `unsupported_member`, `unsupported_content`, `invalid_content` and
  `unsupported_beta` and name what they refuse. Inline images and
  provider-supplied tool definitions are held at a token floor; a Responses
  request is sent with `store: false` unless it names it, and a vendor route
  gets the standard service tier when the request names none or `auto`.
- A spend envelope's `max_amount_cents` is consumed (audit H7). The spend
  proxy and the governed gateway route reserve a quote's ceiling against the
  envelope's window (the UTC day for the spend proxy's envelopes) and the
  balance in one step, so concurrent requests cannot both take the last cents;
  settlement moves the reservation to used, and a release returns it. The
  budget-verdict receipt (`OK_WITHIN_ENVELOPE`) is issued only when that
  reservation succeeds; a refused reservation's logged quote carries the DENY
  verdict. A restart re-applies settled spend to its envelope.
- A spend-proxy dispatch that may have reached the provider is never released
  (audit H8): it is debited at its hold, its usage receipt carries metadata
  `settled_at_hold`, the response is 502 with error type `helm_dispatch_failed`
  and `helm.settled_at_hold: true` (or the provider's answer, when it answered
  without readable usage), and its idempotency key cannot dispatch again. Only
  a failure before the upstream connection opened releases the hold, journalled
  as the new receipt-log kind `dispatch_released`. A client that disconnects no
  longer cancels the provider call.
- The spend proxy holds, on start, a dispatch journalled before its provider
  call that never settled (audit M18); the journal line now carries the note
  `dispatch: journalled before the provider call`, and the start banner and
  `ReplaySummary` report `pending` dispatches and cents. It refuses `n` other
  than 1 and the routing members `models`, `provider`, `plugins` and `route`.
  An answer is priced by the model it names: the quoted model, or its id with
  a dated suffix (`-YYYY-MM-DD`, `-YYYYMMDD`), at its usage; an answer that
  names no model, or the quoted id with another suffix (an alias answered by
  a versioned id), at its usage too, recording `model_mismatch` `no_model` or
  `version_suffix`; another model at the dearer of the two prices, or at least
  the hold when the price book does not have it, recording `response_model`
  and `model_mismatch: true` on the usage receipt.
- `spend-proxy export` verifies what it reports (audit M18): with the new
  `--public-key` flag it checks the detached signature of every receipt line of
  each intent and the budget-verdict seal against that key, and lists them in
  the new JSON member `signatures_checked`; `signature_verified` is true only
  then. A line that is unsigned, signed by another key or whose signature does
  not verify fails the export (exit 1); a malformed key exits 2. The start
  banner prints the public key and `/helm/spend/health` serves it as
  `signing_public_key`.
- The principal sealed into a spend receipt is the envelope's configured
  `principal_id`, never a request header (audit M17), and a header can no
  longer pick among principals: `spend-proxy` gains caller credentials (config
  `callers`, each a token stored as its SHA-256 and bound to an agent, its
  envelopes and its workspaces), and without them it serves exactly one
  principal. A workspace header reaches a signed quote only when a credential
  covers it. The engine refuses a request that names another principal (403
  `ERR_SPEND_ENVELOPE_NOT_FOUND`), and `spend-proxy` refuses a
  `request_defaults.principal_id` that is not its default envelope's. The
  listener stays loopback only (CTL-026).
- The spend proxy's hold bounds the bill as the model gateway's does
  (helm-tracker#313 r1): it reads every request against the same closed list
  and quotes one input token per byte of the request it forwards, plus the
  image and tool floors; it quoted a quarter token per byte and forwarded
  stored conversations, remote images and hosted tools. A provider that bills
  above the hold anyway is debited what it billed, but its usage receipt says
  `ESCALATE` / `ERR_SPEND_PER_REQUEST_LIMIT` (metadata `overage_cents`,
  `quote_ceiling_cents`, `envelope_closed`) instead of `OK_WITHIN_ENVELOPE`,
  an `ALERT` names the closed envelope, and the envelope refuses further
  dispatch (403 `ERR_SPEND_ENVELOPE_INACTIVE`) in the period of the
  reservation and the period the settlement falls in, also when the
  settlement fails, and across restarts (r2).
- `spend-proxy export --public-key` could report a forged usage line as
  verified: a line's signed payload was the first receipt it carried, while
  the pack took the one its kind named. A line's payload is now strictly the
  one its kind names, and the log is refused when a line carries none, more
  than one or another kind's (helm-tracker#313 r1).
- A released reservation can no longer be settled, and a settlement no
  reservation backs is decided against its envelope; `RemainingCents` and
  envelope validation no longer wrap at the int64 limit (helm-tracker#313 r1).
- A settlement line whose usage line never reached the receipt log no longer
  erases its debit on restart: the dispatch is held at its hold, pending
  reconciliation. The new `spend-proxy reconcile` settles a pending dispatch at
  the provider cost an operator found (`--settle-cents`) or releases it
  (`--release`), with a `--reason`, as signed receipt lines the next start
  replays; without `--intent` it lists the pending dispatches
  (helm-tracker#313 r1).
- A request is debited no more than its hold when the provider bills within
  its quote (helm-tracker#313 r2): the platform fee is inside the hold, and an
  overage is judged against the provider's part of it, so the receipt and the
  `ALERT` blame the provider only when its bill went above that part.
- Closing an envelope after an overage closes the window of the reservation
  and the window the settlement falls in, records them on the usage receipt,
  and a restart closes the same windows; an overage whose settlement fails is
  recorded on its signed `settle_failed` line and closes the envelope across a
  restart (r2).
- `spend-proxy reconcile` no longer releases or understates a dispatch the
  log records the provider billed, works without `--sign` against a proxy that
  ran without it, and refuses to run beside a live proxy (r2).
- An overage whose usage or settlement line never reached the receipt log no
  longer reopens the envelope on restart, and its dispatch is held at the
  cost the log records instead of its smaller hold; a reconciled settlement
  of such a dispatch is debited once (helm-tracker#313 r3). `spend-proxy
  reconcile` clears a dispatch journalled under an earlier key, such as one a
  proxy run without `--sign` signed before this version, where it refused
  with no way out.
- A cache write could bill above the hold: the model gateway prices writes on
  `anthropic` and `openai-compatible` routes at Anthropic's premium unless the
  route names its own, and the spend proxy refuses `cache_control` (r2).
- A stock OpenAI client is served in callers mode, an idempotency key is
  scoped to its caller, `/helm/spend/health` needs the caller token, and the
  bearer scheme is matched in any case (r2).
- Unknown members of parts, items and blocks, and Responses `instructions`
  given as a list, are refused instead of forwarded; `anthropic-beta` no
  longer reaches an upstream on the OpenAI APIs; a start verifies the
  signatures of the lines that debit or free a hold (r2).
- Standalone `core` builds resolve the Go SDK from merged revision `33742a8a`,
  which contains the owner-assertion types. The previous branch-only revision
  could not be fetched from origin.
- `helm-ai-kernel spend-proxy` refuses to start on a non-loopback `--addr`. The
  proxy has no caller credential and spends the upstream provider key for any
  caller that reaches it; `proxy` and `mcp serve` already refused an
  unauthenticated non-loopback bind. `controls.yaml` CTL-026 now covers all
  three listeners and is `enforced`, with removal proofs for the bind check and
  the proxy bearer check.
- `helm-ai-kernel evidence envelope verify` reports `verified` only when it
  loaded the manifest and its payload from the local registry and every check
  ran and passed. Before, any `--manifest-hash` and `--native-root` printed
  `verified: true` for an unknown manifest id, the supplied values were never
  compared with a recorded manifest, and a missing payload was rebuilt from the
  manifest and passed against itself. A check with nothing to compare is now
  `SKIPPED`, which is not a pass: the result is `verified: false` and the exit
  code 1. Clients reading `checks` must accept `SKIPPED` beside `PASS` and
  `FAIL`. The text output lists every check with its status.
- `helm-ai-kernel shadow scan` no longer grades a tree it could not read. A
  `--path` that is missing or unreadable, or a scan that read no file and met
  unreadable paths, is an error with exit code 2; it was grade A with exit code
  0. Unreadable entries below a readable root are counted in the new
  `paths_unreadable` report field, shown in the text report and named in the
  grade reason. `setup`, `onboard` and `autoconfigure` reuse this scan, so they
  no longer record a grade for a workspace that could not be read.
- Lifecycle events that carry `args_hash` are published. The publisher's
  substring screen rejected that allowlisted field, so every
  dispatch-completed event built from a receipt was dropped. The exact
  allowlist now decides, and a test holds every allowlisted name to the
  denied-term list.
- Documentation no longer states behaviour the shipped binaries do not have.
  The execution security model, kernel scope, proxy guides, use-case pages and
  operations notes now say that the standalone proxy signs receipts only with
  `--sign`, that a named delegation session is always denied, that `conform`
  runs gate G0 only, that no command re-executes a run, that only CEL expressions
  in a serve policy pack decide an action, and that the effect reservation and
  close write paths were removed. SDK README examples compile against their
  SDKs and use the authenticated typed evaluation route. Documented commands
  that did not run are corrected, including the EvidencePack export, the MCP
  proof verification, `bundle build` and the provider starter smoke scripts.
- A signed receipt could be edited, with no key, so that `jq` and JavaScript
  read one verdict from it while `receipt_verify` verified another: Go's JSON
  decoder matches member names without regard to letter case, and the
  verifier's duplicate-member check did not. Member names are now matched
  exactly.
- The signature of a `receipt.v5` receipt could be replayed as a legacy
  receipt with a different verdict, and `receipt_verify`, the JavaScript
  verifier, `POST /api/v1/evidence/verify` and the dev-local MCP branch of
  `helm-ai-kernel verify` accepted it. The legacy preimage is eight fields
  joined with `:` with no escaping, so the signed bytes of a `receipt.v5`
  receipt can be read as those eight fields. Legacy receipts are now refused
  unless the caller opts in, an opted-in result says that a legacy signature
  does not cover `verdict`, `tool_name` or `timestamp`, and the replay is
  refused under the opt-in as well, by its `receipt_id`.
- A genuine DENY receipt wrapped as
  `{"verdict":"ALLOW","receipts":[...]}` was `VERIFIED` while `jq .verdict`
  and `JSON.parse` read `ALLOW` from the file. A bundle with a receipt member
  beside `receipts` is now refused.
- `POST /api/v1/evidence/verify` verified a receipt file that says `ALLOW` by
  exact member name and restores the signed `DENY` in `"Verdict"`, or that
  writes `verdict` twice.
- `POST /api/demo/verify` took a request member `"Receipt"` for `"receipt"`,
  so a body whose `receipt` says `ALLOW` came back valid when the genuine
  `DENY` stood beside it as `"Receipt"`.
- `helm-ai-kernel verify` could be made to hide a deleted receipt. Its chain
  checks decoded each receipt with Go's JSON decoder, which binds
  `"PREV_HASH"` to `prev_hash`. With the middle receipt of a team pack deleted
  and `"PREV_HASH"` and `"Lamport_Clock"` appended to the next one, outside its
  signature, the chain read unbroken and the re-sealed pack verified. The
  chain checks now refuse such a file.
- The same team-pack operator could put an unsigned file in the deleted
  receipt's place, declaring the deleted receipt's chain hash in a `hash`
  member and joining its session through `executor_id`, and the re-sealed
  pack verified. The signed successor now links only to an identity the
  verifier recomputes, so it is unreachable from genesis and the pack fails.
  Both fixes hold for a deleted receipt that a signed `receipt.v5` receipt in
  the pack follows. The chain checks do not see the last receipt of a chain
  deleted, and a chain of receipts with no `signature_version` still links
  through declared hashes, which nothing can recompute (security ledger
  F-20). The signature check does not require every receipt file to be signed:
  removing the successor's signature members also removes this protection,
  so the operator can still hide a deletion with one fewer checked signature.
- `helm-ai-kernel evidence correlate-host` read a network receipt that says
  `DENY` by exact member name, with `"Status":"ALLOW"` and
  `"Verdict":"ALLOW"` appended, as allowed, and reported no Boundary Drift
  for host egress after the deny.
- `helm-ai-kernel verify receipt` accepted a file whose only version member
  was `"Signature_Version"`, skipping the `receipt.v5` member checks.
- `receipt_verify` took gigabytes of memory on a small file nested 100,000
  levels deep before refusing it.
- `preimage_version` named only the first receipt's preimage, so a chain of a
  `receipt.v5` and a legacy receipt read `receipt.v5`.
- The `integrity` check of `receipt_verify` no longer says "the signed bytes
  are the bytes on disk". It says what it does, and names the receipt whose
  members outside the signature nothing covers: a single receipt, or the last
  of a chain.
- `helm-ai-kernel verify` reported checks that never ran as passed: a pack
  with no hash manifest, no connector evidence, no EU AI Act profile, no
  receipt chain, no replay gate and no signed receipts printed
  `PASS: 12/12 checks passed`. Every check now ends `VERIFIED`, `FAILED`,
  `UNVERIFIABLE` or `NOT_RUN`, the counts are stated separately, and a
  `VERIFIED` result names the checks it does not cover. Evidence the pack is
  required to carry still fails when missing. The CLI and
  `POST /api/v1/evidence/verify` now derive their outcome with one rule.
- `verify` passed a `manifest.json` that does not parse as "no file hashes in
  manifest". It is now a failed `file_hashes` check.
- Check details no longer say "verified" for field-presence checks:
  `eu_ai_act_profile`, `connector_evidence`, `policy_decision_hashes` and
  `replay_determinism` state what was read and what was not recomputed.
- External host receipt checks with nothing to read (no hardware root claim,
  no declared chain hash, no foreign payload to bind, an unsigned receipt with
  no key required) are `NOT_RUN` instead of passed, in `verify` and in
  `verify external-receipt`, whose text output now prints the passed, failed
  and not-run counts and whose `--json` checks carry a `status`.
- `helm-ai-kernel replay` printed `Replay complete: N entries verified`
  without replaying anything. It now serves every recorded entry back through
  the tape replayer and reports tape misses, values that do not match their
  recorded hash, entry files out of sequence order and every field on which
  the manifest and the tape disagree (`type`, `key`, `size_bytes`,
  `component_id` and any other field the manifest carries, not `sha256`
  alone). It states what `COMPLETE` establishes, that it replays recorded
  inputs and does not re-execute the run, and that it does not check the pack
  seal: a tape and manifest rewritten together replay as `COMPLETE`.
- `verify` reported evidence that is present as absent and left the pack
  `VERIFIED`: replay material in a pack whose `gates` omit or misspell `G2`,
  an EU AI Act profile in a file over 2 MiB, and a damaged report file under
  the host evidence directories. Each is now validated or failed, and a
  `NOT_RUN` reason says what was looked for. A tape states no replay result,
  so `replay_determinism` stays `NOT_RUN` on one that replays without a
  determinism manifest, and says so.
- `verify` hashed files outside the pack: a `manifest.json` `file_hashes` key
  such as `../../outside.txt` was `VERIFIED`. Manifest and index paths are
  now held to one containment rule and are not read outside the pack.
- `verify` read files outside the pack through symbolic links in every check
  that reads a fixed name or walks a directory: a
  `02_PROOFGRAPH/determinism_manifest.json` linked to an outside file with
  equal hashes was read as the pack's own, and a link to
  `/dev/stdin` under `12_REPORTS/` or `11_HOST_EVIDENCE/` hung the command.
  Every check except `roots` and `evidence_pack_seal` now reads through an
  `os.Root` on the pack and refuses links that leave it, absolute links and
  files that are not regular files; the result no longer depends on whether
  the pack path is relative or absolute. `roots` and `evidence_pack_seal`
  refuse named pipes and devices before opening them, as they already
  refused symbolic links.
- `verify` and `replay` disagreed on a tape: under gate `G2` the verifier only
  parsed `tape_manifest.json`, so a sealed pack whose manifest said `NETWORK`
  where the entry said `TOOL_OUTPUT` was `VERIFIED`. The replay now lives in
  `core/pkg/tape` and both run it.
- `verify` and `evidence inspect` disagreed on one pack: a sealed pack with a
  valid `manifest.json` was `FAILED` by `verify` (`unexpected top-level
  entry: manifest.json`) and `VERIFIED` by `evidence inspect`, so
  `--require-check file_hashes` could not be satisfied. Both commands now
  reach the verdict through the same code, and `manifest.json` is a legal
  top-level entry.
- `verify --require-check` given twice kept only the last value, so
  `--require-check chain_integrity --require-check structure` verified a pack
  without a receipt chain.
- Text output of `verify`, `evidence inspect` and `replay` printed
  pack-controlled strings raw: an `envelope_id` with line breaks added a
  forged `VERIFIED` line below the real verdict. Control characters, line
  breaks and terminal escapes are now shown as visible escapes; `--json`
  keeps the raw value.
- `roots` was `VERIFIED` on an `00_INDEX.json` that lists no entries while
  `index_integrity` was `NOT_RUN`. Both are `NOT_RUN` there.

## [0.12.0]

### Upgrade notes

- `helm-gateway` now signs its receipts and needs a signing key: set
  `HELM_GATEWAY_RECEIPT_SIGNING_KEY_FILE`, or `gateway.receipts.existingSecret`
  in the chart. Without a key the gateway does not start.
- Nine verify routes are removed because each one reported a verification that
  could not fail: `/api/v1/replay/verify` and the `verify` operations under
  `/api/v1/boundary/records`, `/api/v1/boundary/checkpoints`,
  `/api/v1/evidence/envelopes`, `/api/v1/evidence/verification-scopes`,
  `/api/v1/sandbox/grants`, `/api/v1/telemetry/harness-traces`,
  `/api/v1/plans/transactions` and `/api/v1/harness/change-contracts`.
  Migration: verify evidence with `POST /api/v1/evidence/verify` or offline
  with `receipt_verify`.
- `POST /api/v1/evidence/verify` has a new response: `outcome` is `VERIFIED`,
  `FAILED` or `UNVERIFIABLE`, and `checks_run` names only the checks that ran.
  Clients reading the former synthesized `PASS` fields must move to it.

### Added

- `helm-gateway` signs a hash-chained `receipt.v5` receipt for every admission
  decision, in the same transaction as the decision, and a receipt for the
  outcome of every admitted effect. Each tenant and workspace pair has its own
  chain.
- `receipt_verify` checks the gateway's own facts against their binding
  documents; `--require-bindings` makes that check mandatory. The gateway
  serves its public keys at `GET /api/v1/receipt-keyring` and exports receipt
  chains for offline verification.
- The standalone offline receipt verifier is now a release asset:
  `receipt_verify-linux-amd64`, `receipt_verify-linux-arm64`,
  `receipt_verify-darwin-amd64`, `receipt_verify-darwin-arm64` and
  `receipt_verify-windows-amd64.exe`, each with a keyless cosign bundle and a
  line in `SHA256SUMS.txt`, from the first release after `v0.11.3`. The
  release staging, the `binaries` job and `make release-smoke` fail when an
  asset is missing, too small, or built for a different operating system or CPU
  architecture than its name states, or when the host build does not verify the
  frozen fixture chain and reject a wrong key and a tampered receipt.
- The release reproducibility check now compares binary hashes. It used to
  compare file names only, so differing builds could not fail it.

### Changed

- First-party skill packs: `helm/repo-auditor` 0.2.0 adds the `name` and
  `description` frontmatter agents need to discover it and tightens its body;
  `helm/codex-multi-agent-director` is removed because agents decompose work
  natively.

### Removed

- SDK clients (Go, TypeScript, Python, Java, Rust) no longer expose
  `approveIntent` (`POST /api/v1/kernel/approve`, which always answers 501),
  `approveMcpServer` or `approveMcpRegistryRecord` (both always answer 503).
  The two MCP registry approve operations are now `deprecated: true` in the
  OpenAPI contract and will be removed in a later release. The Go
  `MCPRegistryApprovalRequest`, Python `MCPRegistryApprovalRequest` dataclass,
  Java `HelmClient.MCPRegistryApprovalRequest` and Rust
  `McpRegistryApprovalRequest` types go with them. Migration: approvals use the
  approval ceremony operations under `/api/v1/approvals`.
- The TypeScript framework helpers in `adapters/agent-frameworks.ts`
  (`createAgentFrameworkAdapter`, `buildGovernedToolRequest`,
  `submitGovernedToolIntent`, `toOpenAIFunctionTool` and the fifteen
  `from*ToolCall` normalizers) are removed. They sent the tool call as chat
  text, so nothing evaluated the named tool. Migration: send tool calls to the
  effect gateway with `NativeGatewayClient`.
- `helm-ai-kernel setup --json` no longer reports `framework_adapters`, and the
  compatibility registry lists no framework adapters.
- Code that no shipped binary reached is gone from the kernel, including the
  WASI sandbox and broker, the SafeExecutor, de-scoped Guardian gates with no
  installer, the approval ceremony effect lifecycle, and dead trust, pack,
  registry, identity SSO, MCP scanner, budget and policy tooling. Controls
  covering removed code are retired in `controls.yaml`.

### Fixed

- `core` now requires `sdk/go` at a commit on `main`. The previous requirement
  named a commit from a deleted pull request branch, so a cold module fetch
  failed.
- Gateway runtime tests no longer hand out the same loopback port twice.

## [0.11.3]

### Fixed

- `core` now requires the published `sdk/go` `v0.11.2` instead of a
  pseudo-version, so a build from a cold module cache resolves it.
  `make test-core-module-closure` downloads `core`'s first-party requirements
  directly into a fresh module cache, without the workspace, and fails when one
  cannot be fetched.

### Release process

- The container, Go SDK tag, npm, crates.io and Maven publishers now wait for
  the PyPI SDK job to succeed.
- The PyPI job refuses to publish a `helm-sdk` version that already exists
  instead of skipping the upload.

## [0.11.2]

### Added

- Gateway GitHub effects `github.pull_request.create`,
  `github.pull_request.merge` and `github.git.push`; the push is bound to the
  exact ref object ID, and an ambiguous merge result preserves custody.
- Shared model budgets with affordable default caps, enforced at the model
  gateway; legacy model writers are fenced across gateway upgrades.
- Gateway reads: the outcome of a principal Stop, an observed-only GitHub
  activity trail with a read API, and authenticated team admission counter
  snapshots readable by the team or its provisioner.
- Signed continuation of retained work attempts, and governed cross-seat work
  reassignment with native fence reads. The SDK declares the current work
  reassignment read.
- Scoped provider recovery fences that serialize with native dispatch claims,
  and an exact recovery version lineage. Recovery rejects token scope
  downgrades, and every checkpoint table is under tenant row-level security.
- Chart: `gateway.serving` selects an independent serving image and executable
  for the gateway Deployment. Migration always uses the shared Kernel image.
- TypeScript SDK: an explicit native MCP effect client that keeps the attempt
  identity of a native refusal.

### Changed

- Go toolchain 1.25.13 to 1.26.9 across the workspace, workflows and builder
  images (#1119), then to 1.26.10 (#1151); `golang.org/x/net` v0.60.0 and
  `golang.org/x/crypto` v0.57.0 clear the govulncheck advisories GO-2026-6599
  through GO-2026-6617. `core`, `sdk/go` and the other modules declare
  `go 1.26.10`, so consumers need Go 1.26.10 or newer.
- A Go dependency batch (41 updates across `core`, `sdk/go`, the test modules
  and tools) raises
  `golang.org/x/net` to v0.61.0 and `golang.org/x/crypto` to v0.58.0, among
  others.
- The slim container image refreshes its Alpine runtime packages, clearing
  current OpenSSL and zlib findings on both architectures.
- TypeScript SDK tooling is refreshed to clear its audit findings (HELM-1030),
  and the development chart catalog metadata is staged accurately (HELM-1031).

### Fixed

- The gateway enforces the custom argument schemas that adapters declare for
  their inputs.
- Dependabot coverage now parses singular and plural directories, including
  globs, and checks every tracked Go module and SDK dependency manifest against
  its package ecosystem (HELM-972).

### Release process

- The `dev-image` workflow also runs on every green `main` commit. It publishes
  a development image and a cosign-signed prerelease chart to
  `oci://ghcr.io/mindburn-labs/charts-dev`; the public chart repository never
  receives a prerelease (HELM-968).
- The govulncheck gate fails on an incomplete scan.
- The release verifies tag-only environment policies (HELM-732) and pins the
  verified Console sidecar for the release.

### Release scope

- Partial publication, fixed forward by 0.11.3. The `v0.11.2` tag, the container
  images, the npm package and the `sdk/go/v0.11.2` tag exist. The PyPI SDK job
  failed, so `helm-sdk` 0.11.2 is not on PyPI and no GitHub Release was created.

## [0.11.1]

### Fixed

- Recover a zero-byte regular `root.key` left on an existing durable volume by
  the published 0.7.2 chart. The authority-state init atomically copies the
  nonempty signing Secret while refusing a nonempty differing key or a symlink.
- Cover the rendered init states and the published-0.7.2 Kind upgrade, including
  key matching and receipt persistence across restart.

## [0.11.0]

### Added

- Gateway `ListAttempts` with bounded, stable paging and filters on state, work
  reference, requester, effect type and episode. It returns `settled_before`,
  the safe resume point for an incremental reader.
- Authority provisioning as gateway effects: `helm.authority.provision.v1`
  applies an organization's whole authority plan behind a distinct human's
  approval, and `helm.authority.narrow.v1` applies a plan that only narrows.
  `AuthorityAdminService` (`EnsurePrincipals`, `GetProvisioning`,
  `ListEffectTypes`) and the effect-type catalog are served on the gateway
  listener.
- Approve accepts a single-use step-up proof bound to the attempt and its
  approval digest.
- A native model gateway with per-call settlement, served by
  `helm-gateway serve` when `HELM_GATEWAY_MODEL_ROUTES_FILE` is set:
  `POST /v1/responses`, `POST /v1/chat/completions` and `POST /v1/messages`.
- A governed MCP mount for episode workers. Effect types are served as MCP
  tools, attempts record their worker episode (`EffectAttempt.episode`), and a
  token with an episode claim reads only its own episode's attempts. MCP effects
  keep a stable work intent across revisions, and schema-bound artifact results
  are retained.
- Chart: optional isolated worker and executor gateway listeners
  (`gateway.worker`, `gateway.executor`), each with its own Service and
  audience, and `gateway.models` for model routes and provider credentials.
  All three are off or empty by default.

### Fixed

- The model gateway reserves the configured cache-read surcharge.

### Release process

- The release waits, within a bounded budget, for PyPI to expose the new
  version before creating the GitHub Release.
- The GitHub Release is created as neither a draft nor a prerelease and is
  marked latest.

## [0.10.5]

### Added

- Exact provider tariffs: a versioned nano-cent price
  (`provider_price_snapshot.v2` and `core/pkg/contracts/economic`) keeps the
  provider's price without rounding.
- Usage and settlement receipts v2 (`usage_receipt.v2`,
  `settlement_receipt.v2`) and EvidencePack spend evidence that verifies exact
  tariff accrual and balanced settlement.
- Gateway provisioning and read contracts (HELM-751): the
  `AuthorityAdminService` wire contract, the `helm.authority.provision.v1` and
  `helm.authority.narrow.v1` schemas, `ListAttempts` and the Approve step-up
  proof field. These are contracts, schemas and documentation only; the gateway
  does not serve them until 0.11.0.

### Fixed

- The chart preserves the gateway bootstrap SQL through kubelet environment
  expansion (HELM-789).

### Release scope

- The `v0.10.5` tag, container images, npm package, PyPI package and
  `sdk/go/v0.10.5` tag exist, but no GitHub Release was created: the release
  run failed at its version check while PyPI's cached index still listed the
  previous version. 0.11.0 makes the release wait for PyPI propagation.

## [0.10.4] - 2026-09-29

### Added

- Pass the authenticated gateway attempt, consumed permit and admitted quote to
  adapters after the dispatch claim commits, and reconstruct that context during
  observation. Effect arguments cannot supply or widen this context.
- Expose the existing gateway lifecycle through `pkg/gateway/runtime.Run` so a
  product-owned binary can register adapters without depending on commercial
  components inside Kernel. The OSS gateway uses the same runtime.

### Validation and scope

- The source change passed all PR and merge-group gates, including PostgreSQL
  proofs, control-removal tests, build/race checks and deployment smoke.
- Paired Control Plane proof traverses authenticated admission, finance, a
  synthetic provider, OrganizationRuntime and durable Console readback. This
  release does not activate a hosted provider or qualify model accuracy.

## [0.10.3] - 2026-09-29

### Fixed

- Generate binary provenance with the upstream-supported SLSA generator version
  tag, bind that tag to its reviewed commit, and verify the signed checksum
  manifest with standard SLSA policy plus exact source and identity checks
  before registry publication.
- Require the existing public documentation release metadata and linked routes
  to pass before publishing immutable artifacts. The final check still requires
  the newly released documentation version.

### Release scope

- Fix forward after v0.10.2 failed final docs acceptance. Its artifacts and
  failed workflow receipt remain unchanged; source changes do not qualify old
  provenance for the standard verifier.
- Reuse the reviewed Console source and preserve gateway and trusted-core
  behavior. Publication and the governed runtime journey remain separate gates.

## [0.10.2] - 2026-09-29

### Fixed

- Wait up to 15 minutes for npm publication to expose both the exact SDK
  version and its `latest` tag before producing the release version receipt.
  Authentication failures, malformed responses and conflicting versions fail
  immediately; an exhausted propagation budget still blocks the release.

### Release scope

- Fix-forward release after npm accepted v0.10.1 but its registry propagation
  outlasted the one-shot version check. Published v0.10.1 artifacts remain intact.
- Reuses the reviewed Console source and preserves gateway and trusted-core
  behavior. Artifact publication and runtime acceptance remain separate gates.

## [0.10.1] - 2026-09-28

### Fixed

- Let Homebrew infer the formula version from immutable release URLs, avoiding
  the strict audit failure that blocked the v0.10.0 tap update.
- Check inferred Homebrew versions in release drift monitoring while rejecting
  mixed release URLs and conflicting explicit versions. The release dry run
  rejects redundant formula version directives before publication.

### Release scope

- Fix-forward release after v0.10.0 published immutable packages and artifacts
  but failed Homebrew delivery. Published v0.10.0 tags and assets remain intact.
- Reuses the reviewed Console source from v0.10.0; gateway and trusted-core
  behavior is unchanged.

## [0.10.0] - 2026-09-27

This minor release introduces the gateway service and typed GitHub effect API.
Publication and the qa-arm walking-skeleton acceptance are recorded separately
in the release evidence and HELM-789.

### Added — governed GitHub effects (HELM-751, HELM-753)

- `helm-gateway` serves Propose, GetAttempt, GetAttemptContent, Approve,
  Reject, Cancel, Dispatch and Observe over the authenticated gateway API.
  Admission resolves mandates and records the attempt, reservation and permit
  in one Postgres transaction.
- `github.repository.get`, `github.branch.create_from_changes` and
  `github.pull_request.create_draft` have typed arguments and observation
  results. A draft PR is medium risk and escalates when the mandate requires
  approval. Approval requires a distinct human and a single-use decide token.
- Dispatch consumes the permit before provider I/O and permits only the
  proposing workload to dispatch. The GitHub App credential stays in the
  gateway; installation tokens request the permissions the effect needs.
  Observe verifies the provider result, while an uncertain dispatch becomes
  UNKNOWN and is reconciled through read-back.
- The release rehearsal checks contracts, version surfaces, Console pins,
  chart configuration and publication prerequisites before tagging, and runs
  daily on main (HELM-745).

### Added — deployable gateway and database bootstrap (HELM-789)

- The release image ships `/usr/local/bin/helm-gateway` beside
  `helm-ai-kernel`. The chart gains a `gateway:` block, off by default, that
  deploys `helm-gateway serve` with TLS, Control Plane identity tokens, a
  NetworkPolicy, and a pre-install/pre-upgrade migrate hook. An optional
  database bootstrap creates the ADR-0004 owner role (`helm_owner`) and runtime
  role (`helm_gateway`) with least-privilege grants
  (`deploy/helm-chart/files/gateway-db`), closes the gateway database to
  PUBLIC, and sets the runtime password only as a client-side SCRAM-SHA-256
  verifier (`helm-gateway db scram-verifier`). Default chart renders are
  unchanged. HELM-789.

### Added — gateway conformance, Stop and durable jobs (HELM-751)

- The versioned gateway conformance pack defines 23 scenarios shared by
  the real gateway and Control Plane fakes. Its runner verifies both the
  declared outcomes and a deliberately flipped expectation.
- River persists escalation-expiry and UNKNOWN-reconciliation jobs in the
  gateway database. Approval and expiry make one transition; reconciliation
  respects the dispatch fence and hands an unresolved final attempt to a
  human. `helm-gateway migrate` installs River's schema and `/readyz` checks it.
- `Stop` blocks new work at tenant, principal, mandate or effect-type scope, checking the
  proposing actor, approval participants and dispatcher at their respective
  transitions. Calls already sent to a provider cannot be retracted.
- Stop and operator Cancel require single-use tokens bound to their exact
  target. Replay of the same idempotent request remains safe; a changed
  principal or payload cannot reuse the recorded result.
- `Lift` creates an escalated, high-risk authority-change attempt. Approval
  fails closed until passkey step-up is available; this release does not
  apply a lift. Other active stops continue to block the attempt.

- Admission rejects a quote that omits a unit counted by a summed mandate
  limit, including zero-cost reads that must quote that unit explicitly.
  Authority-change effects do not consume those limits.

### Fixed — Postgres sessions use UTC (HELM-776)

- Every Postgres DSN pins the session timezone to UTC, so admission and
  approval timestamps remain consistent when the database default uses a
  local timezone.

### Changed — the chart wires the organization-runtime key only with the activation public key (HELM-786)

- New value `helm.auth.controlPlaneActivationPublicKey`: the Control Plane
  activation public key (`HELM_CONTROL_PLANE_ACTIVATION_PUBLIC_KEY`), 64
  lowercase hex characters.
- The Kernel needs that key and `HELM_ORGANIZATION_RUNTIME_API_KEY` together;
  one without the other fails its service init. The chart now renders the
  organization-runtime key only with the activation public key, and refuses to
  render the activation public key without the organization-runtime key.
- A 0.9.0 deployment that set the organization-runtime key without the
  activation public key ran in degraded mode; with this chart it renders
  without the organization-runtime key until
  `helm.auth.controlPlaneActivationPublicKey` is set.

## [0.9.0] - 2026-09-26

Source-prepared v0.9.0 notes for the current Kernel tree. These entries do not
claim tag publication, registry availability, hosted or production telemetry,
customer use, GA status, live OrganizationRuntime proof, or positive savings.
The minor version moves because several public routes, commands and SDK
methods are removed or now answer 501; each is listed below.

### Added — native TLS with optional client certificates; public receipt keyring (HELM-786)

- `serve` listens over TLS when `HELM_TLS_CERT_FILE` and `HELM_TLS_KEY_FILE`
  are both set (TLS 1.2 minimum; the certificate is re-read on rotation). Setting
  only one fails at startup. `HELM_TLS_CLIENT_AUTH=require|verify-if-given` with
  `HELM_TLS_CLIENT_CA_FILE` verifies client certificates. Without TLS
  configuration the listener stays plain HTTP, as before.
- The chart gains `helm.tls.existingSecret` (cert-manager compatible, optional
  client CA; probes follow the scheme) and
  `helm.auth.organizationRuntimeAPIKeySecretKey`. Defaults render as before.
- `GET /api/v1/receipt-keyring` is public and read-only. It returns the public
  half of the running receipt signer in the `kernel-evaluate-receipt-keyring.v1`
  shape the Control Plane pins, and answers 503 when no signer is configured.

### Changed — tenant and principal from the Control Plane token (HELM-755, ADR-0005)

- Phase 1 (dual-accept): the Control Plane-called routes accept a signed
  Control Plane token (`HELM_CP_IDENTITY_*`) that names tenant, workspace and
  principal, and cross-check it against the registered principal binding.
  Header identity keeps working while the Control Plane switches over.
- A principal is bound in one tenant only. Binding it into a second tenant is
  refused with 409 `TENANT_ISOLATION`, except for principals listed in
  `HELM_CROSS_TENANT_PRINCIPALS`.
- Every kernel tenant table has forced row-level security, and the tenant is
  bound at connection checkout.
- The route guard derives from the route registry, every served route is in
  that registry, and forwarded client IPs are trusted only from configured
  proxy CIDRs.
- Launchpad routes are off by default; stores without tenant columns serve
  the configured tenant only.

### Changed — one error model; reason codes as strings (HELM-747)

- Errors are Connect errors carrying one HELM detail with `reason_code` and
  `retryable`.
- Reason codes are open strings generated from the one registry
  (`protocols/json-schemas/reason-codes/reason-codes-v1.json`), not closed enums.
- The `helm.gateway.v1` effect API contract (HELM-751) is published as proto
  and generated Go. No server implements it in this release.

### Security — audit remediation (HELM-734 to HELM-743)

- `proxy` and `mcp serve` refuse an unauthenticated bind to a non-loopback
  address (HELM-741).
- The proxy governs non-streaming tool calls and refuses streams it cannot
  govern instead of passing them through (HELM-739).
- The spend proxy checks idempotency, reserves and applies an output ceiling
  before dispatch (HELM-734).
- Evidence verification requires an explicit trust root, and anchors bind that
  root (HELM-738). The evidence signing seed is per install, no longer a
  published literal (HELM-754).
- The credential keystore binds ciphertexts to their context (AAD) with safe
  rotation and revocation (HELM-754).
- Sandbox secrets stay out of docker argv, receipts and compose defaults
  (HELM-754).
- Skill-pack install and revoke are contained to the repository root (HELM-737).
- Launchpad teardown and cloud launch no longer record outcomes that did not
  happen, and egress is enforced on the dialed IP, not SNI (HELM-740, HELM-735).
- Release signing identities are anchored and the SLSA repair lane is removed
  (HELM-733). Dependencies are bumped and every Go module is scanned (HELM-743).

### Added — protocol and telemetry updates

- MCP 2026-07-28 is served beside the earlier handshake revisions (HELM-710).
- RFC 9421 HTTP Message Signatures, proven against the RFC's test vector
  (HELM-711).
- OTel GenAI: `gen_ai.provider.name` and the upstream `execute_tool` span
  (HELM-712).

### Changed — one stop state for serve, proxy and mcp serve (HELM-780)

Breaking for fenced deployments and for `serve --data-dir`.

- **The freeze follows the data directory.** `serve --data-dir` and
  `mcp serve --data-dir` read `freeze_state.json` from that directory, not
  from `./data` under the working directory. `freeze` and `unfreeze` take
  `--data-dir` to write it there. Without the flag both still use
  `$HELM_DATA_DIR`, then `./data`.
- **The emergency-stop fence reaches `proxy` and `mcp serve`.** With
  `HELM_EMERGENCY_STOP_FENCE_ENABLED` on, both open the same fence store as
  `serve` (`DATABASE_URL`, or the Lite Mode `helm.db` in their data directory)
  and bind `HELM_RUNTIME_TENANT_ID` and `HELM_RUNTIME_WORKSPACE_ID`.
  - They refuse to start without that scope.
  - `proxy --tenant-id` must equal `HELM_RUNTIME_TENANT_ID`.
  - MCP tool calls, including those through `serve`'s `/mcp` gateway, are
    decided for the configured scope. Tenant and workspace names in tool
    arguments no longer reach the fence check.

### Removed — the budget status route and `budget verify`; kernel approve retired to 501 (HELM-780)

Breaking.

- **`GET /api/v1/budget/status` is removed.** It answered a constant
  `enforcer: postgres, status: active`, but no shipped binary wires a budget
  tracker into the Guardian. The route was an implementation route, not part
  of the public OpenAPI contract.
- **`helm-ai-kernel budget verify` is removed.** It printed a constant
  `Budget verification: PASS` without checking anything. `budget list` and
  `budget set` are unchanged; the ceilings they record are not enforced.
- **`POST /api/v1/kernel/approve` always answers 501.** Nothing registered a
  pending approval, so every well-formed submission answered 404 and no
  approval could succeed.
  - The operation stays in the OpenAPI contract, marked deprecated, and will be
    removed in a later release together with the SDK `ApproveIntent` methods.
  - Use the approval ceremony operations under `/api/v1/approvals`.
  - `HELM_APPROVER_PUBLIC_KEYS` is no longer read.
  - `ApproveHandler` in `core/pkg/api` and the approval receipt types in
    `core/pkg/contracts` are removed.

### Changed — MCP gateway receipts in the configured tenant (HELM-780)

Breaking for MCP clients that send tenant or principal headers.

- **`/mcp`, `/mcp/v1/capabilities` and `/mcp/v1/execute` on `serve` bind the
  configured tenant.** They take the same `HELM_ADMIN_API_KEY`, now through the
  configured-tenant gate that `/v1/chat/completions` uses.
  - An `X-Helm-Tenant-ID` or `X-Helm-Principal-ID` header that differs from
    `HELM_RUNTIME_TENANT_ID` / `HELM_RUNTIME_PRINCIPAL_ID` is refused with 403.
  - The gateway is single-tenant. Registered principal bindings do not extend
    it.
- **Gateway decision receipts are written in that tenant.** Before this change
  they were written outside tenant scope, so `GET /api/v1/receipts` could not
  list them. Now it lists them for the configured tenant. A decision without an
  authenticated tenant is refused rather than receipted.

### Fixed — the chat proxy never forwards a kernel credential (HELM-780)

- `POST /v1/chat/completions` forwards `Authorization` to the model provider
  as the provider credential.
- A legacy caller that authenticated with `HELM_ADMIN_API_KEY` as a bearer
  token therefore sent the kernel's key to the provider.
- An `Authorization` value that is the admin, service or organization-runtime
  key is now dropped before forwarding. A provider key sent beside
  `X-HELM-API-Key` is still forwarded.

### Removed — `core/pkg/crypto/tee` and its collateral verifier (HELM-756)

<!-- quantum_posture: this entry names a removed attestation package; it adds no cryptographic control. -->

- `core/pkg/crypto/tee` (the SEV-SNP, TDX and Nitro attesters and appraisal)
  and `core/pkg/crypto/tee/collateral` are removed. Nothing has called them
  since the `tee` CLI was retired.
- `make tee-collateral-verify` and its CI step are gone with them.
- `verify --require-tee` still checks the attestation metadata that receipts
  declare. It never used this package.

### Removed — `workstation certify` and the unrouted trust-key handler (HELM-756)

Breaking.

- **`helm-ai-kernel workstation certify` is removed.** It printed an adapter
  certification (`observe-only`, `enforceable`, `high-risk-effect-capable`)
  that it computed from checked-in fixtures, not from a running adapter.
  - The workstation conformance pack no longer lists it.
  - The adapter levels remain as vocabulary.
- **`TrustKeyHandler` in `core/pkg/api` is removed.** Nothing had routed it
  since HELM-742.
- **`GovernedGateway`'s internal-error response now carries the request.**
  Log lines for that response are therefore joined to their trace.

### Removed — TLA+ specifications not tied to code (HELM-756)

- Seven TLA+ specs are removed: six in `proofs/`
  (`CSNFDeterminism`, `DelegationModel`, `ProofGraphConsistency`,
  `SafeDeprecationMode`, `TenantIsolation`, `TrustPropagation`) and
  `protocols/specs/tla/HelmKernel.tla`. None was tied to the code it
  described; four were never model-checked.
- `proofs/GuardianPipeline.tla` stays and is still model-checked by the `tla`
  workflow. `core/pkg/guardian/spec_roster_test.go` ties its gate set to the Go
  `GateID` declarations.
- The workflow now checks only that spec, and the `tla-tools-hardening` gate
  still guards its toolchain download.
- The Lean proof is unchanged.

### Removed — conformance gates G1–G15 and GX, channels; LaunchKit off by default (HELM-756)

Breaking.

- **Conformance gates.** `helm-ai-kernel conform` runs only G0, build
  identity, which is used for the signed release report (`--profile SMB`).
  - G1–G15, GX, the `CORE`/`ENTERPRISE`/`L3`/regulated/agentic profiles and
    `--level L1|L2` are retired: no EvidencePack could pass G1 and G7
    together, and several gates passed without checking anything.
  - `--level` still parses, but exits `2` and points to
    `conform vectors --json`.
  - `conform vectors`, `conform negative` and `conform managed-agents` are
    unchanged.
- **Channels.** `core/pkg/channels`, `channel_gateway` and
  `core/pkg/packs/antispoof` are removed; nothing called them.
- **LaunchKit.** `helm-ai-kernel up` is off by default. Set
  `HELM_LAUNCHKIT_ENABLED=1` to run it.

### Removed — the MCP rug-pull detector, the caller-supplied schema pin and the `tee` CLI (HELM-756)

Breaking.

- The `RugPullDetector` in `core/pkg/mcp` is removed. No code path called
  it, and `mcp-bundle.json` no longer advertises `rug-pull-detection`.
- The MCP firewall no longer reads a caller-supplied schema pin, because the
  same caller supplied both the schema and its pin, so the check bound
  nothing.
  - `mcp authorize-call` no longer escalates a call that omits a pin. It
    still denies a tool schema that is not valid JSON Schema.
  - `--pinned-schema-hash` and `mcp wrap --require-pinned-schema` are still
    accepted, so existing scripts keep parsing, but both are ignored and
    `--require-pinned-schema` defaults to `false`.
  - The HTTP request field `pinned_schema_hash` is deprecated and ignored.
    The discovery field `schema_pin_required` is deprecated and always
    `false`.
- `helm-ai-kernel tee` and the `tee-collateral` command are removed, along
  with the `tee-collateral` workflow. `make tee-collateral-verify` still runs
  the collateral package tests.

### Removed — verification outputs that no check produced (HELM-742)

Breaking. These commands and routes reported PASS, verified, certified or
revoked without running the check they named:

- `helm-ai-kernel certify` is removed. It printed `CERTIFICATION PASSED` for EU
  AI Act, HIPAA, SOX and GDPR from file-name and field-name matching.
- `helm-ai-kernel gui receipts verify` is removed. It recomputed the receipt
  hash instead of comparing it, and GUI action receipts carry no signature.
- `POST /api/v1/conformance/run`, `GET /api/v1/conformance/reports` and
  `GET /api/v1/conformance/reports/{report_id}` answer `501`. They returned a
  fixed PASS, and the list route persisted one. Use `helm-ai-kernel conform`.
- `POST /api/v1/trust/keys/add` and `POST /api/v1/trust/keys/revoke` answer
  `501`. They changed a process-local registry that no verifier reads.
- `POST /api/v1/gui/receipts/verify` answers `501`.

The six operations stay in the OpenAPI contract marked `deprecated` so the
breaking-change gate permits removing them in a later release. The Console
surface catalog marks the Conformance and Trust Keys surfaces `unsupported`.

### Changed — the agent risk scan is its own binary, `helm-risk-scan` (HELM-756)

Breaking.

- `helm-ai-kernel scan` and `helm-ai-kernel verify-scan` move to a separate
  binary built from `tools/riskscan`:
  - `helm-risk-scan scan` takes the same options, except `--upload`,
    `--upload-url` and `--yes`, which are removed;
  - `helm-risk-scan verify` replaces `verify-scan`.
- For one release the kernel keeps both old commands as stubs. They print the
  new command and exit `2`.
- Nothing leaves the machine any more: no service in the target architecture
  receives the upload.
- The default salt file keeps its location, so pseudonyms stay stable.
- The EvidencePack producer that only the scan used moves out of
  `core/pkg/executor` with it.

### Removed — the six retired verification routes (HELM-756)

Breaking. The six operations that answered `501` since HELM-742 are no longer
routed; they now answer `404`. They also leave the OpenAPI contract.

The routes are:
- `POST /api/v1/conformance/run`;
- `GET /api/v1/conformance/reports` and `GET /api/v1/conformance/reports/{report_id}`;
- `POST /api/v1/gui/receipts/verify`;
- `POST /api/v1/trust/keys/add` and `POST /api/v1/trust/keys/revoke`.

The SDK methods that called them are removed:
- Go: `ConformanceRun`, `GetConformanceReport` and `ListConformanceReports`;
- TypeScript and Java: `conformanceRun`, `getConformanceReport` and
  `listConformanceReports`;
- Python and Rust: `conformance_run`, `get_conformance_report` and
  `list_conformance_reports`.

The Console surface catalog drops its Conformance and Trust Keys entries. Run
conformance with `helm-ai-kernel conform` against an evidence pack.

### Changed — verification commands require a trust root (HELM-742)

Breaking for scripts that relied on the old defaults:

- `log verify-consistency` requires `--old-root` and `--new-root`. It no longer
  falls back to the roots embedded in the proof.
- `export aat --verify` requires `--public-key`. Every record must carry an
  `Ed25519` signature by that key; unsigned, re-signed and empty chains fail.
- `tee verify` always requires the vendor signature chain. The CLI configures no
  vendor roots, so vendor quotes now fail closed with the reason instead of
  reporting `ok` for a quote whose signature was never checked.
- `POST /v1/chat/completions` answers `500` and does not forward the request
  when the decision receipt cannot be persisted.

### Changed — EvidencePack verification requires an explicit trust root

`helm-ai-kernel verify` no longer reads `helm/helm.yaml` from the working
directory. Its trust root comes from `--config`, `HELM_EVIDENCE_TRUST_CONFIG`,
or the operator's own data-dir trust config. A pack whose signer no trust root
names is reported `UNVERIFIABLE`, not verified. Embedded receipts are checked
under the same profile as the seal. Anchor receipts must name the pack root: the
Rekor entry hash and integrated time, or the RFC 3161 message imprint.
`evidence inspect` needs `--allow-self-attested` for a self-attested pack.
`verify decision-receipt` reports a bundle-disclosed key as `UNVERIFIABLE`.
`spend-proxy savings-verify` needs `--issuer-key-id` and `--issuer-public-key`
to report `ok=true`. This entry does not claim a tagged release.

### Changed — policy-head signature source contract

The unreleased `policy/reconcile.SignatureVerifier` source contract now verifies
the complete versioned unsigned policy head through `VerifyPolicyHead`. Existing
bundle-only signatures and `VerifyPolicyBundle` implementations must migrate
before adopting this source revision. This entry does not claim a tagged release
or production deployment.

### Changed — production policy replay persistence

Production policy reconciliation now persists private, atomic per-scope epoch
and policy-head commitments before activating a snapshot, so restart does not
erase rollback and equivocation detection. The chart requires a persistent data
volume and one Kernel writer in production until this watermark uses a
distributed transactional store. Production rollouts use `Recreate` to avoid
overlapping old and new writers, restores the watermark's private mode after
Kubernetes `fsGroup` processing, and retains the higher in-process replay floor
when a post-rename directory sync cannot confirm durability. The shipped
production runtime rejects `mountedFile`, whose filesystem timestamp is not a
source-owned monotonic publication epoch. This entry does not claim a tagged
release or production deployment.

### Changed — workstation hook fails closed on shell expansion

The pre-tool hook's shell classifier now routes ANSI-C and locale quoting
(`$'...'`, `$"..."`), brace expansion, command and process substitution that
runs anything outside a small read-only allowlist, globs or variables in
command position, globbed write targets, and writes after an unresolvable `cd`
through the signed decision path instead of passing them without a decision.
A substitution that only runs allowlisted read-only commands on literal input
(`cat` of a heredoc, `date`, `git rev-parse`, `git log`, `pwd`,
`basename`/`dirname`, `printf`/`echo`) yields an opaque word, so the usual
`git commit -m "$(cat <<'EOF' ... EOF)"` still passes, while that word stays
fail-closed in command position, `eval`, `sh -c`, `source`, redirect targets
and destructive operands. Sensitive write targets are normalized before matching and
share one list between the Write tool and shell writes; the list now includes
SSH `authorized_keys`, shell startup files, `.gitconfig`, cron, sudoers,
`.claude/settings.local.json` and the Hermes/DeepSeek hook files. The HELM MCP
self-exemption matches the installed server name exactly, and the Claude Code
matcher adds `NotebookEdit`. Commands that use the decided forms are denied
under the default profile unless a policy profile grants the shell or file
permission. The hook remains an
observed-only integration; see
[workstation governance](docs/reference/workstation-governance.md#coverage-label-observed-only).

## [0.8.5] - 2026-08-23

Source-prepared v0.8.5 notes for the current Kernel tree. These entries do not
claim tag publication, registry availability, hosted or production telemetry,
customer use, GA status, live OrganizationRuntime proof, or positive savings.

### Added — local Prometheus and OTel metrics surfaces (HELM-477)

Local configured scrape surfaces compose existing governance families with
`otelhttp` request RED and Go/process runtime families. Guardian and effects
decision/execution instruments are wired to real local paths with bounded
attributes. This is local observability source and test coverage, not a hosted
or live production telemetry claim.

### Added — paired-replay savings EvidencePack (HELM-618)

The first salvaged paired-replay EvidencePack and its offline verification path
are retained as source-owned evidence. Its parity verdict is negative and its
savings claim is invalid, so no savings, customer, or production result is
implied.

### Changed — Go toolchain and SDK security maintenance (HELM-607)

Source-owned Go modules converge on Go 1.25.13, `cel-go` 0.30.0, and
`klauspost/compress` 1.18.7. SDK TypeScript and Rust lockfiles refresh patched
transitive dependencies. These are source maintenance changes, not publication
or registry claims.

### Changed — Console-sidecar and Quickstart release preflight (HELM-651)

The v0.8.5 Console-sidecar pin records the exact source contract, including
commit/tree, package-lock digest, and workflow reference. Quickstart Console
`--dry-run` shares the real path's read-only trusted-bundle preflight: missing
or untrusted bundles fail before mutation, while a trusted bundle succeeds
without mutation.

### Changed — v0.8.5 source/version preparation

The source-owned `VERSION`, generated release surfaces, and release checks are
prepared for v0.8.5. This is a release-preparation state, not a published
release or deployment claim.

### Added — security instrument operator TUI

On an interactive TTY, bare `helm-ai-kernel` (aliases `tui` / `ui` /
`dashboard`) opens a full-screen operator session. Escape hatches:
`HELM_NO_TUI=1`, `TERM=dumb`, pipes, `--help`, `--json`. Ceremony requires
typing `APPROVE` or `DENY`; click / digits / Ctrl+O never decide. Listeners
(`server`, `serve --policy`, `proxy`, `receipts tail`, non-dry-run
`quickstart`/`onboard`, non-help `scan`) are refused in-TUI. Empty
composer argv uses the same fail-closed defaults as the palette.
`policy init` and `scaffold` require a full-invocation confirm (they write
`policies/` / `helm/`).
No upgrade CTA, YOLO, or GA copy on this surface.

### Added — catalog `--format text|json` contract

Operator-data commands reject unknown `--format` values before work (exit 2).
Legacy `--json` remains an alias. Collision verbs (`verify`, `import`,
`skills`) keep domain `--format` meanings. Listeners and `tui` are document-
exempt. `help --json` is the stable machine catalog.

### Changed — receipts canonical inspect verbs

`receipts status|list|show|verify|export|tail` is the canonical inspect
surface. `status` / `list` / `show` are bounded HTTP; `tail` is SSE and
listener-class in the TUI; `verify` / `export` alias existing routes. None
invent evidence.

### Changed — setup client lifecycle projection

`setup status` reports `client_state` and projected `lifecycle`
(`absent` / `planned` / `pending` / `configured` / `active` / `degraded` /
`repairable`). Only `native_loaded` is an active claim; Cursor / Windsurf /
VS Code never claim native load. Doctor and setup repair suggestions stay
inspect-first and `--dry-run`; they do not recommend `--yes`.

### Changed — doctor agreement

Doctor JSON reports PASS / WARN / FAIL with a `healthy` boolean. Exit 0 =
no WARN/FAIL; exit 1 = WARN only; exit 2 = FAIL. Suggestions point at
`setup status` and `setup repair … --dry-run`.

### Changed — explicit opt-in for locally self-attested EvidencePacks

`helm-ai-kernel verify` continues to reject self-attested EvidencePack seals by
default. Commands generated by local demos, `mcp proof`, and dev-local Launch
flows now include `--profile dev-local --allow-self-attested`; this accepts
internal consistency without claiming provenance. The demos also execute that
CLI verification before printing completion.

### Fixed — executable mounted-policy chart example

The Helm chart smoke fixture now scopes `file_read` through the runtime CEL
path `input.effect.params.path`. The gateway regression test executes that same
path-scoped rule and keeps other paths and tools fail-closed.

### Fixed — governed MCP lifecycle closure and GitHub dispatch wiring

Governed MCP calls rejected at the REST or JSON-RPC ingress boundary now emit
one `helm.request.received.v1` and one `helm.request.failed.v1` event without
reaching policy evaluation or a tool handler. The Helm chart can also activate
the existing signed-permit GitHub effects runtime through an existing Secret;
the snapshot-bound gateway path now registers those configured tools instead of
dropping the effects runtime. Raw GitHub tokens are never accepted as chart
values, and the default remains off.

### Added — offline Kernel receipt.v5 file verify (Building)

Evaluate persist writes a copyable `receipt.v5` JSON file under
`<data-dir>/receipts/evaluate/<receipt_id>/` plus `expected-ed25519.pub`.
`helm-ai-kernel verify receipt --receipt <file> --trusted-public-key-file <key>`
verifies that file offline. Exit 0 requires integrity and signer trust
against the caller-supplied key. Hop fixtures are labeled DENY / no permit.
This is Foundation/offline verify, not AI OS live, not helm-ai-kernel#859,
and not self-attested EvidencePack verification.

### Added — setup deepseek fail-closed hook target

`helm-ai-kernel setup deepseek` writes a Kernel `PreToolUse` hook file and
points the stock DSH `dsh-hooks-claude-code` bridge `configPath` at that
file. DeepSeek stays an adapter on Kernel: not a Cordis plugin, not a new
harness, and not a HELM-native agent runtime. DENY keeps native
`{"kind":"deny"}` on stdout and exit 2, and writes the same reason on
stderr. DSH `parseHookOutput` blocks on exit 2 and reads the reason from
stderr; `{"kind":"deny"}` is never read. This does not claim
`npx @deepseek-ai/dsh web` already sees DENY.

### Added — chart-managed mounted-file runtime rules

The Helm chart can render explicit `helm.policy.runtimeActions` into its
reference pack for governed bootstrap and synthetic-stand policy proof. The
default remains an empty fail-closed rule list; operators should prefer a
signed control-plane or CRD policy source.

### Added — daemon semantic escalation threshold

The daemon and Helm chart can configure the Guardian's existing semantic
threat escalation threshold in basis points. Zero remains advisory-only;
positive thresholds return ESCALATE before dispatch when semantic assessment
is unavailable, truncated, or meets the configured score.

### Added — tenant-scoped receipt query predicates

`GET /api/v1/receipts` can filter the authenticated tenant's V5 receipts by
verdict, reason code, principal/executor, effect/resource, and an RFC3339Nano
half-open time window with at most nine fractional-second digits. Verdict,
reason code, and effect are receipt-signature fields; principal and timestamp
are causal-chain-bound projections, and the listing does not prove
completeness. Canonical rows fail closed if any filter projection differs from
the hash-verified receipt envelope.

### Fixed — daemon correlation propagation

The shared HTTP edge now adopts or mints `X-Helm-Correlation-ID`, echoes the
canonical value, carries it into governed MCP lifecycle events, and stamps it
on the active server span. This closes the daemon path that bypasses the
embedded API server's equivalent correlation edge.

## [0.8.4] - 2026-08-12

Published GitHub Release for the receipt tenant-isolation fix, the corrected EU AI Act
applicability mapping, and a sweep of public claim corrections. v0.8.3 completed
its publication, so this is an ordinary successor rather than another attempt at
a stranded train.

Note for anyone reading the published v0.8.3 notes: its changelog states that
deployed MCP gateway receipts land "into the same store `GET /api/v1/receipts`
reads". That was not true when it shipped and is corrected below. The v0.8.3
artifacts are in immutable registries and cannot be reissued, so the correction
lands here rather than being rewritten there.

### Added

- The GitHub connector executes through the governed MCP bridge on a shipped
  path, so a connector dispatch is subject to the same permit and receipt
  contract as any other governed effect.
- The daemon serve path is traced: a span for the request, the matched route,
  and a flush on shutdown, so a deployed kernel's request path is observable
  without attaching a debugger.

### Fixed

- **Receipt reads are tenant-isolated (HELM-363).** Tenant-authenticated receipt
  HTTP APIs, Console receipt views, and onboarding state and export now exclude
  unscoped and foreign-tenant rows. Onboarding receipts are written into the
  authenticated tenant's scope rather than left unscoped.
- **Corrected claim, same issue:** receipts persisted by the deployed MCP
  gateway are durable and signed but are **not** retrievable through
  `GET /api/v1/receipts`. The gateway routes run under admin authentication,
  which establishes no tenant binding, so those rows are written unscoped by
  design while that route reads only tenant-scoped rows. Local operators with
  direct store access can still include them in offline report and rollup
  workflows. Making them tenant-retrievable requires moving the gateway to
  tenant-scoped auth, a breaking change for MCP clients, still open on HELM-363.
- Daemon output stays structured by default instead of degrading to
  unstructured lines, so log collection does not depend on a flag.
- The CLI no longer overstates what it can do: corrected contract and setup
  narrative, and discovery paths that no longer write state as a side effect.
- The Helm chart's authority initialization accepts a verified pre-existing root
  key instead of failing, so re-running an install against provisioned authority
  no longer requires deleting it first.
- `receipt_verify` CLI contract tests run in the default test gate rather than
  only in a profile nobody invokes locally.

### Changed — public documentation corrected against its own evidence

This release removes several documented capabilities that did not exist. Each was
found by checking a page against the code or evidence file it cited, and the
correction is a removal or a restatement, not a new claim:

- Reference-pack documentation described fixtures as runs, and its documented
  verify command did not work.
- `canonicalization.md` documented a Rust crate that has never existed; the cgo
  bridge to that crate is deleted.
- The conformance guide described an external-implementation runner that does not
  exist.
- `canonical-json-v1` §6.2 cited an unimplemented page as normative.
- `policy-bundle-v1` documented a bundle layout and CLI that do not exist.
- Six stale status claims elsewhere disagreed with the evidence files they
  pointed at.

### Changed — EU AI Act mapping and applicability dates corrected

Regulation (EU) 2026/1744 deferred Chapter III, Sections 1-3 of Regulation
(EU) 2024/1689 to 2027-12-02 for Annex III systems and 2028-08-02 for Annex I
systems, expressly excluding Article 6(5). This narrow amendment does not move
Article 50, Article 73 incident reporting, or CE-marking/registration provisions
outside Sections 1-3 to the same dates.

- Added `reference_packs/eu_ai_act_high_risk.v2.json` as an explicit
  `COMPLIANCE_MAPPING`. It contains candidate mappings and evidence names but no
  supported `runtime_actions` or `actions`; the sample policy therefore remains
  fail-closed with zero runtime rules.
- Preserved the previously released
  `reference_packs/eu_ai_act_high_risk.v1.json` byte-for-byte at SHA-256
  `8a33ad51441d6d939d74da2be388c1d11c12da1e055f1aeca72ca2763ebc05c4`.
  Supersession metadata lives in v2 and documentation, not a rewritten v1.
- Split general, Article 50, Annex III and Annex I applicability dates. The v2
  mapping records the Article 50(2) transition for specified pre-existing
  systems and the Article 6(5) exception.
- Corrected serious-incident reporting from Article 62/72 hours to Article 73:
  15 days generally, two days for the specified accelerated tier, and 10 days
  where a person dies. The compliance API now records the incident tier.
- Removed unsupported pack-driven QTSP, LOTL freshness and budget enforcement
  claims. QTSP is an optional evidence mapping; operator/library verification
  remains a separate explicitly configured path.

Primary sources: CELEX 32024R1689 and CELEX 32026R1744 on EUR-Lex.

## [0.8.3] - 2026-08-09

Completing release target for the v0.8 train. v0.8.0, v0.8.1 and v0.8.2 all
stopped before their GitHub Release and full asset set; none is a completed
public release and none may be described as one. Their partial public records
are permanent and are the reason this train advances the version rather than
reissuing one.

The local Console closure is bound to a distinct v0.8.3 Console workflow tag
while retaining the exact reviewed source pin that built green for the v0.8.1
train (`app-helm-console` commit `c0fd6b446`, sidecar `0.2.1`) — the same
practice recorded for v0.8.1. Console `main` has moved since; folding those
changes into a release whose scope is completing a stranded train would widen
it through a packaging path never exercised on that tree.

### Added

- `EffectPermit` is signed on issuance under the `effect_permit.v1` preimage
  and verified fail-closed before any connector executes: an unsigned permit,
  a permit whose scope or expiry was rewritten after signing, an expired or
  replayed permit, and a permit bound to another connector are all denied.
- `evidence_bindings` has a wire representation in the effects proto, so a
  signed permit keeps verifying after crossing a process boundary. Every
  language binding carries the field.
- A pre-tag `console-sidecar-pin` quality gate requires a Console source pin
  row for the checked-in `VERSION` in the pr, merge and release profiles. The
  release job reads the pin file from the tag commit, so a row missing at tag
  time strands the tag permanently; the gate catches it while it is still one
  line in a pull request.

### Fixed

- The release preflight requires the tagged commit to be reachable from
  `main` rather than identical to it. Requiring identity made a tagged release
  uncompletable as soon as anything merged, which is how v0.8.1 was stranded.
- The CLI refuses to exercise authority it was not given: `approvals
  approve`/`deny`/`assert` no longer default the actor, receipt or approval
  id (a bare `approvals approve` used to approve the bootstrap ceremony and
  attribute it to a principal that does not exist), an unrecognized flag no
  longer starts the server or mints a trust root in the working directory,
  and asking any boundary surface for `--help` no longer seeds or rewrites
  authority state on disk.

## [0.8.2] - stranded, superseded by 0.8.3

Tagged at `7d63fb8c1` and permanently bound to that commit by the Go checksum
transparency log and a Sigstore build-provenance attestation before the
release run failed: the tagged tree carried no Console source pin row for
v0.8.2, and the pin file is read from the tag commit. The tag cannot be moved
without falsifying those records, and no GitHub Release or asset set exists.
The permit-signing and wire-representation work first described under 0.8.2
ships in 0.8.3.

## [0.8.1] - stranded, superseded by 0.8.2

Corrective release target for the completed v0.8 feature train. The v0.8.0
aggregate publication was incomplete: it has no GitHub Release or complete
source-owned asset set, so it must not be described as a completed release.

### Changed

- Retargeted the lockstep CLI, chart, SDK, OpenAPI, and release documentation
  surfaces to v0.8.1 without rewriting any previously published version.
- Bound the local Console closure to a distinct v0.8.1 Console workflow tag
  while retaining its exact reviewed source pin.

## [0.8.0] - incomplete publication

Release preparation record only. The `v0.8.0` aggregate release did not finish
its required asset and provenance gates, and is not a completed public release.

<!-- quantum_posture: v0.8.0 continues classical Ed25519 (and optional ML-DSA-65 hybrid) signatures and SHA-256 content hashes; no new post-quantum cryptographic control is added. -->

### Added

- Guided first-run journey: `helm-ai-kernel setup` front door with read-only
  discovery modes, `--quickstart` local first-run proof path (Claude Code,
  Codex, MCP, and OpenAI-compatible profiles), and `setup install`, `status`,
  `repair`, and `remove` leaf commands with idempotent repair and removal.
- Release-gated local Policies and Receipts Console packaging: a
  Console-including artifact can serve the pinned, digest-verified sidecar
  against the loopback Kernel; source and headless packages fail closed.
- `decision_record.v4` signing preimage binding the evaluated authorization
  tuple (subject, action, resource) and the selected signature algorithm;
  execution authority is restricted to V4 decisions while V2/V3 records remain
  verifiable as evidence.
- Signed `receipt.v5` contract: session-scoped causal receipt chains with
  durable chain hashes, tenant-scoped reads, and semantic `decision_hash`
  persistence; older rows recover only from already-stored trusted metadata and
  otherwise fail closed.
- EventMeta v2 catalog and source-projection helpers for the eight lifecycle
  event types. Runtime emission and telemetry export are not claimed by this
  release entry.
- Deterministic semantic threat-advisory classifier for `threatscan`
  (advisory-only; no policy verdict depends on it).
- Governed capability registry enforcement in Guardian: undeclared
  capabilities cannot execute.
- Desktop authenticated transport v1 for local client integrations.
- Model-actionable deny feedback: ActionInbox deny receipts carry structured
  remediation, cascade-reject, and a doom-loop breaker for repeated denied
  retries.

### Changed

- Every command and subcommand serves side-effect-free `-h`/`--help`; help,
  preview, and dry-run paths cannot mutate state; destructive actions require
  explicit, unambiguous targets and never execute from typo or missing
  authority.
- Human terminal output uses the accessible HELM terminal design system;
  non-TTY, `NO_COLOR`, `TERM=dumb`, and `--json` outputs remain plain and
  stable for automation.
- First-party SDKs (Go, TypeScript, Python, Java, Rust) regenerate from the
  v0.8.0 contract; the served evaluate envelope preserves both the v0.7.5
  `action`/`resource` shape and the V5 `tool`/`effect_level` shape, so v0.7.5
  clients keep working unchanged.
- Kernel library packages no longer pull the OpenTelemetry SDK; correlation
  uses a narrow internal package (HELM-460).
- The canonical executable is `helm-ai-kernel`; release artifacts, the
  Homebrew formula, and documentation do not ship a `helm` executable, so the
  binary cannot collide with Kubernetes Helm on PATH.

### Fixed

- Workstation guard governs previously missed destructive paths, and SafeDep
  emergency activation is bound to the verified execution intent snapshot.
- Deployed MCP gateway enforces the reconciled policy snapshot, so mounted
  reference-pack `runtime_actions` compile into ALLOW rules on the served
  enforcement path instead of staying fail-closed `NO_POLICY_DEFINED`
  (HELM-362).
- Deployed MCP gateway persists a signed, durable receipt for every governed
  decision (ALLOW and DENY). These receipts are written unscoped and are **not**
  retrievable through `GET /api/v1/receipts`: the gateway routes run under
  admin authentication, which establishes no tenant binding, while that route
  reads only tenant-scoped rows. Tenant-authenticated receipt HTTP APIs,
  Console receipt views, and onboarding state/export exclude unscoped and
  foreign-tenant rows; onboarding receipts are written into the authenticated
  tenant scope, and state/export query the latest proof for each onboarding
  step without a fixed total-receipt window. Missing tenant-scoped store
  capabilities and proof-read failures fail closed instead of rendering
  successful-looking empty state. Local operators with direct access to the
  Kernel SQLite database can still include unscoped rows through the offline
  `report` and `rollup` commands, which intentionally operate on the local
  store rather than an HTTP tenant principal. Tenant retrievability for MCP
  gateway clients would require moving the gateway to tenant-scoped auth, a
  breaking change still open on HELM-363.
- MCP OAuth scope enforcement applies only when the gateway runs an OAuth
  channel; with `auth_mode: none` the scoped governance tools (`helm.verify`,
  `helm.evaluate`) are reachable and policy remains the fail-closed enforcement
  boundary (HELM-364).
- Contract-breaking CI gates fail closed instead of skipping on
  misconfiguration.

## [0.7.5] - 2026-07-23

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.5>.

<!-- quantum_posture: v0.7.5 records use classical Ed25519 signatures and SHA-256 content hashes; none add a post-quantum cryptographic control. -->

This section was backfilled during v0.8.0 release preparation; v0.7.5 shipped
without a changelog entry.

### Added

- `correlation_id` identity slice of the telemetry contract with otelhttp
  edges and a context-aware structured-log handler (HELM-325, HELM-333).

### Changed

- `golang.org/x/text` updated to v0.39.0 across the module graph (HELM-354).
- Receipt integrity documentation separates receipt integrity from signer
  trust (HELM-231).

### Fixed

- Workstation signer setup fails closed (previously could proceed unsigned).
- Release-permit workflow accepts a pinned workflow SHA.
- Proxy SSE correlation echo and observability follow-ups (HELM-325/333/345).

## [0.7.4] - 2026-07-21

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.4>.

<!-- quantum_posture: v0.7.4 records use classical Ed25519 signatures and SHA-256 content hashes; none add a post-quantum cryptographic control. -->

- Added the **Boundary Enforcement Profile**. `helm-ai-kernel boundary profile compile`
  emits systemd hardening drop-ins, a default-drop nftables ruleset,
  cgroup limits and device permits from a hash-bound `boundary_profile_input.v1`
  document, sealed by a signed `profile_compile_receipt.v1`. These are text
  artifacts an operator applies with `systemctl` and `nft`: the host's own
  systemd and nftables do the enforcing, and the kernel gains no enforcement
  mechanism of its own — no eBPF program, seccomp filter, TPM binding,
  hardware enclave, or in-process packet filter. HELM compiles and attests;
  the OS enforces.
- `boundary profile attest` reads live OS posture (systemd unit properties, the
  nftables ruleset, cgroup-v2 limits) and emits a hash-sealed
  `posture_attestation.v1` recording `MATCH` or `DRIFT` with per-check
  expected/observed diffs. `--enforce` exits non-zero on anything but a sealed
  `MATCH`, so a systemd dependency can refuse to start the gateway. Drift is
  attested at service (re)start and on demand, not monitored continuously.
- `boundary profile verify` verifies a compile receipt, artifact set and
  attestation entirely offline; `boundary profile bundle-verify` verifies a
  signed offline update bundle against an `update_bundle_manifest.v1`. The
  update-bundle surface is a format and verifier only — no build tooling and no
  OTA mechanism.
- Added sealed-appliance reference units under `deploy/appliance/` (a short-lived
  privileged attestation oneshot gating a fully unprivileged gateway) and the
  deployment guide `docs/deployment/boundary-enforcement-profile.md`.
- Added four `protocols/json-schemas/boundary/` schemas (profile input, compile
  receipt, posture attestation, update-bundle manifest) with schema-parity tests
  binding them to the Go validators, plus two cross-runtime golden vector packs
  (`boundary-profile-v1`, `update-bundle-v1`) verified by independent Python
  implementations and wired into `make verify-fixtures`.

## [0.7.3] - 2026-07-20

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.3>.

<!-- quantum_posture: v0.7.3 release notes cover Ed25519 workstation receipt signer trust hardening plus approval, connector-effect, launch-contract, and release-permit signing; all signatures remain classical Ed25519; none add a post-quantum cryptographic control. -->

- Removed the derivable observe-only workstation receipt signing fallback.
  Receipt minting now requires a persistent per-data-dir Ed25519 signing key
  (0600 file, O_EXCL-created); signing paths hard-error on an empty seed, and
  the MCP bridge maps a missing seed to a fail-closed `PDP_ERROR` deny.
- The retired derivable signer key is permanently rejected as a trust anchor,
  including when a caller explicitly pins its public key.
- Receipt verification separates integrity from trust: the JSON summary
  renames `signature_valid` to `integrity_valid` and adds `signer_trusted`
  and `trust_anchor`. `workstation view` and `verify-decision` now exit 1
  unless the signer is trusted; legacy-signed receipts still load and report
  `integrity: true, trusted: false` with no silent upgrade.
- Pre-tool hooks fail closed on signer or receipt-persistence failure: a
  structured deny is emitted (exit 0), and exit 2 blocks only when the deny
  JSON itself cannot be written. Safe commands never touch the signer, and
  HOME-less setups fail closed without creating CWD-relative keys. Setup
  migration deduplicates legacy hook entries and provisions the key on first
  classified call.
- Established a durable approval foundation: approvals bind source-owned
  grants to a signed assertion contract, verify a trusted-signer quorum, and
  carry durable ceremony authority with sealed store read authority.
  Consumption of an approval grant is fenced, and dispositions move over an
  authenticated transport with signed active-work disposition records.
- Hardened the connector effect lifecycle: effects are reserved before
  dispatch, dispatch admission is fenced, connector authority is bound to
  approvals, certified connector release authority is persisted, and effects
  close with signed evidence.
- Added universal workload and cloud route contracts and fail-closed launch
  effect preview contracts: prepared executions are sealed, credentials stay
  inside the runner boundary and are deferred until dispatch, unsupervised
  detached execution is rejected, authorization is bound to the signed effect
  digest, previews cannot dispatch effects or reuse credits, and routes are
  bounded by certification expiry.
- Added a persisted principal↔tenant binding registry (SQLite and Postgres)
  with an admin endpoint, so the kernel can authorize multiple tenants
  instead of a single environment-configured pair.
- Added the `helm connect` device-code cloud flow, including headless Codex
  project connection; Desktop Codex sidecar readiness is now certified before
  use, and launch tokens and config links are contained to the project
  workspace.
- Added a deterministic autonomous release permit: reviewer identity is
  canonicalized, case-folded self-review and merge self-pins are rejected,
  and authority generation lineage is bound.
- `scan` now fails closed on incomplete local coverage.
- CI and release tooling: PRs that backward-break a public contract now fail
  a breaking-change gate (`oasdiff`/`buf breaking` against the base branch,
  with an explicit major-version or labeled override), and the release
  workflow can publish a signed container image for an arbitrary commit sha.

No RiskEnvelope, website, checkout, connector certification, or Company AI OS
GA scope is included.

## [0.7.2] - 2026-07-13

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.2>.

<!-- quantum_posture: v0.7.2 release notes cover a Go toolchain rebuild, an OpenAPI contract alignment, enforcement and containment hardening, and dependency updates; none add a post-quantum cryptographic control. -->

- The tag-triggered release workflow will rebuild both container images on Go
  1.25.12 (up from 1.25.10), which includes the cumulative upstream
  standard-library security fixes for `crypto/x509`, `mime`, `net/textproto`,
  `crypto/tls`, and `os`. Post-release Trivy and Artifact Hub evidence is
  required before claiming any CVE clearance. Rebuild only; no code or runtime
  behavior change.
- Aligned the canonical `BoundaryStatus` OpenAPI schema and the generated Java,
  Python, Rust, and TypeScript models with the JSON already emitted by
  `GET /api/v1/boundary/status`. Replaced legacy generated properties such as
  `receipt_store_ready`, `signer_ready`, `last_checkpoint_id`, and `checked_at`
  with the existing runtime properties, and documented the consumer migration
  mapping. This correction does not change Kernel runtime JSON behavior.
- Replaced the deny-only MCP runtime adapter with an optional governed
  execution bridge that returns real `ALLOW`/`DENY`/`ESCALATE` verdicts: the
  `mcp.ExecutionFirewall` boundary gate (allowlist, server identity, permission
  scope, pinned schema, JCS argument hash) runs before policy; `workstation.Decide`
  issues a signed decision receipt; writes go through an approval-gated
  `ESCALATE` tier bound to the canonical request hash and a single-use,
  replay-protected `EffectPermit`; and each effect is linked to its intent in
  the ProofGraph. Fail-closed by default — with no bridge configured the adapter
  stays deny-only.
- Added a scoped emergency-stop fence with a recorded cryptography posture, and
  preserved JCS Unicode separators in its reference pack.
- Made the replay-determinism verifier gate fail closed.
- Made the sandbox fail closed on an ambiguous network posture.
- Updated the `golang.org/x/crypto`, Jackson Databind, and Python `cryptography`
  build dependencies to current patched releases.

No RiskEnvelope, scan, upload, cloud, checkout, website, connector
certification, or Company AI OS GA scope is included.

## [0.7.1] - 2026-07-07

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.1>.

<!-- quantum_posture: v0.7.1 release notes mention existing SLSA and cosign release verification only; this release adds no post-quantum cryptographic control. -->

- Added a published-release SLSA subject integrity gate that compares
  `multiple.intoto.jsonl` subjects against the published `SHA256SUMS.txt`
  manifest.
- Converted the standalone SLSA provenance workflow into a manual repair path
  for already-published release assets so normal tag releases use the lockstep
  `release.yml` provenance job.
- Repaired the `v0.7.0` provenance asset so its SLSA subjects match the
  published checksum manifest before starting `v0.8.0` RiskEnvelope work.

No RiskEnvelope, scan, upload, cloud, checkout, website, connector
certification, or Company AI OS GA scope is included.

## [0.7.0] - 2026-07-05

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.7.0>.

<!-- quantum_posture: v0.7.0 release notes mention existing cosign release verification only; this release adds no post-quantum cryptographic control. -->

- Cut the EvidencePack and ProofGraph beta release without adding product,
  cloud, GA, connector certification, or checkout scope.
- Made native EvidencePack verification fail closed when any regular pack file
  is neither listed in `00_INDEX.json` nor a separately verified control file
  such as `00_INDEX.json`, `07_ATTESTATIONS/evidence_pack.sig`, or
  `07_ATTESTATIONS/conformance_report.sig`.
- Bound declared `99_EXT/` extension files to pack verification so formal-proof
  and future extension material must be indexed before a seal verifies.
- Froze ProofGraph hash-reference validation for `node_hash` and `parents[]`
  as 64-character lowercase SHA-256 hex refs.
- Hardened the legacy tar EvidencePack verifier against duplicate,
  unsupported, or unmanifested archive entries.
- Added a release-asset gate that verifies the staged `evidence-pack.tar` and
  then proves an appended tampered copy is rejected by the same offline verifier.

## [0.6.0] - 2026-07-02

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.6.0>.

<!-- quantum_posture: v0.6.0 release notes mention existing cosign release verification only; this release adds no post-quantum cryptographic control. -->

- Cut a release-infrastructure hardening release after the `v0.5.20` tag
  exposed manual publish recovery gaps, without adding product, cloud, GA,
  connector certification, or checkout scope.
- Restored token-based PyPI publication as the fallback path when Trusted
  Publishing is unavailable, and added manual Python SDK publish dispatch from
  an immutable release tag so recovery can publish the tagged source version
  after `main` advances.
- Fixed published-version drift matching so rejected shorter versions such as
  `0.5.2` cannot satisfy a later valid version such as `0.5.20`.
- Routed docs truth through the public org reusable workflow and pinned that
  reusable workflow's docs-truth runner checkout so `MINDBURN_ORG_READ_TOKEN`
  is not paired with floating runner code.
- Clarified HELM Kernel and HELM Enterprise quantum-security wording so public
  release material does not imply an added post-quantum cryptographic control.

## [0.5.20] - 2026-07-01

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.20>.

<!-- quantum_posture: v0.5.20 release notes mention existing cosign release verification only; this release adds no post-quantum cryptographic control. -->

- Cut a corrective lockstep release after the `v0.5.19` tag exposed release
  evidence and SDK contract drift, without adding product, cloud, GA, connector
  certification, or checkout scope.
- Completed the account session and entitlement SDK contract alignment on
  `plan_id`, with public plan enums limited to `free`, `developer`, `team`,
  `scale`, and `enterprise` across OpenAPI and generated Go, Java, Python,
  Rust, and TypeScript SDK types.
- Added exact `v0.5.19` and `v0.5.20` OpenVEX source files and made OpenVEX
  generation reproducible under `SOURCE_DATE_EPOCH`.
- Moved Go SDK subdirectory tag publication into the tag-driven release
  workflow with immutable-tag checks and published-channel drift coverage.
- Replaced stale release-document command lists with the maintained gates:
  `quality-merge`, `quality-release`, `release-readiness`, `release-assets`,
  and `version-drift-published`.

## [0.5.19] - 2026-07-01

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.19>.

<!-- quantum_posture: v0.5.19 release notes mention existing cosign release verification only; this release adds no post-quantum cryptographic control. -->

- Hardened hosted sandbox execution guardrails by centralizing timeout caps,
  output caps, secret-bearing environment variable denial, and cleanup
  degradation reporting across sandbox adapters and broker receipts.
- Aligned account session and entitlement SDK contract fields on `plan_id`,
  expanded public plan enums to `free`, `developer`, `team`, `scale`, and
  `enterprise`, and regenerated Go, Java, Python, Rust, and TypeScript SDK
  types from OpenAPI.
- Updated the Java SDK Jackson dependency to `2.22.0`.
- Shipped developer-first integration docs for Codex, Claude Code, MCP,
  OpenAI-compatible proxy use, EvidencePack verification, signed receipts, and
  policy bundles without expanding cloud, GA, connector certification, or
  checkout claims.
- Updated release version-surface automation for the rewritten Developer
  Journey and Quickstart docs so future patch bumps remain tool-driven.

## [0.5.16] - 2026-06-18

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.16>.

- Added Formal Verification Worker v0 contracts, deterministic proof-result
  hashing, CPI status mapping, EvidencePack extension validation, and
  conformance vectors for the no-side-effect-before-approval invariant.
- Added docs-only LEAP research notes under `research/leap/` to record the
  verifier-guided proof-search pattern without adding a LEAP, Lean, or SMT
  runtime dependency.
- Included optional OpenEnv safety fixtures and the sharpened README front-door
  copy shipped after `v0.5.15`.

## [0.5.15] - 2026-06-14

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.15>.

- Anchored receipt issuance into the append-only transparency log and persisted
  the receipt transparency anchor fields (`log_id`, `leaf_index`, transparency
  payload) across the Postgres and SQLite receipt stores (MIN-720).
- Added the certification evidence gate, verifier telemetry, demo MCP surface,
  and receipt comparison tooling (MIN-719/568/609/570).
- Fixed the self-serve proof loop so `demo` emits a canonical sealed
  EvidencePack that offline `verify` accepts out of the box (MIN-738).
- Scoped the `scripts/proof-path.sh` conformance steps as a gate-engine smoke
  test against the seeded local baseline (fail-closed by design) rather than a
  hard release gate, so a clean run exits 0 (MIN-740).
- Hardened the release pipeline to block stale Go SDK publication.

## [0.5.13] - 2026-06-13

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.13>.

- Added `helm-ai-kernel quickstart` as the OSS local-first path with loopback
  Kernel startup, same-origin `/console`, starter fail-closed policy material,
  one-time local session exchange, backend-owned onboarding proof APIs, signed
  ALLOW/DENY/ESCALATE receipts, tamper verification, and onboarding
  EvidencePack export.
- Added release workflow wiring that builds the production `app-helm-console`
  web bundle, runs the Console fixture-leak gate, stages bundle
  checksum/SBOM/provenance/lock/manifest sidecars into the kernel release
  assets, and installs the Console bundle through the Homebrew formula.
- Hardened local quickstart auth so the generated session token expires in the
  shared admin/tenant auth path, not only on onboarding routes.

## [0.5.12] - 2026-06-13

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.12>.

- Published the lockstep `0.5.12` release surfaces across the CLI, Helm chart,
  OpenAPI metadata, SDK package manifests, generated SDK headers, verification
  docs, Launchpad clean-install defaults, and release security references.
- Promoted signed Launchpad image references after the multi-arch artifact
  pipeline produced current OpenClaw, Hermes, OpenCode, Kilo Code, and egress
  proxy artifacts.
- Fixed the live OpenRouter/OpenClaw smoke path by proving token reachability
  before the positive Kubernetes smoke and by preserving Helm test logs long
  enough for CI diagnostics.
- Bound `SignDecision` to the canonical effect digest and authenticated release
  setup-protoc lookups to keep the release validation lane deterministic.

## [0.5.10] - 2026-06-04

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.10>.

- Added native EvidencePack customer proof verification: `07_ATTESTATIONS/evidence_pack.sig` is now the seal authority for customer-grade verification, with customer/high-assurance profiles requiring external signer trust, verified Rekor/RFC3161 anchor receipts, and S3 Object Lock storage receipts.
- Added receipt-aware verification commands: `helm-ai-kernel verify` accepts `--profile`, `--config`, and `--storage-receipt` for native EvidencePack trust profiles; top-level `helm-ai-kernel trust init --config helm/helm.yaml` routes to native EvidencePack trust initialization.
- Extended Launchpad verification to carry profile-aware native seal options through evidence pack receipts and verifier execution.

## [0.5.9] - 2026-06-03

Release target: <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.9>.

- Prepared the lockstep `0.5.9` release surfaces across the CLI, Helm chart,
  OpenAPI metadata, SDK package manifests, generated SDK headers, verification
  docs, and Launchpad clean-install defaults.
- Refreshed the Launchpad model-provider catalog so direct OpenRouter,
  Anthropic, DeepSeek, and xAI provider routes are represented in retained
  provider metadata.
- Expanded regression coverage across governance policy streams, executor
  evidence, trust roots, kernel edge cases, guardian checks, MCP quarantine,
  conformance gates, Launchpad session runtime, and pack behavior.

## [0.5.4] - 2026-05-20

Published at <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.4>.

Chart page polish on ArtifactHub. No kernel binary or API changes;
the v0.5.3 work landed three of four chart-page badges -- this release
lights the fourth and makes the values reference panel useful.

- Moved ArtifactHub package metadata (changes, images, links, license,
  prerelease, containsSecurityUpdates, signKey, category) from
  `deploy/helm-chart/artifacthub-pkg.yml` into `Chart.yaml` annotations,
  which is the only file ArtifactHub reads for `kind=helm`. Lights the
  Changelog badge that stayed grey under v0.5.3.
- Annotated every field in `deploy/helm-chart/values.schema.json` with
  a description. The "Values schema reference" panel on the chart's
  ArtifactHub page now shows a one-line description per setting instead
  of an empty pane.
- Deleted the now-redundant `artifacthub-pkg.yml`.

## [0.5.3] - 2026-05-19

Published at <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.3>.

Chart distribution polish. No kernel binary or API changes; this release
lights up the previously-grey ArtifactHub badges on the chart page.

- Added `deploy/helm-chart/values.schema.json` (JSON Schema draft 2020-12)
  covering every documented field in `values.yaml`. Enables IDE autocomplete
  for chart values, lets `helm install` reject malformed values before
  reaching the cluster, and lights the ArtifactHub Values Schema badge.
- Added `deploy/helm-chart/artifacthub-pkg.yml` with display name, license
  tag, structured changelog, container image inventory (main + slim,
  multi-arch), and six external project links. Lights the ArtifactHub
  Changelog badge and replaces the otherwise sparse Chart.yaml description.
- Added `artifacthub-repo` release job that pushes `artifacthub-repo.yml`
  as an OCI artifact (tag `:artifacthub.io`) into the chart namespace so
  ArtifactHub picks up the Verified Publisher UID for the OCI-backed
  Helm repository.
- Added `cosign-chart` release job that signs the chart OCI artifact by
  digest with sigstore keyless OIDC, lighting the ArtifactHub Signed badge.

## [0.5.2] - 2026-05-19

Published at <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.2>
on 2026-05-19T16:13:38Z.

- Fixed default boundary policy initialization so the retained production
  surface starts fail-closed when default policy material is missing or invalid.
- Anchored KMS keystore state under the configured runtime data directory and
  added regression coverage for that path.
- Wired release build metadata into container builds and disabled the phantom
  chart metrics port by default.
- Refreshed Artifact Hub repository metadata and bumped the Helm chart release
  contract to `0.5.2` / `v0.5.2`.
- Kept release asset export and verification output visible during staging so
  failing commands are diagnosable from workflow logs.

## [0.5.1] - 2026-05-18

Published at <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.1>.

- Fixed tag-driven release asset staging so release binaries, SBOM, OpenVEX,
  Homebrew formula metadata, and release attestations use the tag version
  instead of falling back to `VERSION` when a tag is cut before the file is
  bumped.
- Fixed audit EvidencePack export so every file listed in `00_INDEX.json`,
  including `01_SCORE.json.sha256`, is preserved in exported tar archives and
  verified during `make release-assets`.
- Added release staging diagnostics for exact failing commands and conformance
  gate failures, and require exact OpenVEX documents for tag release assets.
- Normalized pull-request Scorecard SARIF categories so GitHub code scanning
  sees the same `supply-chain/branch-protection` configuration on PR refs as it
  sees on `main`.
- Moved first-party GitHub setup actions to Node 24-capable pinned SHAs and
  configured Go workflow caching against `**/go.sum` for the monorepo layout.
- Downgraded the local release-smoke missing-cosign message from a GitHub
  warning annotation to a plain informational log unless cosign bundles are
  explicitly required.
- Bumped source, CLI fallback, SDK package manifests, Helm chart `appVersion`,
  OpenAPI version metadata, generated SDK version comments, Console visible
  version, and launch verification scripts to `0.5.1`.

## [0.5.0] - 2026-05-13

Published at <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.5.0>
on 2026-05-13T09:15:00Z.

- Bumped source, CLI fallback, OpenAPI, SDK package manifests, generated SDK
  version comments, Helm chart metadata, and Console visible version to
  `0.5.0`.
- Added canonical release asset staging through `make release-assets`, including
  five CLI binaries, checksums, SBOM, OpenVEX, release attestation,
  `evidence-pack.tar`, `helm-ai-kernel.mcpb`, `helm-ai-kernel.rb`, and complete sample policy
  material.
- Fixed offline EvidencePack verification for canonical
  `02_PROOFGRAPH/receipts/` packs while preserving legacy root `receipts/`
  compatibility.
- Made audit export include `04_EXPORTS`.
- Added local launch-smoke coverage for MCP wrapping and the HTTP proxy using
  checked-in local fixtures with no external side effects.
- Retargeted Homebrew release workflow/docs to `mindburnlabs/homebrew-tap`.
- Corrected the release baseline: no public `v0.4.1` GitHub Release exists, so
  `v0.4.0` is the actual public baseline for the `v0.5.0` delta.

- Established `helm.docs.mindburn.org` as the canonical product docs surface while keeping HELM AI Kernel source docs in this repository.
- Reduced duplicate public docs routes so `/helm-ai-kernel` is the Kernel portal entry and older `/oss` links redirect.
- Expanded the OpenAI-compatible proxy, MCP, SDK, OWASP mapping, verification, publishing, and compatibility docs for agent-readable exports.
- Normalized the retained OSS surface around the kernel, contracts, SDKs, static viewer, examples, deployment material, and verification artifacts that remain in the repository.
- Removed stale workflows, hosted-demo collateral, internal planning material, tracked binaries, and generated repository junk from the public documentation path.

## [0.4.0] - 2026-04-25

- Published the public quickstart release at
  <https://github.com/Mindburn-Labs/helm-ai-kernel/releases/tag/v0.4.0>.
- Shipped `helm-ai-kernel serve --policy` TOML policy support and local receipt APIs.
- Shipped positional `helm-ai-kernel verify <pack>` with optional `--online`.
- Shipped `helm-ai-kernel receipts tail` for SSE receipt streaming.
- Published the `release.high_risk.v3.toml` sample policy and an
  offline-verifiable `evidence-pack.tar` fixture.
- Published platform binaries for Darwin, Linux, and Windows, plus
  `SHA256SUMS.txt`, `sbom.json`, `helm-ai-kernel.mcpb`, `helm-ai-kernel.rb`, and
  `release-attestation.json`.
- Documented that the included `evidence-pack.tar` verifies offline and reports
  `anchor offline`; public proof anchoring depends on the public proof deployment
  and public proof credentials.
