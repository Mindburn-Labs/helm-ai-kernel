<!-- quantum_posture: this page documents workstation flows that use classical Ed25519 receipts and does not claim post-quantum protection. -->

# Workstation Governance

HELM workstation governance starts as a manifest-first proof surface for local coding-agent runs and adds a selected-effect CLI/hook enforcement bridge. It does not claim HELM controls every Codex, Claude Code, IDE, browser, or desktop action. The adapter imports artifact sets, maps them into ProofGraph nodes, emits signed Agent Run Receipts, and can produce signed policy decision receipts that wrapper scripts must obey.

## Current mode

The first profile is `workstation.observe_draft.v1`.

| Class | Meaning | M0-M2 behavior |
| --- | --- | --- |
| Observe | Read-only inspection, git status or diff, tests, builds, and validation commands. | Imported and receipted. |
| Draft | Workspace-scoped file edits and generated artifacts. | Imported and receipted as draft effects. |
| Operate | Network egress, MCP mutation, durable memory writes, recurring loops, deploys, publishes, payments, and secret-sensitive actions. | Fails closed in policy evaluation when no explicit permission exists. The `workstation enforce` CLI refuses selected denied effects before running a wrapped command. |

An empty egress allowlist denies network egress. Empty operate permissions deny operate-class effects. Memory writes are represented as effects with TTL and sensitivity so they can enter review queues later instead of becoming implicit agent memory.

## Artifact set

`helm-ai-kernel workstation import --artifacts <dir>` expects:

- `run.manifest.json`
- `git.diff-summary.json`
- `validation.json`
- optional `tool-events.ndjson`
- optional `policy-profile.json`

The importer hashes each artifact, maps the goal to an `INTENT` node, maps source artifacts to an `ATTESTATION` node, maps file/tool/memory/deny records to `EFFECT` nodes, and emits a `CHECKPOINT` node for the signed receipt reference.

## Receipt viewer

Use the viewer when an operator needs the run summary without reading the original conversation:

```bash
helm-ai-kernel workstation import --artifacts fixtures/workstation/denied-network --out /tmp/workstation-receipt.json
helm-ai-kernel workstation view --receipt /tmp/workstation-receipt.json
```

### Local signer and trusted verification

The first local import, decision, capture, or installed hook provisions one
Ed25519 signer for that HELM data directory. The private seed stays at
`~/.helm-ai-kernel/keys/workstation-ed25519.seed` with `0600` permissions; the
directory has `0700` permissions. Its public key is written next to it as
`workstation-ed25519.pub`. This is a local trust anchor, not a HELM release or
vendor signing key.

If the process has no resolvable home directory, pass an explicit `--data-dir`.
HELM will not create a private key relative to the current working directory.

`workstation view` and `workstation verify-decision` report two separate
results. `integrity` says the receipt was not altered relative to the public
key named inside it. `signer trusted` says that named key matches the expected
local or caller-supplied public key. Both must be `true` for a successful
verification exit code. When verifying a copied receipt on another machine,
supply a separately trusted public-key file:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt /tmp/network-deny.json \
  --trusted-public-key-file ./workstation-ed25519.pub
```

Older receipts made with the retired deterministic signer can still be read
for integrity and migration, but are not trusted. Reissue them with the local
signer rather than treating the legacy key as a trust root.

### What the hook refuses about its own files

The hook and `workstation enforce` refuse a call that reaches:

- the `keys` directory of the data directory in use and of the default one,
  and any file in it;
- a seed passed with `--signing-seed-file`;
- the policy profile passed with `--policy-profile`;
- the data directory named as a whole, as a recursive copy or archive would.
  Other content of the data directory, such as `receipts/`, stays readable.

The refusal is `TRUST_MATERIAL_ACCESS_DENIED`. No policy profile allows it, and
it does not depend on the tool: a shell read, an encoder, a pager, a copy, an
archive, an input redirect, a write or delete, `Read`, `Grep`, `Glob`, `Write`,
`Edit`, an MCP tool and a tool the hook does not classify are refused alike.
A path is compared after `~` and `$HOME` expansion, resolution against the
working directory and any `cd` inside the command, and resolution of symbolic
links before their following `..` segments. Comparisons ignore case. This also
applies to custom seed/policy paths, local FILE URLs and search roots.

Globs are read in a small grammar: path segments separated by `/`, each made
of letters, digits, `.`, `_`, `-`, `+`, `@`, `=`, `%`, `:`, `*` and `?`, a
whole-segment `**` (any number of directories), and in a search glob brace
groups `{a,b}` of two or more alternatives in the grammar, nested at most 4
deep. The grammar is what the hook reads, not an emulation of each tool's
dialect. Inside it the hook matches a glob, ignoring case, against what the
key directory holds as a search tool may anchor it:

- A search (`Grep`, `Glob`, Hermes `search_files`, an MCP tool given `glob`,
  `include`, `file_glob` or a `pattern`) reaches the material only when it
  starts at the data directory, inside it, or above it. The start is the
  `path` argument, else the working directory; `/` is above everything, and a
  start that cannot be resolved, or a `path` that does not exist, is taken as
  `/`. (Hermes searches every part of a `path` that does not exist, split on
  commas or white space.) From there a glob is matched against what the key
  directory holds: from the start or any directory above it, or at any depth
  below the start. So `keys/*` and `**/*.seed` from the home directory are
  refused, while `src/**/*.go` and `docs/*.md` are not.
- Wherever a search starts, a glob whose last segment is aimed at a key file
  name (`*.seed`, `workstation-ed25519.*`, and `*.pub`, which names the
  trusted public key `workstation-ed25519.pub`) is refused: a copy of that file
  is still that file. A last segment that selects files in general (`*`,
  `*.go`) is not aimed at it. Search for a specific public key by name
  (`id_ed25519.pub`) rather than `*.pub`.
- A path pattern (a `Glob` `pattern`) that is absolute, starts with `~`, or
  starts with `.` or `..` is read from the directory its literal leading
  segments name, and from `/` when the first segment of an absolute pattern
  already has a wildcard, a brace group or a bracket (`/*/ivan/.h*/k*/*`,
  `/{Users,x}/...`). Each `..` after a wildcard moves its start one
  directory up. Hermes `search_files` with `target: files` reads a `pattern`
  that holds `/` by its last segment and adds a leading `*`; the hook does
  not follow that, so the names such a search lists can differ from what the
  hook matched.
- Claude Code's `Grep` splits its `glob` on white space, and each part on
  commas unless the part holds a brace group, and gives ripgrep each part:
  the hook decides each part as a glob of its own, so `*.ts,*.tsx` and
  `*.ts *.tsx` are two globs in the grammar. Another client's `glob` is one
  glob.
- An MCP tool's `pattern` may be a glob or a regular expression. In the
  grammar it is decided as a path pattern; outside it (`foo|bar`,
  `\bneedle\b`) it is taken as a regular expression, refused only when the
  search starts at, inside or above the data directory.
- A shell word is expanded as the shell does: a wildcard does not match a
  leading dot unless `dotglob` or `globdots` is set. Brace groups are not
  expanded: a word with one is matched on its text before the first group,
  and is refused when that text is at the data directory, at or inside the
  key directory, or has begun to spell the name of one of them
  (`cat ~/.helm-ai-kernel/{keys,x}/*`, `cat ~/.helm-{ai-kernel,x}/keys/*`).
  A group that spells the data directory's name from above it
  (`cat ~/{.helm-ai-kernel,zz}/keys/*`) or climbs to it with `..`
  (`cat ~/proj/{..,x}/.helm-ai-kernel/k*/*`) is not refused as trust
  material. Brace expansion is an opaque shell operation, which the built-in
  profile refuses and a profile that grants `shell.operate` runs.

A glob with anything else is not read: a bracket class, a backslash, a leading
`/` (which ripgrep anchors where it runs, not at `/`), `!`, white space, a
character outside ASCII, an unbalanced or single-alternative brace group,
braces nested deeper than 4, `.` or `..` segments, or `**` inside a segment.
Such a glob is refused, with a reason that names the construct, when the
search starts at, inside or above the data directory, or when a walk of the
search root (up to 65,536 entries, at most four roots per call) finds a file
with a key file name or cannot finish. In a repository larger than the walk,
a filter outside the grammar (`!node_modules/**`, `*.[jt]s`) is therefore
refused; write it in the grammar (`*.js` and `*.ts`). A shell word with a
bracket class or a segment longer than 1024 bytes is refused when the
directory it starts in is at, inside or above the data directory, so
`cat ~/.helm-ai-kernel/k[]e]ys/*` is refused and `cat src/[ab]*.go` is not.

The globs of one call share one expansion budget: 256 alternatives and 64 KiB
of expansion together, with each glob outside the grammar counting as one
alternative. A call past it is refused with `TRUST_MATERIAL_ACCESS_DENIED`
under every profile and a reason that says its globs are too large to expand.
The hook also stops classifying a call after 10 seconds and refuses it the
same way, well before the 30 second timeout setup installs; the classifier
then ends its work on the call. A call whose classifier panics is refused the
same way, with a signed receipt.

A program passed to an interpreter, or to Hermes
`execute_code`, is refused when its text names the path, and so is a script
file whose content names it when the script is run.

This is a check on what a call says, not isolation. The hook and the agent
run as the same operating-system user, so the agent can read any file the hook
can. A script that computes the path at run time, or a recursive read of a
directory above the data directory, is not refused. Keeping the seed away from
the agent needs a privilege boundary this release does not have: a signer that
runs under another account, or the kernel service signing on the hook's
behalf.

The kernel binary signs with this key and installs the hook, so the hook also
refuses a shell command that runs `helm-ai-kernel setup` (other than
`setup status` or a `--dry-run`), `helm-ai-kernel hook`, or
`helm-ai-kernel workstation decide`, `enforce`, `import` or `capture`. Without
that, one command would uninstall the hook or obtain a signed decision under a
policy profile of the agent's choosing. The match is on the program name: a
renamed copy of the binary is not recognized.

For a classified hook operation, failure to provision the local signer or
persist a denial receipt results in an explicit hook denial. HELM does not
substitute an unsigned or fabricated receipt. If it cannot write the hook
denial protocol at all, it returns the client blocking status instead of a
successful hook exit.

## Enforcement bridge

Selected workstation effects can be evaluated and recorded:

```bash
helm-ai-kernel workstation decide \
  --class network \
  --target https://forbidden.example \
  --out /tmp/network-deny.json

helm-ai-kernel workstation enforce \
  --class network \
  --target https://forbidden.example \
  --out /tmp/network-deny.json
```

`decide` emits a signed policy decision receipt. `enforce` emits the same receipt and exits with code `126` on `DENY`, which makes it usable from shell hooks or wrapper scripts. The bridge covers selected shell, network, MCP, file, memory, and recurring-loop classes; it is not a kernel driver, browser controller, or complete OS sandbox.

When `enforce` is given a command to run (`workstation enforce [flags] -- command args`), it decides on that argv, not on what the flags say about it:

- The argv is classified the way the hook classifies a shell command. Every effect found in it (each network destination, a credential read, a destructive or opaque shell form) gets its own decision, and the command runs only if all of them are operate-mode `ALLOW`.
- `--class network` takes its destinations from the argv. `--target` then names a destination the caller expects; if the argv does not connect there, or names no destination at all, `enforce` refuses with exit code `126` and signs nothing.
- `--class shell` and `--class shell-operate` decide on the command line itself. A `--target` that is not that command line is refused.
- Any other class is decided as declared, in addition to what the argv shows.
- Every receipt for a wrapped command carries `argv_binding: jcs-sha256` and `argv_sha256`, the digest of the exact argv. `--out` receives the receipt that settled the outcome, the first denial or else the first decision, and replaces the file there; `--receipt-dir` receives the others. Every receipt has a request ID of its own, and each file `enforce` names in `--receipt-dir` is created new, so a later run never replaces an earlier run's receipt.
- The command inherits the wrapper's environment, and the decision covers the variables in it that change where a client connects or what a shell runs first (see [Network egress decisions](#network-egress-decisions)).

Exit codes: `126` when the command is not run, because an effect is denied, the declaration cannot be matched to the argv, a receipt cannot be written, or a receipt is not an operate-mode `ALLOW`; the command's own exit code when it runs, `128` plus the signal number when a signal ends it, and `127` when it cannot be started; `2` when the flags cannot be parsed or no decision can be made, because the policy profile cannot be loaded or the signing seed is unavailable. The command does not run on `2` either, and nothing is signed.

A command that is refused leaves only its denials in `--out` and `--receipt-dir`, as a refused hook call does, so no `ALLOW` receipt stands for an effect of a command that never ran. A command whose decisions are all `ALLOW` but not all in operate mode (`--class shell` decides in observe mode) is refused before any receipt is written and leaves none. Every receipt of one run carries, in its signed bytes, `call_id` (shared by the receipts of that run), `call_receipts` (how many receipts the run wrote) and `call_verdict` (its outcome), beside `argv_binding` and `argv_sha256`. When a receipt cannot be written, the `ALLOW` receipts already written for the run are removed as far as removal works; the denials stay.

The command is looked up on `PATH` when it runs. The decision names the program as written, not the file that `PATH` resolves it to.

### Network egress decisions

A network decision is made per destination. The hook and `enforce` read the destinations from the command, and the policy compares each one with `egress.allowlist`.

- A destination is `scheme://host[:port]`. The host is the one a client connects to: the part after any `user:password@`, in lower case, without a trailing dot, as punycode for an internationalized name, and in shortest form for an IP address. A default port is dropped. Allowlist hosts go through the same form, so `API.Example.com.`, `[2001:DB8::1]` and `bücher.example` in a profile match their other spellings. An allowlist entry with no `protocol` allows its host over any scheme; ports are not compared.
- Every URL argument is a destination, not only the first. An option that moves the connection adds the place it moves to: `curl --proxy`, `--preproxy`, `--socks*`, `--connect-to`, `--resolve` and `--doh-url`, `ssh -J` and `-o ProxyJump`, `-o HostName` and `-p`, `nc -x`, and the `http_proxy`, `https_proxy`, `all_proxy`, `ftp_proxy` and `rsync_proxy` variables set anywhere in the command.
- Curl remappings (`--connect-to` or `--resolve`) combined with multiple protocols are undetermined and refused under an allowlist, including across `--next`. Split those transfers into separate commands. For `--connect-to`, an omitted destination host or port inherits the corresponding explicit source field; inheritance from a wildcard source is undetermined. Single-protocol remappings with explicit endpoints remain supported.
- Git `http.curloptResolve` overrides, including URL-scoped `http.<url>.curloptResolve`, and curl `--no-ftp-skip-pasv-ip` are undetermined because they can connect somewhere other than the URL host. Ordinary scoped Git settings and explicit curl `--ftp-skip-pasv-ip` remain supported. A destination-changing override makes the whole call undetermined, even if another option later resets it.
- SSH reverse forwarding (`-R` and `-o RemoteForward`) is undetermined, including the destination-free SOCKS form, because the peer can trigger additional connections from the local client. OpenSSL DTLS (`-dtls`, `-dtls1`, `-dtls1_2`) is checked as UDP; ordinary TLS remains TCP. Conflicting TLS/DTLS flags and DTLS combined with a proxy are undetermined.
- Curl `--hsts` is undetermined for file-backed and memory-only caches: cached or learned rules can change the protocol during the call. Git executable helper overrides (`--upload-pack`, `--receive-pack`, `--exec`, and clone's `-u`) are undetermined, including local and configured repositories and lower-level fetch/send/archive commands. Helpers can execute locally; an ordinary local repository operation without an override remains supported.
- OpenSSL help preserves refusals for earlier opaque options, which can load executable providers or engines before help is handled. The `scp -D` local SFTP program override is undetermined. Plain help and ordinary remote copies remain supported.
- Recursive wget modes (`-r`/`--recursive`, `-m`/`--mirror`, `-p`/`--page-requisites`) are undetermined because page discovery can introduce another protocol or destination. Netcat `-Z` is undetermined because supported variants can select DCCP rather than TCP. Ordinary wget transfers and TCP/UDP netcat calls remain supported.
- Wget `--use-askpass` and `--hsts-file` are undetermined: the first executes a local credential handler and the second can upgrade an HTTP URL to HTTPS. Ordinary wget calls with redirects disabled remain supported. Ambient client configuration remains an operator assumption.
- Local `file:` URL paths are percent-decoded once before trust-material and secret-read checks, including local authorities, encoded separators and symlink paths. Symlink components resolve before `..`, including operator-supplied protected seed/policy paths and search roots. Recognized curl, wget and OpenSSH option values are checked as paths after extraction, including attached short options and curl file-input markers, so symlink aliases cannot hide protected material behind an option prefix. Ordinary local files remain readable; malformed or unsupported local FILE URLs are undetermined.
- `curl`, `wget`, `git`, `ssh`, `scp`, `sftp`, `rsync`, `nc`, `ncat`, `netcat`, `telnet` and `openssl s_client` are parsed. A bash `/dev/tcp` or `/dev/udp` redirect is a destination. A heredoc or here-string fed to a shell is classified as the script it is, and so is a network client that follows a prefix command the scanner does not know (`watch curl URL`).
- A command whose destinations cannot all be named is denied with `EGRESS_DESTINATION_UNDETERMINED` under any profile that has an allowlist. That covers an argument computed at run time (a variable, a command substitution, `xargs`), an option the parser does not know, a destination read from a file (`curl --config`, `wget --input-file`, `ssh -F`), a replaced connection program (`ssh -o ProxyCommand`, `rsync -e`, `GIT_SSH_COMMAND`), a `HOME` or configuration override, a client that follows redirects (`curl --location`, `wget` without `--max-redirect=0`, `git` over HTTP without `-c http.followRedirects=false`), a URL that parsers read differently (a backslash, an `@` after the authority, a percent-encoded or numeric host), and a network client that is not parsed (`aria2c`, `ftp`, `lftp`, `socat`, HTTPie, `proxychains`, `torsocks`).
- `git` with an address on the command line is decided on that address, including `git remote add`, `git remote set-url` and `git config remote.<name>.url`. A remote named in git configuration is the operator's setting: `git push origin main` is not classified, and a `-c` override or connection variable on the same command is.
- With several destinations the hook writes one receipt per destination. Each carries `egress.destination_count` and `egress.destination_set_sha256`, the SHA-256 of the sorted destinations joined by newlines, so one receipt shows how many others belong to the call. A call that names more than 64 destinations is decided as one `EGRESS_DESTINATION_UNDETERMINED` network decision that still carries the count and digest of all of them, and a call that names more than 64 credential paths as one secret read with `secret.target_count`.
- A hook network receipt's `request.target` is the SHA-256 of the canonical destination, not of the URL, under `target_binding: sha256:utf-8:network-destination`. Receipts written by earlier releases hashed the whole URL under `sha256:utf-8`; they still verify. Other hook receipts keep `sha256:utf-8`, the digest of the text the decision names.
- `workstation enforce` also decides on its own environment, which the command inherits: a proxy variable set there is a destination, and `CURL_HOME`, `WGETRC`, the `GIT_SSH*`, `GIT_PROXY_COMMAND`, `GIT_CONFIG*` and `GIT_EXEC_PATH` variables, `RSYNC_RSH`, `RSYNC_CONNECT_PROG`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV` and `ENV` leave the destinations undetermined. Its own `HOME` and `XDG_CONFIG_HOME` are not decided on: they locate the user's configuration, which the decision does not read. `BASH_ENV` and `ENV` set on a hook command line are decided the same way.

The hook is not on the network path. It does not see a redirect, a DNS answer, a hostname alias in `~/.ssh/config`, a default in `~/.curlrc`, or what a script does when it runs. Writes to `.curlrc`, `.wgetrc`, `.netrc`, `.ssh/` and `.git/` are sensitive writes for that reason.

An allowlist bounds the commands whose destinations can be read. A profile that also grants `shell.operate` allows shell forms the scanner cannot read (a computed command word, `eval` of a variable, a program passed to an interpreter), and those can connect anywhere. A profile meant to bound egress should not grant it. A program outside the client table (curl, wget, the ssh family, rsync, git, netcat, telnet, openssl) is not classified as egress: package managers, language toolchains, DNS tools and other HTTP clients connect without a network decision. For a client in the table, an option the table does not know makes the destination undetermined, which an allowlist profile denies.

The shell guard parses shell syntax before classifying selected destructive
forms, including chained and wrapped commands. It routes recognized force-push,
database-drop, Terraform-destroy, and S3-removal forms through the signed
decision path. Where a selected destructive invocation cannot be resolved
statically, it also routes to a decision rather than silently allowing it.
This remains a selected-effect guardrail, not a complete OS sandbox or a claim
to recognize every destructive tool, alias, or `eval` payload.

A credential path (`.env`, a private key, `.ssh/`, cloud and registry
credential files) given to any command is a secret read, whatever the command:
an encoder, a pager, an editor, an archiver, an interpreter given the path, or
an input redirect. Commands that only list, test, create, remove or
re-permission a file are the exception.

A public key (a name ending in `.pub`) and an example env file
(`.env.example`, `.env.sample`, `.env.template`) are not credentials: reading
one is a plain read, through a shell and through a read tool alike.

Tools that are not a shell are classified too. `Read`, `Grep` and the other
read tools are a secret read when given a credential path, or a search glob
that selects credential files (`.env`, `**/*.pem`), and pass otherwise. A
search glob in the grammar above is decided on what it can name; one outside
it (`.en[v]`, `.en\v`) is a secret read when a walk of the search root finds
a credential file or cannot finish, and the reason says so. A credential
file inside a directory (`.docker/config.json`, `.ssh/config`, `.kube/config`,
`.aws/credentials`, `.config/gcloud/`) is selected only by a glob that names
the directory or whose `**` can stand for it: `**/*.json`, `**/config`,
`*/credentials` and `.docker/*.json` are secret reads, while `*.json`, `*.db`,
`*config` and `credentials` are not, although ripgrep matches them at any
depth. A glob whose last segment matches ordinary file names (`*`, `*.*`)
selects files in general and is a secret read only when its text names a
credential path: `.ssh/*` is one, and `.docker/*`, `.kube/*` and `.aws/*` are
not, although ripgrep selects the credential file in that directory with
each of them. `Grep`'s
`pattern`, and Hermes `search_files` `pattern` unless `target` is `files`, is
a regular expression for a content search and is not read as a glob. Through
a shell, a credential path is read with a backslash taken as quoting the next
character, so `rg -g '.en\v'` and `grep --include='.en\v'` are secret reads.
A shell word whose wildcard or bracket would expand to a credential file
(`cat .en?`, `cat .e*`, `cat .en[v]`) is decided on its text, not on what it
expands to: under the built-in profile it is not a secret read.
`WebFetch`, Hermes `browser_navigate` and the other fetch tools are network
egress to the host of their URL; a search tool, which names no URL, has an
undetermined destination. Hermes `vision_analyze` is a read when its
`image_url` is a local file and network egress otherwise. Hermes
`execute_code` runs a program the hook cannot read as a command line, so it is
a shell operation that needs `shell.operate`, like a shell tool call whose
`command` is missing or is not a string. Claude Code `ReadMcpResourceTool` and
`ListMcpResourcesTool` are MCP calls to the server they name, except the HELM
server setup installs. A tool the hook has no class for is decided as a tool
call with its input digest in the receipt and needs the `mcp.mutate`
permission; under the default profile it is denied. The built-in default
profile is unchanged: it allows observe- and draft-class actions and denies
every operate-class one.

The hook decides on the first JSON value on standard input. It does not wait
for the end of the input, so a client that leaves standard input open still
gets its answer, and what follows the first value is not read. It reads at
most 4 MiB. A larger payload is not classified: it is denied with
`TOOL_INPUT_TOO_LARGE` and a receipt of effect type
`WORKSTATION_MCP_TOOL_CALL`, the type of a call into a tool the hook cannot
see into, that carries `tool_input_limit_bytes`. In place of the digest of
the canonical tool input it binds the bytes the hook read:
`tool_input_binding: payload-prefix-sha256`, `tool_input_sha256` (their
SHA-256) and `tool_input_bytes_read`. Its `tool_id` names the tool when the
payload names it (`tool_name`, or `toolName`) before the input that does not
fit, as the clients do, and is `unknown` otherwise.

Every effect of one call is decided before any receipt is written. When one is
denied, only the denials are written, so no `ALLOW` receipt stands for a call
that did not run. Every receipt of a call carries, in its signed bytes,
`call_id` (shared by the receipts of that call), `call_receipts` (how many
receipts the call wrote), `call_verdict` (the outcome of the whole call) and
`tool_input_binding: jcs-sha256` with `tool_input_sha256`, the digest of the
canonical tool input. If a receipt cannot be written the call is denied and
the `ALLOW` receipts already written for it are removed; one that cannot be
removed still shows, through `call_receipts`, that its set is incomplete. A
denial already written stays: it records a refusal that did happen.

Shell syntax whose meaning is only known after expansion also routes to a
decision rather than passing unclassified: ANSI-C or locale quoting (`$'...'`,
`$"..."`), brace expansion, a command or process substitution that runs
anything beyond a small read-only allowlist (`cat` of a heredoc or here-string,
`date`, `git rev-parse`, `git log`, `pwd`, `basename`, `dirname`, `printf`,
`echo`, all with literal words), a glob or variable in command position, a
globbed write target, and a relative write after a `cd` whose target cannot be
resolved. An allowlisted substitution is opaque text: it still fails closed as
a command name, an `eval`, `sh -c` or `source` payload, a redirect target, or a
destructive operand. Under the default profile these
commands are denied; a policy profile that grants the matching permission
allows them with a signed receipt. Sensitive write targets are compared after
path normalization (separators, case, `.`, `..` and repeated slashes, the
working directory, and `cd` inside the command), and the Write, Edit,
MultiEdit and NotebookEdit tools use the same rules as shell writes.

### Coverage label: observed-only

Local coding-agent hooks (`setup claude-code`, `codex`, `hermes`, `deepseek`)
are an **observed-only** integration, not an enforced boundary. The hook sees
only the tool calls the client chooses to send it and classifies command text,
which cannot be made sound against every shell construct. It records what the
agent attempted, signs a receipt for each classified decision, and denies the
cases it recognizes, including anything it cannot evaluate statically. Treat it
as defense in depth. Enforcement for these clients comes from HELM holding the
credential or the egress path, for example through HELM-served MCP tools, not
from the hook.

Setup checks MCP family coverage, not just a sample tool name. The shipped
matchers, unrestricted wildcard matchers and simple unrestricted MCP-prefix
branches establish coverage. More complex custom family coverage is unverified
and leaves status degraded; shared entries receive a warning and are preserved.
An additional HELM entry with complete coverage satisfies the check.

## Operator workflow

The local operator read model answers the M4 questions from receipts:

```bash
helm-ai-kernel workstation list --input fixtures/workstation/reference/receipts
helm-ai-kernel workstation denied --input fixtures/workstation/reference/receipts
helm-ai-kernel workstation memory --input fixtures/workstation/reference/receipts
helm-ai-kernel workstation loops --input fixtures/workstation/reference/receipts
```

This renders run list, receipt detail references, denied action timeline, memory review queue, and recurring loop registry from receipts only.

These commands check each input receipt before using it. The signature is checked against the key the receipt names, and the signer against the local workstation public key or the one passed with `--trusted-public-key-file` (`--data-dir` selects the local key). Each run row carries a `signature_status`:

| Status | Meaning |
| --- | --- |
| `signed_by_trusted_key` | The signature matches and the signer is the trusted key. |
| `signed_by_untrusted_key` | The signature matches a key other than the trusted one. |
| `signed_by_retired_key` | The signature matches the retired built-in key, which anyone can reproduce. |
| `signer_not_checked` | The signature matches; no trusted key was available to compare the signer with. |
| `invalid_signature` | The content does not match the signature. |
| `unsigned` | There is no signature. |

A row is listed for every input. The denied timeline, memory queue and loop registry are built only from receipts whose signature matches their content; an `unsigned` or `invalid_signature` input is named in the output and left out of them. Each item in them carries the `signature_status` of the receipt it came from. A receipt signed by any key other than the trusted one shows what its signer claims, not what this workstation decided. An input file that repeats a receipt already read (the same receipt hash) is counted once and named under `duplicate_inputs`.

With `--json`, `operator` prints the whole view and `list`, `denied`, `memory` and `loops` print one section in the same envelope: an object with the section's items under the key the whole view uses (`runs`, `denied_timeline`, `memory_review_queue`, `recurring_loops`) and `verification`, which holds `trust_anchor`, `signature_statuses`, `not_counted` and `duplicate_inputs`. No JSON schema is published for this output.

Enterprise Console exposes the same read model as workspace-scoped API routes after a receipt or decision receipt is imported:

- `POST /api/v1/workspaces/{id}/workstation/receipts/import`
- `GET /api/v1/workspaces/{id}/workstation/runs`
- `GET /api/v1/workspaces/{id}/workstation/runs/{run_id}`
- `GET /api/v1/workspaces/{id}/workstation/denied`
- `GET /api/v1/workspaces/{id}/workstation/memory`
- `GET /api/v1/workspaces/{id}/workstation/loops`

The run detail route returns sanitized receipt fields and operator queues, not raw chat transcript bodies.

## Agent Scope Audit

Use `audit scope` when a B2B reviewer needs one report across high-impact agent boundaries instead of separate operator queues:

```bash
helm-ai-kernel audit scope \
  --input fixtures/workstation/reference/receipts \
  --out /tmp/helm-scope-audit \
  --evidence-pack
```

The command accepts `AgentRunReceipt` and `WorkstationPolicyDecisionReceipt` JSON files or directories. It writes `scope-audit.json`, `scope-audit.md`, `evidence-refs.json`, and, when `--evidence-pack` is set, `scope-audit-evidencepack/`. Add `--json` to print the canonical report JSON to stdout. The `--out` directory must be new or empty, as `workstation evidence` requires of its output directory: a used one is refused before anything is written. Every file is created new through the opened directory, so a file or directory linked to one elsewhere is not written through.

The report groups events into `mcp`, `filesystem`, `network`, `memory`, `secret`, `deploy`, `payment`, `loop`, and `shell`. It counts allowed, denied, tainted, and unknown actions; lists out-of-scope attempts; records missing controls; summarizes memory TTL/sensitivity/review state; and preserves source receipt hashes and signature presence. Secret, deploy, and payment details are metadata conventions in v1 (`secret_ref`, `lease_ref`, `redaction_ref`, `environment`, `artifact_digest`, `approval_ref`, `rollback_ref`, `verification_ref`, `amount`, `currency`, `counterparty_ref`, `spend_cap_ref`, `idempotency_key`, `ledger_ref`) so existing receipt compatibility is preserved.

`audit scope` checks signatures the same way as the operator commands and takes the same `--data-dir` and `--trusted-public-key-file` flags. An input that is unsigned or does not match its signature is left out of every count and named in `limitations`; the report also states there which key signer trust was checked against, or that it was not checked. When a trusted key is available, a receipt signed by any other key, the retired built-in key included, is counted apart in `summary.untrusted_signer_receipts` and `summary.untrusted_signer_actions` and in no other count. Without a trusted key every receipt whose signature holds is counted, as `limitations` says. A repeated receipt is counted once. With no input left the command fails instead of writing an empty report.

`audit scope` is an audit and evidence export over HELM-owned receipts, wrapper decisions, and imported artifacts. It does not imply OS-wide control, full browser control, hosted Console enforcement, or control of proprietary hosted agents unless the relevant action passed through HELM receipts, wrappers, or adapters.

## Conformance and proof

The fixture-grading `workstation certify` command was removed in HELM-756:
it certified adapters from checked-in fixtures, not from a running adapter.
Export evidence with `helm-ai-kernel workstation evidence` and verify it with
`helm-ai-kernel verify`. `workstation evidence` accepts a `receipt_id` made of
letters, digits, `_` and `-` only, and writes every file through the pack
directory, so a receipt cannot place a file outside it. The output directory
must be new or empty: one that holds files is refused with a non-zero exit, so
no file left from an earlier export sits in the pack unlisted and no link in
it is written through. Every pack file is created new, and two names that a
case-insensitive filesystem would store as one file are refused.

Reference receipts live under `fixtures/workstation/reference/receipts/`. A sample EvidencePack lives under `fixtures/workstation/sample-evidencepack/`.

## Boundaries

This feature is not full desktop enforcement. Public copy should say “manifest-first,” “selected-effect enforcement bridge,” and “receipted wrapper/hook path.” For proprietary hosted agents, HELM governs only artifacts and effects that pass through the adapter or wrapper.

Related market context:

- OpenAI describes Codex local, mobile, and remote environment workflows where files, credentials, permissions, and setup stay on the operating machine: <https://openai.com/index/work-with-codex-from-anywhere/>
- OpenAI describes the Codex App Server event model as JSON-RPC over stdio for client-facing agent events and approvals: <https://openai.com/index/unlocking-the-codex-harness/>
- OpenAI describes managed network policy, rules, and OTel audit logs for Codex safety posture: <https://openai.com/index/running-codex-safely/>
