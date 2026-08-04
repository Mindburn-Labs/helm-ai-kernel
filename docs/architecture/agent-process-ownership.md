# Agent process ownership

> **Status: in development.** The packages described here are implemented and
> unit-tested in `helm-ai-kernel`. They are **not** yet wired to a CLI command, a
> control-plane route, or a signed receipt, and no sterile native-client session
> proof is attached. This document describes a boundary model and the code that
> implements it — not a shipped capability. See [Claim boundaries](#claim-boundaries).

## The problem

HELM's existing native-client integration installs HELM *into* a vendor coding
agent. `helm-ai-kernel setup claude-code` registers the kernel as an MCP server
and writes a `PreToolUse` hook into the client's own configuration.

That is a real boundary, and it stays. But it has a ceiling that no amount of
hardening removes: **it governs only the calls the client chooses to route
through it.** Tool classes the hook does not cover, MCP servers the client
declines to consult, and any action taken outside the hooked surface never reach
HELM at all. The kernel observes what the agent discloses.

This is why the estate's own boundary language says hooks and configured MCP
servers "govern only the selected hooked tool classes or routed MCP calls they
actually receive" and do not govern arbitrary client actions.

## The inversion

Rather than asking the agent to report to HELM, HELM runs the agent.

```
HELM (parent process)
  └── vendor CLI (child, own process group)
        ├── cwd  = isolated git worktree        core/pkg/worktree
        ├── HOME = scoped, sibling of the tree  core/pkg/worktree
        ├── env  = cross-provider scrubbed      core/pkg/harness
        └── work product = git diff, not narration
                └── apply gated fail-closed     core/pkg/patchdelivery
```

A hook governs what an agent *discloses*. A parent process governs what it *can
do*. The vendor CLI is unmodified and unaware; the constraint is structural.

## The three packages

### `core/pkg/worktree` — where the run executes

An isolated git worktree at a recorded `BaseSHA`, plus a scoped `HOME`.

Two placement rules carry the isolation:

- The harness `cwd` is the worktree.
- The harness `HOME` is a **sibling** of the worktree, never a child. Vendor CLIs
  write sessions, transcripts, plugin caches and credential material into `HOME`.
  Inside the tree, the `git add -A` in capture would pull credentials into a diff.

Work product is captured as a diff from git, never from model narration, and the
capture path reads **raw bytes**. This is load-bearing rather than stylistic: a
line scanner splits on a lone `\r` and rejoins with `\n`, silently rewriting CRLF
content and corrupting the patch at the point of capture. A diff that cannot
round-trip byte-for-byte is not evidence. Tests pin CRLF and binary round-trip.

Not to be confused with [`core/pkg/envelope`](../../core/pkg/envelope), the
**Autonomy Envelope** — the signed runtime boundary *contract* a run binds to
before effects execute. A run binds an Autonomy Envelope and executes in a Tree.
It has both.

### `core/pkg/harness` — how the process is owned

An adapter contract plus `claude` and `codex` implementations. Three properties
are security-critical and each is mutation-tested:

**Process group, not process.** The child is spawned with its own process group
and terminated by signalling the *negative* pid, so grandchildren — shell tools,
MCP servers the agent spawned — die with the leader. `SIGTERM` escalates to
`SIGKILL` on a timer.

**Cross-provider credential scrub.** Every provider credential and base-URL
redirect is removed from the child environment, not just the selected vendor's.
Scrubbing only the routed provider leaks the *other* provider's credentials into
the child. Proxy and CA-bundle variables (`HTTP_PROXY`, `NODE_EXTRA_CA_CERTS`,
`SSL_CERT_FILE`, …) deliberately survive, or a corporate-proxy user has no egress.

**Read-only is probed, not assumed.** If the vendor CLI lacks the flags that make
read-only real, the run is refused rather than run under an unenforced label.

An observed model is **never** backfilled from the requested model. Route proof
exists to catch silent fallback, so an unobserved model stays unobserved.

### `core/pkg/patchdelivery` — whether the work product may land

Between capture and apply, the live tree moves. The apply path re-proves the
patch against a clean base immediately before it is allowed to touch anything.

The distinction the package exists to preserve:

| Verifier result | Meaning | Overridable |
| --- | --- | --- |
| `AppliedCleanly == false` | **Proven** conflict — factually undeliverable | **Never** |
| `AppliedCleanly == nil` | Verifier **errored** — never proven against a clean base | Yes, via accept-risk |
| `GatesPassed == nil` | Applied clean, **no gates configured** | n/a — never reported as passed |

**Overrides may bypass UNKNOWN, never PROVEN-FALSE.** A human may accept the risk
of an unproven patch; no human may accept a patch that has been proven not to
apply.

An operator override is bound to `sha256(patch)`. Mutating one byte invalidates
it — `EffectPermit` semantics for a filesystem write: authorization bound to
content so it cannot be replayed against different bytes.

Every path that can mutate a live tree registers in the mutation registry with
its fence. An unregistered mutation path is a release blocker.

Not to be confused with [`core/pkg/delivery`](../../core/pkg/delivery), which is
progressive **release** rollout (shadow, canary, blue-green, SLO promotion). That
delivers a release to an environment; this delivers a patch to a working tree.

## Relationship to the hook path

The two are complementary, not competing:

| | Hook / MCP registration | Process ownership |
| --- | --- | --- |
| Applies to | Sessions HELM did **not** launch | Sessions HELM launches |
| Coverage | Hooked tool classes and routed MCP calls | Everything the child process does |
| Vendor changes | Client config is modified | Client is unmodified |
| Evidence | What the agent discloses | What the process was permitted to do |

Neither subsumes the other. A developer's own `claude` session is reachable only
by the hook path. A HELM-initiated run is better served by process ownership.

## Claim boundaries

What this code does **not** establish:

- **No native-runtime proof.** No sterile native Codex or Claude Code session has
  been observed end to end against these packages. The estate's
  `ClientLoadObserved=false` boundary language stands unchanged.
- **No receipt integration.** These packages do not yet emit an
  `AgentRunReceipt`, a ProofGraph node, or an EvidencePack.
- **No governed-execution claim.** Nothing here routes through the Guardian gate
  ladder, issues an `EffectPermit`, or produces a signed verdict.
- **Two capability flags are unverified.** `MCPInjectionRequiresFullAccess` on
  both adapters is inherited empirical posture, marked `UNVERIFIED` in source and
  pinned by no test. It must be re-proven against live CLIs before any claim
  depends on it.
- **Unix only.** The process layer uses `syscall.Kill`/`Setpgid` without build
  tags; release binaries target linux and darwin.

## Prior art

The boundary model — isolated envelope, byte-faithful diff capture, fresh
pre-apply re-verification, and the proven-versus-unknown distinction — follows
[razzant/claudexor](https://github.com/razzant/claudexor) (MIT), reimplemented in
Go for HELM.

One divergence is deliberate. That project documents config-owned
`protected_paths` as a user-facing approvals feature, but its producer is
hardcoded empty, so the feature is inert. HELM does not port that mechanism.
Human approval belongs on
[`core/pkg/boundary/approvalceremony`](../../core/pkg/boundary/approvalceremony),
where approvals are *spendable* — consumed rather than merely checked — which
composes with `EffectPermit`'s single-use and nonce semantics.
