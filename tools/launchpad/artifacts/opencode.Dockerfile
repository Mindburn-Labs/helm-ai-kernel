# syntax=docker/dockerfile:1.7

# HELM-owned OpenCode build recipe.
# Build context: pinned upstream sst/opencode checkout.
FROM oven/bun:1.3.14-debian@sha256:9dba1a1b43ce28c9d7931bfc4eb00feb63b0114720a0277a8f939ae4dfc9db6f AS build

WORKDIR /src/opencode
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates g++ git make python3 \
    && rm -rf /var/lib/apt/lists/*
COPY . .

# An immutable upstream tag can still declare floating git dependency specs. At
# v1.15.5, packages/app/package.json asks for
# "ghostty-web": "github:anomalyco/ghostty-web#main" while bun.lock records the
# commit that branch pointed at when the tag was cut. Bun re-resolves branch refs
# on every install, so as soon as the upstream branch advances past the locked
# commit, `bun install --frozen-lockfile` fails permanently and the pinned tag
# stops building — no artifact, no signature, no SBOM.
#
# Rewrite each git spec to the commit bun.lock already attests, so the frozen
# lockfile check verifies the tree the tag was cut against instead of whatever
# the branch tip happens to be today. This tightens the build: --frozen-lockfile
# stays on and now actually holds. Fails closed — a git spec with no resolved
# commit in bun.lock, or one that cannot be rewritten, aborts the build.
RUN <<'SH'
set -eu
cat > /tmp/pin-git-specs.mjs <<'JS'
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const lockText = readFileSync("bun.lock", "utf8");

// Resolution rows in bun.lock look like:
//   "ghostty-web": ["ghostty-web@github:anomalyco/ghostty-web#20bd361", {}, ...],
const locked = new Map();
for (const m of lockText.matchAll(/^\s*"([^"]+)":\s*\["[^"]*@github:([^#"]+)#([^"]+)"/gm)) {
  locked.set(`${m[1]}@${m[2]}`, m[3]);
}

const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];

function* declaredSpecs(pkg) {
  for (const section of SECTIONS) {
    for (const entry of Object.entries(pkg[section] ?? {})) yield entry;
  }
  const ws = pkg.workspaces;
  if (ws && !Array.isArray(ws)) {
    for (const entry of Object.entries(ws.catalog ?? {})) yield entry;
    for (const catalog of Object.values(ws.catalogs ?? {})) {
      for (const entry of Object.entries(catalog ?? {})) yield entry;
    }
  }
}

function manifests(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === ".git") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) manifests(p, out);
    else if (e.name === "package.json") out.push(p);
  }
  return out;
}

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const fail = (message) => {
  console.error(`pin-git-specs: ${message}`);
  process.exit(1);
};

let pinned = 0;
for (const file of manifests(".")) {
  const text = readFileSync(file, "utf8");
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    continue;
  }
  let next = text;
  for (const [name, spec] of declaredSpecs(pkg)) {
    if (typeof spec !== "string") continue;
    const parsed = /^github:([^#]+)#(.+)$/.exec(spec);
    if (!parsed) continue;
    const [, repo, ref] = parsed;
    const commit = locked.get(`${name}@${repo}`);
    if (!commit) fail(`${file}: "${name}": "${spec}" has no resolved commit in bun.lock`);
    if (commit === ref) continue;
    const pattern = new RegExp(
      `("${escape(name)}"\\s*:\\s*")github:${escape(repo)}#${escape(ref)}(")`,
      "g",
    );
    const rewritten = next.replace(pattern, `$1github:${repo}#${commit}$2`);
    if (rewritten === next) fail(`${file}: could not rewrite "${name}": "${spec}"`);
    next = rewritten;
    console.log(`pin-git-specs: ${name} ${ref} -> ${commit} (${file})`);
    pinned += 1;
  }
  if (next !== text) writeFileSync(file, next);
}
console.log(`pin-git-specs: pinned ${pinned} floating git dependency spec(s) from bun.lock`);
JS
bun /tmp/pin-git-specs.mjs
rm -f /tmp/pin-git-specs.mjs
SH

RUN bun install --frozen-lockfile
RUN bun run --cwd packages/opencode build
RUN install -d /licenses/opencode && cp LICENSE /licenses/opencode/LICENSE

FROM node:24-bookworm-slim@sha256:24dc26ef1e3c3690f27ebc4136c9c186c3133b25563ae4d7f0692e4d1fe5db0e

ARG OPENCODE_VERSION
LABEL io.mindburn.helm.launchpad.recipe="opencode.helm-owned.v1"
ENV NODE_ENV=production \
    OPENCODE_VERSION=${OPENCODE_VERSION}
WORKDIR /opt/opencode

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system helm \
    && useradd --system --gid helm --home-dir /opt/opencode --shell /usr/sbin/nologin helm

COPY --from=build /src/opencode /opt/opencode
COPY --from=build /licenses /licenses
COPY .helm-launchpad-model-gateway-check.sh /usr/local/bin/helm-launchpad-model-gateway-check

RUN <<'SH'
set -eu
cat > /usr/local/bin/opencode <<'RUNNER'
#!/bin/sh
set -eu
case "$(uname -m)" in
  aarch64|arm64) target="/opt/opencode/packages/opencode/dist/opencode-linux-arm64/bin/opencode" ;;
  *) target="/opt/opencode/packages/opencode/dist/opencode-linux-x64/bin/opencode" ;;
esac
exec "${target}" "$@"
RUNNER
ln -sf /usr/local/bin/helm-launchpad-model-gateway-check /usr/local/bin/helm-launchpad-openrouter-check
chmod 0755 /usr/local/bin/opencode /usr/local/bin/helm-launchpad-model-gateway-check
chown -R helm:helm /opt/opencode /licenses
SH

USER helm
CMD ["opencode"]
