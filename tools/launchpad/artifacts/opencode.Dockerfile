# syntax=docker/dockerfile:1.7

# HELM-owned OpenCode build recipe.
# Build context: pinned upstream sst/opencode checkout.
FROM oven/bun:1.3.14-debian@sha256:9dba1a1b43ce28c9d7931bfc4eb00feb63b0114720a0277a8f939ae4dfc9db6f AS build

WORKDIR /src/opencode
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates g++ git make python3 \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN bun install --frozen-lockfile
RUN bun run --cwd packages/opencode build
RUN install -d /licenses/opencode && cp LICENSE /licenses/opencode/LICENSE

FROM node:24-bookworm-slim@sha256:24dc26ef1e3c3690f27ebc4136c9c186c3133b25563ae4d7f0692e4d1fe5db0e

LABEL io.mindburn.helm.launchpad.recipe="opencode.helm-owned.v1"
ENV NODE_ENV=production
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
