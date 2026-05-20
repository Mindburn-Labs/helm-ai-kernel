# syntax=docker/dockerfile:1.7

# HELM-owned OpenCode build recipe.
# Build context: pinned upstream sst/opencode checkout.
FROM oven/bun:1.3.14-debian@sha256:9dba1a1b43ce28c9d7931bfc4eb00feb63b0114720a0277a8f939ae4dfc9db6f AS build

WORKDIR /src/opencode
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

RUN <<'SH'
set -eu
ln -sf /opt/opencode/packages/opencode/bin/opencode /usr/local/bin/opencode
cat > /usr/local/bin/helm-launchpad-openrouter-check <<'CHECK'
#!/bin/sh
set -eu
if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY missing" >&2
  exit 42
fi
if [ -z "${HTTPS_PROXY:-}" ] && [ -z "${HTTP_PROXY:-}" ]; then
  echo "Launchpad egress proxy missing" >&2
  exit 43
fi
status="$(curl --silent --show-error --connect-timeout 10 --max-time 30 \
  --output /dev/null --write-out "%{http_code}" \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  https://openrouter.ai/api/v1/key || true)"
if [ "$status" != "200" ]; then
  echo "OpenRouter key check failed with HTTP status ${status}" >&2
  exit 44
fi
CHECK
chmod 0755 /usr/local/bin/helm-launchpad-openrouter-check
chown -R helm:helm /opt/opencode /licenses
SH

USER helm
CMD ["opencode"]
