# syntax=docker/dockerfile:1.7

# HELM-owned Kilo Code build recipe.
# Build context: pinned upstream Kilo-Org/kilocode checkout.
FROM oven/bun:1.3.13-debian@sha256:e95356cb8e1de62ad69ab3bd3584ba947013d27650a226804d2fc0af4e17dac2 AS build

WORKDIR /src/kilocode
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates g++ git make python3 \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN bun install --frozen-lockfile
RUN bun run --cwd packages/opencode build
RUN install -d /licenses/kilocode && cp LICENSE /licenses/kilocode/LICENSE

FROM node:24-bookworm-slim@sha256:24dc26ef1e3c3690f27ebc4136c9c186c3133b25563ae4d7f0692e4d1fe5db0e

LABEL io.mindburn.helm.launchpad.recipe="kilocode.helm-owned.v1"
ENV NODE_ENV=production
WORKDIR /opt/kilocode

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system helm \
    && useradd --system --gid helm --home-dir /opt/kilocode --shell /usr/sbin/nologin helm

COPY --from=build /src/kilocode /opt/kilocode
COPY --from=build /licenses /licenses

RUN <<'SH'
set -eu
cat > /usr/local/bin/kilocode <<'RUNNER'
#!/bin/sh
set -eu
case "$(uname -m)" in
  aarch64|arm64) target="/opt/kilocode/packages/opencode/dist/@kilocode/cli-linux-arm64/bin/kilo" ;;
  *) target="/opt/kilocode/packages/opencode/dist/@kilocode/cli-linux-x64/bin/kilo" ;;
esac
exec "${target}" "$@"
RUNNER
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
chmod 0755 /usr/local/bin/kilocode /usr/local/bin/helm-launchpad-openrouter-check
chown -R helm:helm /opt/kilocode /licenses
SH

USER helm
CMD ["kilocode"]
