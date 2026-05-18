# syntax=docker/dockerfile:1.7

# HELM-owned OpenClaw build recipe.
# Build context: pinned upstream openclaw/openclaw checkout.
FROM node:24-bookworm@sha256:3a09d9a8e3f4f34e8426515af2c7aa3a4d27ee6dd203d1f92b1d6c5b4d3c8ec8 AS build

WORKDIR /src/openclaw
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build:docker
RUN install -d /licenses/openclaw && cp LICENSE /licenses/openclaw/LICENSE

FROM node:24-bookworm-slim@sha256:e8e27cccd2d6b083a01fe8efce115471e0a8018615ed37c4110b3abb162ec907

LABEL io.mindburn.helm.launchpad.recipe="openclaw.helm-owned.v1"
ENV NODE_ENV=production
WORKDIR /opt/openclaw

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system helm \
    && useradd --system --gid helm --home-dir /opt/openclaw --shell /usr/sbin/nologin helm

COPY --from=build /src/openclaw /opt/openclaw
COPY --from=build /licenses /licenses

RUN <<'SH'
set -eu
ln -sf /opt/openclaw/openclaw.mjs /usr/local/bin/openclaw
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
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
  https://openrouter.ai/api/v1/key >/dev/null
CHECK
chmod 0755 /usr/local/bin/helm-launchpad-openrouter-check
chown -R helm:helm /opt/openclaw /licenses
SH

USER helm
ENTRYPOINT ["openclaw"]
