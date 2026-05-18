# syntax=docker/dockerfile:1.7

# HELM-owned OpenClaw build recipe.
# Build context: pinned upstream openclaw/openclaw checkout.
FROM node:24-bookworm@sha256:050bf2bbe33c1d6754e060bec89378a79ed831f04a7bb1a53fe45e997df7b3bb AS build

WORKDIR /src/openclaw
RUN corepack enable
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm build:docker
RUN install -d /licenses/openclaw && cp LICENSE /licenses/openclaw/LICENSE

FROM node:24-bookworm-slim@sha256:24dc26ef1e3c3690f27ebc4136c9c186c3133b25563ae4d7f0692e4d1fe5db0e

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
CMD ["openclaw"]
