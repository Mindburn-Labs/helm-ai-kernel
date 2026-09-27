# syntax=docker/dockerfile:1.7

# HELM-owned OpenClaw build recipe.
# Build context: pinned upstream openclaw/openclaw checkout.
FROM node:26-bookworm@sha256:2aaae6d91f99fee84cfc92da9b52c22a185752d247746052bbc3f961e44478c6 AS build

WORKDIR /src/openclaw
RUN corepack enable
COPY . .
RUN pnpm install --frozen-lockfile
RUN pnpm build:docker
RUN install -d /licenses/openclaw && cp LICENSE /licenses/openclaw/LICENSE

FROM node:26-bookworm-slim@sha256:662933cf47f013bc8e4beb31a6116448427a82057ba7c42c97e4c5ba766504c2

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
COPY .helm-launchpad-model-gateway-check.sh /usr/local/bin/helm-launchpad-model-gateway-check

RUN <<'SH'
set -eu
ln -sf /opt/openclaw/openclaw.mjs /usr/local/bin/openclaw
ln -sf /usr/local/bin/helm-launchpad-model-gateway-check /usr/local/bin/helm-launchpad-openrouter-check
chmod 0755 /usr/local/bin/helm-launchpad-model-gateway-check
chown -R helm:helm /opt/openclaw /licenses
SH

USER helm
CMD ["openclaw"]
