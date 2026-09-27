# syntax=docker/dockerfile:1.7

# HELM-owned Hermes build recipe.
# Build context: pinned upstream NousResearch/hermes-agent checkout.
FROM node:22-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 AS node

FROM ghcr.io/astral-sh/uv:0.9.30-python3.12-bookworm@sha256:85d4cb1afa769a7338e095b927bee941cf5ec92266c7424b3f6c0f2748567248 AS build
WORKDIR /src/hermes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY . .
RUN uv sync --frozen --no-dev
RUN install -d /licenses/hermes && cp LICENSE /licenses/hermes/LICENSE

FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56

LABEL io.mindburn.helm.launchpad.recipe="hermes.helm-owned.v1"
ENV PATH="/opt/hermes/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1
WORKDIR /opt/hermes

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system helm \
    && useradd --system --gid helm --home-dir /opt/hermes --shell /usr/sbin/nologin helm

COPY --from=build /src/hermes /opt/hermes
COPY --from=build /licenses /licenses
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY .helm-launchpad-model-gateway-check.sh /usr/local/bin/helm-launchpad-model-gateway-check

RUN <<'SH'
set -eu
cat > /usr/local/bin/hermes <<'HERMES'
#!/bin/sh
set -eu
exec python /opt/hermes/cli.py "$@"
HERMES
ln -sf /usr/local/bin/helm-launchpad-model-gateway-check /usr/local/bin/helm-launchpad-openrouter-check
ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
node --version | grep -Eq '^v22\.'
npm --version >/dev/null
chmod 0755 /usr/local/bin/hermes /usr/local/bin/helm-launchpad-model-gateway-check
chown -R helm:helm /opt/hermes /licenses
SH

USER helm
CMD ["hermes"]
