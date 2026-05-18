# syntax=docker/dockerfile:1.7

# HELM-owned Hermes build recipe.
# Build context: pinned upstream NousResearch/hermes-agent checkout.
FROM ghcr.io/astral-sh/uv:0.8.14-python3.12-bookworm@sha256:317f1a5529e59e55e1280c04c950e40afb264df4968ec0bcd3a3d79708c814a4 AS build

WORKDIR /src/hermes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY . .
RUN uv sync --frozen --no-dev
RUN install -d /licenses/hermes && cp LICENSE /licenses/hermes/LICENSE

FROM python:3.12-slim-bookworm@sha256:b0223e13f68ee4a20edfc81510103d8bb34821f0f25b68f8594dffa4af4613d3

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

RUN <<'SH'
set -eu
cat > /usr/local/bin/hermes <<'HERMES'
#!/bin/sh
set -eu
exec python /opt/hermes/cli.py "$@"
HERMES
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
chmod 0755 /usr/local/bin/hermes /usr/local/bin/helm-launchpad-openrouter-check
chown -R helm:helm /opt/hermes /licenses
SH

USER helm
ENTRYPOINT ["hermes"]
