# syntax=docker/dockerfile:1.7

# HELM-owned Hermes build recipe.
# Build context: pinned upstream NousResearch/hermes-agent checkout.
FROM ghcr.io/astral-sh/uv:0.8.14-python3.12-bookworm@sha256:6f0e5c8496f34eba70f7f9f2e55d49e008b095d0395c16e3dda3437f95a2ec71 AS build

WORKDIR /src/hermes
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY . .
RUN uv sync --frozen --no-dev
RUN install -d /licenses/hermes && cp LICENSE /licenses/hermes/LICENSE

FROM python:3.12-slim-bookworm@sha256:d193c6f51a7dbd10395d6328de3a7edb0516fb0608ca138036576f574c3e07d2

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
CMD ["hermes"]
