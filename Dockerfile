# ── Stage 1: Build ─────────────────────────────────────
# SC-004: Base images pinned by digest for supply chain integrity
FROM --platform=$BUILDPLATFORM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS builder
ARG TARGETOS
ARG TARGETARCH
# Build metadata injected via ldflags into main.{version,commit,buildTime} and
# surfaced through GET /version. Defaults stay "unknown" so a bare `docker build`
# without --build-arg still produces a working binary, just without provenance.
ARG BUILD_VERSION=unknown
ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN apk add --no-cache git ca-certificates
RUN mkdir -p /runtime-data

WORKDIR /src
COPY core/go.mod core/go.sum ./core/
WORKDIR /src/core
RUN --mount=type=cache,id=helm-ai-kernel-go-mod,target=/go/pkg/mod go mod download

WORKDIR /src
COPY core/ ./core/

# Build Kernel CLI
WORKDIR /src/core
RUN --mount=type=cache,id=helm-ai-kernel-go-mod,target=/go/pkg/mod --mount=type=cache,id=helm-ai-kernel-go-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build \
      -ldflags="-s -w -X main.version=${BUILD_VERSION} -X main.commit=${BUILD_COMMIT} -X main.buildTime=${BUILD_TIME}" \
      -o /helm-ai-kernel ./cmd/helm-ai-kernel/

# ── Stage 2: Runtime ───────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1

COPY --from=builder /helm-ai-kernel /usr/local/bin/helm-ai-kernel
COPY --from=builder --chown=65532:65532 /runtime-data/ /var/lib/helm-ai-kernel/
COPY release.high_risk.v3.toml /etc/helm-ai-kernel/release.high_risk.v3.toml
COPY reference_packs/ /etc/helm-ai-kernel/reference_packs/

EXPOSE 8080
EXPOSE 8081

ENV HELM_DATA_DIR=/var/lib/helm-ai-kernel

USER nonroot:nonroot

ENTRYPOINT ["helm-ai-kernel"]
CMD ["serve", "--policy", "/etc/helm-ai-kernel/release.high_risk.v3.toml", "--addr", "0.0.0.0", "--port", "8080", "--data-dir", "/var/lib/helm-ai-kernel"]
