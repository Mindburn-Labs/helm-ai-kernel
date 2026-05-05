# ── Stage 1: Build ─────────────────────────────────────
# SC-004: Base images pinned by digest for supply chain integrity
FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git ca-certificates
RUN mkdir -p /runtime-data

WORKDIR /src
COPY core/go.mod core/go.sum ./core/
WORKDIR /src/core
RUN --mount=type=cache,id=helm-oss-go-mod,target=/go/pkg/mod go mod download

WORKDIR /src
COPY core/ ./core/

# Build Kernel CLI
WORKDIR /src/core
RUN --mount=type=cache,id=helm-oss-go-mod,target=/go/pkg/mod --mount=type=cache,id=helm-oss-go-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build -ldflags="-s -w" -o /helm ./cmd/helm/

# ── Stage 2: Runtime ───────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1

COPY --from=builder /helm /usr/local/bin/helm
COPY --from=builder --chown=65532:65532 /runtime-data/ /var/lib/helm/
COPY apps/console/dist/ /usr/share/helm/console/
COPY release.high_risk.v3.toml /etc/helm/release.high_risk.v3.toml
COPY reference_packs/ /etc/helm/reference_packs/

EXPOSE 8080
EXPOSE 8081

ENV HELM_CONSOLE_DIR=/usr/share/helm/console
ENV HELM_DATA_DIR=/var/lib/helm

USER nonroot:nonroot

ENTRYPOINT ["helm"]
CMD ["serve", "--policy", "/etc/helm/release.high_risk.v3.toml", "--addr", "0.0.0.0", "--port", "8080", "--data-dir", "/var/lib/helm", "--console", "--console-dir", "/usr/share/helm/console"]
