# ── Stage 1: Build ─────────────────────────────────────
# SC-004: Base images pinned by digest for supply chain integrity
FROM --platform=$BUILDPLATFORM golang:1.25.13-alpine@sha256:1e0126852075c9c60731c8ba49088448b91f63e2aed97ca9d1a9791622a05946 AS builder
ARG TARGETOS
ARG TARGETARCH
# Build metadata for /version. See /Dockerfile for the full explanation.
ARG BUILD_VERSION=unknown
ARG BUILD_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,id=helm-ai-kernel-go-mod,target=/go/pkg/mod go mod download

COPY . ./
RUN --mount=type=cache,id=helm-ai-kernel-go-mod,target=/go/pkg/mod --mount=type=cache,id=helm-ai-kernel-go-build,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" go build \
      -ldflags="-s -w -X main.version=${BUILD_VERSION} -X main.commit=${BUILD_COMMIT} -X main.buildTime=${BUILD_TIME}" \
      -trimpath -o /helm-ai-kernel ./cmd/helm-ai-kernel/

# ── Stage 2: Runtime ───────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1

COPY --from=builder /helm-ai-kernel /usr/local/bin/helm-ai-kernel

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["helm-ai-kernel"]
