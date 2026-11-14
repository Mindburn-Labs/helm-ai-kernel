# ── Stage 1: Build ─────────────────────────────────────
# SC-004: Base images pinned by digest for supply chain integrity
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /helm-ai-kernel /usr/local/bin/helm-ai-kernel

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["helm-ai-kernel"]
