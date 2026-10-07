FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
# Copy the whole package (main.go + build-tagged origdst_{linux,other}.go + go.mod)
# and build in package mode so the linux SO_ORIGINAL_DST file is selected.
COPY tools/launchpad/egressproxy/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/helm-launchpad-egress-proxy .

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# iptables is required for the init-container role: the same image runs once with
# CAP_NET_ADMIN to install the transparent-redirect rules, then again unprivileged
# as the long-lived egress proxy sidecar.
RUN apk add --no-cache iptables
RUN addgroup -S helm && adduser -S -G helm helm
COPY --from=build /out/helm-launchpad-egress-proxy /usr/local/bin/helm-launchpad-egress-proxy
USER helm
ENTRYPOINT ["/usr/local/bin/helm-launchpad-egress-proxy"]
