FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
WORKDIR /src
# Copy the whole package (main.go + build-tagged origdst_{linux,other}.go + go.mod)
# and build in package mode so the linux SO_ORIGINAL_DST file is selected.
COPY tools/launchpad/egressproxy/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/helm-launchpad-egress-proxy .

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# iptables is required for the init-container role: the same image runs once with
# CAP_NET_ADMIN to install the transparent-redirect rules, then again unprivileged
# as the long-lived egress proxy sidecar.
RUN apk add --no-cache iptables
RUN addgroup -S helm && adduser -S -G helm helm
COPY --from=build /out/helm-launchpad-egress-proxy /usr/local/bin/helm-launchpad-egress-proxy
USER helm
ENTRYPOINT ["/usr/local/bin/helm-launchpad-egress-proxy"]
