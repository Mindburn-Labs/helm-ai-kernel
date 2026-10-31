FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
# Copy the whole package (main.go + build-tagged origdst_{linux,other}.go + go.mod)
# and build in package mode so the linux SO_ORIGINAL_DST file is selected.
COPY tools/launchpad/egressproxy/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/helm-launchpad-egress-proxy .

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# iptables is required for the init-container role: the same image runs once with
# CAP_NET_ADMIN to install the transparent-redirect rules, then again unprivileged
# as the long-lived egress proxy sidecar.
RUN apk add --no-cache iptables
RUN addgroup -S helm && adduser -S -G helm helm
COPY --from=build /out/helm-launchpad-egress-proxy /usr/local/bin/helm-launchpad-egress-proxy
USER helm
ENTRYPOINT ["/usr/local/bin/helm-launchpad-egress-proxy"]
