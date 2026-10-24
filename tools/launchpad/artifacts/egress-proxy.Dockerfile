FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
# Copy the whole package (main.go + build-tagged origdst_{linux,other}.go + go.mod)
# and build in package mode so the linux SO_ORIGINAL_DST file is selected.
COPY tools/launchpad/egressproxy/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/helm-launchpad-egress-proxy .

FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601
# iptables is required for the init-container role: the same image runs once with
# CAP_NET_ADMIN to install the transparent-redirect rules, then again unprivileged
# as the long-lived egress proxy sidecar.
RUN apk add --no-cache iptables
RUN addgroup -S helm && adduser -S -G helm helm
COPY --from=build /out/helm-launchpad-egress-proxy /usr/local/bin/helm-launchpad-egress-proxy
USER helm
ENTRYPOINT ["/usr/local/bin/helm-launchpad-egress-proxy"]
