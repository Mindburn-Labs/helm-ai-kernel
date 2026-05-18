FROM golang:1.25.10-alpine AS build
WORKDIR /src
COPY tools/launchpad/egressproxy/main.go ./main.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/helm-launchpad-egress-proxy ./main.go

FROM alpine:3.22
RUN addgroup -S helm && adduser -S -G helm helm
COPY --from=build /out/helm-launchpad-egress-proxy /usr/local/bin/helm-launchpad-egress-proxy
USER helm
ENTRYPOINT ["/usr/local/bin/helm-launchpad-egress-proxy"]
