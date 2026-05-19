FROM golang:1.25.10-alpine@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS build
WORKDIR /src
COPY tools/launchpad/egressproxy/main.go ./main.go
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/helm-launchpad-egress-proxy ./main.go

FROM alpine:3.22@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601
RUN addgroup -S helm && adduser -S -G helm helm
COPY --from=build /out/helm-launchpad-egress-proxy /usr/local/bin/helm-launchpad-egress-proxy
USER helm
ENTRYPOINT ["/usr/local/bin/helm-launchpad-egress-proxy"]
