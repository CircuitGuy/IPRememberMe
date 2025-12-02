FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/ipremember

FROM scratch
ARG IMAGE_VERSION=dev
ARG VCS_REF=unknown
COPY --from=builder /out/ipremember /ipremember
ENV LISTEN_ADDR=:8080
EXPOSE 8080
LABEL org.opencontainers.image.title="Authelia-IPRememberMe" \
      org.opencontainers.image.description="Lightweight sidecar that marks IPs trusted after Authelia login and refreshes TTL only with a signed cookie; includes status/admin endpoints and in-memory allowlist." \
      org.opencontainers.image.url="https://github.com/CircuitGuy/IPRememberMe" \
      org.opencontainers.image.source="https://github.com/CircuitGuy/IPRememberMe" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
ENTRYPOINT ["/ipremember"]
