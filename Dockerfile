FROM cgr.dev/chainguard/go:latest AS builder
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
USER 65532:65532
LABEL org.opencontainers.image.title="Authelia-IPRememberMe" \
      org.opencontainers.image.description="Adds an Authelia 2nd factor that trusts an IP after one login before exposing a self-hosted login screen; simple status/admin UI; everything stored in memory only." \
      org.opencontainers.image.url="https://github.com/CircuitGuy/IPRememberMe" \
      org.opencontainers.image.source="https://github.com/CircuitGuy/IPRememberMe" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
ENTRYPOINT ["/ipremember"]
