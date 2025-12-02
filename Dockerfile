FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/ipremember

FROM scratch
COPY --from=builder /out/ipremember /ipremember
ENV LISTEN_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/ipremember"]
